"""
Flask web front-end for the recon engine.

Design changes from the old app:
  * Scans run on the new standalone engine (scanner/), not inline Scapy code.
  * Live updates stream over Server-Sent Events (/scan/stream/<job>) instead of
    700ms polling, so the browser gets each event as it happens.
  * SQLite writes are batched: the job row is persisted on meaningful
    transitions, not on every single log line (the old code rewrote the whole
    row, logs included, per line under a global lock).
  * The server keeps ALL results; the client filters open/closed, so the
    "show all" toggle is restorable (old bug).
  * Jobs are capped and cancellable; finished jobs are pruned.
  * No external calls, so nothing about a target leaves the machine.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
import uuid
from typing import Dict, Optional

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from scanner import authorization, reporting
from scanner.engine import ScanEngine
from scanner.models import EventType, ScanConfig, ScanEvent, ScanType
from scanner.packet.raw import capability_report
from scanner.timing import template

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "scan_data.db")
MAX_JOBS = 50
MAX_PORTS = 65535
MAX_HOSTS = 1024

_JOBS: Dict[str, "Job"] = {}
_JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- DB
def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_HISTORY_COLUMNS = {
    "id", "timestamp", "target", "scan_type", "hosts", "ports",
    "open_count", "open_ports", "result",
}


def init_db() -> None:
    conn = _db()
    try:
        # Migrate away from the old incompatible schema (target_key/... columns).
        existing = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='history'"
        ).fetchone()
        if existing:
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(history)")}
            if cols != _HISTORY_COLUMNS:
                conn.execute("DROP TABLE history")
                conn.commit()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                target TEXT,
                scan_type TEXT,
                hosts INTEGER,
                ports INTEGER,
                open_count INTEGER,
                open_ports TEXT,
                result TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _record_history(result) -> Dict[str, list]:
    """Persist a finished scan and diff it against the previous run of the same target."""
    open_keys = sorted(
        f"{p.host}:{p.port}" for p in result.all_ports()
        if p.state.value.startswith("open")
    )
    compare = {"opened": open_keys, "closed": []}
    conn = _db()
    try:
        row = conn.execute(
            "SELECT open_ports FROM history WHERE target = ? ORDER BY id DESC LIMIT 1",
            (result.target,),
        ).fetchone()
        if row:
            prev = set(json.loads(row["open_ports"] or "[]"))
            cur = set(open_keys)
            compare = {"opened": sorted(cur - prev), "closed": sorted(prev - cur)}
        conn.execute(
            "INSERT INTO history (timestamp, target, scan_type, hosts, ports, open_count, open_ports, result) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                int(time.time()), result.target, result.scan_type, len(result.hosts),
                len(result.port_query), len(open_keys), json.dumps(open_keys),
                json.dumps(result.to_dict()),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return compare


# ------------------------------------------------------------------------- Jobs
class Job:
    """One running scan: owns its engine, an event queue, and a buffered log."""

    def __init__(self, job_id: str, config: ScanConfig):
        self.id = job_id
        self.config = config
        self.status = "queued"
        self.created_at = time.time()
        self.events: "queue.Queue[ScanEvent]" = queue.Queue()
        self.log: list[str] = []
        self.progress = {"completed": 0, "total": 0, "percent": 0.0, "eta_seconds": None}
        self.result_dict: Optional[dict] = None
        self.error: Optional[str] = None
        self.engine = ScanEngine(config, on_event=self._on_event)
        self._thread: Optional[threading.Thread] = None

    def _on_event(self, e: ScanEvent) -> None:
        if e.type is EventType.PROGRESS:
            self.progress = {
                "completed": e.data.get("completed", 0),
                "total": e.data.get("total", 0),
                "percent": e.data.get("percent", 0.0),
                "eta_seconds": e.data.get("eta_seconds"),
            }
        elif e.message:
            self.log.append(e.message)
            if len(self.log) > 500:
                del self.log[:250]
        self.events.put(e)

    def start(self) -> None:
        self.status = "running"
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            result = self.engine.run()
            compare = _record_history(result)
            d = result.to_dict()
            d["compare"] = compare
            self.result_dict = d
            self.status = "failed" if result.warnings and not result.hosts else "completed"
        except Exception as exc:  # pragma: no cover - defensive
            self.error = str(exc)
            self.status = "failed"
            self.events.put(ScanEvent(EventType.ERROR, f"Scan crashed: {exc}"))
        finally:
            self.events.put(ScanEvent(EventType.DONE, "stream-end", data={"final": True}))

    def cancel(self) -> None:
        self.engine.cancel()
        self.status = "cancelled"


def _prune_jobs() -> None:
    with _JOBS_LOCK:
        if len(_JOBS) <= MAX_JOBS:
            return
        done = sorted(
            (j for j in _JOBS.values() if j.status in ("completed", "failed", "cancelled")),
            key=lambda j: j.created_at,
        )
        for j in done[: len(_JOBS) - MAX_JOBS]:
            _JOBS.pop(j.id, None)


def _build_config(data: dict) -> ScanConfig:
    scan_type = ScanType(data.get("scan_type", "connect")) if data.get("scan_type") in ScanType._value2member_map_ else ScanType.CONNECT
    ports, query = _parse_ports(data.get("ports", "1-1000"))
    tmpl = template(int(data.get("timing", 3)))
    for cidr in data.get("allow", []) or []:
        try:
            authorization.add_allowed(cidr)
        except ValueError:
            pass
    return ScanConfig(
        target=str(data.get("target", "")).strip(),
        ports=ports,
        port_query=query,
        scan_type=scan_type,
        timing=int(data.get("timing", 3)),
        max_concurrency=tmpl.max_concurrency,
        timeout=float(data.get("timeout", tmpl.timeout)),
        retries=tmpl.retries,
        scan_delay=tmpl.scan_delay,
        jitter=tmpl.jitter,
        skip_discovery=bool(data.get("skip_discovery", False)),
        discover_all_hosts=bool(data.get("scan_all_hosts", True)),
        service_detection=bool(data.get("service_detection", True)),
        os_detection=bool(data.get("os_detection", False)),
        vuln_check=bool(data.get("vuln_check", True)),
        frag_mtu=int(data.get("frag_mtu", 0)),
        decoys=[d.strip() for d in str(data.get("decoys", "")).split(",") if d.strip()],
        source_port=int(data["source_port"]) if data.get("source_port") else None,
        ttl=int(data["ttl"]) if data.get("ttl") else None,
        authorized=bool(data.get("authorized", False)),
    )


def _parse_ports(spec: str):
    spec = str(spec).strip()
    if spec == "-":
        return list(range(1, 65536)), "1-65535"
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if not (1 <= lo_i <= hi_i <= 65535):
                raise ValueError(f"bad range: {chunk}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            p = int(chunk)
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of range: {chunk}")
            ports.add(p)
    if not ports:
        raise ValueError("no ports parsed")
    return sorted(ports), spec


# ----------------------------------------------------------------------- Routes
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "capability": capability_report()})


@app.route("/capability")
def capability():
    return jsonify(capability_report())


@app.route("/scan/start", methods=["POST"])
def scan_start():
    data = request.get_json(silent=True) or {}
    if not data.get("target"):
        return jsonify({"error": {"message": "No target specified"}}), 400
    try:
        config = _build_config(data)
    except ValueError as exc:
        return jsonify({"error": {"message": f"Invalid scan options: {exc}"}}), 400
    if len(config.ports) > MAX_PORTS:
        return jsonify({"error": {"message": "Too many ports requested"}}), 400

    job_id = str(uuid.uuid4())
    job = Job(job_id, config)
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    _prune_jobs()
    job.start()
    return jsonify({"job_id": job_id, "capability": capability_report()})


@app.route("/scan/stream/<job_id>")
def scan_stream(job_id):
    """Server-Sent Events: forward engine events to the browser as they occur."""
    job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": {"message": "job not found"}}), 404

    @stream_with_context
    def generate():
        yield f"data: {json.dumps({'type': 'hello', 'capability': capability_report()})}\n\n"
        while True:
            try:
                e = job.events.get(timeout=30)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            payload = e.to_dict()
            if e.type is EventType.DONE and e.data.get("final"):
                payload["status"] = job.status
                payload["result"] = job.result_dict
                yield f"data: {json.dumps(payload, default=str)}\n\n"
                break
            yield f"data: {json.dumps(payload, default=str)}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/scan/result/<job_id>")
def scan_result(job_id):
    job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": {"message": "job not found"}}), 404
    if job.status in ("queued", "running"):
        return jsonify({"status": job.status, "progress": job.progress}), 202
    if job.status == "failed" and not job.result_dict:
        return jsonify({"status": "failed", "error": job.error or "scan failed"}), 400
    return jsonify({"status": job.status, "result": job.result_dict})


@app.route("/scan/cancel/<job_id>", methods=["POST"])
def scan_cancel(job_id):
    job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": {"message": "job not found"}}), 404
    job.cancel()
    return jsonify({"status": "cancelled"})


@app.route("/scan/report/<job_id>.<fmt>")
def scan_report(job_id, fmt):
    job = _JOBS.get(job_id)
    if not job or not job.result_dict:
        return jsonify({"error": {"message": "no result"}}), 404
    # Rebuild a lightweight ScanResult view is overkill; render from stored dict.
    from scanner.models import ScanResult, HostResult, PortResult, PortState, Service, Vulnerability, OSMatch
    d = job.result_dict
    hosts = []
    for h in d.get("hosts", []):
        ports = []
        for p in h.get("ports", []):
            svc = None
            if p.get("service"):
                s = p["service"]
                svc = Service(
                    name=s.get("name", ""), product=s.get("product", ""),
                    version=s.get("version", ""), extra=s.get("extra", ""),
                    banner=s.get("banner", ""), confidence=s.get("confidence", 0.0),
                    vulns=[Vulnerability(**v) for v in s.get("vulns", [])],
                )
            ports.append(PortResult(
                host=p["host"], port=p["port"], protocol=p.get("protocol", "tcp"),
                state=PortState(p["state"]), reason=p.get("reason", ""),
                service=svc, rtt_ms=p.get("rtt_ms"),
            ))
        os_m = OSMatch(**h["os"]) if h.get("os") else None
        hosts.append(HostResult(host=h["host"], hostname=h.get("hostname"),
                                state=h.get("state", "up"), ports=ports, os=os_m))
    result = ScanResult(
        target=d["target"], scan_type=d["scan_type"], port_query=d["port_query"],
        started_at=d["started_at"], finished_at=d["finished_at"], hosts=hosts,
        capability=d.get("capability", {}), evasion=d.get("evasion", []),
        warnings=d.get("warnings", []),
    )
    try:
        body = reporting.render(result, fmt)
    except ValueError:
        return jsonify({"error": {"message": "unknown format"}}), 400
    ctype = {"json": "application/json", "csv": "text/csv", "xml": "application/xml",
             "html": "text/html", "markdown": "text/markdown", "md": "text/markdown"}.get(fmt, "text/plain")
    return Response(body, mimetype=ctype,
                    headers={"Content-Disposition": f'attachment; filename="recon_{job_id[:8]}.{fmt}"'})


@app.route("/history")
def history():
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT timestamp, target, scan_type, hosts, ports, open_count "
            "FROM history ORDER BY id DESC LIMIT 25"
        ).fetchall()
        return jsonify({"history": [dict(r) for r in rows]})
    finally:
        conn.close()


init_db()


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    # Threaded so SSE streams and scans run concurrently.
    app.run(host=host, port=port, debug=debug, threaded=True)
