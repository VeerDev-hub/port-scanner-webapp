from flask import Flask, request, jsonify, render_template
import os
import socket
import threading
import time
import uuid
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

from enrichment import (
    detect_firewall,
    detect_os,
    discover_hosts,
    get_geolocation,
    get_route_table,
    reverse_dns,
)
from scanner_core import scan_port
from validators import extract_domain, parse_bool, parse_port_targets

app = Flask(__name__)

SCAN_JOBS = {}
SCAN_LOCK = threading.Lock()
DB_PATH = os.path.join(os.path.dirname(__file__), "scan_data.db")


def _db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT,
                created_at REAL,
                started_at REAL,
                finished_at REAL,
                target TEXT,
                target_mode TEXT,
                completed INTEGER,
                total INTEGER,
                percent REAL,
                eta_seconds REAL,
                logs TEXT,
                error TEXT,
                result TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                target_key TEXT,
                target_mode TEXT,
                scanned_hosts TEXT,
                scanned_ports INTEGER,
                open_ports_count INTEGER,
                open_ports TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _persist_job(job):
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO jobs (
                job_id, status, created_at, started_at, finished_at, target, target_mode,
                completed, total, percent, eta_seconds, logs, error, result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                status=excluded.status,
                created_at=excluded.created_at,
                started_at=excluded.started_at,
                finished_at=excluded.finished_at,
                target=excluded.target,
                target_mode=excluded.target_mode,
                completed=excluded.completed,
                total=excluded.total,
                percent=excluded.percent,
                eta_seconds=excluded.eta_seconds,
                logs=excluded.logs,
                error=excluded.error,
                result=excluded.result
            """,
            (
                job.get("id"),
                job.get("status"),
                job.get("created_at"),
                job.get("started_at"),
                job.get("finished_at"),
                job.get("target"),
                job.get("target_mode"),
                int(job.get("completed", 0)),
                int(job.get("total", 0)),
                float(job.get("percent", 0.0)),
                None if job.get("eta_seconds") is None else float(job.get("eta_seconds")),
                json.dumps(job.get("logs", [])),
                json.dumps(job.get("error")) if job.get("error") is not None else None,
                json.dumps(job.get("result")) if job.get("result") is not None else None,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _fetch_job_from_db(job_id):
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["job_id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "target": row["target"],
            "target_mode": row["target_mode"],
            "completed": row["completed"] or 0,
            "total": row["total"] or 0,
            "percent": row["percent"] or 0.0,
            "eta_seconds": row["eta_seconds"],
            "logs": json.loads(row["logs"] or "[]"),
            "error": json.loads(row["error"]) if row["error"] else None,
            "result": json.loads(row["result"]) if row["result"] else None,
        }
    finally:
        conn.close()


init_db()


def error_response(message, code="bad_request", status=400, hint=None, details=None):
    payload = {"error": {"code": code, "message": message}}
    if hint:
        payload["error"]["hint"] = hint
    if details is not None:
        payload["error"]["details"] = details
    return jsonify(payload), status


def _set_job(job_id, **updates):
    with SCAN_LOCK:
        if job_id in SCAN_JOBS:
            SCAN_JOBS[job_id].update(updates)
            _persist_job(SCAN_JOBS[job_id])


def _append_log(job_id, line):
    with SCAN_LOCK:
        if job_id not in SCAN_JOBS:
            return
        logs = SCAN_JOBS[job_id].setdefault("logs", [])
        logs.append(line)
        if len(logs) > 400:
            del logs[:200]
        _persist_job(SCAN_JOBS[job_id])


def _snapshot_job(job_id):
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)
        if job:
            return dict(job)
    return _fetch_job_from_db(job_id)


def _record_history(result):
    target_key = result.get("target", "unknown")
    open_ports = sorted(
        f"{entry.get('host', result.get('ip', 'unknown'))}:{entry.get('port')}"
        for entry in result.get("results", [])
        if "open" in (entry.get("status", "").lower())
    )

    compare = {"opened": open_ports, "closed": []}
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT open_ports FROM history WHERE target_key = ? ORDER BY id DESC LIMIT 1",
            (target_key,),
        )
        row = cur.fetchone()
        if row:
            previous_ports = json.loads(row["open_ports"] or "[]")
            previous_set = set(previous_ports)
            current_set = set(open_ports)
            compare = {
                "opened": sorted(current_set - previous_set),
                "closed": sorted(previous_set - current_set),
            }

        cur.execute(
            """
            INSERT INTO history (
                timestamp, target_key, target_mode, scanned_hosts, scanned_ports, open_ports_count, open_ports
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(time.time()),
                target_key,
                result.get("target_mode"),
                json.dumps(result.get("scanned_hosts", [])),
                int(result.get("scanned_ports", 0)),
                int(len(open_ports)),
                json.dumps(open_ports),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return compare


def _resolve_scan_targets(target_raw, scan_all_hosts=False):
    target_clean = extract_domain(target_raw)
    if not target_clean:
        raise ValueError("No target specified")

    if "/" in target_clean:
        alive_hosts = discover_hosts(target_clean)
        if not alive_hosts:
            raise ValueError("No alive hosts discovered in CIDR target")
        if scan_all_hosts:
            return target_clean, "cidr", alive_hosts, alive_hosts
        return target_clean, "cidr", alive_hosts, [alive_hosts[0]]

    try:
        ip = socket.gethostbyname(target_clean)
    except Exception as exc:
        raise ValueError("Invalid domain or IP") from exc
    return target_clean, "single", [ip], [ip]


def run_scan_job(job_id, payload):
    try:
        target_input = payload.get("target")
        port_range_raw = payload.get("port_range", "")
        scan_type_raw = str(payload.get("scan_type", "SYN")).upper()
        scan_type = scan_type_raw if scan_type_raw in {"SYN", "UDP", "STEALTH", "CONNECT"} else "SYN"
        show_all = parse_bool(payload.get("show_all"), default=False)
        include_route = parse_bool(payload.get("include_route"), default=True)
        scan_all_hosts = parse_bool(payload.get("scan_all_hosts"), default=False)

        ports_list, port_query = parse_port_targets(
            port_range_raw=port_range_raw,
            ports_count_raw=payload.get("ports", 100),
        )

        try:
            workers = int(payload.get("workers", 200))
        except Exception:
            workers = 200
        workers = max(1, min(1000, workers))
        try:
            timeout_seconds = float(payload.get("timeout", 1.0))
        except Exception:
            timeout_seconds = 1.0
        timeout_seconds = max(0.2, min(5.0, timeout_seconds))
        try:
            retries = int(payload.get("retries", 0))
        except Exception:
            retries = 0
        retries = max(0, min(3, retries))
        try:
            delay_seconds = float(payload.get("delay", 0.0))
        except Exception:
            delay_seconds = 0.0
        delay_seconds = max(0.0, min(1.0, delay_seconds))

        target_clean, target_mode, alive_hosts, scan_hosts = _resolve_scan_targets(
            target_input, scan_all_hosts=scan_all_hosts
        )
        primary_ip = scan_hosts[0]
        total = len(scan_hosts) * len(ports_list)
        started_at = time.time()

        _set_job(
            job_id,
            status="running",
            target=target_clean,
            target_mode=target_mode,
            alive_hosts=alive_hosts,
            scanned_hosts=scan_hosts,
            total=total,
            completed=0,
            percent=0.0,
            started_at=started_at,
        )
        _append_log(job_id, f"Starting {scan_type} scan on {target_clean} ({target_mode})")
        _append_log(job_id, f"Ports: {port_query}")

        geolocation = get_geolocation(primary_ip)
        firewall = detect_firewall(primary_ip, host_header=target_clean)
        os_detected = detect_os(primary_ip)
        hostname = reverse_dns(primary_ip)
        route_table = get_route_table(primary_ip) if include_route else []

        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {}
            for host in scan_hosts:
                for port in ports_list:
                    future = executor.submit(
                        scan_port,
                        host,
                        port,
                        scan_type,
                        timeout_seconds,
                        retries,
                        delay_seconds,
                        target_clean,
                    )
                    future_map[future] = host

            for future in as_completed(future_map):
                host = future_map[future]
                result = future.result()
                result["host"] = host
                results.append(result)
                _append_log(
                    job_id,
                    f"{host}:{result.get('port')} -> {result.get('status', 'Unknown')}"
                )
                completed += 1
                percent = round((completed / total) * 100, 2) if total else 100.0
                elapsed = max(0.001, time.time() - started_at)
                eta_seconds = ((elapsed / completed) * (total - completed)) if completed > 0 else None
                if completed % 20 == 0 or completed == total:
                    _append_log(job_id, f"Progress: {completed}/{total}")
                _set_job(job_id, completed=completed, percent=percent, eta_seconds=eta_seconds)

        if not show_all:
            results = [r for r in results if "open" in r.get("status", "").lower()]

        results = sorted(results, key=lambda x: (x.get("host", ""), x.get("port", 0)))

        final_result = {
            "target": target_clean,
            "target_mode": target_mode,
            "alive_hosts": alive_hosts,
            "scanned_hosts": scan_hosts,
            "ip": primary_ip,
            "hostname": hostname,
            "geolocation": geolocation,
            "os": os_detected,
            "scan_type": scan_type,
            "port_query": port_query,
            "scanned_ports": len(ports_list),
            "firewall": firewall,
            "include_route": include_route,
            "route_table": route_table,
            "logs": _snapshot_job(job_id).get("logs", []),
            "results": results,
        }
        final_result["compare"] = _record_history(final_result)

        _set_job(
            job_id,
            status="completed",
            completed=total,
            percent=100.0,
            eta_seconds=0.0,
            finished_at=time.time(),
            result=final_result,
        )
        _append_log(job_id, "Scan complete.")
    except ValueError as exc:
        _set_job(
            job_id,
            status="failed",
            finished_at=time.time(),
            error={"code": "validation_error", "message": str(exc)},
        )
    except Exception as exc:
        _set_job(
            job_id,
            status="failed",
            finished_at=time.time(),
            error={
                "code": "internal_error",
                "message": "Internal server error during scanning.",
                "details": str(exc),
            },
        )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/history")
def history():
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT timestamp, target_key, target_mode, scanned_hosts, scanned_ports, open_ports_count
            FROM history
            ORDER BY id DESC
            LIMIT 20
            """
        )
        rows = cur.fetchall()
        items = []
        for row in rows:
            items.append(
                {
                    "timestamp": row["timestamp"],
                    "target_key": row["target_key"],
                    "target_mode": row["target_mode"],
                    "scanned_hosts": json.loads(row["scanned_hosts"] or "[]"),
                    "scanned_ports": row["scanned_ports"] or 0,
                    "open_ports_count": row["open_ports_count"] or 0,
                }
            )
        return jsonify({"history": items})
    finally:
        conn.close()


@app.route("/scan/start", methods=["POST"])
def scan_start():
    data = request.json or {}
    if not data.get("target"):
        return error_response("No target specified", hint="Provide a domain, IP, or CIDR block.")

    job_id = str(uuid.uuid4())
    with SCAN_LOCK:
        SCAN_JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "created_at": time.time(),
            "logs": [],
            "completed": 0,
            "total": 0,
            "percent": 0.0,
            "eta_seconds": None,
        }
        _persist_job(SCAN_JOBS[job_id])

    thread = threading.Thread(target=run_scan_job, args=(job_id, data), daemon=True)
    thread.start()
    return jsonify({"job_id": job_id})


@app.route("/scan/status/<job_id>")
def scan_status(job_id):
    job = _snapshot_job(job_id)
    if not job:
        return error_response("Scan job not found", code="not_found", status=404)

    return jsonify(
        {
            "job_id": job_id,
            "status": job.get("status"),
            "completed": job.get("completed", 0),
            "total": job.get("total", 0),
            "percent": job.get("percent", 0.0),
            "eta_seconds": job.get("eta_seconds"),
            "logs": job.get("logs", []),
            "target": job.get("target"),
            "target_mode": job.get("target_mode"),
        }
    )


@app.route("/scan/result/<job_id>")
def scan_result(job_id):
    job = _snapshot_job(job_id)
    if not job:
        return error_response("Scan job not found", code="not_found", status=404)

    status = job.get("status")
    if status in {"queued", "running"}:
        return jsonify({"job_id": job_id, "status": status}), 202
    if status == "failed":
        err = job.get("error") or {"code": "scan_failed", "message": "Scan failed"}
        return jsonify({"job_id": job_id, "status": status, "error": err}), 400
    return jsonify(job.get("result", {}))


@app.route("/scan", methods=["POST"])
def scan_legacy():
    """
    Backward-compatible sync route.
    Starts an async job, waits for completion, then returns result.
    """
    data = request.json or {}
    if not data.get("target"):
        return error_response("No target specified", hint="Provide a domain, IP, or CIDR block.")

    job_id = str(uuid.uuid4())
    with SCAN_LOCK:
        SCAN_JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "created_at": time.time(),
            "logs": [],
            "completed": 0,
            "total": 0,
            "percent": 0.0,
            "eta_seconds": None,
        }
        _persist_job(SCAN_JOBS[job_id])
    run_scan_job(job_id, data)
    job = _snapshot_job(job_id)
    if not job:
        return error_response("Scan job disappeared", code="internal_error", status=500)
    if job.get("status") == "failed":
        return jsonify({"error": job.get("error", {"message": "Scan failed"})}), 400
    return jsonify(job.get("result", {}))


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)
