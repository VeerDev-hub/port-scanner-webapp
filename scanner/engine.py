"""
The scan engine: turns a ScanConfig into a ScanResult, emitting ScanEvents as
it goes so both the CLI and the web app can show live progress.

Pipeline:
    authorize -> resolve targets -> discover live hosts -> port scan
    -> service/version detection -> OS fingerprint -> vuln match -> done

The port-scan concurrency, timing and evasion all come from the config. Raw
scan types are gated by raw.can_craft_tcp(); when unavailable the engine warns
and falls back to the connect scan rather than failing.
"""

from __future__ import annotations

import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from . import authorization, discovery, osfingerprint
from .evasion import Evasion, expand_decoys
from .models import (
    EventType, HostResult, PortResult, PortState, ScanConfig, ScanEvent,
    ScanResult, ScanType, Service,
)
from .packet.raw import can_craft_tcp, capability_report, local_source_ip
from .scans import ack, connect, maimon, stealth, syn, udp
from .service import banner as banner_mod
from .timing import template
from .vulns import match as vuln_match

EventSink = Callable[[ScanEvent], None]


class ScanEngine:
    def __init__(self, config: ScanConfig, on_event: Optional[EventSink] = None):
        self.cfg = config
        self._sink = on_event or (lambda e: None)
        self._cancel = threading.Event()
        self._completed = 0
        self._total = 0
        self._lock = threading.Lock()
        self._evasion = self._build_evasion()

    # ------------------------------------------------------------------ events
    def cancel(self) -> None:
        self._cancel.set()

    def _emit(self, etype: EventType, message: str = "", **data) -> None:
        self._sink(ScanEvent(type=etype, message=message, data=data))

    def _log(self, message: str) -> None:
        self._emit(EventType.LOG, message)

    # --------------------------------------------------------------- evasion
    def _build_evasion(self) -> Evasion:
        c = self.cfg
        return Evasion(
            frag_mtu=c.frag_mtu,
            decoys=list(c.decoys),
            spoof_source=c.spoof_source,
            source_port=c.source_port,
            ttl=c.ttl,
            bad_checksum=c.bad_checksum,
            data_length=c.data_length,
        )

    # --------------------------------------------------------------- scanning
    def _effective_scan_type(self, warnings: List[str]) -> ScanType:
        st = self.cfg.scan_type
        if st.needs_raw and st is not ScanType.UDP and not can_craft_tcp():
            warnings.append(
                f"{st.value.upper()} scan needs raw sockets (unavailable here); "
                f"falling back to TCP connect scan."
            )
            return ScanType.CONNECT
        return st

    def _scan_one_port(self, host: str, port: int, scan_type: ScanType) -> PortResult:
        ev = self._evasion
        timeout = self.cfg.timeout
        retries = self.cfg.retries

        if self.cfg.scan_delay:
            delay = self.cfg.scan_delay
            if self.cfg.jitter:
                delay += random.uniform(0, self.cfg.jitter)
            time.sleep(delay)

        proto = "udp" if scan_type is ScanType.UDP else "tcp"
        if scan_type is ScanType.CONNECT:
            state, reason, rtt = connect.scan(host, port, timeout, ev.source_port)
        elif scan_type is ScanType.SYN:
            state, reason, rtt = syn.scan(host, port, timeout, retries, ev)
        elif scan_type in (ScanType.FIN, ScanType.NULL, ScanType.XMAS):
            state, reason, rtt = stealth.scan(host, port, scan_type.value, timeout, retries, ev)
        elif scan_type is ScanType.ACK:
            state, reason, rtt = ack.scan(host, port, False, timeout, retries, ev)
        elif scan_type is ScanType.WINDOW:
            state, reason, rtt = ack.scan(host, port, True, timeout, retries, ev)
        elif scan_type is ScanType.MAIMON:
            state, reason, rtt = maimon.scan(host, port, timeout, retries, ev)
        elif scan_type is ScanType.UDP:
            state, reason, rtt = udp.scan(host, port, max(timeout, 2.0))
        else:
            state, reason, rtt = PortState.ERROR, "unsupported", None

        return PortResult(host=host, port=port, protocol=proto, state=state, reason=reason, rtt_ms=rtt)

    def _enrich_port(self, result: PortResult, host_header: str) -> None:
        """Service/version detection + vuln match for an open TCP port."""
        if result.protocol != "tcp":
            return
        if result.state not in (PortState.OPEN, PortState.OPEN_FILTERED):
            return
        svc: Service = banner_mod.identify(result.host, result.port, host_header, self.cfg.timeout)
        if self.cfg.vuln_check and svc.product and svc.version:
            svc.vulns = vuln_match.lookup(svc.product, svc.version)
        result.service = svc

    # ------------------------------------------------------------------- run
    def run(self) -> ScanResult:
        cfg = self.cfg
        started = time.time()
        warnings: List[str] = []

        # 1) Resolve the target expression into IPs.
        self._emit(EventType.STAGE, "Resolving targets")
        try:
            hosts = discovery.expand_targets(cfg.target)
        except (socket.gaierror, ValueError) as exc:
            self._emit(EventType.ERROR, f"Could not resolve target: {exc}")
            return ScanResult(cfg.target, cfg.scan_type.value, cfg.port_query, started, time.time(),
                              warnings=[f"resolve failed: {exc}"])
        if not hosts:
            self._emit(EventType.ERROR, "No hosts to scan")
            return ScanResult(cfg.target, cfg.scan_type.value, cfg.port_query, started, time.time(),
                              warnings=["no hosts"])

        # 2) Authorization gate (every host must pass or be explicitly authorized).
        for ip in hosts:
            try:
                authorization.check(ip, cfg.authorized)
            except authorization.AuthorizationError as exc:
                self._emit(EventType.ERROR, str(exc))
                return ScanResult(cfg.target, cfg.scan_type.value, cfg.port_query, started, time.time(),
                                  warnings=[str(exc)])
        self._log(authorization.banner(cfg.authorized))

        # 3) Resolve decoys now that we know the real source IP. Decoy tokens
        #    may include "RND:n" and "ME"; expand_decoys always keeps the real
        #    source in the list so genuine replies still reach us.
        if cfg.decoys:
            real_source = local_source_ip(hosts[0])
            self._evasion.decoys = expand_decoys(",".join(cfg.decoys), real_source)
        if self._evasion.active:
            for note in self._evasion.summary():
                self._emit(EventType.WARNING, f"evasion: {note}")

        # 4) Host discovery.
        live = hosts
        if not cfg.skip_discovery and len(hosts) > 1:
            self._emit(EventType.STAGE, f"Discovering live hosts ({len(hosts)} candidates)")
            live = discovery.discover(
                hosts, timeout=cfg.timeout, max_concurrency=cfg.max_concurrency,
                on_host_up=lambda ip, reason: self._emit(EventType.HOST_UP, f"{ip} up ({reason})", host=ip, reason=reason),
            )
            if not live:
                warnings.append("No live hosts discovered; use skip_discovery to scan anyway.")
            if not cfg.discover_all_hosts and live:
                live = live[:1]

        scan_type = self._effective_scan_type(warnings)
        for w in warnings:
            self._emit(EventType.WARNING, w)

        # 5) Port scan (across all live hosts), concurrent, with ordering control.
        ordered_hosts = list(live)
        if cfg.randomize_hosts:
            random.shuffle(ordered_hosts)
        ports = list(cfg.ports)
        if cfg.randomize_ports:
            random.shuffle(ports)

        self._total = len(ordered_hosts) * len(ports)
        self._completed = 0
        self._emit(EventType.STAGE, f"Scanning {len(ports)} ports x {len(ordered_hosts)} host(s) [{scan_type.value}]")

        host_results: dict[str, HostResult] = {
            ip: HostResult(host=ip, hostname=_safe_rdns(ip)) for ip in ordered_hosts
        }

        work = [(h, p) for h in ordered_hosts for p in ports]
        with ThreadPoolExecutor(max_workers=max(1, min(cfg.max_concurrency, 1000))) as pool:
            futures = {pool.submit(self._scan_one_port, h, p, scan_type): (h, p) for h, p in work}
            for fut in as_completed(futures):
                if self._cancel.is_set():
                    break
                h, p = futures[fut]
                try:
                    res = fut.result()
                except Exception as exc:
                    res = PortResult(host=h, port=p, state=PortState.ERROR, reason=str(exc)[:80])
                host_results[h].ports.append(res)
                with self._lock:
                    self._completed += 1
                    done, total = self._completed, self._total
                if res.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                    self._emit(EventType.PORT_RESULT, f"{h}:{p} {res.state.value}",
                               host=h, port=p, state=res.state.value, reason=res.reason)
                pct = round(done / total * 100, 1) if total else 100.0
                eta = None
                elapsed = time.time() - started
                if done:
                    eta = round((elapsed / done) * (total - done), 1)
                self._emit(EventType.PROGRESS, "", completed=done, total=total, percent=pct, eta_seconds=eta)

        # 6) Service/version detection + vuln match on open TCP ports.
        if cfg.service_detection and scan_type is not ScanType.UDP:
            self._emit(EventType.STAGE, "Service/version detection")
            self._enrich_all(host_results, warnings)

        # 7) OS fingerprint (one per host, needs an open port ideally).
        if cfg.os_detection:
            self._emit(EventType.STAGE, "OS fingerprinting")
            for hr in host_results.values():
                if self._cancel.is_set():
                    break
                open_tcp = next((pt.port for pt in hr.open_ports() if pt.protocol == "tcp"), None)
                hr.os = osfingerprint.fingerprint(hr.host, open_tcp, hr.ports, cfg.timeout)
                if hr.os and hr.os.name != "Unknown":
                    self._emit(EventType.LOG, f"{hr.host} OS guess: {hr.os.name} ({hr.os.confidence:.0%})")

        # 8) Sort ports for stable output and finish.
        for hr in host_results.values():
            hr.ports.sort(key=lambda x: (x.protocol, x.port))

        result = ScanResult(
            target=cfg.target,
            scan_type=scan_type.value,
            port_query=cfg.port_query,
            started_at=started,
            finished_at=time.time(),
            hosts=[host_results[ip] for ip in ordered_hosts if ip in host_results],
            capability=capability_report(),
            evasion=self._evasion.summary(),
            warnings=warnings,
        )
        self._emit(EventType.DONE, "Scan complete",
                   open_ports=sum(len(h.open_ports()) for h in result.hosts))
        return result

    def _enrich_all(self, host_results: dict, warnings: List[str]) -> None:
        tasks = []
        for hr in host_results.values():
            host_header = hr.hostname or hr.host
            for pt in hr.ports:
                if pt.protocol == "tcp" and pt.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                    tasks.append((pt, host_header))
        if not tasks:
            return
        with ThreadPoolExecutor(max_workers=max(1, min(50, len(tasks)))) as pool:
            futs = {pool.submit(self._enrich_port, pt, hh): pt for pt, hh in tasks}
            for fut in as_completed(futs):
                if self._cancel.is_set():
                    break
                pt = futs[fut]
                try:
                    fut.result()
                    if pt.service and pt.service.name:
                        extra = f" {pt.service.product} {pt.service.version}".rstrip()
                        self._emit(EventType.LOG, f"{pt.host}:{pt.port} -> {pt.service.name}{extra}")
                    for v in (pt.service.vulns if pt.service else []):
                        self._emit(EventType.WARNING, f"{pt.host}:{pt.port} {v.cve} ({v.severity}) {v.summary}")
                except Exception as exc:
                    warnings.append(f"enrich {pt.host}:{pt.port} failed: {exc}")


def _safe_rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def run_scan(config: ScanConfig, on_event: Optional[EventSink] = None) -> ScanResult:
    """Convenience wrapper: build an engine, run it, return the result."""
    return ScanEngine(config, on_event).run()
