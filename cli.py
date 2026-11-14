#!/usr/bin/env python3
"""
recon — a from-scratch network reconnaissance tool (CLI).

Nmap-style flags drive the same engine the web app uses. Examples:

    python cli.py 192.168.1.0/24 -p 1-1000 -sS -sV -O
    python cli.py scanme.lab -p- -T4 --authorized
    python cli.py 10.0.0.5 -sU -p 53,123,161
    python cli.py 10.0.0.5 -sF -f --mtu 8 -D RND:4,ME        # stealth + evasion (lab)
    python cli.py 10.0.0.5 -p 80,443 -oX report.xml -oJ report.json

Authorized use only. By default it scans only loopback/RFC-1918/lab ranges;
pass --authorized to assert you have permission for anything else.
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from scanner import authorization, reporting
from scanner.engine import run_scan
from scanner.models import EventType, ScanConfig, ScanEvent, ScanType
from scanner.packet.raw import capability_report
from scanner.timing import template


# ---- colour (ANSI, degrade gracefully) -------------------------------------
class C:
    G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; B = "\033[36m"; D = "\033[2m"; X = "\033[0m"


def _color(enabled: bool):
    if enabled:
        return C
    class Plain:  # noqa
        G = R = Y = B = D = X = ""
    return Plain


def parse_ports(spec: str) -> tuple[List[int], str]:
    """Parse '1-1024,3306,8080' or '-' (all). Returns (ports, query-string)."""
    if spec.strip() == "-":
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
    return sorted(ports), spec.strip()


_SCAN_FLAGS = {
    "sT": ScanType.CONNECT, "sS": ScanType.SYN, "sF": ScanType.FIN,
    "sN": ScanType.NULL, "sX": ScanType.XMAS, "sA": ScanType.ACK,
    "sW": ScanType.WINDOW, "sM": ScanType.MAIMON, "sU": ScanType.UDP,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="IP, hostname, CIDR (10.0.0.0/24) or range (10.0.0.1-20)")
    p.add_argument("-p", "--ports", default="1-1000", help="ports: '80,443', '1-1024', or '-' for all")

    g = p.add_argument_group("scan type")
    for flag in _SCAN_FLAGS:
        g.add_argument(f"-{flag}", action="store_true", help=f"{_SCAN_FLAGS[flag].value} scan")

    d = p.add_argument_group("detection")
    d.add_argument("-sV", dest="service", action="store_true", help="service/version detection")
    d.add_argument("-O", dest="osdetect", action="store_true", help="OS fingerprinting")
    d.add_argument("--no-vuln", action="store_true", help="skip offline CVE matching")
    d.add_argument("-Pn", dest="skip_discovery", action="store_true", help="skip host discovery (treat as up)")

    t = p.add_argument_group("timing")
    for i in range(6):
        t.add_argument(f"-T{i}", dest="timing", action="store_const", const=i, help=argparse.SUPPRESS)
    t.add_argument("--timeout", type=float, help="per-probe timeout seconds (override template)")
    t.add_argument("--max-concurrency", type=int, help="max concurrent probes")

    e = p.add_argument_group("evasion (authorized lab use)")
    e.add_argument("-f", dest="frag", action="store_true", help="fragment packets (MTU 8)")
    e.add_argument("--mtu", type=int, default=0, help="fragment to this data MTU (multiple of 8)")
    e.add_argument("-D", dest="decoys", help="decoys: 'RND:5' or '1.2.3.4,ME,5.6.7.8'")
    e.add_argument("-S", dest="spoof", help="spoof source IP (replies won't return)")
    e.add_argument("--source-port", type=int, help="fix source port (e.g. 53)")
    e.add_argument("--ttl", type=int, help="custom IP TTL")
    e.add_argument("--badsum", action="store_true", help="send a bad TCP checksum")
    e.add_argument("--data-length", type=int, default=0, help="append N random payload bytes")

    o = p.add_argument_group("output")
    o.add_argument("-oJ", dest="out_json", help="write JSON report to file")
    o.add_argument("-oX", dest="out_xml", help="write XML report to file")
    o.add_argument("-oC", dest="out_csv", help="write CSV report to file")
    o.add_argument("-oM", dest="out_md", help="write Markdown report to file")
    o.add_argument("--no-color", action="store_true", help="disable coloured output")

    p.add_argument("--authorized", action="store_true",
                   help="assert you are authorized to scan non-lab targets")
    p.add_argument("--allow", action="append", default=[], metavar="CIDR",
                   help="add a CIDR to the authorization allowlist (repeatable)")
    return p


def chosen_scan_type(args) -> ScanType:
    for flag, st in _SCAN_FLAGS.items():
        if getattr(args, flag, False):
            return st
    return ScanType.CONNECT


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    col = _color(not args.no_color and sys.stdout.isatty())

    for cidr in args.allow:
        authorization.add_allowed(cidr)

    try:
        ports, query = parse_ports(args.ports)
    except ValueError as exc:
        print(f"{col.R}port error:{col.X} {exc}", file=sys.stderr)
        return 2

    tmpl = template(args.timing if args.timing is not None else 3)
    scan_type = chosen_scan_type(args)

    cfg = ScanConfig(
        target=args.target,
        ports=ports,
        port_query=query,
        scan_type=scan_type,
        timing=args.timing if args.timing is not None else 3,
        max_concurrency=args.max_concurrency or tmpl.max_concurrency,
        timeout=args.timeout or tmpl.timeout,
        retries=tmpl.retries,
        scan_delay=tmpl.scan_delay,
        jitter=tmpl.jitter,
        skip_discovery=args.skip_discovery,
        service_detection=args.service,
        os_detection=args.osdetect,
        vuln_check=not args.no_vuln,
        frag_mtu=(args.mtu or (8 if args.frag else 0)),
        decoys=[d.strip() for d in args.decoys.split(",")] if args.decoys else [],
        spoof_source=args.spoof,
        source_port=args.source_port,
        ttl=args.ttl,
        bad_checksum=args.badsum,
        data_length=args.data_length,
        authorized=args.authorized,
    )

    cap = capability_report()
    print(f"{col.D}# recon — {cap['os']} | {cap['note']}{col.X}")
    print(f"{col.B}# target {args.target} | {scan_type.value} scan | ports {query} | {tmpl.name} timing{col.X}\n")

    def on_event(e: ScanEvent) -> None:
        if e.type is EventType.PORT_RESULT:
            print(f"  {col.G}{e.data.get('host')}:{e.data.get('port')}{col.X} "
                  f"{e.data.get('state')} ({e.data.get('reason')})")
        elif e.type is EventType.STAGE:
            print(f"{col.B}[*] {e.message}{col.X}")
        elif e.type is EventType.WARNING:
            print(f"  {col.Y}[!] {e.message}{col.X}")
        elif e.type is EventType.HOST_UP:
            print(f"{col.G}[+] {e.message}{col.X}")
        elif e.type is EventType.ERROR:
            print(f"{col.R}[x] {e.message}{col.X}", file=sys.stderr)

    result = run_scan(cfg, on_event=on_event)

    # Summary table.
    print(f"\n{col.B}=== Results ==={col.X}")
    for host in result.hosts:
        name = f" ({host.hostname})" if host.hostname else ""
        print(f"\n{col.G}{host.host}{name}{col.X}")
        if host.os and host.os.name != "Unknown":
            print(f"  OS: {host.os.name} ({host.os.confidence:.0%})")
        opens = [p for p in host.ports if p.state.value.startswith("open")]
        shown = opens or host.ports[:10]
        print(f"  {'PORT':<9}{'STATE':<14}{'SERVICE':<12}VERSION")
        for p in shown:
            svc = p.service
            sname = svc.name if svc else ""
            sver = f"{svc.product} {svc.version}".strip() if svc else ""
            print(f"  {str(p.port)+'/'+p.protocol:<9}{p.state.value:<14}{sname:<12}{sver}")
            for v in (svc.vulns if svc else []):
                print(f"    {col.R}{v.cve}{col.X} {v.severity} — {v.summary}")
    print(f"\n{col.D}done in {result.duration:.1f}s{col.X}")

    # Reports.
    for attr, fmt in (("out_json", "json"), ("out_xml", "xml"), ("out_csv", "csv"), ("out_md", "markdown")):
        path = getattr(args, attr)
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(reporting.render(result, fmt))
            print(f"{col.D}wrote {fmt} -> {path}{col.X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
