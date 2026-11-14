"""
Report writers: turn a ScanResult into CSV, JSON, XML, Markdown or HTML.

All output is generated locally and escaped where it lands in markup, so a
hostile banner (e.g. one containing HTML/XML) cannot inject into a report.
"""

from __future__ import annotations

import html
import json
import io
import csv as _csv
from xml.sax.saxutils import escape as xml_escape, quoteattr
from typing import Any, Dict

from .models import ScanResult


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["host", "hostname", "port", "protocol", "state", "reason",
                "service", "product", "version", "rtt_ms", "cves"])
    for host in result.hosts:
        for p in host.ports:
            svc = p.service
            cves = ";".join(v.cve for v in svc.vulns) if svc else ""
            w.writerow([
                p.host, host.hostname or "", p.port, p.protocol, p.state.value, p.reason,
                svc.name if svc else "", svc.product if svc else "",
                svc.version if svc else "", p.rtt_ms if p.rtt_ms is not None else "",
                cves,
            ])
    return buf.getvalue()


def to_markdown(result: ScanResult) -> str:
    d = result.to_dict()
    lines = [
        f"# Reconnaissance Report — {d['target']}",
        "",
        f"- **Scan type:** {d['scan_type']}",
        f"- **Ports:** {d['port_query']}",
        f"- **Duration:** {d['duration']:.1f}s",
        f"- **Capability:** {d['capability'].get('note', '')}",
    ]
    if d["evasion"]:
        lines.append(f"- **Evasion:** {', '.join(d['evasion'])}")
    if d["warnings"]:
        lines.append(f"- **Warnings:** {'; '.join(d['warnings'])}")
    lines.append("")
    for host in result.hosts:
        lines.append(f"## {host.host}" + (f" ({host.hostname})" if host.hostname else ""))
        if host.os and host.os.name != "Unknown":
            lines.append(f"- OS guess: {host.os.name} ({host.os.confidence:.0%})")
        lines.append("")
        lines.append("| Port | Proto | State | Service | Product | Version | CVEs |")
        lines.append("|---:|---|---|---|---|---|---|")
        for p in host.ports:
            svc = p.service
            cves = ", ".join(v.cve for v in svc.vulns) if svc else ""
            lines.append(
                f"| {p.port} | {p.protocol} | {p.state.value} | "
                f"{svc.name if svc else ''} | {svc.product if svc else ''} | "
                f"{(svc.version if svc else '')} | {cves} |"
            )
        lines.append("")
    return "\n".join(lines)


def to_xml(result: ScanResult) -> str:
    d = result.to_dict()
    out = ['<?xml version="1.0" encoding="UTF-8"?>']
    out.append(
        f'<reconrun target={quoteattr(d["target"])} scantype={quoteattr(d["scan_type"])} '
        f'ports={quoteattr(d["port_query"])} duration="{d["duration"]:.2f}">'
    )
    for host in result.hosts:
        out.append(f'  <host addr={quoteattr(host.host)} state={quoteattr(host.state)}>')
        if host.hostname:
            out.append(f'    <hostname name={quoteattr(host.hostname)}/>')
        if host.os and host.os.name != "Unknown":
            out.append(f'    <os name={quoteattr(host.os.name)} confidence="{host.os.confidence:.2f}"/>')
        out.append("    <ports>")
        for p in host.ports:
            svc = p.service
            out.append(f'      <port protocol={quoteattr(p.protocol)} portid="{p.port}">')
            out.append(f'        <state state={quoteattr(p.state.value)} reason={quoteattr(p.reason)}/>')
            if svc:
                out.append(
                    f'        <service name={quoteattr(svc.name)} product={quoteattr(svc.product)} '
                    f'version={quoteattr(svc.version)}/>'
                )
                for v in svc.vulns:
                    out.append(
                        f'        <vuln id={quoteattr(v.cve)} severity={quoteattr(v.severity)}>'
                        f'{xml_escape(v.summary)}</vuln>'
                    )
            out.append("      </port>")
        out.append("    </ports>")
        out.append("  </host>")
    out.append("</reconrun>")
    return "\n".join(out)


def to_html(result: ScanResult) -> str:
    d = result.to_dict()
    e = html.escape
    rows = []
    for host in result.hosts:
        for p in host.ports:
            svc = p.service
            cves = ", ".join(e(v.cve) for v in svc.vulns) if svc else ""
            rows.append(
                "<tr>"
                f"<td>{e(p.host)}</td><td>{p.port}</td><td>{e(p.protocol)}</td>"
                f"<td>{e(p.state.value)}</td>"
                f"<td>{e(svc.name if svc else '')}</td>"
                f"<td>{e(svc.product if svc else '')}</td>"
                f"<td>{e(svc.version if svc else '')}</td>"
                f"<td>{cves}</td></tr>"
            )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>Recon report — {e(d['target'])}</title>"
        "<style>body{font-family:monospace;background:#0a120a;color:#d3ffe1;padding:20px}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #1b3a22;padding:4px 8px;text-align:left}"
        "th{color:#39ff70}</style></head><body>"
        f"<h1>Recon report — {e(d['target'])}</h1>"
        f"<p>Scan type: {e(d['scan_type'])} | Ports: {e(d['port_query'])} | "
        f"Duration: {d['duration']:.1f}s</p>"
        "<table><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th>"
        "<th>Service</th><th>Product</th><th>Version</th><th>CVEs</th></tr>"
        + "".join(rows) +
        "</table></body></html>"
    )


WRITERS = {
    "json": to_json,
    "csv": to_csv,
    "markdown": to_markdown,
    "md": to_markdown,
    "xml": to_xml,
    "html": to_html,
}


def render(result: ScanResult, fmt: str) -> str:
    writer = WRITERS.get(fmt.lower())
    if not writer:
        raise ValueError(f"Unknown report format: {fmt}")
    return writer(result)
