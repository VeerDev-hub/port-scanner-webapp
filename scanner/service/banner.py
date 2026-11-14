"""
Banner grabbing and service identification over plain sockets.

Replaces the old `requests`-based HTTP enrichment. For each open TCP port we
try the probes suited to it (see probes.py): read any greeting, optionally
send a request, wrap in TLS where needed, then feed the response to the
signature table. We also pull an HTTP <title> and the certificate subject so
the UI has something human-readable.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional

from ..models import Service
from . import probes as probe_defs
from . import signatures

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HTTP_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _read(sock: socket.socket, limit: int = 4096) -> bytes:
    chunks = []
    got = 0
    try:
        while got < limit:
            data = sock.recv(min(2048, limit - got))
            if not data:
                break
            chunks.append(data)
            got += len(data)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def _grab_one(host: str, port: int, probe: "probe_defs.Probe", host_header: str, timeout: float) -> bytes:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    sock: socket.socket = raw
    try:
        raw.connect((host, port))
        if probe.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host_header or host)

        banner = b""
        if probe.wait_banner:
            banner += _read(sock, 2048)
        if probe.payload:
            payload = probe.payload
            if probe.name in ("http", "https"):
                payload = payload.replace(
                    b"\r\n\r\n",
                    b"\r\nHost: " + (host_header or host).encode("idna", "ignore") + b"\r\n\r\n",
                    1,
                )
            sock.sendall(payload)
            banner += _read(sock, 4096)
        return banner
    except (socket.timeout, OSError, ssl.SSLError):
        return b""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _cert_subject(host: str, port: int, host_header: str, timeout: float) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host_header or host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return ""
                subject = cert.get("subject", [])
                cn = ""
                for rdn in subject:
                    for k, v in rdn:
                        if k == "commonName":
                            cn = v
                return cn
    except (OSError, ssl.SSLError, ValueError):
        return ""


def identify(host: str, port: int, host_header: Optional[str] = None, timeout: float = 2.0) -> Service:
    """
    Probe an open TCP port and return a populated Service (name/product/
    version/banner + a confidence estimate). ``host_header`` is the per-host
    name to present to HTTP/TLS (fixes the old CIDR bug where the whole
    CIDR string was used as the Host).
    """
    host_header = host_header or host
    best = Service()
    for probe in probe_defs.probes_for_port(port):
        banner_bytes = _grab_one(host, port, probe, host_header, timeout)
        if not banner_bytes:
            continue
        text = banner_bytes.decode("utf-8", "replace")
        service, product, version = signatures.match(text)

        svc = Service(banner=text.strip()[:500])
        if service:
            svc.name = service
            svc.product = product
            svc.version = version
            svc.confidence = 0.9 if version else 0.6
        # HTTP niceties: title + Server header even if signature was generic.
        if probe.name in ("http", "https"):
            svc.name = svc.name or ("https" if probe.tls else "http")
            m = _TITLE_RE.search(text)
            if m:
                svc.extra = f"title: {m.group(1).strip()[:120]}"
            sm = _HTTP_SERVER_RE.search(text)
            if sm and not svc.product:
                svc.product = sm.group(1).strip()
                svc.confidence = max(svc.confidence, 0.5)
            if probe.tls:
                cn = _cert_subject(host, port, host_header, timeout)
                if cn:
                    svc.extra = (svc.extra + f"; CN={cn}").strip("; ")

        # Keep the most informative result across probes.
        if svc.confidence > best.confidence or (svc.banner and not best.banner):
            best = svc
        if best.version:
            break  # a concrete version is good enough; stop probing
    return best
