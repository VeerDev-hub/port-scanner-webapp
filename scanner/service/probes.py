"""
Probe definitions: what to send to coax a service into identifying itself.

Many services announce themselves the moment you connect (SSH, FTP, SMTP,
POP3, IMAP, Redis), so the "NULL probe" — connect and just read — handles
them. Others stay silent until spoken to (HTTP, TLS), so we send a tailored
request. Probes are tried in order of how likely they are for a given port.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Probe:
    name: str
    payload: bytes                 # bytes to send (empty = just read)
    ports: List[int] = field(default_factory=list)  # ports this probe suits
    tls: bool = False              # wrap the socket in TLS first
    wait_banner: bool = True       # read a greeting before/after sending


# The generic greeting reader — works for most text protocols.
NULL = Probe(name="null", payload=b"", ports=[], wait_banner=True)

# A deliberately generic HTTP request (host header filled in by the grabber).
HTTP = Probe(
    name="http",
    payload=b"GET / HTTP/1.0\r\nUser-Agent: recon\r\nAccept: */*\r\n\r\n",
    ports=[80, 8080, 8000, 8888, 591, 8008, 8081, 3000, 5000],
    wait_banner=False,
)

HTTPS = Probe(
    name="https",
    payload=b"GET / HTTP/1.0\r\nUser-Agent: recon\r\nAccept: */*\r\n\r\n",
    ports=[443, 8443, 9443, 4433],
    tls=True,
    wait_banner=False,
)

# Redis answers PING with +PONG; MySQL/Mongo send a handshake on connect.
REDIS = Probe(name="redis", payload=b"PING\r\n", ports=[6379], wait_banner=False)
HELP = Probe(name="help", payload=b"HELP\r\n", ports=[], wait_banner=True)


def probes_for_port(port: int) -> List[Probe]:
    """Ordered list of probes to try for a TCP port."""
    ordered: List[Probe] = []
    if port in HTTPS.ports:
        ordered.append(HTTPS)
    if port in HTTP.ports:
        ordered.append(HTTP)
    if port in REDIS.ports:
        ordered.append(REDIS)
    # The NULL probe is always worth trying for banner-first services.
    ordered.append(NULL)
    # As a last resort, nudge a silent service.
    ordered.append(HELP)
    return ordered
