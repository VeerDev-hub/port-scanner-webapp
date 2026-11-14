"""
UDP scan (-sU).

UDP has no handshake, so inference is indirect:

    UDP data reply            -> OPEN
    ICMP port-unreachable     -> CLOSED      (type 3, code 3)
    ICMP other unreachable    -> FILTERED
    nothing                   -> OPEN|FILTERED

We use a *connected* UDP socket, which is portable (Linux and Windows both
surface an incoming ICMP port-unreachable as a ConnectionRefused-style error
on the next recv). For well-known ports we send a real protocol probe instead
of an empty datagram, because many UDP services only answer a valid request —
sending nothing would leave every port looking open|filtered.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Tuple

from ..models import PortState


def _dns_query() -> bytes:
    # A minimal DNS A-record query for "version.bind" style probe -> any reply = open.
    txn = b"\x12\x34"
    flags = b"\x01\x00"  # standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qname = b"\x07version\x04bind\x00"
    qtype_class = struct.pack("!HH", 16, 3)  # TXT, CHAOS
    return txn + flags + counts + qname + qtype_class


def _ntp_query() -> bytes:
    # NTP mode 3 (client) request, 48 bytes.
    return b"\x1b" + b"\x00" * 47


def _snmp_query() -> bytes:
    # SNMPv1 get-request, community "public", for sysDescr.0 — compact canned packet.
    return bytes.fromhex(
        "302602010004067075626c6963a019020400000000020100020100"
        "300b300906052b060102010500"
    )


# Port -> payload that is likely to elicit a response from that service.
_PROBES = {
    53: _dns_query(),
    123: _ntp_query(),
    161: _snmp_query(),
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
}


def scan(host: str, port: int, timeout: float = 2.0) -> Tuple[PortState, str, float | None]:
    payload = _PROBES.get(port, b"\x00")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    start = time.perf_counter()
    try:
        s.connect((host, port))
        s.send(payload)
        data = s.recv(2048)
        rtt = (time.perf_counter() - start) * 1000.0
        if data:
            return PortState.OPEN, "udp-reply", round(rtt, 2)
        return PortState.OPEN_FILTERED, "empty-reply", round(rtt, 2)
    except socket.timeout:
        # No answer: could be an open service that ignores our probe, or filtered.
        return PortState.OPEN_FILTERED, "no-response", None
    except ConnectionRefusedError:
        # The kernel saw an ICMP port-unreachable -> port is closed.
        return PortState.CLOSED, "icmp-port-unreach", None
    except OSError as exc:
        return PortState.FILTERED, f"oserror:{exc.errno}", None
    finally:
        try:
            s.close()
        except OSError:
            pass
