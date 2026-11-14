"""
Raw-socket send/receive and per-OS capability detection.

Crafted-packet scans (SYN, stealth, ACK, fragmentation, decoys, spoofing)
need to put bytes on the wire ourselves and sniff the replies. That requires:

  * Linux/macOS: root (or CAP_NET_RAW). Fully supported.
  * Windows:     the OS silently drops *outgoing TCP* sent over raw sockets
                 (a deliberate restriction since XP SP2), so crafted TCP scans
                 do not work without a capture driver (Npcap). We detect this
                 and let the engine fall back to the connect scan.

`can_craft_tcp()` is the single gate the engine checks before choosing a
raw scan. Nothing here imports Scapy — the fallback is our own connect scan.
"""

from __future__ import annotations

import platform
import socket
import struct
import time
from typing import Optional, Tuple

from .ipv4 import PROTO_TCP, PROTO_UDP, PROTO_ICMP

IS_WINDOWS = platform.system().lower().startswith("win")

_capability_cache: Optional[bool] = None


def can_craft_tcp() -> bool:
    """
    True if this process can send crafted TCP packets on raw sockets.

    Requires privilege everywhere, and is effectively unavailable on Windows.
    The result is cached after the first probe.
    """
    global _capability_cache
    if _capability_cache is not None:
        return _capability_cache

    if IS_WINDOWS:
        # Even as Administrator, Windows will not transmit raw TCP. Treat as
        # unavailable so the engine degrades to the connect scan.
        _capability_cache = False
        return _capability_cache

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.close()
        _capability_cache = True
    except (PermissionError, OSError):
        _capability_cache = False
    return _capability_cache


def capability_report() -> dict:
    """Human-readable summary of what this host can do, for the UI/CLI banner."""
    raw = can_craft_tcp()
    return {
        "os": platform.system(),
        "raw_tcp": raw,
        "note": (
            "Crafted-packet scans (SYN/stealth/frag/decoy) available."
            if raw
            else (
                "Raw TCP unavailable on Windows; crafted scans fall back to "
                "TCP connect. Run on Linux as root for the full feature set."
                if IS_WINDOWS
                else "Raw sockets need root/CAP_NET_RAW; run with sudo for crafted scans."
            )
        ),
    }


class RawSender:
    """
    An IP_HDRINCL raw socket: we supply the whole IP header, the kernel just
    transmits. Used for every crafted scan. One sender can be reused for many
    probes; it is not thread-safe, so give each worker thread its own.
    """

    def __init__(self, proto: int = PROTO_TCP):
        if not can_craft_tcp() and proto in (PROTO_TCP, PROTO_UDP):
            raise PermissionError("Raw packet crafting unavailable on this host")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(self, packet: bytes, dst_ip: str, dst_port: int = 0) -> None:
        self.sock.sendto(packet, (dst_ip, dst_port))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "RawSender":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class RawReceiver:
    """
    Sniff inbound IP packets of one protocol. We read whole IP packets
    (including the header) and hand them to the IPv4 parser.

    A single receiver collects replies for many outstanding probes; callers
    filter by src/dst/port themselves. Linux delivers the IP header on a
    SOCK_RAW of the given protocol.
    """

    def __init__(self, proto: int = PROTO_TCP, timeout: float = 2.0):
        self.proto = proto
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        self.sock.settimeout(timeout)

    def set_timeout(self, timeout: float) -> None:
        self.sock.settimeout(max(0.0, timeout))

    def recv(self) -> Optional[Tuple[bytes, str]]:
        """Return (raw_ip_packet, src_ip) or None on timeout."""
        try:
            data, addr = self.sock.recvfrom(65535)
            return data, addr[0]
        except socket.timeout:
            return None
        except OSError:
            return None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "RawReceiver":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def local_source_ip(dst_ip: str) -> str:
    """
    Discover the source IP the kernel would use to reach ``dst_ip`` (needed
    to fill in our crafted IP header and to checksum TCP/UDP). A connected
    UDP socket sends nothing but resolves the route.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
