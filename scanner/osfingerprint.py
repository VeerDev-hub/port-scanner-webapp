"""
OS detection, two complementary ways.

1. Active TCP/IP stack fingerprinting (raw sockets, Linux/root). We send a SYN
   and read the reply's low-level tells:
     * IP TTL        — initial value is ~64 (Linux/Unix), ~128 (Windows),
                       255 (many network devices). We round the observed TTL
                       up to the nearest of these (hops only ever lower it).
     * TCP window    — distinctive per stack (64240, 65535, 8192, ...).
     * MSS           — cross-check.

2. Passive banner inference (works everywhere, no privilege). Service banners
   frequently name the OS outright — "Ubuntu" in an SSH string,
   "Microsoft-IIS" or "Win64" in an HTTP Server header, "(Unix)"/"(CentOS)"
   after Apache. When raw sockets are unavailable (e.g. on Windows) this is
   the only signal we have; when both are available we combine them.

The result is a best guess with a confidence, never a certainty.
"""

from __future__ import annotations

import re
import time
from typing import List, Optional

from .models import OSMatch, PortResult
from .packet import ipv4, tcp
from .packet.raw import RawSender, RawReceiver, can_craft_tcp, local_source_ip
import random


def _round_ttl(observed: int) -> int:
    """Round an observed TTL up to the nearest common initial value."""
    for base in (64, 128, 255):
        if observed <= base:
            return base
    return 255


# initial-TTL -> OS family, used by the active path.
_TTL_OS = {
    64: ("Linux / Unix (kernel 2.4+)", 0.7),
    128: ("Windows", 0.7),
    255: ("Network device / BSD (Cisco, Solaris, ...)", 0.6),
}

# window-size refinement (adds confidence when it agrees with the TTL family).
_WINDOW_HINT = {
    64240: "Linux", 65535: "Windows/BSD", 29200: "Linux", 5840: "Linux",
    8192: "Windows", 8760: "Linux", 16384: "Windows", 4128: "Cisco",
}

# Banner substrings -> (OS label, confidence). Checked case-insensitively.
_BANNER_OS = [
    (r"\bubuntu\b", "Linux (Ubuntu)", 0.85),
    (r"\bdebian\b", "Linux (Debian)", 0.85),
    (r"\braspbian\b", "Linux (Raspbian)", 0.85),
    (r"\bcentos\b", "Linux (CentOS)", 0.85),
    (r"\bred hat\b|\brhel\b|\.el\d", "Linux (RHEL/CentOS)", 0.8),
    (r"\bfedora\b", "Linux (Fedora)", 0.85),
    (r"\bgentoo\b|\bsuse\b|\bamzn\b|\bamazon linux\b", "Linux", 0.8),
    (r"microsoft-iis|\bwin32\b|\bwin64\b|\bwindows\b", "Windows", 0.85),
    (r"\(unix\)", "Unix", 0.6),
    (r"freebsd", "FreeBSD", 0.85),
    (r"openbsd", "OpenBSD", 0.85),
    (r"netbsd", "NetBSD", 0.85),
    (r"\bdarwin\b|mac ?os", "macOS", 0.8),
    (r"mikrotik|routeros", "MikroTik RouterOS", 0.85),
    (r"cisco", "Cisco IOS", 0.8),
]


def _active(host: str, port: int, timeout: float) -> Optional[tuple[int, int, Optional[int]]]:
    """Send a SYN, return (ttl, window, mss) from the raw reply, or None."""
    try:
        src = local_source_ip(host)
        src_port = random.randint(1025, 65534)
        seg = tcp.build(src, host, src_port, port, seq=random.randint(0, 0xFFFFFFFF),
                        flags=tcp.SYN, options=tcp.default_options())
        packet = ipv4.build(src, host, ipv4.PROTO_TCP, seg, ttl=64)
        with RawSender(ipv4.PROTO_TCP) as sender, RawReceiver(ipv4.PROTO_TCP, timeout) as rx:
            sender.send(packet, host)
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                got = rx.recv()
                if not got:
                    break
                data, from_ip = got
                if from_ip != host:
                    continue
                ip = ipv4.parse(data)
                if not ip or ip.proto != ipv4.PROTO_TCP:
                    continue
                t = tcp.parse(ip.payload)
                if not t or t.src_port != port or t.dst_port != src_port:
                    continue
                mss = None
                opts = t.option_dict()
                if tcp.OPT_MSS in opts and len(opts[tcp.OPT_MSS]) == 2:
                    mss = int.from_bytes(opts[tcp.OPT_MSS], "big")
                # Tear down the half-open connection.
                if t.has(tcp.SYN) and t.has(tcp.ACK):
                    try:
                        rst = tcp.build(src, host, src_port, port, seq=t.ack, flags=tcp.RST)
                        sender.send(ipv4.build(src, host, ipv4.PROTO_TCP, rst), host)
                    except OSError:
                        pass
                return ip.ttl, t.window, mss
    except (OSError, PermissionError):
        return None
    return None


def _from_active(host: str, open_port: Optional[int], timeout: float) -> OSMatch:
    observed = _active(host, open_port or 80, timeout)
    if observed is None:
        return OSMatch(name="Unknown", confidence=0.0, details="no response to SYN probe")
    ttl, window, mss = observed
    initial = _round_ttl(ttl)
    name, conf = _TTL_OS.get(initial, ("Unknown", 0.3))
    detail = f"ttl={ttl}~{initial}, window={window}"
    if mss:
        detail += f", mss={mss}"
    # Bump confidence when the window agrees with the TTL-derived family.
    hint = _WINDOW_HINT.get(window, "")
    if hint and hint.lower().split("/")[0] in name.lower():
        conf = min(0.95, conf + 0.15)
    return OSMatch(name=name, confidence=round(conf, 2), ttl=initial, window=window, details=detail)


def _from_banners(ports: List[PortResult]) -> OSMatch:
    """Infer the OS from service banners / product strings. Works unprivileged."""
    corpus_parts: List[str] = []
    for p in ports:
        if not p.service:
            continue
        corpus_parts.append(p.service.banner or "")
        corpus_parts.append(p.service.product or "")
        corpus_parts.append(p.service.extra or "")
    corpus = " ".join(corpus_parts).lower()
    if not corpus.strip():
        return OSMatch(name="Unknown", confidence=0.0, details="no banners to infer from")
    for pattern, label, conf in _BANNER_OS:
        if re.search(pattern, corpus):
            return OSMatch(name=label, confidence=conf, details=f"inferred from service banner ({label})")
    return OSMatch(name="Unknown", confidence=0.0, details="no OS hint in banners")


def fingerprint(
    host: str,
    open_port: Optional[int],
    ports: Optional[List[PortResult]] = None,
    timeout: float = 2.0,
) -> OSMatch:
    """
    Best-effort OS guess. Uses active stack fingerprinting when raw sockets are
    available, banner inference always, and returns whichever is more confident
    (preferring agreement between the two).
    """
    ports = ports or []
    banner_guess = _from_banners(ports)

    if not can_craft_tcp():
        # Windows / unprivileged: banners are all we have.
        if banner_guess.name != "Unknown":
            return banner_guess
        return OSMatch(name="Unknown", confidence=0.0,
                       details="raw sockets unavailable (no active fingerprint); "
                               "no OS hint in service banners")

    active_guess = _from_active(host, open_port, timeout)

    # If both agree on a family, combine confidence.
    if (active_guess.name != "Unknown" and banner_guess.name != "Unknown"
            and _family(active_guess.name) == _family(banner_guess.name)):
        best = banner_guess if banner_guess.confidence >= active_guess.confidence else active_guess
        best.confidence = min(0.98, max(active_guess.confidence, banner_guess.confidence) + 0.1)
        best.details = f"{active_guess.details}; {banner_guess.details}"
        return best

    # Otherwise take the more confident of the two.
    return active_guess if active_guess.confidence >= banner_guess.confidence else banner_guess


def _family(name: str) -> str:
    n = name.lower()
    if "linux" in n or "unix" in n or "ubuntu" in n or "debian" in n or "centos" in n:
        return "linux"
    if "windows" in n:
        return "windows"
    if "bsd" in n or "macos" in n:
        return "bsd"
    return n
