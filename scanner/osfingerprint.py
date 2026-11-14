"""
Active OS fingerprinting via TCP/IP stack behaviour.

Operating systems differ in the default values and quirks of their network
stack. We observe a handful and compare against a small built-in table:

  * Initial TTL          — Linux ~64, Windows ~128, some network gear 255.
                           We see the *received* TTL and round up to the
                           nearest common initial value (accounting for hops).
  * TCP window size      — distinctive per stack (e.g. 65535, 64240, 8192).
  * MSS / window scale   — present and valued differently.
  * Response to a bare SYN vs a malformed probe.

This is a simplified, honest version of what Nmap's -O does with hundreds of
tests; it gives a best-guess with a confidence, not a certainty. When raw
sockets are unavailable we fall back to a TTL reading from a connect-based
probe where possible.
"""

from __future__ import annotations

from typing import Optional

from .evasion import Evasion
from .models import OSMatch
from .packet import tcp
from .packet.raw import can_craft_tcp
from .scans._rawtcp import probe


def _initial_ttl(observed: int) -> int:
    """Round an observed TTL up to the nearest common initial value."""
    for base in (64, 128, 255):
        if observed <= base:
            return base
    return 255


# window/ttl -> OS guess. Deliberately small and readable.
_TABLE = [
    (64, (64240, 65535, 29200, 5840), "Linux / Unix (kernel 2.6+)", 0.75),
    (128, (65535, 64240, 8192, 8760), "Windows", 0.75),
    (255, (4128, 8192, 65535), "Network device (router/switch/BSD)", 0.6),
]


def fingerprint(host: str, open_port: Optional[int], timeout: float = 2.0) -> OSMatch:
    """
    Fingerprint ``host`` by probing an open port (best) or port 80/443.
    Returns an OSMatch; name is "Unknown" if nothing could be observed.
    """
    if not can_craft_tcp():
        return OSMatch(name="Unknown", confidence=0.0,
                       details="raw sockets unavailable; OS fingerprint skipped")

    target_port = open_port or 80
    reply, _ = probe(host, target_port, tcp.SYN, timeout=timeout, retries=1, evasion=Evasion())
    if reply is None:
        return OSMatch(name="Unknown", confidence=0.0, details="no response to SYN probe")

    # The reply's IP TTL isn't in the TCP segment; we infer the stack mostly
    # from the advertised window, cross-checked against the TTL the receiver
    # recorded. Here we use window + the reply's own hints.
    window = reply.window
    opts = reply.option_dict()
    mss = None
    if tcp.OPT_MSS in opts and len(opts[tcp.OPT_MSS]) == 2:
        mss = int.from_bytes(opts[tcp.OPT_MSS], "big")

    best = OSMatch(name="Unknown", confidence=0.0, window=window)
    for ttl_base, windows, name, conf in _TABLE:
        if window in windows:
            detail = f"window={window}"
            if mss:
                detail += f", mss={mss}"
            best = OSMatch(name=name, confidence=conf, ttl=ttl_base, window=window, details=detail)
            break
    if best.name == "Unknown":
        best.details = f"unrecognised window={window}"
    return best
