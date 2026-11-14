"""
TCP connect scan (-sT).

The portable baseline: a normal OS-level TCP handshake. No privilege needed,
works on every platform (and is the automatic fallback when raw sockets are
unavailable). State is decided by the *type* of outcome, never by scraping an
error string:

    connected            -> OPEN
    ConnectionRefused    -> CLOSED
    timeout / unreachable-> FILTERED
"""

from __future__ import annotations

import socket
import time
from typing import Tuple

from ..models import PortState


def scan(host: str, port: int, timeout: float = 1.0, source_port: int | None = None) -> Tuple[PortState, str, float | None]:
    """Return (state, reason, rtt_ms) for a single TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if source_port:
        try:
            s.bind(("", source_port))
        except OSError:
            pass  # source port may be privileged or busy; fall back to ephemeral
    start = time.perf_counter()
    try:
        s.connect((host, port))
        rtt = (time.perf_counter() - start) * 1000.0
        return PortState.OPEN, "tcp-connect", round(rtt, 2)
    except ConnectionRefusedError:
        return PortState.CLOSED, "conn-refused", None
    except socket.timeout:
        return PortState.FILTERED, "timeout", None
    except OSError as exc:
        # Unreachable / reset-by-peer / etc. — treat as filtered but keep the errno.
        if exc.errno == 111:  # ECONNREFUSED on some stacks
            return PortState.CLOSED, "conn-refused", None
        return PortState.FILTERED, f"oserror:{exc.errno}", None
    finally:
        try:
            s.close()
        except OSError:
            pass
