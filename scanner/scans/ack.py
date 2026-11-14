"""
ACK scan (-sA) and Window scan (-sW) — firewall state mapping.

An ACK probe never tells you whether a port is open; it tells you whether a
*stateful firewall* is in the way:

    RST reply  -> UNFILTERED (the packet reached the host; no firewall blocking)
    no reply   -> FILTERED   (a stateful firewall dropped it)
    ICMP error -> FILTERED

The Window scan is the same probe, but it inspects the TCP window field of the
returned RST: on a few older stacks an open port returns a non-zero window and
a closed port returns zero, which can distinguish open from closed where a
plain ACK scan cannot. Treated as a best-effort refinement.

Requires raw sockets (Linux/root).
"""

from __future__ import annotations

from typing import Optional, Tuple

from ..evasion import Evasion
from ..models import PortState
from ..packet import tcp
from ..packet.raw import RawSender, RawReceiver
from ._rawtcp import probe


def scan(
    host: str,
    port: int,
    window_mode: bool = False,
    timeout: float = 1.5,
    retries: int = 1,
    evasion: Optional[Evasion] = None,
    sender: Optional[RawSender] = None,
    receiver: Optional[RawReceiver] = None,
) -> Tuple[PortState, str, Optional[float]]:
    reply, rtt = probe(
        host, port, tcp.ACK,
        timeout=timeout, retries=retries, evasion=evasion,
        sender=sender, receiver=receiver,
    )
    if evasion and evasion.spoof_source:
        return PortState.FILTERED, "spoofed-no-reply", None
    if reply is None:
        return PortState.FILTERED, "no-response", None
    if reply.has(tcp.RST):
        if window_mode:
            # Non-zero window on the RST hints the port is open on some stacks.
            if reply.window > 0:
                return PortState.OPEN, "window>0", rtt
            return PortState.CLOSED, "window=0", rtt
        return PortState.UNFILTERED, "rst", rtt
    return PortState.FILTERED, f"flags:{reply.flag_str}", rtt
