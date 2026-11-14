"""
Maimon scan (-sM).

Named after Uriel Maimon, who noted that many BSD-derived stacks drop a
FIN/ACK probe when the port is open but send a RST when it is closed — even
though RFC 793 says a RST should come back either way. So:

    RST reply -> CLOSED
    no reply  -> OPEN|FILTERED
    ICMP err  -> FILTERED

Useless against stacks that behave per-RFC (they RST regardless), but a neat
demonstration of implementation-specific behaviour. Requires raw sockets.
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
    timeout: float = 1.5,
    retries: int = 1,
    evasion: Optional[Evasion] = None,
    sender: Optional[RawSender] = None,
    receiver: Optional[RawReceiver] = None,
) -> Tuple[PortState, str, Optional[float]]:
    reply, rtt = probe(
        host, port, tcp.FIN | tcp.ACK,
        timeout=timeout, retries=retries, evasion=evasion,
        sender=sender, receiver=receiver,
    )
    if evasion and evasion.spoof_source:
        return PortState.OPEN_FILTERED, "spoofed-no-reply", None
    if reply is None:
        return PortState.OPEN_FILTERED, "no-response", None
    if reply.has(tcp.RST):
        return PortState.CLOSED, "rst", rtt
    return PortState.FILTERED, f"flags:{reply.flag_str}", rtt
