"""
Stealth scans: FIN (-sF), NULL (-sN), XMAS (-sX).

These exploit RFC 793: a probe with no SYN/RST/ACK sent to a *closed* port
must elicit a RST; sent to an *open* port it is silently dropped. So:

    RST reply   -> CLOSED
    no reply    -> OPEN|FILTERED   (we cannot tell which — hence the combined
                                     state; this was a bug in the old code,
                                     which reported plain "Filtered")
    ICMP unreach-> FILTERED

They can slip past stateless firewalls and some packet filters that only look
for SYN. They are unreliable against Windows targets, which send RST for both
open and closed ports (so everything looks closed) — a limitation worth noting
in a report. Requires raw sockets (Linux/root).
"""

from __future__ import annotations

from typing import Optional, Tuple

from ..evasion import Evasion
from ..models import PortState
from ..packet import tcp
from ..packet.raw import RawSender, RawReceiver
from ._rawtcp import probe

# Flag combinations per variant.
_FLAGS = {
    "fin": tcp.FIN,
    "null": 0x00,
    "xmas": tcp.FIN | tcp.PSH | tcp.URG,
}


def scan(
    host: str,
    port: int,
    variant: str = "fin",
    timeout: float = 1.5,
    retries: int = 1,
    evasion: Optional[Evasion] = None,
    sender: Optional[RawSender] = None,
    receiver: Optional[RawReceiver] = None,
) -> Tuple[PortState, str, Optional[float]]:
    flags = _FLAGS.get(variant, tcp.FIN)
    reply, rtt = probe(
        host, port, flags,
        timeout=timeout, retries=retries, evasion=evasion,
        sender=sender, receiver=receiver,
    )
    if evasion and evasion.spoof_source:
        return PortState.OPEN_FILTERED, "spoofed-no-reply", None
    if reply is None:
        # No response is the informative case for these scans.
        return PortState.OPEN_FILTERED, "no-response", None
    if reply.has(tcp.RST):
        return PortState.CLOSED, "rst", rtt
    return PortState.FILTERED, f"flags:{reply.flag_str}", rtt
