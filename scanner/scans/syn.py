"""
SYN scan (-sS) — "half-open".

Send a lone SYN and read the reply without completing the handshake:

    SYN/ACK (flags 0x12) -> OPEN   (we send a RST to tear it down quietly)
    RST/ACK (flags 0x14) -> CLOSED
    no reply             -> FILTERED (after retries)

Faster and quieter than a full connect, because the connection is never
established at the application layer. Requires raw sockets (Linux/root).
"""

from __future__ import annotations

import random
from typing import Optional, Tuple

from ..evasion import Evasion
from ..models import PortState
from ..packet import ipv4, tcp
from ..packet.raw import RawSender, RawReceiver, local_source_ip
from ._rawtcp import probe


def _send_rst(dst_ip: str, dst_port: int, src_port: int, ack_seq: int) -> None:
    """Politely abort a half-open connection so the target doesn't retransmit."""
    try:
        src_ip = local_source_ip(dst_ip)
        seg = tcp.build(src_ip, dst_ip, src_port, dst_port, seq=ack_seq, flags=tcp.RST)
        with RawSender(ipv4.PROTO_TCP) as s:
            s.send(ipv4.build(src_ip, dst_ip, ipv4.PROTO_TCP, seg), dst_ip)
    except OSError:
        pass


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
        host, port, tcp.SYN,
        timeout=timeout, retries=retries, evasion=evasion,
        sender=sender, receiver=receiver,
    )
    if evasion and evasion.spoof_source:
        return PortState.FILTERED, "spoofed-no-reply", None
    if reply is None:
        return PortState.FILTERED, "no-response", None
    if reply.has(tcp.SYN) and reply.has(tcp.ACK):
        _send_rst(host, port, reply.dst_port, reply.ack)
        return PortState.OPEN, "syn-ack", rtt
    if reply.has(tcp.RST):
        return PortState.CLOSED, "rst", rtt
    return PortState.FILTERED, f"flags:{reply.flag_str}", rtt
