"""
Shared machinery for the raw TCP scans (SYN, FIN, NULL, XMAS, ACK, Window,
Maimon). It crafts a TCP probe with the requested flags, applies any evasion
options, transmits it (optionally fragmented and/or alongside decoys), and
sniffs for the matching reply.

Reply matching: we filter sniffed TCP segments to those coming *from* the
target port and addressed *to* our chosen source port, so concurrent probes
don't pick up each other's answers.
"""

from __future__ import annotations

import random
import time
from typing import Optional

from ..evasion import Evasion
from ..packet import ipv4, tcp
from ..packet.raw import RawSender, RawReceiver, local_source_ip


def _emit(sender: RawSender, src_ip: str, dst_ip: str, tcp_segment: bytes, ev: Evasion) -> None:
    """Transmit one probe, honouring fragmentation and decoys."""
    ttl = ev.ttl if ev.ttl is not None else 64

    # Decoys: send forged-source copies around the real probe. The real source
    # (src_ip) is always in the list so the genuine reply reaches us.
    sources = ev.decoys if ev.decoys else [src_ip]
    for source in sources:
        if ev.frag_mtu:
            for frag in ipv4.fragment(source, dst_ip, ipv4.PROTO_TCP, tcp_segment, ev.frag_mtu, ttl=ttl):
                sender.send(frag, dst_ip)
        else:
            packet = ipv4.build(source, dst_ip, ipv4.PROTO_TCP, tcp_segment, ttl=ttl)
            sender.send(packet, dst_ip)


def probe(
    dst_ip: str,
    dst_port: int,
    flags: int,
    *,
    timeout: float = 1.5,
    retries: int = 1,
    evasion: Optional[Evasion] = None,
    sender: Optional[RawSender] = None,
    receiver: Optional[RawReceiver] = None,
) -> tuple[Optional[tcp.TCPSegment], Optional[float]]:
    """
    Send a TCP probe with ``flags`` and return (reply_segment, rtt_ms).

    reply_segment is None when nothing came back within the timeout. A sender
    and receiver may be supplied for reuse across many probes; otherwise
    short-lived ones are created. The caller interprets the flags.
    """
    ev = evasion or Evasion()
    src_ip = local_source_ip(dst_ip)
    src_port = ev.source_port or random.randint(1025, 65534)
    seq = random.randint(0, 0xFFFFFFFF)

    own_sender = sender is None
    own_receiver = receiver is None
    if own_sender:
        sender = RawSender(ipv4.PROTO_TCP)
    if own_receiver:
        receiver = RawReceiver(ipv4.PROTO_TCP, timeout=timeout)

    try:
        attempt = 0
        while attempt <= retries:
            segment = tcp.build(
                src_ip, dst_ip, src_port, dst_port,
                seq=seq, flags=flags, options=b"",
                payload=ev.padding(), bad_checksum=ev.bad_checksum,
            )
            start = time.perf_counter()
            _emit(sender, src_ip, dst_ip, segment, ev)

            # If we've spoofed the source entirely, replies won't come to us.
            if ev.spoof_source:
                return None, None

            receiver.set_timeout(timeout)
            deadline = start + timeout
            while time.perf_counter() < deadline:
                got = receiver.recv()
                if not got:
                    break
                data, from_ip = got
                if from_ip != dst_ip:
                    continue
                ip = ipv4.parse(data)
                if not ip or ip.proto != ipv4.PROTO_TCP:
                    continue
                seg = tcp.parse(ip.payload)
                if not seg:
                    continue
                if seg.src_port == dst_port and seg.dst_port == src_port:
                    rtt = (time.perf_counter() - start) * 1000.0
                    return seg, round(rtt, 2)
            attempt += 1
        return None, None
    finally:
        if own_sender and sender:
            sender.close()
        if own_receiver and receiver:
            receiver.close()
