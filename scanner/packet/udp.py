"""
UDP header: build and parse.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +--------+--------+--------+--------+
   |     Source      |   Destination   |
   |      Port       |      Port       |
   +--------+--------+--------+--------+
   |     Length      |    Checksum     |
   +--------+--------+--------+--------+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .checksums import transport_checksum
from .ipv4 import PROTO_UDP


def build(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    *,
    bad_checksum: bool = False,
) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    segment = header + payload
    checksum = transport_checksum(src_ip, dst_ip, PROTO_UDP, segment)
    # A zero UDP checksum means "not computed"; RFC says send 0xFFFF instead.
    if checksum == 0:
        checksum = 0xFFFF
    if bad_checksum:
        checksum ^= 0xFFFF
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


@dataclass
class UDPSegment:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes


def parse(data: bytes) -> UDPSegment | None:
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return UDPSegment(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        payload=data[8:],
    )
