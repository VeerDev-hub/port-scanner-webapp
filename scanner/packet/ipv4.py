"""
IPv4 header: build, parse, and fragment.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass
from typing import List

from .checksums import internet_checksum

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# Flag bits packed into the high 3 bits of the flags+fragment-offset field.
FLAG_DF = 0x4000   # Don't Fragment
FLAG_MF = 0x2000   # More Fragments
OFFSET_MASK = 0x1FFF


def build(
    src_ip: str,
    dst_ip: str,
    proto: int,
    payload: bytes,
    *,
    ttl: int = 64,
    identification: int | None = None,
    flags: int = 0,
    frag_offset: int = 0,
    tos: int = 0,
    bad_checksum: bool = False,
) -> bytes:
    """
    Build a complete IPv4 packet (20-byte header, no options) + ``payload``.

    ``frag_offset`` is expressed in 8-byte units, exactly as it rides on the
    wire. ``flags`` carries FLAG_DF / FLAG_MF. ``bad_checksum`` deliberately
    corrupts the header checksum (an IDS-evasion demonstration).
    """
    version_ihl = (4 << 4) | 5  # IPv4, 5 * 32-bit words = 20-byte header
    total_length = 20 + len(payload)
    if identification is None:
        identification = random.randint(0, 0xFFFF)
    flags_frag = (flags & 0xE000) | (frag_offset & OFFSET_MASK)

    header_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        proto,
        0,  # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    checksum = internet_checksum(header_wo_checksum)
    if bad_checksum:
        checksum ^= 0xFFFF  # flip every bit so the receiver's check fails

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        proto,
        checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return header + payload


@dataclass
class IPv4Packet:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    checksum: int
    src: str
    dst: str
    payload: bytes


def parse(data: bytes) -> IPv4Packet | None:
    """Parse an IPv4 packet. Returns None if it is too short or not IPv4."""
    if len(data) < 20:
        return None
    version_ihl = data[0]
    version = version_ihl >> 4
    if version != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl:
        return None

    (
        _vihl, tos, total_length, identification, flags_frag, ttl, proto, checksum,
    ) = struct.unpack("!BBHHHBBH", data[:12])
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return IPv4Packet(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        flags=flags_frag & 0xE000,
        frag_offset=flags_frag & OFFSET_MASK,
        ttl=ttl,
        proto=proto,
        checksum=checksum,
        src=src,
        dst=dst,
        payload=data[ihl:],
    )


def fragment(
    src_ip: str,
    dst_ip: str,
    proto: int,
    payload: bytes,
    mtu: int,
    *,
    ttl: int = 64,
    identification: int | None = None,
) -> List[bytes]:
    """
    Split ``payload`` across several IPv4 fragments whose data portions are at
    most ``mtu`` bytes (rounded down to a multiple of 8, as the fragment-offset
    field counts 8-byte blocks).

    All fragments share one Identification value; every fragment except the
    last sets the More-Fragments flag. This is the classic ``-f`` evasion:
    a naive inspector that only reads the first fragment never sees the full
    TCP header. Use only where you are authorized to test.
    """
    chunk = max(8, (mtu // 8) * 8)
    if identification is None:
        identification = random.randint(0, 0xFFFF)

    fragments: List[bytes] = []
    offset = 0
    total = len(payload)
    while offset < total:
        piece = payload[offset:offset + chunk]
        more = (offset + len(piece)) < total
        flags = FLAG_MF if more else 0
        fragments.append(
            build(
                src_ip,
                dst_ip,
                proto,
                piece,
                ttl=ttl,
                identification=identification,
                flags=flags,
                frag_offset=offset // 8,
            )
        )
        offset += len(piece)

    if not fragments:  # zero-length payload — still emit one bare packet
        fragments.append(
            build(src_ip, dst_ip, proto, b"", ttl=ttl, identification=identification)
        )
    return fragments
