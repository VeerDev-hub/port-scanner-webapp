"""
TCP header: build, parse, options.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .checksums import transport_checksum
from .ipv4 import PROTO_TCP

# Flag bits.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

# Common TCP option kinds.
OPT_EOL = 0
OPT_NOP = 1
OPT_MSS = 2
OPT_WSCALE = 3
OPT_SACK_PERM = 4
OPT_TIMESTAMP = 8


def default_options() -> bytes:
    """
    A realistic Linux-like option block (MSS, SACK-permitted, timestamp,
    NOP, window scale), padded to a 4-byte boundary. Sending plausible
    options makes probes look like ordinary connections.
    """
    opts = b""
    opts += struct.pack("!BBH", OPT_MSS, 4, 1460)
    opts += struct.pack("!BB", OPT_SACK_PERM, 2)
    opts += struct.pack("!BBII", OPT_TIMESTAMP, 10, 0, 0)
    opts += struct.pack("!B", OPT_NOP)
    opts += struct.pack("!BBB", OPT_WSCALE, 3, 7)
    # Pad with NOPs to a multiple of 4 bytes.
    while len(opts) % 4:
        opts += struct.pack("!B", OPT_NOP)
    return opts


def build(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    seq: int = 0,
    ack: int = 0,
    flags: int = SYN,
    window: int = 64240,
    options: bytes = b"",
    payload: bytes = b"",
    bad_checksum: bool = False,
) -> bytes:
    """Build a TCP segment with a correct (or deliberately wrong) checksum."""
    if len(options) % 4:
        raise ValueError("TCP options must be padded to a 4-byte boundary")
    data_offset = 5 + len(options) // 4         # in 32-bit words
    offset_flags = (data_offset << 12) | (flags & 0x3F)

    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        0,      # checksum placeholder
        0,      # urgent pointer
    )
    segment = header + options + payload
    checksum = transport_checksum(src_ip, dst_ip, PROTO_TCP, segment)
    if bad_checksum:
        checksum ^= 0xFFFF

    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        checksum,
        0,
    )
    return header + options + payload


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent: int
    options: List[Tuple[int, bytes]]
    payload: bytes

    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)

    @property
    def flag_str(self) -> str:
        names = [
            (FIN, "F"), (SYN, "S"), (RST, "R"),
            (PSH, "P"), (ACK, "A"), (URG, "U"),
        ]
        return "".join(ch for bit, ch in names if self.flags & bit) or "-"

    def option_dict(self) -> Dict[int, bytes]:
        return {kind: val for kind, val in self.options}


def _parse_options(opt_bytes: bytes) -> List[Tuple[int, bytes]]:
    options: List[Tuple[int, bytes]] = []
    i = 0
    while i < len(opt_bytes):
        kind = opt_bytes[i]
        if kind == OPT_EOL:
            break
        if kind == OPT_NOP:
            options.append((OPT_NOP, b""))
            i += 1
            continue
        if i + 1 >= len(opt_bytes):
            break
        length = opt_bytes[i + 1]
        if length < 2 or i + length > len(opt_bytes):
            break
        options.append((kind, opt_bytes[i + 2:i + length]))
        i += length
    return options


def parse(data: bytes) -> TCPSegment | None:
    """Parse a TCP segment (the transport payload of an IP packet)."""
    if len(data) < 20:
        return None
    (src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent) = struct.unpack(
        "!HHIIHHHH", data[:20]
    )
    data_offset = (offset_flags >> 12) & 0xF
    header_len = data_offset * 4
    if header_len < 20 or len(data) < header_len:
        return None
    flags = offset_flags & 0x3F
    options = _parse_options(data[20:header_len])
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent=urgent,
        options=options,
        payload=data[header_len:],
    )
