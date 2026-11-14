"""
ICMP: build echo requests (for host discovery) and parse replies / errors.

We care about two things:
  * Echo reply (type 0)      -> the host is alive.
  * Destination Unreachable  -> tells UDP/stealth scans what happened.
       type 3, code 3  = port unreachable  -> the UDP port is CLOSED
       type 3, other   = net/host/proto/admin-prohibited -> FILTERED

    Destination Unreachable layout:
      type(1) code(1) checksum(2) unused(4) + copy of the original IP header
      and first 8 bytes of its payload. We parse that embedded header so we
      can match an ICMP error back to the probe that caused it.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from .checksums import internet_checksum

ECHO_REPLY = 0
ECHO_REQUEST = 8
DEST_UNREACH = 3
TIME_EXCEEDED = 11

# Destination-unreachable codes that mean "closed" vs "filtered".
CODE_PORT_UNREACH = 3
FILTERED_CODES = {1, 2, 9, 10, 13}  # host, protocol, admin-prohibited, etc.


def build_echo(identifier: int | None = None, seq: int = 1, payload: bytes = b"recon-ping") -> bytes:
    """Build an ICMP echo request with a correct checksum."""
    if identifier is None:
        identifier = os.getpid() & 0xFFFF
    header = struct.pack("!BBHHH", ECHO_REQUEST, 0, 0, identifier, seq)
    checksum = internet_checksum(header + payload)
    header = struct.pack("!BBHHH", ECHO_REQUEST, 0, checksum, identifier, seq)
    return header + payload


@dataclass
class ICMPMessage:
    type: int
    code: int
    checksum: int
    rest: bytes          # 4 bytes after the checksum (id/seq or unused)
    payload: bytes       # for errors: embedded original IP packet


def parse(data: bytes) -> ICMPMessage | None:
    if len(data) < 8:
        return None
    msg_type, code, checksum = struct.unpack("!BBH", data[:4])
    return ICMPMessage(
        type=msg_type,
        code=code,
        checksum=checksum,
        rest=data[4:8],
        payload=data[8:],
    )


def classify_unreachable(code: int) -> str:
    """Map a destination-unreachable code to a port state keyword."""
    if code == CODE_PORT_UNREACH:
        return "closed"
    if code in FILTERED_CODES:
        return "filtered"
    return "filtered"
