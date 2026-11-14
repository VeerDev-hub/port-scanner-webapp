"""
The Internet checksum (RFC 1071) and the TCP/UDP pseudo-header.

The same 16-bit one's-complement checksum protects IP, ICMP, TCP and UDP
headers. TCP and UDP additionally fold in a "pseudo-header" (source IP,
dest IP, protocol, segment length) so that a misdelivered packet is detected.
"""

from __future__ import annotations

import socket
import struct


def internet_checksum(data: bytes) -> int:
    """
    Compute the RFC 1071 16-bit one's-complement checksum over ``data``.

    The data is summed as a sequence of 16-bit big-endian words; a trailing
    odd byte is padded with a zero byte. Carries are folded back in, and the
    result is the one's complement of the final sum.
    """
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]

    # Fold 32-bit sum down to 16 bits (twice is enough for our sizes).
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudo_header(src_ip: str, dst_ip: str, proto: int, length: int) -> bytes:
    """
    Build the IPv4 pseudo-header used when checksumming TCP/UDP segments.

    Layout (12 bytes): src addr, dst addr, zero, protocol, segment length.
    """
    return (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, proto, length)
    )


def transport_checksum(src_ip: str, dst_ip: str, proto: int, segment: bytes) -> int:
    """Checksum a TCP/UDP ``segment`` (header + payload) with its pseudo-header."""
    return internet_checksum(pseudo_header(src_ip, dst_ip, proto, len(segment)) + segment)
