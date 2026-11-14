"""
Firewall / IDS evasion techniques — authorized testing only.

Each option here mirrors a real Nmap capability and exists so you can
*demonstrate* how perimeter defences can be probed or confused in a lab you
control. None of it is magic: the docstrings state plainly what each does and
where it stops working, so a report can explain the technique honestly.

    fragmentation (-f/--mtu) : split the TCP header across tiny IP fragments so
                               an inspector that only reads the first fragment
                               never sees the flags. Beaten by any firewall
                               that reassembles before inspecting.
    decoys (-D)              : send the same probe with several forged source
                               IPs mixed in, so the target's logs cannot tell
                               which source is the real scanner. The real probe
                               is always present (replies must reach us).
    spoof source (-S)        : forge the source IP entirely. Replies go to the
                               spoofed host, not us, so this is for IDS-reaction
                               and idle-scan style demos, not for reading state.
    source port              : scan from 53/80/443 to slip past firewalls that
                               implicitly trust DNS/HTTP source ports.
    ttl / bad checksum /     : low-level knobs for fingerprint evasion and for
    data padding               exercising how middleboxes handle odd packets.

All of these require raw-socket crafting (Linux/root). They are ignored by the
connect scan.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Evasion:
    frag_mtu: int = 0
    decoys: List[str] = field(default_factory=list)
    spoof_source: Optional[str] = None
    source_port: Optional[int] = None
    ttl: Optional[int] = None
    bad_checksum: bool = False
    data_length: int = 0

    @property
    def active(self) -> bool:
        return bool(
            self.frag_mtu or self.decoys or self.spoof_source
            or self.source_port or self.ttl or self.bad_checksum or self.data_length
        )

    def summary(self) -> List[str]:
        """Short, labelled notes for the UI/CLI so the user sees what is on."""
        notes: List[str] = []
        if self.frag_mtu:
            notes.append(f"IP fragmentation (data MTU {self.frag_mtu}B)")
        if self.decoys:
            notes.append(f"{len(self.decoys)} decoy source(s)")
        if self.spoof_source:
            notes.append(f"spoofed source {self.spoof_source} (replies won't return)")
        if self.source_port:
            notes.append(f"source port {self.source_port}")
        if self.ttl is not None:
            notes.append(f"custom TTL {self.ttl}")
        if self.bad_checksum:
            notes.append("bad TCP checksum")
        if self.data_length:
            notes.append(f"{self.data_length}B payload padding")
        return notes

    def padding(self) -> bytes:
        return random.randbytes(self.data_length) if self.data_length else b""


def expand_decoys(spec: str, real_source: str) -> List[str]:
    """
    Parse a decoy spec like "RND:5" or "10.0.0.1,10.0.0.2,ME,10.0.0.3".

    "RND:n" generates n random IPs; "ME" marks where the real source sits in
    the ordering. The real source is always included so replies come back.
    """
    decoys: List[str] = []
    if not spec:
        return decoys
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if token.upper() == "ME":
            decoys.append(real_source)
        elif token.upper().startswith("RND:"):
            try:
                n = int(token.split(":", 1)[1])
            except ValueError:
                n = 1
            for _ in range(max(0, n)):
                decoys.append(str(ipaddress.IPv4Address(random.randint(0x01000001, 0xDFFFFFFE))))
        else:
            decoys.append(token)
    if real_source not in decoys:
        decoys.append(real_source)
    return decoys
