"""
Hand-rolled packet crafting and parsing.

Every header here is built and parsed byte-by-byte with `struct` — no Scapy,
no external packet library. This is the heart of the project: it shows exactly
how IP/TCP/UDP/ICMP are laid out on the wire.
"""
