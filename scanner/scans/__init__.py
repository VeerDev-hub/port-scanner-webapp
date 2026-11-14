"""
Scan techniques.

Each module implements one family of probes and returns a
``(PortState, reason)`` pair. The connect scan is pure sockets and runs
anywhere; the rest craft raw packets and require ``raw.can_craft_tcp()``.
"""
