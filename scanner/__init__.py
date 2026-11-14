"""
scanner — a from-scratch network reconnaissance engine.

No third-party scanning libraries: IP/TCP/UDP/ICMP packets are crafted
byte-by-byte on top of the standard library (socket + struct). The engine
is standalone and is driven by both the CLI (cli.py) and the web app (app.py).

Intended for authorized use only (your own hosts / labs with permission).
"""

__version__ = "2.0.0"
