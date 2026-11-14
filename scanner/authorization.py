"""
Authorization gate — keep this a responsible, lab-oriented tool.

Active scanning of a host you do not own or have permission to test can be
illegal. This module refuses, by default, to scan anything outside a safe
allowlist (loopback + RFC 1918 private ranges + any CIDRs the operator adds),
unless the operator explicitly asserts authorization (``authorized=True``,
the CLI ``--authorized`` flag, or the ``RECON_AUTHORIZED=1`` env var).

The goal is friction, not DRM: it makes "I only meant to scan my lab" the
default and forces a conscious choice before touching anything else.
"""

from __future__ import annotations

import ipaddress
import os
from typing import List, Optional

# Always-allowed destinations: scanning your own machine and private labs.
_DEFAULT_ALLOW = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Operators can add their lab's public ranges here or via add_allowed().
_EXTRA_ALLOW: List[ipaddress._BaseNetwork] = []


class AuthorizationError(PermissionError):
    """Raised when a target is outside the allowlist and not explicitly authorized."""


def add_allowed(cidr: str) -> None:
    _EXTRA_ALLOW.append(ipaddress.ip_network(cidr, strict=False))


def _env_authorized() -> bool:
    return os.environ.get("RECON_AUTHORIZED", "").strip().lower() in ("1", "true", "yes")


def is_allowlisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _DEFAULT_ALLOW + _EXTRA_ALLOW:
        if addr.version == net.version and addr in net:
            return True
    return False


def check(ip: str, authorized: bool = False) -> None:
    """
    Raise AuthorizationError unless ``ip`` is allowlisted or authorization has
    been explicitly asserted (flag or env var).
    """
    if authorized or _env_authorized():
        return
    if is_allowlisted(ip):
        return
    raise AuthorizationError(
        f"Refusing to scan {ip}: not in the private/lab allowlist. "
        f"Scan only hosts you own or are authorized to test. "
        f"If you are authorized, pass --authorized (CLI), set authorized=True, "
        f"or export RECON_AUTHORIZED=1."
    )


def banner(authorized: bool = False) -> str:
    mode = "AUTHORIZED OVERRIDE" if (authorized or _env_authorized()) else "allowlist (private/lab only)"
    return (
        f"[authorization] mode: {mode}. "
        f"Use only against systems you own or have explicit written permission to test."
    )
