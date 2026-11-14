"""
Signature table: regex patterns that map a banner to a product + version.

Each signature names a service, a compiled pattern, and which capture groups
hold the product and version. The first match wins. Patterns are intentionally
readable so the table doubles as documentation of what each service's banner
looks like. Extend freely — this is our own data, not a third-party feed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class Signature:
    service: str
    pattern: re.Pattern
    product_group: int = 0
    version_group: int = 0


def _c(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE | re.DOTALL)


# Order matters: put more specific patterns first. Patterns match the product
# and (where present) a version; they avoid anchoring on line endings, since a
# product token may be followed by free-form text (e.g. "OpenSSH_8.9p1 Ubuntu-3").
SIGNATURES = [
    # SSH:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"  /  "SSH-2.0-dropbear_2022.83"
    Signature("ssh", _c(r"SSH-\d+\.\d+-([A-Za-z][\w.\-]*?)[_/ ]v?([\d][\w.\-]*)"), 1, 2),
    Signature("ssh", _c(r"SSH-\d+\.\d+-([A-Za-z][\w.\-]+)"), 1, 0),
    # HTTP Server header: "Server: nginx/1.24.0"  /  "Server: Apache/2.4.49 (Unix)"
    Signature("http", _c(r"Server:\s*([A-Za-z][\w .\-]*?)/([\d][\w.\-]*)"), 1, 2),
    Signature("http", _c(r"Server:\s*([A-Za-z][\w .\-]+)"), 1, 0),
    # FTP:  "220 ProFTPD 1.3.5 Server"  /  "220 (vsFTPd 2.3.4)"
    Signature("ftp", _c(r"220[ -].*?([A-Za-z][\w\-]*FTP[dD]?)[ /v]*([\d][\w.\-]*)"), 1, 2),
    Signature("ftp", _c(r"220[ -].*?([A-Za-z][\w\-]*FTP[dD]?)"), 1, 0),
    # SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    Signature("smtp", _c(r"220[ -].*?ESMTP\s+([A-Za-z][\w\-]+)(?:\s+([\d][\w.\-]*))?"), 1, 2),
    # POP3 / IMAP greetings:  "+OK Dovecot ready"  /  "* OK Dovecot ready"
    Signature("pop3", _c(r"\+OK\b.*?\b([A-Za-z][\w\-]{2,})(?:[ /]([\d][\w.\-]*))?"), 1, 2),
    Signature("imap", _c(r"\*\s*OK\b.*?\b([A-Za-z][\w\-]{2,})(?:[ /]([\d][\w.\-]*))?"), 1, 2),
    # MySQL/MariaDB handshake embeds the version as ASCII before a NUL byte.
    Signature("mysql", _c(r"([\d]+\.[\d]+\.[\d]+[\w.\-]*?)\x00"), 0, 1),
    # Redis INFO / PONG.
    Signature("redis", _c(r"redis_version:([\d.]+)"), 0, 1),
    Signature("redis", _c(r"\+PONG"), 0, 0),
]


def match(banner: str) -> Tuple[str, str, str]:
    """
    Return (service, product, version) for the best signature match.
    Empty strings when nothing matches.
    """
    if not banner:
        return "", "", ""
    for sig in SIGNATURES:
        m = sig.pattern.search(banner)
        if not m:
            continue
        product = ""
        version = ""
        if sig.product_group and sig.product_group <= m.re.groups:
            product = (m.group(sig.product_group) or "").strip()
        if sig.version_group and sig.version_group <= m.re.groups:
            version = (m.group(sig.version_group) or "").strip()
        return sig.service, product, version
    return "", "", ""
