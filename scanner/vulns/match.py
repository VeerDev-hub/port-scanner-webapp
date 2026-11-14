"""
Match a detected (product, version) against the bundled offline CVE dataset.

Version comparison uses a tuple-of-integers compare on the dotted numeric
prefix (e.g. "1.17.7" -> (1,17,7)); non-numeric suffixes like "p1" or
"-MariaDB" are ignored for the comparison but kept for display. This is a
pragmatic approximation, not semver — every hit is clearly marked as needing
confirmation against an authoritative source.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import Vulnerability

_DB_PATH = Path(__file__).with_name("cve_db.json")

# product-name aliases -> dataset key
_ALIASES = {
    "apache": "apache",
    "apache httpd": "apache",
    "httpd": "apache",
    "openssh": "openssh",
    "openssh_": "openssh",
    "nginx": "nginx",
    "mariadb": "mariadb",
    "mysql": "mysql",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "redis": "redis",
    "exim": "exim",
    "postfix": "postfix",
    "dovecot": "dovecot",
}


@lru_cache(maxsize=1)
def _load() -> dict:
    try:
        return json.loads(_DB_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _version_tuple(v: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    # pad to equal length
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _satisfies(version: str, entry: dict) -> bool:
    if "version_exact" in entry:
        return _cmp(version, entry["version_exact"]) == 0
    if "version_lt" in entry:
        return _cmp(version, entry["version_lt"]) < 0
    if "version_range" in entry:
        lo, hi = entry["version_range"]
        ok = True
        for bound in (lo, hi):
            op = re.match(r"(>=|<=|>|<|=)?\s*([\d.]+)", bound)
            if not op:
                continue
            sym, ver = op.group(1) or "=", op.group(2)
            c = _cmp(version, ver)
            if sym == ">=" and not c >= 0:
                ok = False
            elif sym == "<=" and not c <= 0:
                ok = False
            elif sym == ">" and not c > 0:
                ok = False
            elif sym == "<" and not c < 0:
                ok = False
            elif sym == "=" and c != 0:
                ok = False
        return ok
    return False


def _resolve_key(product: str) -> Optional[str]:
    if not product:
        return None
    p = product.strip().lower()
    if p in _ALIASES:
        return _ALIASES[p]
    for alias, key in _ALIASES.items():
        if alias in p:
            return key
    return None


def lookup(product: str, version: str) -> List[Vulnerability]:
    """Return known vulnerabilities for a product/version, or []."""
    db = _load()
    key = _resolve_key(product)
    if not key or key not in db or not version:
        return []
    hits: List[Vulnerability] = []
    for entry in db[key]:
        try:
            if _satisfies(version, entry):
                hits.append(
                    Vulnerability(
                        cve=entry["cve"],
                        severity=entry.get("severity", "unknown"),
                        cvss=entry.get("cvss"),
                        summary=entry.get("summary", ""),
                    )
                )
        except (KeyError, ValueError):
            continue
    return hits
