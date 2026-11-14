"""
Timing templates (T0..T5), modelled on Nmap's -T0..-T5.

A template bundles the knobs that trade speed against stealth and reliability:
concurrency, per-probe timeout, retries, and an inter-probe delay (with
optional random jitter so the traffic pattern is less regular).

  T0 paranoid  — serial, long delays (IDS evasion)
  T1 sneaky    — very slow
  T2 polite    — gentle on the target
  T3 normal    — the default
  T4 aggressive— fast, for reliable LANs
  T5 insane    — maximum speed
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Timing:
    name: str
    max_concurrency: int
    timeout: float
    retries: int
    scan_delay: float
    jitter: float


_TEMPLATES = {
    0: Timing("paranoid", 1, 5.0, 2, 10.0, 0.0),
    1: Timing("sneaky", 1, 4.0, 2, 1.0, 0.5),
    2: Timing("polite", 10, 3.0, 2, 0.4, 0.2),
    3: Timing("normal", 300, 1.5, 1, 0.0, 0.0),
    4: Timing("aggressive", 700, 0.8, 1, 0.0, 0.0),
    5: Timing("insane", 1200, 0.5, 0, 0.0, 0.0),
}


def template(level: int) -> Timing:
    """Return the timing template for level 0..5 (clamped)."""
    level = max(0, min(5, int(level)))
    return _TEMPLATES[level]
