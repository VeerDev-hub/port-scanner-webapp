"""
Core data models shared across the engine, CLI and web app.

Everything the engine produces is one of these dataclasses, so the CLI,
the reporting module and the web layer all speak the same language.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanType(str, Enum):
    """Scan techniques, mirroring the common Nmap flags."""

    CONNECT = "connect"   # -sT  full TCP handshake (no privilege needed)
    SYN = "syn"           # -sS  half-open
    FIN = "fin"           # -sF  stealth
    NULL = "null"         # -sN  stealth
    XMAS = "xmas"         # -sX  stealth
    ACK = "ack"           # -sA  firewall state mapping
    WINDOW = "window"     # -sW  window-size variant of ACK
    MAIMON = "maimon"     # -sM  FIN/ACK probe
    UDP = "udp"           # -sU

    @property
    def needs_raw(self) -> bool:
        """True if this scan type requires crafting raw packets."""
        return self is not ScanType.CONNECT


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"
    ERROR = "error"


class EventType(str, Enum):
    """Streamed to the UI/CLI as a scan progresses."""

    LOG = "log"
    HOST_UP = "host_up"
    PORT_RESULT = "port_result"
    PROGRESS = "progress"
    STAGE = "stage"
    WARNING = "warning"
    DONE = "done"
    ERROR = "error"


@dataclass
class ScanEvent:
    type: EventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "message": self.message,
            "data": self.data,
            "ts": self.ts,
        }


@dataclass
class Vulnerability:
    cve: str
    severity: str
    cvss: Optional[float] = None
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    banner: str = ""
    confidence: float = 0.0  # 0..1
    vulns: List[Vulnerability] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vulns"] = [v.to_dict() for v in self.vulns]
        return d


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str = "tcp"          # tcp | udp
    state: PortState = PortState.FILTERED
    reason: str = ""               # e.g. "syn-ack", "rst", "no-response", "icmp-unreach"
    service: Optional[Service] = None
    rtt_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state.value,
            "reason": self.reason,
            "service": self.service.to_dict() if self.service else None,
            "rtt_ms": self.rtt_ms,
        }


@dataclass
class Hop:
    hop: int
    ip: str
    rtt_ms: Optional[float]
    status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OSMatch:
    name: str = "Unknown"
    confidence: float = 0.0
    ttl: Optional[int] = None
    window: Optional[int] = None
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    host: str
    hostname: Optional[str] = None
    state: str = "up"              # up | down
    ports: List[PortResult] = field(default_factory=list)
    os: Optional[OSMatch] = None
    route: List[Hop] = field(default_factory=list)

    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
            "os": self.os.to_dict() if self.os else None,
            "route": [h.to_dict() for h in self.route],
        }


@dataclass
class ScanConfig:
    """Everything needed to run one scan. Built by the CLI or the web layer."""

    target: str = ""                       # raw user input: domain/IP/CIDR/range
    ports: List[int] = field(default_factory=list)
    port_query: str = ""                   # human-readable description of the port set
    scan_type: ScanType = ScanType.CONNECT

    # timing / concurrency (resolved from a timing template, overridable)
    timing: int = 3                        # T0..T5
    max_concurrency: int = 500
    timeout: float = 1.0
    retries: int = 1
    scan_delay: float = 0.0
    jitter: float = 0.0

    # discovery
    skip_discovery: bool = False           # -Pn equivalent (treat hosts as up)
    discover_all_hosts: bool = True        # scan every alive host in a CIDR

    # feature toggles
    service_detection: bool = True         # -sV
    os_detection: bool = False             # -O
    vuln_check: bool = True
    traceroute: bool = False
    randomize_hosts: bool = True
    randomize_ports: bool = True

    # evasion (crafted-packet scans only; see evasion.py for labels + limits)
    frag_mtu: int = 0                      # 0 = off; else fragment IP payload to this size
    decoys: List[str] = field(default_factory=list)
    spoof_source: Optional[str] = None     # -S  (responses won't return to us)
    source_port: Optional[int] = None      # --source-port
    ttl: Optional[int] = None
    bad_checksum: bool = False
    data_length: int = 0                   # bytes of random padding appended

    # safety
    authorized: bool = False               # explicit "I am authorized" override

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scan_type"] = self.scan_type.value
        return d


@dataclass
class ScanResult:
    """The complete outcome of one scan run."""

    target: str
    scan_type: str
    port_query: str
    started_at: float
    finished_at: float
    hosts: List[HostResult] = field(default_factory=list)
    capability: Dict[str, Any] = field(default_factory=dict)
    evasion: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    compare: Dict[str, List[str]] = field(default_factory=lambda: {"opened": [], "closed": []})

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def all_ports(self) -> List[PortResult]:
        out: List[PortResult] = []
        for h in self.hosts:
            out.extend(h.ports)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "port_query": self.port_query,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "capability": self.capability,
            "evasion": self.evasion,
            "warnings": self.warnings,
            "compare": self.compare,
            "hosts": [h.to_dict() for h in self.hosts],
        }
