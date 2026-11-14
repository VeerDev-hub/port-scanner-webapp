"""
Host discovery (the "ping" phase).

Given a single host, a CIDR, or a range, work out which hosts are alive before
spending time scanning ports. We use several methods so discovery still works
when ICMP is filtered (common on hardened networks):

  * ICMP echo        — classic ping (raw socket; Linux/root).
  * TCP "ping"       — connect to a few common ports. A SYN/ACK *or* a RST both
                       prove the host is up (RST means "up, port closed"). This
                       is portable and works on Windows and without privilege.
  * UDP ping         — a datagram to a closed UDP port drawing an ICMP
                       unreachable also proves liveness (best-effort).

The TCP method is the workhorse; ICMP is added when available.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .packet import icmp, ipv4
from .packet.raw import RawSender, RawReceiver, can_craft_tcp, local_source_ip

# Ports probed during TCP discovery (most-likely-open first).
_TCP_PING_PORTS = (80, 443, 22, 3389, 445, 21, 25, 3306)


def expand_targets(target: str, max_hosts: int = 4096) -> List[str]:
    """
    Turn a target expression into a list of IP strings.

      "10.0.0.5"          -> ["10.0.0.5"]
      "10.0.0.0/28"       -> every usable host in the block
      "10.0.0.1-20"       -> 10.0.0.1 .. 10.0.0.20
      "example.com"       -> resolved A record
    """
    target = target.strip()
    # CIDR
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        return hosts[:max_hosts]
    # dashed range in the last octet: a.b.c.x-y
    if "-" in target and target.count(".") == 3:
        base, last = target.rsplit(".", 1)
        if "-" in last:
            lo, hi = last.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            return [f"{base}.{i}" for i in range(lo_i, hi_i + 1)][:max_hosts]
    # single IP or hostname
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        return [socket.gethostbyname(target)]


def _tcp_ping(ip: str, timeout: float) -> Optional[str]:
    """Return a reason string if the host answers on any common TCP port."""
    for port in _TCP_PING_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return f"tcp-synack:{port}"
        except ConnectionRefusedError:
            return f"tcp-rst:{port}"      # refused => host is up, port closed
        except (socket.timeout, OSError):
            continue
        finally:
            try:
                s.close()
            except OSError:
                pass
    return None


def _icmp_ping(ip: str, timeout: float) -> Optional[str]:
    """ICMP echo via raw socket (Linux/root). Returns reason or None."""
    if not can_craft_tcp():
        return None
    try:
        with RawSender(ipv4.PROTO_ICMP) as sender, RawReceiver(ipv4.PROTO_ICMP, timeout) as rx:
            src = local_source_ip(ip)
            echo = icmp.build_echo()
            sender.send(ipv4.build(src, ip, ipv4.PROTO_ICMP, echo), ip)
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                got = rx.recv()
                if not got:
                    break
                data, from_ip = got
                if from_ip != ip:
                    continue
                parsed = ipv4.parse(data)
                if parsed and parsed.proto == ipv4.PROTO_ICMP:
                    msg = icmp.parse(parsed.payload)
                    if msg and msg.type == icmp.ECHO_REPLY:
                        return "icmp-echo-reply"
    except (OSError, PermissionError):
        return None
    return None


def is_alive(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Probe one host with the available methods; return a reason or None."""
    reason = _icmp_ping(ip, timeout)
    if reason:
        return reason
    return _tcp_ping(ip, timeout)


def discover(
    hosts: List[str],
    timeout: float = 1.0,
    max_concurrency: int = 256,
    on_host_up=None,
) -> List[str]:
    """
    Probe many hosts in parallel; return the alive ones in input order.
    ``on_host_up(ip, reason)`` is called as each live host is found (for live
    UI updates).
    """
    alive: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=min(max_concurrency, max(1, len(hosts)))) as pool:
        futures = {pool.submit(is_alive, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                reason = fut.result()
            except Exception:
                reason = None
            if reason:
                alive[ip] = True
                if on_host_up:
                    on_host_up(ip, reason)
    return [ip for ip in hosts if ip in alive]
