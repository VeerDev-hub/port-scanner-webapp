# Recon Console — a from-scratch network reconnaissance engine

A Nmap-style reconnaissance tool whose packet engine is written **from
scratch** on the Python standard library. There is no Scapy, no nmap binary,
no `requests`, and no external API — every IP/TCP/UDP/ICMP header is crafted
and parsed byte-by-byte with `socket` + `struct`, and nothing about a target
ever leaves your machine.

It ships as both a **Nmap-style CLI** and a **live web console**, both driven
by the same engine (`scanner/`).

> ⚠️ **Authorized use only.** Active scanning of systems you do not own or have
> written permission to test may be illegal. By default this tool refuses to
> scan anything outside loopback / RFC-1918 / your own lab ranges; see
> [Authorization](#authorization).

---

## Highlights

- **Hand-crafted packet engine** — `scanner/packet/` builds and parses IPv4,
  TCP (with options), UDP and ICMP, computes the Internet checksum and the
  TCP/UDP pseudo-header, and fragments IP payloads. Validated by unit tests
  that re-sum checksums to zero and round-trip every header.
- **Scan techniques:** TCP connect (`-sT`), SYN half-open (`-sS`),
  FIN/NULL/XMAS stealth (`-sF/-sN/-sX`), ACK & Window firewall mapping
  (`-sA/-sW`), Maimon (`-sM`), and UDP (`-sU`) — each with correct state logic
  (e.g. stealth "no reply" ⇒ `open|filtered`, UDP ICMP port-unreachable ⇒
  `closed`).
- **Host discovery** via ICMP echo + TCP SYN/connect ping, so it still works
  when ICMP is filtered.
- **Service & version detection** — our own probe set + regex signature table
  (`scanner/service/`) identifies SSH, HTTP(S), FTP, SMTP, POP3, IMAP,
  MySQL/MariaDB, Redis… and pulls out versions. Replaces the old
  `requests`-based HTTP enrichment.
- **OS fingerprinting** from TCP/IP stack behaviour (TTL, window, MSS, options).
- **Offline CVE matching** — a bundled, clearly-labelled demonstration dataset
  (`scanner/vulns/cve_db.json`) maps product+version to known CVEs with **no
  network lookup**.
- **Firewall / IDS evasion** (raw-socket scans, lab use): IP fragmentation
  (`-f/--mtu`), decoys (`-D`), source-IP spoofing (`-S`), source-port tricks,
  custom TTL, bad checksums, payload padding, and `T0`–`T5` timing with
  randomised host/port order. Each is labelled with what it does and its limits.
- **Live web console** — progress, logs and findings stream over Server-Sent
  Events; results, OS, services and CVEs render in one dashboard with a
  per-target scan **diff** (newly-open / now-closed). All output is HTML-escaped
  (the old UI was XSS-prone).
- **Reports:** CSV, JSON, XML (Nmap-ish), Markdown and HTML.

---

## Platform support

| Capability | Linux (root / `CAP_NET_RAW`) | Windows |
|---|---|---|
| TCP connect, UDP, host discovery, service/version, CVE match, reports | ✅ | ✅ |
| SYN / FIN / NULL / XMAS / ACK / Window / Maimon | ✅ | ⛔ falls back to connect |
| Fragmentation, decoys, spoofing, custom TTL | ✅ | ⛔ |
| OS fingerprinting | ✅ | ⛔ (skipped) |

Windows blocks sending TCP over raw sockets at the OS level, so crafted-packet
scans are Linux-only. The engine **detects this automatically** and degrades to
the connect scan, telling you exactly which features are active — it never
silently pretends to do a SYN scan. Run on Linux as root for the full feature
set. (There is deliberately no Scapy fallback.)

---

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### CLI

```bash
# Connect scan + service/version detection on your own machine
python cli.py 127.0.0.1 -p 1-1000 -sV

# SYN + version + OS on a lab host (Linux, as root)
sudo python cli.py 192.168.56.0/24 -p- -sS -sV -O -T4

# UDP scan of common services
python cli.py 192.168.56.10 -sU -p 53,123,161

# Stealth + evasion in a lab you control
sudo python cli.py 192.168.56.10 -sF -f --mtu 8 -D RND:4,ME --source-port 53

# Write reports
python cli.py 192.168.56.10 -p 80,443 -oX report.xml -oJ report.json
```

Run `python cli.py --help` for every flag.

### Web console

```bash
python app.py            # http://127.0.0.1:5000
```

---

## Authorization

The tool only scans loopback and private (RFC-1918) ranges by default. To scan
anything else you must explicitly assert authorization:

- CLI: add `--authorized`, or allowlist a block with `--allow 203.0.113.0/24`
- Web: tick **"I am authorized…"** or add an allowlist CIDR
- Env: `export RECON_AUTHORIZED=1`

This is friction by design: "I only meant to scan my lab" is the default.

---

## Testing

```bash
pytest -q
```

The suite is fully offline (no sockets, no root): checksum correctness,
header build/parse round-trips, fragmentation reassembly, port/target parsing,
service signatures, CVE version matching, the authorization gate, and report
escaping.

---

## Project layout

```
scanner/            the engine (standalone; no Flask dependency)
  packet/           hand-rolled IPv4/TCP/UDP/ICMP + checksums + raw sockets
  scans/            connect, syn, stealth, ack, maimon, udp
  service/          probes, signatures, banner grabbing
  vulns/            offline CVE dataset + matcher
  discovery.py      host discovery
  osfingerprint.py  TCP/IP stack fingerprinting
  evasion.py        fragmentation / decoys / spoofing / timing knobs
  timing.py         T0..T5 templates
  authorization.py  allowlist + authorization gate
  reporting.py      CSV / JSON / XML / Markdown / HTML
  engine.py         orchestration + live event stream
cli.py              Nmap-style command-line interface
app.py              Flask web console (SSE live updates)
templates/, static/ web UI
tests/              offline pytest suite
```

---

## Docker

```bash
docker compose up --build     # http://127.0.0.1:5000
```

The container is granted `NET_RAW`/`NET_ADMIN` so crafted scans work on Linux.
Scan only what you are authorized to.

---

## Legal / ethical use

For education and authorized security testing only. Use exclusively against
systems and networks you own or have explicit written permission to assess.
The bundled CVE data is an approximate demonstration set — confirm every
finding against an authoritative source (e.g. NVD) before acting on it.
