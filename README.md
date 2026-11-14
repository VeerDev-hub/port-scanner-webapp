<div align="center">

# 🛰️ Recon Console

### A from-scratch, Nmap-style network reconnaissance engine

Packets crafted **by hand** on the Python standard library — no Scapy, no `nmap`,
no `requests`, no external API. Ships as a **command-line tool** *and* a
**live web console**, both driven by one engine.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![deps](https://img.shields.io/badge/scan%20deps-stdlib%20only-brightgreen)
![tests](https://img.shields.io/badge/tests-34%20passing-success)
![license](https://img.shields.io/badge/use-authorized%20only-red)

</div>

> ### ⚠️ Authorized use only
> Active scanning of systems you do not own or lack written permission to test
> may be **illegal**. By default this tool refuses to scan anything outside
> loopback / private (RFC-1918) / your own lab ranges. See
> [Authorization](#-authorization).

---

## Table of contents

- [Why this exists](#-why-this-exists)
- [Features](#-features)
- [How it works](#-how-it-works)
- [Install](#-install)
- [Using the CLI](#-using-the-cli)
- [Using the web console](#-using-the-web-console)
- [Platform support (read this)](#-platform-support-read-this)
- [Authorization](#-authorization)
- [Reports](#-reports)
- [Testing](#-testing)
- [Project layout](#-project-layout)
- [Docker](#-docker)
- [Roadmap](#-roadmap)
- [Legal & ethics](#-legal--ethics)

---

## 🎯 Why this exists

Most "port scanners" are thin wrappers around `nmap` or Scapy. This one is the
opposite: the interesting part — **assembling and decoding raw IP/TCP/UDP/ICMP
packets** — is written out in full so you can read exactly how a scan works at
the byte level. It's built for learning and for authorized lab testing, and it
keeps everything **offline**: no target data ever leaves your machine.

---

## ✨ Features

| Area | What you get |
|---|---|
| **Packet engine** | Hand-written IPv4/TCP/UDP/ICMP build + parse, Internet checksum, TCP/UDP pseudo-header, IP fragmentation |
| **Scan types** | TCP connect `-sT`, SYN half-open `-sS`, FIN/NULL/XMAS `-sF/-sN/-sX`, ACK & Window `-sA/-sW`, Maimon `-sM`, UDP `-sU` |
| **Host discovery** | ICMP echo + TCP SYN/connect ping — still finds hosts when ICMP is filtered |
| **Service & version** | Own probe set + regex signatures: SSH, HTTP(S), FTP, SMTP, POP3, IMAP, MySQL/MariaDB, Redis… with versions |
| **OS detection** | Active TCP/IP stack fingerprint (TTL, window, MSS) **and** passive banner inference (works even without raw sockets) |
| **Vulnerabilities** | Offline, bundled CVE dataset → product/version matching, **no network lookup** |
| **Evasion (lab)** | Fragmentation `-f/--mtu`, decoys `-D`, source spoof `-S`, source-port, custom TTL, bad checksum, padding, `T0`–`T5` timing |
| **Live web console** | Server-Sent-Events streaming of progress/logs/findings, scan **diff** vs last run, fully HTML-escaped output |
| **Reports** | CSV · JSON · XML (Nmap-ish) · Markdown · HTML |
| **Safety** | Authorization allowlist gate so lab-only is the default |

---

## 🔬 How it works

```
 target ─▶ resolve ─▶ host discovery ─▶ port scan ─▶ service/version ─▶ OS fingerprint ─▶ CVE match ─▶ report
                                         │                                                              ▲
                                         └──────────── live events stream to CLI / web ─────────────────┘
```

Every stage emits events, so the CLI prints findings as they happen and the web
console streams them over SSE — no polling.

**A scan, in bytes:** for a SYN scan the engine builds a 20-byte IPv4 header
(filling in version, length, ID, flags, a computed header checksum, source and
destination), prepends it to a TCP header whose checksum folds in the TCP/UDP
pseudo-header, transmits it on a raw socket, then sniffs the reply and reads the
flags: `SYN|ACK` ⇒ **open**, `RST` ⇒ **closed**, nothing ⇒ **filtered**. All of
that lives in `scanner/packet/` and `scanner/scans/` in plain, commented Python.

---

## 📦 Install

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The only runtime dependency is **Flask** (for the web UI). The scan engine
itself is pure standard library.

---

## 🖥️ Using the CLI

```bash
# Connect scan + service/version detection on your own machine
python cli.py 127.0.0.1 -p 1-1000 -sV

# SYN + version + OS on a lab subnet  (Linux, run as root)
sudo python cli.py 192.168.56.0/24 -p- -sS -sV -O -T4

# UDP scan of common services
python cli.py 192.168.56.10 -sU -p 53,123,161

# Stealth scan with evasion, in a lab you control
sudo python cli.py 192.168.56.10 -sF -f --mtu 8 -D RND:4,ME --source-port 53

# Save reports
python cli.py 192.168.56.10 -p 80,443 -sV -oX report.xml -oJ report.json
```

**Common flags**

| Flag | Meaning |
|---|---|
| `-p 80,443` · `-p 1-1024` · `-p-` | ports: list, range, or all 65535 |
| `-sT -sS -sF -sN -sX -sA -sW -sM -sU` | scan type |
| `-sV` | service/version detection |
| `-O` | OS detection |
| `-Pn` | skip host discovery (treat as up) |
| `-T0`…`-T5` | timing: paranoid → insane |
| `-f` / `--mtu N` | fragment packets |
| `-D RND:5` / `-D ip,ME,ip` | decoy sources |
| `--source-port 53` | fixed source port |
| `-oJ/-oX/-oC/-oM file` | write JSON/XML/CSV/Markdown report |
| `--authorized` / `--allow CIDR` | authorization override / allowlist |

Run `python cli.py --help` for the full list.

---

## 🌐 Using the web console

```bash
python app.py                   # open http://127.0.0.1:5000
```

- Pick a target, ports, scan type and timing; toggle service/OS/CVE detection.
- Watch the **live log** and progress bar stream in real time.
- Results show open ports, detected services + versions, matched CVEs
  (highlighted), an **OS guess**, and a **diff against your previous scan** of
  the same target.
- Download the report as CSV / JSON / XML / Markdown / HTML.

> **Enable "OS fingerprint (-O)"** in the Detection box to get an OS guess — it
> is off by default. See the note below about what works on Windows.

---

## 💻 Platform support (read this)

| Capability | Linux (root / `CAP_NET_RAW`) | Windows |
|---|:--:|:--:|
| Connect scan, UDP, discovery, service/version, CVE match, reports | ✅ | ✅ |
| SYN / FIN / NULL / XMAS / ACK / Window / Maimon | ✅ | ⛔ → connect |
| Fragmentation, decoys, spoofing, custom TTL | ✅ | ⛔ |
| **OS detection — active stack fingerprint** (TTL/window) | ✅ | ⛔ |
| **OS detection — banner inference** (reads "Ubuntu", "IIS", …) | ✅ | ✅ |

**Windows cannot send TCP over raw sockets** — the OS blocks it. So the
crafted-packet scans are Linux-only; on Windows the engine **detects this and
falls back to the connect scan**, and tells you so (it never pretends to run a
SYN scan). There is deliberately **no Scapy fallback**.

**"OS detection shows Unknown on Windows?"** The *active* fingerprint needs raw
sockets, so it's skipped on Windows. The engine then uses **banner inference**,
which only works when an open service actually names its OS (e.g. an SSH banner
ending `Ubuntu-3` or an HTTP `Server: Microsoft-IIS/10.0`). If no open service
reveals an OS string, it honestly reports `Unknown` with the reason. For full
TTL/window-based OS detection, **run on Linux as root**.

---

## 🔐 Authorization

The tool scans only loopback and private ranges by default. To scan anything
else you must explicitly assert you're authorized:

- **CLI:** `--authorized`, or add a block with `--allow 203.0.113.0/24`
- **Web:** tick *"I am authorized…"*, or add an allowlist CIDR
- **Env:** `export RECON_AUTHORIZED=1`

This is friction by design: *"I only meant to scan my lab"* is the default.

---

## 📄 Reports

Every scan can be exported to **CSV, JSON, XML (Nmap-ish), Markdown or HTML**.
All formats are generated locally and HTML/XML output is escaped, so a hostile
banner can't inject into a report. In the CLI use `-oJ/-oX/-oC/-oM`; in the web
console use the download buttons.

---

## 🧪 Testing

```bash
pytest -q
```

34 tests, **fully offline** (no sockets, no root): checksum correctness, header
build/parse round-trips, fragmentation reassembly, port/target parsing, service
signatures, CVE version matching, the authorization gate, and report escaping.

---

## 🗂️ Project layout

```
scanner/              the engine (standalone; no Flask dependency)
├─ packet/            hand-rolled IPv4/TCP/UDP/ICMP + checksums + raw sockets
├─ scans/             connect, syn, stealth, ack, maimon, udp
├─ service/           probes, signatures, banner grabbing
├─ vulns/             offline CVE dataset + matcher
├─ discovery.py       host discovery
├─ osfingerprint.py   active stack + passive banner OS detection
├─ evasion.py         fragmentation / decoys / spoofing / timing knobs
├─ timing.py          T0..T5 templates
├─ authorization.py   allowlist + authorization gate
├─ reporting.py       CSV / JSON / XML / Markdown / HTML
└─ engine.py          orchestration + live event stream
cli.py                Nmap-style command-line interface
app.py                Flask web console (SSE live updates)
templates/ static/    web UI
tests/                offline pytest suite
```

---

## 🐳 Docker

```bash
docker compose up --build       # http://127.0.0.1:5000
```

The container gets `NET_RAW`/`NET_ADMIN` so crafted scans work on Linux. Scan
only what you are authorized to.

---

## 🧭 Roadmap

- Idle / zombie scan (`-sI`) via the IP-ID side channel
- IPv6 crafted-packet scans (IPv6 currently supported at the connect level)
- Optional SOCKS/Tor routing for connect scans
- A larger service-probe and CVE dataset

---

## ⚖️ Legal & ethics

For education and **authorized** security testing only — use exclusively against
systems and networks you own or have explicit written permission to assess. The
bundled CVE data is an approximate **demonstration** set; confirm every finding
against an authoritative source (e.g. [NVD](https://nvd.nist.gov/)) before
acting on it.

<div align="center">

Crafted by **V33R** · [GitHub](https://github.com/VeerDev-hub) · [LinkedIn](https://www.linkedin.com/in/veer-pratap-singh-99a368310)

</div>
