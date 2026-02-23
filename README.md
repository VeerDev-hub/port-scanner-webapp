# Port Scanner Webapp

A hacker-themed port scanner with a modern async workflow, live terminal logs, progress+ETA, CIDR discovery, route tracing, and exportable reports.

---

## What It Does

- Async scans with job tracking (`/scan/start`, `/scan/status/<job_id>`, `/scan/result/<job_id>`)
- Live progress bar + percentage + ETA
- Live terminal-style scan logs
- Port range support (`1-1024,443,3306`) and top-port presets
- Scan modes: `SYN`, `UDP`, `STEALTH`, `CONNECT`
- CIDR host discovery + optional “scan all alive hosts”
- Route table (traceroute-style)
- Service enrichment:
  - HTTP title/headers
  - TLS certificate info
- History and compare (`opened` / `closed`) persisted in SQLite
- Export reports: CSV, JSON, Markdown

---

## UI Preview (Key Panels)

- Scanner control panel (target, ports, presets, scan mode)
- Progress strip with ETA
- Live terminal log stream
- Result table + route table
- Recent scans history panel

---

## Tech Stack

- Python 3
- Flask
- Scapy
- Requests
- SQLite
- Gunicorn (production)

---

## Quick Start (Local)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open: `http://127.0.0.1:5000`

---

## Docker

```powershell
docker compose up --build
```

Open: `http://127.0.0.1:5000`

Notes:

- Container runs with `NET_RAW` and `NET_ADMIN` capabilities for packet-level scans.
- Use only on targets you are explicitly authorized to test.

---

## API

- `GET /health`
- `POST /scan/start`
- `GET /scan/status/<job_id>`
- `GET /scan/result/<job_id>`
- `GET /history`
- `POST /scan` (sync compatibility route)

---

## Project Structure

- `app.py` -> routes, async jobs, SQLite persistence
- `validators.py` -> target/port parsing and validation
- `scanner_core.py` -> scan engine + protocol enrichment
- `enrichment.py` -> geolocation, OS guess, route table, host discovery
- `templates/index.html` -> UI markup
- `static/script.js` -> UI behavior, polling, exports
- `static/style.css` -> hacker-style responsive theme
- `tests/` -> parser/API tests

---

## Testing

```powershell
pytest -q
```

---

## Legal/Ethical Use

Run scans only against systems and networks you own or have explicit permission to assess.
