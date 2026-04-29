# boomStick

Cross-platform (Windows 10/11 + Linux Debian/Ubuntu) cybersecurity scanning tool with a modern **CustomTkinter** GUI.

## Ethics / authorization

Use this tool only on systems you own or where you have explicit written permission to test. You are responsible for complying with applicable laws and rules of engagement.

## Features (v1)

- **GUI**: target entry (IP/domain), quiet/loud mode, enum/vuln/both, subdomain strategy, progress + results tabs, export JSON.
- **Enumeration**:
  - Quiet: TCP connect port scan (bounded common ports)
  - Loud: `nmap` service enumeration (XML parse) when installed
  - DNS records (A/AAAA/MX/NS/TXT), optional `dig` output (loud)
  - Subdomain discovery strategies: bounded brute force / passive CT + brute force / external tools (amass/subfinder if installed)
  - Traceroute: loud uses `traceroute`/`tracepath` (Linux) or `tracert` (Windows); quiet best-effort TCP hop inference
- **Vulnerabilities** (safe heuristics, robots-aware crawling):
  - Reflected XSS (reflection heuristic)
  - SQLi (boolean response fingerprint heuristic)
  - Directory traversal (passwd marker heuristic)
- **Loud-mode web scanning**: OWASP ZAP (daemon + API alerts; optional spider/active scan)
- **CVE lookup**: Offline NVD mirror (SQLite) built from NVD JSON feeds (no API rate limits)

## Install (Python deps)

Python 3.11+ recommended.

```bash
pip install -r requirements.txt
```

## System dependencies (loud mode)

Quiet mode uses Python-only checks and does not require external tools.

### Windows

- Install **Nmap** (recommended). Default install path is usually:
  - `C:\\Program Files\\Nmap\\nmap.exe` or `C:\\Program Files (x86)\\Nmap\\nmap.exe`
- If `nmap` isn’t on PATH, set:
  - `BOOMSTICK_NMAP=C:\\Path\\To\\nmap.exe`

OWASP ZAP (loud-mode vulnerability engine):
- Auto-install is attempted via `winget` when missing.
- You can also set an explicit path:
  - `BOOMSTICK_ZAP=C:\\Path\\To\\zap.bat` (or `zap.exe`)

Traceroute uses the built-in `tracert` (present by default).

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y nmap dnsutils whois traceroute
```

OWASP ZAP (loud-mode vulnerability engine):
- Auto-install is attempted via `apt install zaproxy` when missing.
- You can also set an explicit path:
  - `BOOMSTICK_ZAP=/opt/zap/zap.sh`

## Run

```bash
python main.py
```

## Offline NVD database (recommended)

Build/update the local SQLite database (default `data/nvd.sqlite`):

```bash
python tools/update_nvd_db.py
```

First-time build (recommended): import year feeds (bigger) and then keep updated via `modified`:

```bash
# example: last 2 years + modified
python tools/update_nvd_db.py --feeds 2026 2025 modified
```

To store the DB elsewhere, set:

- `BOOMSTICK_NVD_DB=C:\\Path\\To\\nvd.sqlite` (Windows) or `BOOMSTICK_NVD_DB=/path/to/nvd.sqlite` (Linux)

## Packaging (PyInstaller)

Basic build:

```bash
pyinstaller main.py --name boomStick --windowed --add-data "data;data"
```

Notes:
- On Linux, the `--add-data` separator is `:` instead of `;` (e.g. `data:data`).
- If `--onefile` triggers AV false positives, prefer `--onedir`.
