# CVE confidence calibration lab (Phase D)

This lab validates **real HTTP fingerprints** against pinned Docker web stacks (**nginx + Apache httpd**) so Phase B/C heuristic weights can be tuned without surprise regressions.

It is **optional**: default pytest runs skip these tests unless you opt in.

## Prerequisites

- Docker with Linux containers (Docker Desktop on Windows with WSL2 backend is typical).
- Repository dependencies: `pip install -r requirements.txt -r requirements-dev.txt`.

## Stack

[`tests/compose/docker-compose.yml`](tests/compose/docker-compose.yml) defines:

- **`nginx_cal`** (`nginx:1.24-alpine`) published at host port **18081**
- **`httpd_cal`** (`httpd:2.4.67-alpine`) published at host port **18082**

Bring it up:

```bash
docker compose -f tests/compose/docker-compose.yml up -d nginx_cal httpd_cal
sleep 2
```

Or start the full compose stack (DNS + Flask + nginx + httpd):

```bash
docker compose -f tests/compose/docker-compose.yml up -d --build
```

## Run calibration tests

From the repo root:

```bash
export BOOMSTICK_RUN_CALIBRATION=1
export TEST_NGINX_ORIGIN=http://127.0.0.1:18081   # optional override
export TEST_APACHE_ORIGIN=http://127.0.0.1:18082  # optional override
python -m pytest tests/calibration -q
```

PowerShell:

```powershell
$env:BOOMSTICK_RUN_CALIBRATION="1"
$env:TEST_NGINX_ORIGIN="http://127.0.0.1:18081"
$env:TEST_APACHE_ORIGIN="http://127.0.0.1:18082"
python -m pytest tests/calibration -q
```

Convenience scripts: [`run_calibration_lab.sh`](../tools/run_calibration_lab.sh), [`run_calibration_lab.ps1`](../tools/run_calibration_lab.ps1).

## What is asserted today

- **`test_nginx_lab_exposes_server_header`** — GET `/` returns `Server` containing `nginx`.
- **`test_builtin_crawl_records_fingerprint_for_host_port`** — [`crawl_and_test`](core/vulnerability/web_vuln.py) fills [`WebVulnOutput.http_fingerprints_by_port`](core/vulnerability/web_vuln.py) for the mapped host port with a nginx-like `server` string.
- **`test_httpd_lab_exposes_server_header`** — GET `/` returns `Server` containing `Apache`/`httpd`.
- **`test_httpd_server_header_penalizes_nginx_fingerprint`** — live Apache `Server` header triggers the nginx↔apache conflict penalty branch (guards heuristic drift).

These checks should **fail** if header capture, redirect handling, or port-keying regress.

## Tuning workflow

1. Change constants only in [`core/vulnerability/cve_confidence.py`](core/vulnerability/cve_confidence.py) (and applicability helpers if needed).
2. Run **unit** regressions (fast, no Docker):

   ```bash
   python -m pytest tests/unit/test_cve_confidence.py tests/unit/test_nvd_cpe_applicability.py tests/unit/test_http_corroboration.py -q
   ```

3. Run **calibration** (Docker + opt-in env):

   ```bash
   BOOMSTICK_RUN_CALIBRATION=1 python -m pytest tests/calibration -q
   ```

4. **Deterministic offline NVD fixture** for automated tests: [`tests/fixtures/nvd_minimal_db.py`](tests/fixtures/nvd_minimal_db.py) builds a tiny SQLite DB (set **`BOOMSTICK_NVD_DB`** to the generated path). See [`tests/unit/test_nvd_minimal_fixture.py`](tests/unit/test_nvd_minimal_fixture.py). Full-scan calibration against your real `data/nvd.sqlite` remains manual.

## CI

Calibration runs in GitHub Actions **Ubuntu** integration job (still not on Windows runners; they lack Docker for Linux containers).

See also: [`docs/cve_confidence_development_leg.md`](cve_confidence_development_leg.md) §Phase D and [`docs/accuracy_testing.md`](accuracy_testing.md).
