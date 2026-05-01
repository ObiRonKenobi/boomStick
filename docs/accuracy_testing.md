# Automated accuracy testing for boomStick

This document describes the **hermetic pytest harness** used to verify scan correctness (precision/recall against golden fixtures), emit **Cursor-actionable** failure JSON, and run in **CI** without relying on the public internet for core gates.

## Section 1 — Test environment setup

### Layout

- [`tests/compose/docker-compose.yml`](tests/compose/docker-compose.yml) — local **DNS** (dnsmasq on Alpine) + **Flask** crawl fixture.
- [`tests/compose/dnsmasq/dnsmasq.conf`](tests/compose/dnsmasq/dnsmasq.conf) — zone `boomstick.test` answers for integration tests.
- [`tests/fixtures/flask_site/`](tests/fixtures/flask_site/) — minimal multi-page site + `robots.txt`.
- [`tests/golden/`](tests/golden/) — golden JSON fixtures compared against tool outputs.
- [`tests/harness/compare.py`](tests/harness/compare.py) — normalization + precision/recall helpers.

### Starting the stack

From the repository root:

```bash
docker compose -f tests/compose/docker-compose.yml up -d --build
sleep 5
```

Published ports:

- DNS stub: host `127.0.0.1`, UDP/TCP port **5353** (maps to container port 53).
- Web fixture: **http://127.0.0.1:18080**

### Resolver override (tests / lab DNS)

[`ScanConfig`](core/models.py) supports:

- `dns_nameservers: tuple[str, ...]` — when non-empty, enumeration uses these IPs.
- `dns_nameserver_port: int` — port for every listed IP (default **53**; harness uses **5353**).

[`core/utils/dns_resolver_config.py`](core/utils/dns_resolver_config.py) centralizes `dns.resolver.Resolver` setup.

### Crawl telemetry (accuracy only)

When `ScanConfig.export_crawl_telemetry` is **True**, [`crawl_and_test`](core/vulnerability/web_vuln.py) fills `WebVulnOutput.telemetry` with:

- `visited_urls` — final URLs after successful GETs  
- `skipped_robots` — URLs skipped due to `robots.txt` policy (capped)  
- `forms` — deduplicated form metadata `{url, method, params}`  

The GUI keeps defaults **off** so normal scans stay lightweight.

---

## Section 2 — Ground truth generation

Run:

```bash
python tests/fixtures/generate_golden.py
```

This refreshes JSON under [`tests/golden/`](tests/golden/). Edit the generator when the docker zone or Flask routes intentionally change.

Golden files:

- `dns_boomstick_test.json` — expected RR sets for `boomstick.test` (subset enforced in tests).
- `web_static_paths.json` — paths that **must** be visited vs **disallowed** paths.

---

## Section 3 — Test case table

| test_id | Tool / module | Input | Expected behaviour |
|--------|----------------|-------|-------------------|
| `dns/basic_records` | [`dns_enumerate`](core/enumeration/dns_enum.py) | `boomstick.test` via `127.0.0.1:5353` | RR sets match golden for declared types |
| `subdomain/bruteforce` | [`discover_subdomains`](core/enumeration/subdomain.py) | wordlist `www`,`api` | `www.boomstick.test`, `api.boomstick.test` found |
| `web/crawl_static_graph` | [`crawl_and_test`](core/vulnerability/web_vuln.py) | Flask fixture | Required paths visited; `/disallowed/*` never GET-visitable |

Optional future rows (AXFR, loud tools) should stay **mocked** or **dockerized**—not rate-limited public APIs.

Markers:

- `@pytest.mark.integration` — docker stack required  
- `@pytest.mark.accuracy_id("dns/basic_records")` — stable ID in [`tests/harness/mappings.yaml`](tests/harness/mappings.yaml)

---

## Section 4 — Comparison logic

Implementations live in [`tests/harness/compare.py`](tests/harness/compare.py):

- `normalize_url` — fragment strip, host lowercasing, sorted query pairs  
- `prf1(expected_set, actual_set)` → precision, recall, F1, tp/fp/fn  
- `compare_dns_records` — per RR-type comparison with TXT quote normalization  
- `compare_url_sets` — thresholded precision/recall for crawl URLs  
- `compare_results` — thin dispatcher (`dns_records`, `urls`)

---

## Section 5 — Cross-platform instructions

### Running locally

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -q
BOOMSTICK_RUN_INTEGRATION=1 python -m pytest tests/integration -q
```

On Windows PowerShell:

```powershell
$env:BOOMSTICK_RUN_INTEGRATION="1"
pytest tests/integration -q
```

### Normalisation for hashing / diff

1. Sort JSON keys (`sort_keys=True`).  
2. Normalize URLs via `normalize_url`.  
3. Strip trailing dots from DNS labels where applicable (handled in `compare_dns_records`).  
4. Compare reports across OS: any mismatch in canonical normalized payloads should be flagged `platform_specific` in future extensions (hook placeholder in JSON schema).

### Windows vs Linux CI

- GitHub **`windows-latest`** runners **do not** ship Docker for Linux containers.  
- **Integration** tests run on **`ubuntu-latest`** only in [`.github/workflows/accuracy.yml`](.github/workflows/accuracy.yml).  
- **Unit** tests execute on both Ubuntu and Windows.

---

## Section 6 — JSON output schema (Cursor-friendly)

After each pytest session the plugin [`tests/plugins/cursor_report.py`](tests/plugins/cursor_report.py) writes:

`artifacts/cursor_report.json`

Example shape:

```json
{
  "timestamp": "2026-04-29T12:00:00+00:00",
  "platform": "Linux",
  "python": "3.11.0",
  "summary": {
    "total_tests_collected": 12,
    "failed_reports": 1,
    "exitstatus": 1,
    "accuracy_by_tool": {}
  },
  "failures": [
    {
      "test_id": "dns/basic_records",
      "pytest_nodeid": "tests/integration/test_dns_accuracy.py::test_dns_records_match_golden",
      "reproduction_steps": "pytest -q tests/integration/test_dns_accuracy.py::test_dns_records_match_golden",
      "tool": "dns",
      "source_file": "core/enumeration/dns_enum.py",
      "symbol": "dns_enumerate",
      "line_number": 42,
      "longrepr": "...pytest failure text...",
      "platform_specific": false
    }
  ],
  "full_log": "/path/to/repo/artifacts/pytest_session_note.txt"
}
```

**Guidance for Cursor “Fix with AI”**: pass `failures[]` entries together with the referenced `source_file` / `line_number` / `symbol` and the reproduction command.

---

## Section 7 — CI (GitHub Actions)

Workflow: [`.github/workflows/accuracy.yml`](.github/workflows/accuracy.yml)

- **Matrix unit job** — Ubuntu + Windows, `pytest tests/unit`.  
- **Integration job** — Ubuntu only, `docker compose up`, then `BOOMSTICK_RUN_INTEGRATION=1 pytest tests/integration`.  
- **Artifacts** — JUnit XML + `artifacts/cursor_report.json` (when failures occur, reports still emit summaries).

Runtime target: integration suite stays small (**under ~10 minutes**) via minimal fixtures and tight crawl limits.

---

## Section 8 — Promoting golden references

Use [`tools/update_golden.py`](tools/update_golden.py) **after human review** of a candidate JSON:

```bash
python tools/update_golden.py --source /tmp/candidate_dns.json --dest tests/golden/dns_boomstick_test.json --i-understand
```

This copies the file and writes a `.sha256` sidecar next to the golden.

---

## Paywalls / rate limits

Core gates use **local Docker only**—no paid APIs. External smoke tests (not enabled here) should remain non-blocking.
