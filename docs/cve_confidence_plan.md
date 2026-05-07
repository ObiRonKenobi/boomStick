# CVE match confidence — checklist & execution plan

For the **full phased roadmap** (architecture, phases B–E, risks, testing, definition of done), see [**cve_confidence_development_leg.md**](cve_confidence_development_leg.md).

This document tracks **match confidence** (0–100 + High/Medium/Low band) separately from **CVSS severity** from NVD.

## Rules (locked)

- **Confidence score** answers: “How likely does this CVE apply to what we observed?”
- **CVSS `score`** on each CVE row remains **severity only** (unchanged field name for backward compatibility).
- **High confidence band (80–100)** requires **hard evidence**:
  - At least one **CPE** on `Service.cpes`, **or**
  - Both **product** and **version** strings on the service fingerprint.
- Without hard evidence, score is **capped at 79**, so **High cannot be assigned** (reduces keyword-only false positives).

### Bands (defaults)

| Band   | Score range |
|--------|-------------|
| High   | 80–100      |
| Medium | 50–79       |
| Low    | 0–49        |

---

## Implementation checklist

### Done (baseline)

- [x] `core/vulnerability/cve_confidence.py` — scoring + hard-evidence gate + bands  
- [x] `core/vulnerability/cve_checker.py` — attach `confidence_*` fields per CVE  
- [x] `gui/app.py` — CVE tab grouped by band; summary counts High/Medium/Low  
- [x] `gui/results_display.py` — export text includes confidence + CVSS + operator blurb; shared `build_cve_section_lines()`  
- [x] `tests/unit/test_cve_confidence.py` — regression tests for gates  

### Next (optional improvements)

- [x] Feed **HTTP / tech fingerprint** signals into `score_cve_match()` — **Phase C v1** (builtin crawl `Server` / `X-Powered-By` per port → `http_context`; LOUD/ZAP path included via bootstrap probe).  
- [x] Parse **CVE JSON CPE criteria** from offline DB (`raw_json`) — **Phase B v1** (`nvd_cpe_applicability.py` + `score_cve_match(..., nvd_criteria_cpes=…)`); version-range parsing still backlog (see development leg §Phase B).  
- [x] Benchmark lab **scaffold** — pinned nginx + httpd in Compose + opt-in `tests/calibration` + [`calibration_lab.md`](calibration_lab.md).  
- [x] Operator toggle: hide **Low** match-confidence band by default in GUI (`Hide Low match-confidence CVEs`), persisted via `%LOCALAPPDATA%/boomStick/gui_prefs.json` (Windows) or `~/.config/boomStick/gui_prefs.json` (Linux), override with **`BOOMSTICK_GUI_PREFS`**.  
- [x] **Export CVE CSV** (flat columns including confidence + CVSS).  

---

## Phased work plan

1. **Stabilize scoring** — run unit tests; ship current weights.  
2. **Add tech signals** — after HTTP enumeration lands, bump confidence when headers agree with service fingerprint.  
3. **Calibrate** — docker benchmark + adjust constants in `cve_confidence.py` only (single tuning surface).  
4. **Document operator interpretation** — README §CVE match confidence vs CVSS (`README.md`).  

---

## Verification commands

```bash
python -m pytest tests/unit/test_cve_confidence.py tests/unit/test_results_display_cves.py -q
```

Optional Docker lab:

```bash
BOOMSTICK_RUN_CALIBRATION=1 python -m pytest tests/calibration -q
```
