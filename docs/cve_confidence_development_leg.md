# Development leg: CVE match confidence & applicability

This document is the **full execution plan** for evolving BoomStick’s offline CVE workflow beyond the baseline **match confidence** implementation. It complements the short checklist in [`cve_confidence_plan.md`](cve_confidence_plan.md).

---

## 1. Scope of this leg

**In scope**

- Improve **how confidently** an offline NVD hit applies to an **observed service fingerprint**, without conflating that with **CVSS severity**.
- Preserve backward compatibility for consumers of `score` (NVD severity) on each CVE dict.
- Keep **hard-evidence rules** for the **High** band (see §3).

**Explicitly out of scope (unless later approved)**

- Replacing offline search with live NVD API calls in the default path.
- Automated exploit mapping or exploitability scoring (beyond existing optional MSF hints elsewhere).
- Pushing changes to GitHub remotes (only when you explicitly ask).

---

## 2. Goals & success criteria

| Goal | Measurable outcome |
|------|-------------------|
| **Separation of concerns** | Every CVE row exposes **CVSS-based severity** (`score`) and **match confidence** (`confidence_score`, `confidence_band`, reasons). |
| **Trustworthy High band** | **High** never appears from keyword-only correlation; requires CPE **or** product **and** version on the port fingerprint (§3). |
| **Explainability** | Operators see **human-readable reasons** and structured **evidence** (`confidence_evidence`) suitable for reports. |
| **Single tuning surface** | Weight/threshold changes for confidence live primarily in `core/vulnerability/cve_confidence.py` unless a cross-cutting type forces a small API change. |
| **Regression safety** | `tests/unit/test_cve_confidence.py` grows with each behavioral change; optional integration/fixture tests for end-to-end scans. |

---

## 3. Locked product rules (do not weaken without explicit decision)

These align with **industry-style** triage language while staying statistically conservative.

### 3.1 Confidence vs severity

- **`confidence_*`**: “How well does this CVE match what we saw on the wire?”
- **`score`**: NVD CVSS numeric severity for that CVE (unchanged meaning).

Operators must be guided to treat **High CVSS + Low match confidence** as “investigate applicability first,” not “panic now.”

### 3.2 Bands (default thresholds)

| Band | Score range |
|------|----------------|
| High | 80–100 |
| Medium | 50–79 |
| Low | 0–49 |

Constants: `HIGH_MIN`, `MEDIUM_MIN` in [`core/vulnerability/cve_confidence.py`](../core/vulnerability/cve_confidence.py).

### 3.3 Hard evidence gate for **High**

**High** is allowed only when **hard evidence** exists on the [`Service`](../core/models.py) fingerprint:

1. Non-empty `Service.cpes`, **or**
2. Non-empty **both** `Service.product` and `Service.version` (after strip).

If hard evidence is missing:

- Raw score is **capped at 79** before banding.
- A clear reason is appended explaining the cap (keyword / product-only path).

Implementation must retain a **belt-and-suspenders** check: even if weights drift, **High** cannot occur without hard evidence.

---

## 4. Current architecture (baseline)

### 4.1 Data flow

1. **Enumeration** fills `ScanResult.enumeration.open_ports` as `list[Service]`.
2. **`CVE` scan step** ([`core/orchestrator.py`](../core/orchestrator.py) `_run_cve`) calls `query_offline_nvd_for_services(open_ports, ...)`.
3. [`cve_checker.query_offline_nvd_for_services`](../core/vulnerability/cve_checker.py) builds a text keyword from CPE-derived parts or product/version/name, searches [`nvd_offline`](../core/vulnerability/nvd_offline.py), and for each hit calls `score_cve_match(service, match_query=..., nvd_criteria_cpes=..., http_context=...)`.
4. GUI ([`gui/app.py`](../gui/app.py)) and exports ([`gui/results_display.py`](../gui/results_display.py)) group and label CVEs by confidence band.

### 4.2 Offline DB

- SQLite column `cves.raw_json` holds each feed item `v` (the **`vulnerabilities[]` element**) from the NVD CVE JSON **2.0** gzip feeds ingested by [`tools/update_nvd_db.py`](../tools/update_nvd_db.py).
- **Phase B (implemented):** `raw_json` is selected in offline search results and drives CPE **criteria** extraction plus confidence bonuses/penalties (see Phase B below).

### 4.3 Web crawl & HTTP fingerprints

- **`WebVuln`** runs **before** **`CVE`** in the plan order.
- Built-in crawler returns [`WebVulnOutput`](../core/vulnerability/web_vuln.py); optional **`telemetry`** exists when `ScanConfig.export_crawl_telemetry` is enabled.
- **Phase C (builtin path):** each successful crawl `GET` records **first-seen** `Server` and `X-Powered-By` (truncated) keyed by **destination port** into [`EnumerationReport.http_fingerprints_by_port`](../core/models.py). [`query_offline_nvd_for_services`](../core/vulnerability/cve_checker.py) passes `http_context = fingerprints_by_port.get(service.port)` into scoring.
- **LOUD / OWASP ZAP path:** after ZAP finishes, a lightweight **GET probe** per base URL records the same `Server` / `X-Powered-By` map (see [`probe_http_fingerprints_by_port`](../core/utils/http_fingerprint.py) in [`zap_scanner`](../core/vulnerability/zap_scanner.py)).

---

## 5. Work breakdown — phases

Each phase has **deliverables**, **acceptance criteria**, and **dependencies**.

### Phase A — Baseline stability (mostly complete)

**Deliverables**

- Confidence module + checker wiring + GUI/export + unit tests (already landed per checklist).

**Acceptance criteria**

- [ ] `python -m pytest tests/unit/test_cve_confidence.py -q` passes on CI/local.
- [ ] No duplicate CVE IDs per service query path beyond intentional `seen` set behavior.
- [ ] Documentation links severity vs confidence for operators (§9).

**Dependencies:** None.

---

### Phase B — CVE-side applicability from `raw_json` (high leverage)

**Objective:** Use **structured NVD data** (especially **CPE match criteria**) so hits that are **implausible** for the observed stack lose confidence or are annotated, without breaking offline-first behavior.

#### B.1 Stored JSON shape (NVD CVE JSON 2.0 feed item)

The SQLite `raw_json` text is the **per-CVE wrapper object** written by `upsert_cve(..., raw_json=v)` where `v` is one element of `vulnerabilities[]` from the official feed.

**Primary paths used for extraction**

| Purpose | JSON path (pseudo) | Notes |
|--------|---------------------|--------|
| CVE metadata | `raw_json["cve"]` | Required container |
| Configurations | `raw_json["cve"]["configurations"]` | List of configuration blocks |
| Logical nodes | `...["configurations"][*]["nodes"]` | Operator trees (`AND`/`OR` handled implicitly by flattening matches) |
| CPE rows | `...["nodes"][*]["cpeMatch"]` | Each match may include `criteria`, `vulnerable`, version ranges |

**`cpeMatch` handling**

- **`criteria`**: string URI — typically `cpe:2.3:a:vendor:product:version:…` for applications.
- **`vulnerable`**: matches with **`vulnerable: false`** are skipped (non-vulnerable CPE rows).
- **Version ranges** (`versionStartIncluding`, `versionEndExcluding`, …): **not yet interpreted** in Phase B v1; applicability uses **vendor/product** alignment on `criteria` URIs only. A later iteration can layer semver/range checks once calibration data exists.

**Legacy / alternate shapes**

- Some datasets may include nested `configurations` without `nodes`, or future NVD tweaks. The extractor is intentionally defensive (`isinstance` guards); empty extraction yields **no Phase B adjustment** (neutral).

#### B.2 Implementation map (current)

**Parsing note:** A naive `split(":")` on CPE 2.3 bindings yields `["cpe", "2.3", part, vendor, product, …]` — the schema version is the single token `2.3`, not separate `2` and `3` fields. Vendor/product indices follow that prefix.

| Piece | Location |
|-------|-----------|
| Criteria extraction + vendor/product helpers | [`core/vulnerability/nvd_cpe_applicability.py`](../core/vulnerability/nvd_cpe_applicability.py) |
| Score deltas + evidence keys | [`core/vulnerability/cve_confidence.py`](../core/vulnerability/cve_confidence.py) — constants `NVD_CPE_ALIGN_BONUS`, `NVD_PRODUCT_VERSION_CRITERIA_HINT_BONUS`, `NVD_APPLICATION_MISMATCH_PENALTY` |
| `raw_json` on search hits + per-scan CVE criteria cache | [`core/vulnerability/nvd_offline.py`](../core/vulnerability/nvd_offline.py), [`core/vulnerability/cve_checker.py`](../core/vulnerability/cve_checker.py) |

**Scoring rules (v1)**

1. **Bonus (+12)** — Observed **application** CPE (`cpe:2.3:a:…` or legacy `cpe:/a:…`) **vendor/product** matches at least one extracted **criteria** URI (wildcard `*` in criteria matches any observed token).
2. **Weak bonus (+8)** — No CPE on the service, but **both** `product` and `version` exist **and** the version string appears inside concatenated criteria text **and** a coarse product token (≥3 chars) matches — reduces reliance on pure FTS coincidence without granting the strong CPE alignment signal.
3. **Penalty (−14)** — Service carries at least one parsed application CPE, CVE lists at least one **non–double-wildcard** `cpe:2.3:a:*:*…` criteria row (vendor/product not both `*`), and **no** vendor/product alignment — flags likely **false positives** when FTS matched keywords in prose/CPE noise.

Adjustments run **after** the fingerprint evidence block **before** the hard-evidence **High** cap, so NVD alignment cannot promote keyword-only rows past **79**.

**Evidence surfaced to GUI/export**

- `confidence_evidence["nvd_applicability"]`: counts, booleans, `sample_criteria` (first five URIs).

#### B.3 Deliverables vs backlog

**Done (baseline Phase B v1)**

- [x] Extract criteria from `raw_json` / JSON string; dedupe; honor `vulnerable: false`.
- [x] Wire `raw_json` through [`OfflineCve`](../core/vulnerability/nvd_offline.py) and FTS / LIKE search SELECTs.
- [x] Per-scan **`criteria_cache`** keyed by CVE id in [`cve_checker`](../core/vulnerability/cve_checker.py).
- [x] Integrate into `score_cve_match(..., nvd_criteria_cpes=…)`.
- [x] Unit tests: [`tests/unit/test_nvd_cpe_applicability.py`](../tests/unit/test_nvd_cpe_applicability.py), extended [`tests/unit/test_cve_confidence.py`](../tests/unit/test_cve_confidence.py) compatibility.

**Backlog (Phase B+)**

- [ ] Parse **CPE 2.3 version ranges** on `cpeMatch` objects and compare to `Service.version` (requires careful normalization + calibration).
- [ ] Handle **escaped colons** / malformed URIs without splitting bugs on `cpe:2.3:` strings.
- [ ] Optional: respect **AND/OR** grouping in configurations instead of flattening all matches (reduce rare false penalties).
- [ ] Enrich OS/hardware (`cpe:2.3:o:…`) when service fingerprints expose OS CPE from scanner.

**Acceptance criteria**

- [x] Unit tests with minimal `raw_json`-shaped fixtures (including `vulnerable` filtering).
- [x] No network required for tests.
- [x] Parse/extract cached once per CVE id per `query_offline_nvd_for_services` invocation.

**Dependencies**

- Satisfied: `search()` returns `raw_json` alongside metadata.

**Risks**

- NVD CPE 2.3 complexity → v1 intentionally limits **mismatch penalty** to cases with identifiable **`cpe:2.3:a:`** criteria with concrete vendor/product; OS-only CVE records do not trigger application mismatch penalties.
- Flattening OR graphs can theoretically over-count criteria; penalty requires **specific** application tuples to stay conservative.

---

### Phase C — HTTP / tech corroboration

**Objective:** When the target exposes HTTP(S), use **responses observed during the scan** to corroborate or contradict port-scan fingerprints for CVE relevance.

#### C.1 Implementation map (builtin crawl v1)

| Piece | Location |
|-------|-----------|
| Capture `Server` / `X-Powered-By` per destination port | [`core/vulnerability/web_vuln.py`](../core/vulnerability/web_vuln.py) (`_record_http_fingerprint`, `WebVulnOutput.http_fingerprints_by_port`) |
| Persist on scan result | [`core/models.py`](../core/models.py) `EnumerationReport.http_fingerprints_by_port`; merged in [`core/orchestrator.py`](../core/orchestrator.py) `_run_web_vuln` |
| Pass into CVE scoring | [`core/vulnerability/cve_checker.py`](../core/vulnerability/cve_checker.py) `http_fingerprints_by_port=` → `score_cve_match(..., http_context=…)` |
| Heuristic bonuses / penalties | [`core/vulnerability/cve_confidence.py`](../core/vulnerability/cve_confidence.py) — `HTTP_STACK_ALIGN_BONUS`, `HTTP_VERSION_IN_SERVER_BONUS`, `HTTP_STACK_CONFLICT_PENALTY` |

**Fingerprint shape**

- Key: **integer TCP port** matching [`Service.port`](../core/models.py) (derived from the **final** redirect URL).
- Value: `{"server": str≤256, "x_powered_by": str≤128}` — first non-empty value wins per field while crawling.

#### C.2 Scoring rules (v1)

Runs **after Phase B NVD criteria adjustments**, **before** the hard-evidence cap.

1. **Neutral** if `http_context` missing, headers empty, HTTP-derived stack tokens empty, or port-scan **stack tokens** cannot be inferred (`Service` lacks nginx/apache/tomcat/IIS signals in name/product/version/CPE text).
2. **Bonus (+6)** when inferred port-scan stack tokens **intersect** inferred tokens from `Server` + `X-Powered-By` (nginx/OpenResty, Apache/httpd, Tomcat/Coyote, IIS).
3. **Extra (+4)** when (2) applies **and** `Service.version` (length ≥ 3) appears as a substring inside those headers (case-insensitive).
4. **Penalty (−8)** only on **clear nginx ↔ Apache/httpd** mismatches (nginx fingerprint vs `apache` token in headers without nginx; Apache/httpd fingerprint vs nginx-only headers without apache/tomcat tokens). **Tomcat-only** fingerprints are excluded from the Apache→nginx penalty branch to reduce reverse-proxy false positives.

**Evidence**

- `confidence_evidence["http_corroboration"]`: trimmed header sample plus sorted token sets.

#### C.3 Deliverables vs backlog

**Done (Phase C v1 — builtin engine)**

- [x] Reuse crawl `GET` responses — no extra probe traffic.
- [x] Per-port header map on `EnumerationReport` + orchestrator merge + checker plumbing.
- [x] `score_cve_match(..., http_context=…)`.
- [x] Unit tests: [`tests/unit/test_http_corroboration.py`](../tests/unit/test_http_corroboration.py).

**Backlog**

- [x] **LOUD / ZAP** path: bootstrap GET probe per base URL (`probe_http_fingerprints_by_port`).
- [ ] Richer token families (Node, Express, PHP generic) once calibration exists.
- [ ] Optional HTML `<meta generator=` hints (bounded parse).

**Acceptance criteria**

- [x] When web ports absent or crawl skipped, fingerprint map stays empty — CVE scoring unchanged vs pre–Phase C for those runs.
- [x] Unit tests with synthetic `http_context` dicts (no live HTTP).
- [x] Headers truncated before persistence (see limits above).

**Privacy / storage**

- Only **two** header fields are retained, truncated; no full response bodies.

---

### Phase D — Calibration lab & weight tuning

**Objective:** Replace guesswork with **repeatable** benchmarks so **High** stays sparse and meaningful.

#### D.1 Landed (Phase D v1 scaffold)

| Piece | Location |
|-------|-----------|
| Pinned **nginx** service (`nginx:1.24-alpine`, host **18081**) | [`tests/compose/docker-compose.yml`](../tests/compose/docker-compose.yml) `nginx_cal` |
| Pinned **httpd** service (`httpd:2.4.67-alpine`, host **18082**) | [`tests/compose/docker-compose.yml`](../tests/compose/docker-compose.yml) `httpd_cal` |
| Opt-in pytest module (`BOOMSTICK_RUN_CALIBRATION=1`) | [`tests/calibration/`](../tests/calibration/) |
| Operator / developer doc | [`docs/calibration_lab.md`](calibration_lab.md) |
| Runner scripts | [`tools/run_calibration_lab.sh`](../tools/run_calibration_lab.sh), [`tools/run_calibration_lab.ps1`](../tools/run_calibration_lab.ps1) |

**Assertions today:** live nginx + Apache `Server` probes + builtin crawl populates `http_fingerprints_by_port` for the mapped ports (guards Phase C wiring + mismatch penalties).

**Tuning contract:** change weights in [`cve_confidence.py`](../core/vulnerability/cve_confidence.py), then run unit suites in §7 **and** optional calibration tests per [`calibration_lab.md`](calibration_lab.md).

#### D.2 Backlog

1. [x] **Second stack** (pinned Apache httpd) for nginx ↔ Apache conflict regression in Docker.
2. [x] **Tiny offline SQLite fixture** — [`tests/fixtures/nvd_minimal_db.py`](../tests/fixtures/nvd_minimal_db.py) + [`tests/unit/test_nvd_minimal_fixture.py`](../tests/unit/test_nvd_minimal_fixture.py).
3. [x] **GitHub Actions** job (Ubuntu integration) runs `tests/calibration` with `BOOMSTICK_RUN_CALIBRATION=1`.

**Acceptance criteria**

- [x] Documented local-only calibration flow + pinned container(s).
- [x] At least one Docker-backed assertion that fails if HTTP fingerprint capture regresses.
- [x] Threshold / bonus changes should continue to update **unit** expectations (`tests/unit/test_*confidence*.py`) — already required; calibration asserts cover nginx↔apache mismatch branches.

**Dependencies:** Phases B and C stabilized enough that tuning affects real signal, not noise.

---

### Phase E — Operator UX & exports

**Deliverables**

1. **GUI toggle:** “Hide Low match-confidence CVEs” — **on by default**; preference **saved** to disk ([`gui_prefs.py`](../core/utils/gui_prefs.py)); CVE panel shows how many Low rows are hidden and how to reveal them; toggling re-renders from [`MainWindow._last_result`](../gui/app.py).
2. **Shared CVE text builder:** [`gui/results_display.build_cve_section_lines`](../gui/results_display.py) + [`CVE_OPERATOR_BLURB`](../gui/results_display.py) used by the GUI and plain-text vulnerability export formatting (consistent ordering: band → confidence score → CVSS).
3. **Operator copy:** README subsection **“CVE match confidence vs CVSS”** ([`README.md`](../README.md)).

**Backlog**

- [x] **CSV export** — GUI **Export CVE CSV** + [`format_cves_csv`](../gui/results_display.py).
- [x] **Persist hide-low** — [`core/utils/gui_prefs.py`](../core/utils/gui_prefs.py) + env override `BOOMSTICK_GUI_PREFS`.

**Acceptance criteria**

- [x] Toggle defaults to hiding Low band; choice **persisted** in user prefs JSON ([`gui_prefs.py`](../core/utils/gui_prefs.py)), overridable via **`BOOMSTICK_GUI_PREFS`**.
- [x] Text export path uses same band ordering and operator blurb as the CVE list builder.

---

## 6. API evolution guidelines

- Prefer **additive** kwargs (`http_context`, `cpe_hints`) on `score_cve_match` over breaking positional signatures.
- Keep **JSON-serializable** payloads on CVE dicts for GUI/export.
- Any new field on `Service` should default safely for older callers.

---

## 7. Testing strategy

| Layer | Responsibility |
|-------|----------------|
| **Unit** | `cve_confidence` gates, weight math, CPE JSON fixtures, fake HTTP context. |
| **Integration** | Optional: orchestrator step order + CVE row shape snapshot (mock DB). |
| **Calibration** | Docker-known stacks → expected bands for golden CVE ids. |

**Mandatory command for this leg (baseline regression):**

```bash
python -m pytest tests/unit/test_cve_confidence.py tests/unit/test_nvd_cpe_applicability.py tests/unit/test_http_corroboration.py tests/unit/test_results_display_cves.py -q
```

Optional Docker lab (after touching confidence weights):

```bash
# See docs/calibration_lab.md
BOOMSTICK_RUN_CALIBRATION=1 python -m pytest tests/calibration -q
```

After Phase B/C changes, run full `tests/unit` before merge.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Over-tuning weights → false lows | Phase D golden containers; cap penalties; log reasons. |
| `raw_json` schema drift | Version-pin NVD feed tooling; fixture tests on parse failures (graceful degrade). |
| Extra HTTP traffic | Share crawler session; feature-flag probes. |
| Operator confusion | Explicit UI labels: “Match confidence” vs “CVSS (NVD)”. |

---

## 9. Documentation deliverables

- [x] Operator-facing paragraph: confidence bands vs severity ([`README.md`](README.md) §CVE match confidence vs CVSS).
- [ ] Developer note: consolidate tuning pointers (weights in `cve_confidence.py`; criteria in `nvd_cpe_applicability.py`; HTTP heuristics in `cve_confidence.py`) into a single short CONTRIBUTING or architecture note — optional cleanup.
- [x] Keep [`cve_confidence_plan.md`](cve_confidence_plan.md) checklist updated as phases complete.

---

## 10. Suggested execution order

1. **Phase A** — verify CI/tests green on baseline.
2. **Phase B** — `raw_json` CPE applicability (**v1 landed**: criteria extraction + alignment bonus / mismatch penalty); finish backlog items (version ranges, OR-graph fidelity) before heavy calibration.
3. **Phase C** — HTTP corroboration (**v1 landed** for builtin crawl and LOUD/ZAP; extend richer tokens later).
4. **Phase D** — calibration lab (**v1 landed**: nginx+httpd compose + opt-in `tests/calibration`; CI-enabled on Ubuntu).
5. **Phase E** — UX polish and operator docs (**v1 landed**: Low-hide toggle + README blurb + shared CVE lines helper).

Parallelization: Phase E (copy-only README) can start early; GUI toggle should wait until bands stabilize after B/D.

---

## 11. Definition of done (this leg)

This development leg is **complete** when:

1. Hard-evidence rules remain enforced (§3.3).
2. At least **Phase B** or **Phase C** is implemented with tests, **and** Phase **D** has an initial calibration story.
3. Operators have a short, authoritative explanation of **confidence vs CVSS** (§9 — README).

Optional stretch: Phase E toggle + structured JSON export of confidence fields.

---

## 12. Appendix — key files reference

| Area | Path |
|------|------|
| Scoring | `core/vulnerability/cve_confidence.py` |
| NVD criteria extraction & CPE compare | `core/vulnerability/nvd_cpe_applicability.py` |
| Offline query wiring | `core/vulnerability/cve_checker.py` |
| FTS / SQLite | `core/vulnerability/nvd_offline.py` |
| Service model | `core/models.py` |
| Scan order | `core/orchestrator.py` |
| Web crawl output | `core/vulnerability/web_vuln.py` |
| HTTP header merge / URL probes | `core/utils/http_fingerprint.py` |
| ZAP scan | `core/vulnerability/zap_scanner.py` |
| GUI prefs | `core/utils/gui_prefs.py` |
| GUI | `gui/app.py`, `gui/results_display.py` |
| Minimal NVD fixture (tests) | `tests/fixtures/nvd_minimal_db.py` |
| Tests | `tests/unit/test_cve_confidence.py`, `tests/unit/test_nvd_cpe_applicability.py`, `tests/unit/test_http_corroboration.py`, `tests/unit/test_results_display_cves.py`, `tests/unit/test_nvd_minimal_fixture.py`, `tests/unit/test_gui_prefs.py`, `tests/unit/test_format_cves_csv.py` |
| Calibration lab | `tests/calibration/`, `docs/calibration_lab.md` |
