from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urljoin

import pytest

from core.models import ScanConfig
from core.vulnerability.web_vuln import crawl_and_test
from tests.harness.compare import normalize_url


@pytest.mark.integration
@pytest.mark.accuracy_id("web/crawl_static_graph")
def test_static_crawl_covers_expected_paths() -> None:
    origin = os.environ.get("TEST_WEB_ORIGIN", "http://127.0.0.1:18080").rstrip("/")
    golden_path = Path(__file__).resolve().parents[1] / "golden" / "web_static_paths.json"
    spec = json.loads(golden_path.read_text(encoding="utf8"))

    cfg = ScanConfig(
        target="127.0.0.1",
        export_crawl_telemetry=True,
        max_pages=30,
        crawl_depth=4,
        http_timeout_s=8,
    )
    out = crawl_and_test(cfg, base_urls=[origin + "/"])

    assert out.telemetry is not None
    visited = {normalize_url(u) for u in out.telemetry["visited_urls"]}

    for p in spec["paths"]:
        expect = normalize_url(urljoin(origin + "/", p.lstrip("/")))
        assert expect in visited, f"missing {expect} in {sorted(visited)}"

    for bad in spec["disallowed_paths"]:
        bad_u = normalize_url(urljoin(origin + "/", bad.lstrip("/")))
        assert bad_u not in visited, f"robotsdisallowed URL was fetched: {bad_u}"

    extra = visited - {normalize_url(urljoin(origin + "/", p.lstrip("/"))) for p in spec["paths"]}
    fp_rate = len(extra) / max(1, len(visited))
    assert fp_rate < 0.02, f"too many extra URLs: {extra}"
