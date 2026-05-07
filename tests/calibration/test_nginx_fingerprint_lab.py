"""
Phase D smoke: real ``Server`` header + builtin crawl fingerprint map.

Requires ``nginx_cal`` from ``tests/compose/docker-compose.yml`` (host port 18081).

When tuning constants in ``cve_confidence.py``, run::

    BOOMSTICK_RUN_CALIBRATION=1 pytest tests/calibration -q

after ``docker compose -f tests/compose/docker-compose.yml up -d nginx_cal``.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
import requests

from core.models import ScanConfig, ScanMode, ScanScope
from core.vulnerability.web_vuln import crawl_and_test


NGINX_ORIGIN = os.environ.get("TEST_NGINX_ORIGIN", "http://127.0.0.1:18081").rstrip("/")


def _origin_port(origin: str) -> int:
    p = urlparse(origin)
    if p.port is not None:
        return int(p.port)
    return 443 if (p.scheme or "http").lower() == "https" else 80


@pytest.mark.calibration
@pytest.mark.network
def test_nginx_lab_exposes_server_header() -> None:
    try:
        r = requests.get(f"{NGINX_ORIGIN}/", timeout=5)
    except requests.RequestException as e:
        pytest.fail(f"Cannot reach {NGINX_ORIGIN} — start nginx_cal? ({e})")
    assert r.status_code == 200
    server = (r.headers.get("Server") or "").lower()
    assert "nginx" in server, f"expected nginx in Server header, got {server!r}"


@pytest.mark.calibration
@pytest.mark.network
def test_builtin_crawl_records_fingerprint_for_host_port() -> None:
    cfg = ScanConfig(
        target="127.0.0.1",
        mode=ScanMode.QUIET,
        scope=ScanScope.VULN,
        max_pages=5,
        crawl_depth=1,
        http_timeout_s=8,
    )
    out = crawl_and_test(cfg, base_urls=[f"{NGINX_ORIGIN}/"])
    assert out.http_fingerprints_by_port is not None
    parsed_port = _origin_port(NGINX_ORIGIN)
    fp = out.http_fingerprints_by_port.get(parsed_port)
    assert fp is not None, f"no fingerprint for port {parsed_port}, keys={list(out.http_fingerprints_by_port.keys())}"
    srv = (fp.get("server") or "").lower()
    assert "nginx" in srv, fp
