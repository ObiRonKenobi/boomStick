"""
Phase D smoke: pinned Apache httpd ``Server`` header + builtin crawl fingerprint map.

Requires ``httpd_cal`` from ``tests/compose/docker-compose.yml`` (host port 18082).
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
import requests

from core.models import ScanConfig, ScanMode, ScanScope, Service
from core.vulnerability.cve_confidence import HTTP_STACK_CONFLICT_PENALTY, score_cve_match
from core.vulnerability.web_vuln import crawl_and_test


HTTPD_ORIGIN = os.environ.get("TEST_APACHE_ORIGIN", "http://127.0.0.1:18082").rstrip("/")


def _origin_port(origin: str) -> int:
    p = urlparse(origin)
    if p.port is not None:
        return int(p.port)
    return 443 if (p.scheme or "http").lower() == "https" else 80


@pytest.mark.calibration
@pytest.mark.network
def test_httpd_lab_exposes_server_header() -> None:
    try:
        r = requests.get(f"{HTTPD_ORIGIN}/", timeout=5)
    except requests.RequestException as e:
        pytest.fail(f"Cannot reach {HTTPD_ORIGIN} — start httpd_cal? ({e})")
    assert r.status_code == 200
    server = (r.headers.get("Server") or "").lower()
    assert "apache" in server or "httpd" in server, f"expected apache/httpd in Server header, got {server!r}"


@pytest.mark.calibration
@pytest.mark.network
def test_builtin_crawl_records_fingerprint_for_httpd_host_port() -> None:
    cfg = ScanConfig(
        target="127.0.0.1",
        mode=ScanMode.QUIET,
        scope=ScanScope.VULN,
        max_pages=5,
        crawl_depth=1,
        http_timeout_s=8,
    )
    out = crawl_and_test(cfg, base_urls=[f"{HTTPD_ORIGIN}/"])
    assert out.http_fingerprints_by_port is not None
    parsed_port = _origin_port(HTTPD_ORIGIN)
    fp = out.http_fingerprints_by_port.get(parsed_port)
    assert fp is not None, f"no fingerprint for port {parsed_port}, keys={list(out.http_fingerprints_by_port.keys())}"
    srv = (fp.get("server") or "").lower()
    assert "apache" in srv or "httpd" in srv, fp


@pytest.mark.calibration
@pytest.mark.network
def test_httpd_server_header_penalizes_nginx_fingerprint() -> None:
    """
    Guard the "nginx↔apache mismatch" branch using a live httpd Server header.
    """
    try:
        r = requests.get(f"{HTTPD_ORIGIN}/", timeout=5)
    except requests.RequestException as e:
        pytest.fail(f"Cannot reach {HTTPD_ORIGIN} — start httpd_cal? ({e})")
    server = (r.headers.get("Server") or "").strip()
    assert server

    svc = Service(port=80, proto="tcp", state="open", product="nginx", version="1.24", cpes=["cpe:/a:nginx:nginx"])
    base = score_cve_match(svc, match_query="nginx", http_context=None).score
    hit = score_cve_match(svc, match_query="nginx", http_context={"server": server}).score
    assert hit == base - HTTP_STACK_CONFLICT_PENALTY

