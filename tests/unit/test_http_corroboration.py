from __future__ import annotations

from core.models import Service
from core.vulnerability.cve_confidence import (
    HTTP_STACK_ALIGN_BONUS,
    HTTP_STACK_CONFLICT_PENALTY,
    HTTP_VERSION_IN_SERVER_BONUS,
    score_cve_match,
)


def test_http_headers_boost_when_stack_aligns_and_version_visible() -> None:
    svc = Service(
        port=80,
        proto="tcp",
        state="open",
        name="http",
        product="nginx",
        version="1.24.0",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    ctx = {"server": "nginx/1.24.0"}
    base = score_cve_match(svc, match_query="nginx", http_context=None).score
    boosted = score_cve_match(svc, match_query="nginx", http_context=ctx).score
    assert boosted == base + HTTP_STACK_ALIGN_BONUS + HTTP_VERSION_IN_SERVER_BONUS


def test_http_headers_conflict_apache_server_nginx_fingerprint() -> None:
    svc = Service(
        port=80,
        proto="tcp",
        state="open",
        product="nginx",
        version="1.24",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    ctx = {"server": "Apache/2.4.58 (Unix)"}
    base = score_cve_match(svc, match_query="nginx", http_context=None).score
    hit = score_cve_match(svc, match_query="nginx", http_context=ctx).score
    assert hit == base - HTTP_STACK_CONFLICT_PENALTY


def test_http_skipped_without_observable_stack_tokens() -> None:
    svc = Service(port=80, proto="tcp", state="open", name="http")
    ctx = {"server": "nginx/1.24.0"}
    base = score_cve_match(svc, match_query="http", http_context=None).score
    same = score_cve_match(svc, match_query="http", http_context=ctx).score
    assert base == same
