from __future__ import annotations

from core.models import Service
from core.vulnerability.cve_confidence import HIGH_MIN, has_hard_evidence, score_cve_match


def test_keyword_only_never_high() -> None:
    svc = Service(port=80, proto="tcp", state="open", name="http")
    r = score_cve_match(svc, match_query="nginx")
    assert not has_hard_evidence(svc)
    assert r.score <= HIGH_MIN - 1
    assert r.band != "high"


def test_cpe_can_reach_high() -> None:
    svc = Service(
        port=443,
        proto="tcp",
        state="open",
        name="https",
        product="nginx",
        version="1.24.0",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    r = score_cve_match(svc, match_query="nginx nginx 1.24.0")
    assert has_hard_evidence(svc)
    assert r.band == "high"
    assert r.score >= HIGH_MIN


def test_product_version_can_reach_high() -> None:
    svc = Service(
        port=8080,
        proto="tcp",
        state="open",
        name="http",
        product="Apache httpd",
        version="2.4.58",
    )
    r = score_cve_match(svc, match_query="Apache httpd 2.4.58")
    assert has_hard_evidence(svc)
    assert r.band == "high"


def test_product_only_capped_below_high() -> None:
    svc = Service(
        port=80,
        proto="tcp",
        state="open",
        name="http",
        product="nginx",
    )
    r = score_cve_match(svc, match_query="nginx")
    assert not has_hard_evidence(svc)
    assert r.score <= HIGH_MIN - 1
