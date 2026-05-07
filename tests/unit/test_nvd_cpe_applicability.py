from __future__ import annotations

import json

from core.models import Service
from core.vulnerability.cve_confidence import (
    NVD_APPLICATION_MISMATCH_PENALTY,
    NVD_CPE_ALIGN_BONUS,
    score_cve_match,
)
from core.vulnerability.nvd_cpe_applicability import (
    extract_cpe_criteria_from_stored_vuln,
)


def _minimal_vuln(*criteria: str) -> dict:
    matches = [{"vulnerable": True, "criteria": c} for c in criteria]
    return {
        "cve": {
            "id": "CVE-XXXX-0000",
            "configurations": [{"nodes": [{"cpeMatch": matches}]}],
        }
    }


def test_extract_criteria_from_json_string() -> None:
    blob = _minimal_vuln("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*:*:*:*")
    got = extract_cpe_criteria_from_stored_vuln(json.dumps(blob))
    assert len(got) == 1
    assert "vendor" in got[0]


def test_extract_criteria_respects_vulnerable_flag() -> None:
    blob = {
        "cve": {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": False, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*:*:*:*:*"},
                                {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ]
        }
    }
    got = extract_cpe_criteria_from_stored_vuln(blob)
    assert len(got) == 1
    assert "nginx" in got[0]


def test_nvd_criteria_bonus_when_aligned_with_service_cpe() -> None:
    svc = Service(
        port=443,
        proto="tcp",
        state="open",
        name="https",
        product="nginx",
        version="1.24.0",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    criteria = ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*:*:*:*"]
    base = score_cve_match(svc, match_query="nginx", nvd_criteria_cpes=None).score
    boosted = score_cve_match(svc, match_query="nginx", nvd_criteria_cpes=criteria).score
    assert boosted == base + NVD_CPE_ALIGN_BONUS


def test_nvd_criteria_penalty_when_application_cpe_conflicts() -> None:
    svc = Service(
        port=443,
        proto="tcp",
        state="open",
        name="https",
        product="nginx",
        version="1.24.0",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    apache_only = _minimal_vuln("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*:*:*:*:*")
    criteria = extract_cpe_criteria_from_stored_vuln(apache_only)
    base = score_cve_match(svc, match_query="nginx", nvd_criteria_cpes=None).score
    penalized = score_cve_match(svc, match_query="nginx", nvd_criteria_cpes=criteria).score
    assert penalized == base - NVD_APPLICATION_MISMATCH_PENALTY
