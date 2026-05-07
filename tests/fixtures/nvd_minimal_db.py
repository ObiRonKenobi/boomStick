"""
Build a tiny deterministic NVD SQLite DB for tests (no network).

Use ``BOOMSTICK_NVD_DB`` pointing at the generated file and call
``query_offline_nvd_for_services`` with a controlled ``project_root``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.vulnerability.nvd_offline import open_db, upsert_cve


def _vuln_wrapper(*, cve_id: str, summary: str, criteria: list[str]) -> dict[str, Any]:
    matches = [{"vulnerable": True, "criteria": c} for c in criteria]
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00",
            "lastModified": "2024-01-02T00:00:00",
            "descriptions": [{"lang": "en", "value": summary}],
            "configurations": [{"nodes": [{"cpeMatch": matches}]}],
        }
    }


def build_minimal_nvd_sqlite(db_path: Path) -> None:
    """Insert two synthetic CVEs (nginx vs apache CPE rows) for matcher regression."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, list[str]]] = [
        (
            "CVE-TEST-NGINX-001",
            # LIKE fallback matches the full cpe-derived keyword substring (vendor product version).
            "nginx nginx 1.24.0 minimal fixture test advisory",
            ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*:*:*:*"],
        ),
        (
            "CVE-TEST-APACHE-001",
            "apache http_server test advisory minimal fixture",
            ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*:*:*:*:*"],
        ),
    ]
    conn = open_db(db_path)
    try:
        for cve_id, summary, cpes in rows:
            v = _vuln_wrapper(cve_id=cve_id, summary=summary, criteria=cpes)
            cve_block = v["cve"]
            blob = " ".join([cve_id, summary, " ".join(cpes)]).strip()
            upsert_cve(
                conn,
                cve_id=cve_id,
                published=str(cve_block.get("published")),
                modified=str(cve_block.get("lastModified")),
                score=7.5,
                summary=summary,
                text=blob,
                raw_json=v,
            )
        conn.commit()
    finally:
        conn.close()
