from __future__ import annotations

from pathlib import Path

from core.models import Service
from core.vulnerability.cve_checker import query_offline_nvd_for_services
from tests.fixtures.nvd_minimal_db import build_minimal_nvd_sqlite


def test_minimal_nvd_sqlite_finds_nginx_cve(monkeypatch, tmp_path: Path) -> None:
    db = tmp_path / "nvd.sqlite"
    build_minimal_nvd_sqlite(db)
    monkeypatch.setenv("BOOMSTICK_NVD_DB", str(db))
    root = Path(__file__).resolve().parents[2]
    svc = Service(
        port=443,
        proto="tcp",
        state="open",
        name="https",
        product="nginx",
        version="1.24.0",
        cpes=["cpe:/a:nginx:nginx:1.24.0"],
    )
    out = query_offline_nvd_for_services([svc], project_root=root, results_per_query=20)
    ids = {row["cve"] for row in out.cves}
    assert "CVE-TEST-NGINX-001" in ids
    nginx_rows = [r for r in out.cves if r["cve"] == "CVE-TEST-NGINX-001"]
    assert nginx_rows
    assert "confidence_score" in nginx_rows[0]
    assert "confidence_band" in nginx_rows[0]
