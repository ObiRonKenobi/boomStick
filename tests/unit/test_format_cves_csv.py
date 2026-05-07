from __future__ import annotations

import csv
from io import StringIO

from gui.results_display import format_cves_csv


def test_format_cves_csv_includes_headers_and_row() -> None:
    cves = [
        {
            "cve": "CVE-2024-0001",
            "score": 9.1,
            "confidence_score": 88,
            "confidence_band": "high",
            "published": "2024-01-01",
            "modified": "2024-01-02",
            "summary": "Example",
            "url": "https://example.invalid/cve",
            "source": "nvd_offline",
            "match": {"query": "nginx"},
            "service": {
                "port": 443,
                "proto": "tcp",
                "name": "https",
                "product": "nginx",
                "version": "1.24.0",
                "cpes": ["cpe:/a:nginx:nginx"],
            },
            "confidence_reasons": ["reason a", "reason b"],
        }
    ]
    text = format_cves_csv(cves)
    r = csv.reader(StringIO(text))
    rows = list(r)
    assert rows[0][0] == "cve"
    assert rows[1][0] == "CVE-2024-0001"
    assert rows[1][2] == "88"
    assert "reason a" in rows[1][13]
