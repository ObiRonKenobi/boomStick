from __future__ import annotations

from gui.results_display import build_cve_section_lines


def test_build_cve_section_hides_low_band() -> None:
    cves = [
        {"cve": "CVE-2024-0001", "confidence_band": "high", "confidence_score": 90, "score": 9.0},
        {"cve": "CVE-2024-0002", "confidence_band": "low", "confidence_score": 10, "score": 5.0},
    ]
    lines, n_hidden = build_cve_section_lines(cves, hide_low_band=True, max_rows=50)
    assert n_hidden == 1
    blob = "\n".join(lines)
    assert "CVE-2024-0001" in blob
    assert "CVE-2024-0002" not in blob


def test_build_cve_section_shows_all_when_not_hiding() -> None:
    cves = [
        {"cve": "CVE-2024-0001", "confidence_band": "high", "confidence_score": 90, "score": 9.0},
        {"cve": "CVE-2024-0002", "confidence_band": "low", "confidence_score": 10, "score": 5.0},
    ]
    lines, n_hidden = build_cve_section_lines(cves, hide_low_band=False, max_rows=50)
    assert n_hidden == 0
    blob = "\n".join(lines)
    assert "CVE-2024-0001" in blob
    assert "CVE-2024-0002" in blob
