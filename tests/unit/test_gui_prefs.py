from __future__ import annotations

from pathlib import Path

from core.utils.gui_prefs import load_gui_prefs, save_gui_prefs


def test_gui_prefs_roundtrip_via_env(monkeypatch, tmp_path: Path) -> None:
    p = tmp_path / "gui_prefs.json"
    monkeypatch.setenv("BOOMSTICK_GUI_PREFS", str(p))
    save_gui_prefs({"hide_low_confidence_cves": False, "other": 1})
    loaded = load_gui_prefs()
    assert loaded.get("hide_low_confidence_cves") is False
    assert loaded.get("other") == 1
