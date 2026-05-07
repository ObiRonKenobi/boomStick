"""Persistent GUI preferences (per-user JSON file)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _prefs_file_path() -> Path:
    override = os.environ.get("BOOMSTICK_GUI_PREFS", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "boomStick" / "gui_prefs.json"
    return Path.home() / ".config" / "boomStick" / "gui_prefs.json"


def load_gui_prefs() -> dict[str, Any]:
    path = _prefs_file_path()
    if not path.is_file():
        return {}
    try:
        raw = path.read_text(encoding="utf8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_gui_prefs(prefs: dict[str, Any]) -> None:
    path = _prefs_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(prefs, indent=2, sort_keys=True), encoding="utf8")
    tmp.replace(path)
