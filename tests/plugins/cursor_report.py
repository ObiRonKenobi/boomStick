from __future__ import annotations

import importlib
import inspect
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

_MAPPINGS_PATH = Path(__file__).resolve().parents[1] / "harness" / "mappings.yaml"


def pytest_configure(config):  # type: ignore[no-untyped-def]
    config._boomstick_failures = []  # type: ignore[attr-defined]


def _module_from_rel_py(rel: str) -> object:
    mp = rel.replace("/", ".").removesuffix(".py")
    return importlib.import_module(mp)


def _line_for_symbol(rel_file: str, symbol: str) -> int | None:
    try:
        mod = _module_from_rel_py(rel_file)
        obj = getattr(mod, symbol)
        _, start = inspect.getsourcelines(obj)
        return int(start)
    except Exception:
        return None


def _load_mappings() -> dict:
    if not _MAPPINGS_PATH.is_file():
        return {}
    return yaml.safe_load(_MAPPINGS_PATH.read_text(encoding="utf8")) or {}


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):  # type: ignore[no-untyped-def]
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call" or rep.passed:
        return

    fid = None
    for m in item.iter_markers(name="accuracy_id"):
        if m.args:
            fid = str(m.args[0])
            break

    entry: dict = {
        "test_id": fid or item.nodeid,
        "pytest_nodeid": item.nodeid,
        "reproduction_steps": f"pytest -q {item.nodeid}",
        "longrepr": str(rep.longrepr)[:8000],
        "platform_specific": False,
    }

    maps = _load_mappings()
    if fid and fid in maps:
        hint = maps[fid]
        entry["tool"] = fid.split("/")[0]
        entry["source_file"] = hint["file"]
        entry["symbol"] = hint["symbol"]
        ln = _line_for_symbol(hint["file"], hint["symbol"])
        if ln is not None:
            entry["line_number"] = ln

    failures = getattr(item.session.config, "_boomstick_failures", None)
    if isinstance(failures, list):
        failures.append(entry)


def pytest_sessionfinish(session, exitstatus):  # type: ignore[no-untyped-def]
    root = Path(session.config.rootpath)
    art = root / "artifacts"
    art.mkdir(exist_ok=True)
    failures = getattr(session.config, "_boomstick_failures", []) or []
    rep_path = art / "cursor_report.json"
    note_path = art / "pytest_session_note.txt"
    note_path.write_text(
        f"exitstatus={exitstatus}\nfailures_recorded={len(failures)}\n",
        encoding="utf8",
    )
    collected = getattr(session, "testscollected", 0)
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(),
        "python": platform.python_version(),
        "summary": {
            "total_tests_collected": collected,
            "failed_reports": len(failures),
            "exitstatus": exitstatus,
            "accuracy_by_tool": {},
        },
        "failures": failures,
        "full_log": str(note_path.resolve()),
    }
    rep_path.write_text(json.dumps(report, indent=2), encoding="utf8")
