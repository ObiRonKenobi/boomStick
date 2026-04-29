from __future__ import annotations

import queue
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import ScanConfig, ScanResult
from core.orchestrator import build_plan


def _toolish_label(step_name: str, config: ScanConfig) -> str:
    if step_name == "Ports" and config.mode.value == "loud":
        return "Running nmap"
    if step_name == "DNS" and config.mode.value == "loud":
        return "Running dig"
    if step_name == "Traceroute" and config.mode.value == "loud":
        return "Running traceroute/tracert"
    if step_name == "WebVuln" and config.mode.value == "loud":
        return "Running OWASP ZAP"
    if step_name == "CVE":
        return "Matching CVEs (offline NVD)"
    return f"Running {step_name}"


def _jsonify(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _jsonify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonify(v) for v in obj]
    if isinstance(obj, tuple):
        return [_jsonify(v) for v in obj]
    return obj


def serialize_result(result: ScanResult) -> dict[str, Any]:
    data = _jsonify(asdict(result))
    data["duration_s"] = result.duration_s()
    data["summary"] = result.summary()
    return data


def scan_worker(
    config: ScanConfig,
    q: queue.Queue,
    cancel: threading.Event,
    *,
    project_root: Path,
) -> None:
    """
    Worker thread entrypoint. Never touches Tk widgets directly.
    Emits messages:
      - progress: {type,pct,label}
      - partial: {type,step,payload}
      - log: {type,text}
      - done: {type,result}
      - error: {type,message}
    """
    result = ScanResult(target=config.target)
    try:
        q.put({"type": "progress", "pct": 0.02, "label": "Planning"})
        plan = build_plan(config, project_root=project_root, cancel_event=cancel)
        total = max(1, len(plan))

        for i, step in enumerate(plan):
            if cancel.is_set():
                q.put({"type": "error", "message": "Cancelled"})
                return
            label = _toolish_label(step.name, config)
            q.put({"type": "progress", "pct": (i / total), "label": label})
            q.put({"type": "log", "text": f"[start] {label}\n"})
            try:
                payload: dict[str, Any] = step.run(result)
                merged = dict(payload)
                merged["ok"] = True
                q.put({"type": "partial", "step": step.name, "payload": merged})
                q.put({"type": "log", "text": f"[ok] {step.name}\n"})
            except Exception as e:
                # Don’t kill the whole scan for one step; log and continue.
                result.warnings.append(f"{step.name} failed: {e}")
                q.put({"type": "partial", "step": step.name, "payload": {"ok": False, "error": str(e)}})
                q.put({"type": "log", "text": f"[fail] {step.name}: {e}\n"})

        result.finish()
        q.put({"type": "progress", "pct": 1.0, "label": "Done"})
        q.put({"type": "done", "result": serialize_result(result)})
    except Exception as e:
        result.errors.append(str(e))
        result.finish()
        q.put({"type": "error", "message": str(e)})
        q.put({"type": "done", "result": serialize_result(result)})

