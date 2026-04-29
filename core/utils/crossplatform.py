from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class ExternalToolNotFound(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolPaths:
    nmap: Path | None = None
    dig: Path | None = None
    whois: Path | None = None
    traceroute: Path | None = None  # traceroute/tracepath/tracert


def _which(name: str) -> Path | None:
    p = shutil.which(name)
    return Path(p) if p else None


def platform_name() -> str:
    return platform.system()


def find_nmap() -> Path | None:
    system = platform_name()
    candidates: list[Path] = []
    w = _which("nmap")
    if w:
        candidates.append(w)
    if system == "Windows":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        env = os.environ.get("BOOMSTICK_NMAP")
        if env:
            candidates.append(Path(env))
        candidates += [
            Path(pfx86) / "Nmap" / "nmap.exe",
            Path(pf) / "Nmap" / "nmap.exe",
        ]
    for p in candidates:
        if p and p.is_file():
            return p
    return None


def find_dig() -> Path | None:
    env = os.environ.get("BOOMSTICK_DIG")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    return _which("dig")


def find_whois() -> Path | None:
    env = os.environ.get("BOOMSTICK_WHOIS")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    return _which("whois")


def find_traceroute() -> Path | None:
    system = platform_name()
    if system == "Windows":
        return _which("tracert")
    # Linux
    return _which("traceroute") or _which("tracepath")


def detect_tools() -> ToolPaths:
    return ToolPaths(
        nmap=find_nmap(),
        dig=find_dig(),
        whois=find_whois(),
        traceroute=find_traceroute(),
    )


def run_cmd_safe(
    argv: Sequence[str],
    *,
    timeout_s: int = 120,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    proc = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=str(cwd) if cwd else None,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def require_tool(path: Path | None, label: str) -> Path:
    if path is None:
        raise ExternalToolNotFound(f"{label} not found. Install it or set BOOMSTICK_{label.upper()} to its path.")
    return path

