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


SYSTEM = platform.system()


@dataclass(frozen=True)
class ToolPaths:
    nmap: Path | None = None
    dig: Path | None = None
    whois: Path | None = None
    traceroute: Path | None = None  # traceroute/tracepath/tracert
    zap: Path | None = None  # OWASP ZAP launcher (zap.sh / zap.bat / zap.exe)


def _which(name: str) -> Path | None:
    p = shutil.which(name)
    return Path(p) if p else None


def platform_name() -> str:
    # Cached at import time so the app chooses tools consistently per run.
    return SYSTEM


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
    p = _which("dig")
    if p:
        return p
    # Windows: dig is typically shipped with ISC BIND
    if platform_name() == "Windows":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        candidates = [
            Path(pf) / "ISC BIND 9" / "bin" / "dig.exe",
            Path(pfx86) / "ISC BIND 9" / "bin" / "dig.exe",
            Path(pf) / "BIND9" / "bin" / "dig.exe",
            Path(pfx86) / "BIND9" / "bin" / "dig.exe",
        ]
        for c in candidates:
            if c.is_file():
                return c
    return None


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


def find_zap() -> Path | None:
    """
    Locate an OWASP ZAP launcher.
    - PATH: zap.sh (Linux), zap.bat/zap.exe (Windows)
    - Common install locations (best-effort)
    - Env override: BOOMSTICK_ZAP
    """
    env = os.environ.get("BOOMSTICK_ZAP")
    if env:
        p = Path(env)
        if p.is_file():
            return p

    system = platform_name()
    candidates: list[Path | None] = []

    if system == "Windows":
        candidates += [_which("zap.bat"), _which("zap.exe"), _which("zap")]
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        for base in (Path(pf), Path(pfx86)):
            candidates += [
                base / "OWASP" / "ZAP" / "Zed Attack Proxy" / "zap.bat",
                base / "OWASP" / "ZAP" / "Zed Attack Proxy" / "zap.exe",
                base / "ZAP" / "Zed Attack Proxy" / "zap.bat",
                base / "ZAP" / "Zed Attack Proxy" / "zap.exe",
            ]
    else:
        candidates += [_which("zap.sh"), _which("zap"), _which("zaproxy")]
        candidates += [
            Path("/opt/zap/zap.sh"),
            Path("/opt/ZAP/zap.sh"),
            Path("/usr/share/zaproxy/zap.sh"),
        ]

    for p in candidates:
        if p and p.is_file():
            return p
    return None


def detect_tools() -> ToolPaths:
    return ToolPaths(
        nmap=find_nmap(),
        dig=find_dig(),
        whois=find_whois(),
        traceroute=find_traceroute(),
        zap=find_zap(),
    )


def run_cmd_safe(
    argv: Sequence[str],
    *,
    timeout_s: int = 120,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(cwd) if cwd else None,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError as e:
        # Missing executable (common when optional loud tools aren't installed).
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), (e.stderr or f"timeout after {timeout_s}s")


def require_tool(path: Path | None, label: str) -> Path:
    if path is None:
        raise ExternalToolNotFound(f"{label} not found. Install it or set BOOMSTICK_{label.upper()} to its path.")
    return path


def install_zap() -> tuple[bool, str]:
    """
    Best-effort install of OWASP ZAP using platform package managers.
    - Windows: winget install --id ZAP.ZAP -e
    - Linux (Debian/Ubuntu): apt-get install zaproxy (may require sudo)
    Returns (ok, message).
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install ZAP manually or add it to PATH"
            rc, out, err = run_cmd_safe([str(winget), "install", "--id", "ZAP.ZAP", "-e", "--source", "winget"], timeout_s=600)
            if rc == 0:
                return True, "Installed ZAP via winget"
            return False, f"winget install failed: {err.strip() or out.strip() or rc}"
        # Linux
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return False, "apt not found; install ZAP manually (snap/flatpak) or add zap.sh to PATH"
        # Try without sudo first; if it fails, user can rerun with sudo or install manually.
        rc, out, err = run_cmd_safe([str(apt), "update"], timeout_s=600)
        if rc != 0:
            return False, f"apt update failed: {err.strip() or out.strip() or rc}"
        rc, out, err = run_cmd_safe([str(apt), "install", "-y", "zaproxy"], timeout_s=600)
        if rc == 0:
            return True, "Installed ZAP (zaproxy) via apt"
        return False, f"apt install zaproxy failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"ZAP install failed: {e}"


def install_nmap() -> tuple[bool, str]:
    """
    Best-effort install of nmap.
    - Windows: winget install --id Insecure.Nmap -e
    - Linux: apt install nmap (may require sudo)
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install Nmap manually"
            rc, out, err = run_cmd_safe(
                [str(winget), "install", "--id", "Insecure.Nmap", "-e", "--source", "winget"],
                timeout_s=600,
            )
            if rc == 0:
                return True, "Installed Nmap via winget"
            return False, f"winget install failed: {err.strip() or out.strip() or rc}"
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return False, "apt not found; install nmap manually"
        rc, out, err = run_cmd_safe([str(apt), "update"], timeout_s=600)
        if rc != 0:
            return False, f"apt update failed: {err.strip() or out.strip() or rc}"
        rc, out, err = run_cmd_safe([str(apt), "install", "-y", "nmap"], timeout_s=600)
        if rc == 0:
            return True, "Installed nmap via apt"
        return False, f"apt install nmap failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"nmap install failed: {e}"


def install_dig() -> tuple[bool, str]:
    """
    Best-effort install of dig.
    - Windows: winget install --id ISC.BIND -e (dig ships with BIND)
    - Linux: apt install dnsutils
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install BIND/dig manually"
            # winget IDs can vary by manifest; try a few common ones.
            for pkg_id in ("ISC.BIND", "ISC.BIND9", "ISC.Bind"):
                rc, out, err = run_cmd_safe(
                    [str(winget), "install", "--id", pkg_id, "-e", "--source", "winget"],
                    timeout_s=600,
                )
                if rc == 0:
                    return True, f"Installed {pkg_id} (dig) via winget"
            return False, "winget could not install a BIND package (try installing BIND/dig manually and set BOOMSTICK_DIG)"
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return False, "apt not found; install dnsutils manually"
        rc, out, err = run_cmd_safe([str(apt), "update"], timeout_s=600)
        if rc != 0:
            return False, f"apt update failed: {err.strip() or out.strip() or rc}"
        rc, out, err = run_cmd_safe([str(apt), "install", "-y", "dnsutils"], timeout_s=600)
        if rc == 0:
            return True, "Installed dnsutils (dig) via apt"
        return False, f"apt install dnsutils failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"dig install failed: {e}"


def install_traceroute() -> tuple[bool, str]:
    """
    Best-effort install of traceroute equivalents.
    - Windows: tracert is built-in (no install)
    - Linux: apt install traceroute (or iputils-tracepath as an alternative)
    """
    system = platform_name()
    if system == "Windows":
        return True, "tracert is built-in on Windows"
    try:
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return False, "apt not found; install traceroute manually"
        rc, out, err = run_cmd_safe([str(apt), "update"], timeout_s=600)
        if rc != 0:
            return False, f"apt update failed: {err.strip() or out.strip() or rc}"
        # Prefer traceroute; many distros also have tracepath in iputils-tracepath.
        rc, out, err = run_cmd_safe([str(apt), "install", "-y", "traceroute"], timeout_s=600)
        if rc == 0:
            return True, "Installed traceroute via apt"
        rc2, out2, err2 = run_cmd_safe([str(apt), "install", "-y", "iputils-tracepath"], timeout_s=600)
        if rc2 == 0:
            return True, "Installed tracepath (iputils-tracepath) via apt"
        return False, f"apt install traceroute failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"traceroute install failed: {e}"


def install_whois() -> tuple[bool, str]:
    """
    Best-effort install of whois.
    - Windows: winget install --id GNU.Whois -e
    - Linux: apt install whois
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install whois manually"
            rc, out, err = run_cmd_safe(
                [str(winget), "install", "--id", "GNU.Whois", "-e", "--source", "winget"],
                timeout_s=600,
            )
            if rc == 0:
                return True, "Installed whois via winget"
            return False, f"winget install whois failed: {err.strip() or out.strip() or rc}"
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return False, "apt not found; install whois manually"
        rc, out, err = run_cmd_safe([str(apt), "update"], timeout_s=600)
        if rc != 0:
            return False, f"apt update failed: {err.strip() or out.strip() or rc}"
        rc, out, err = run_cmd_safe([str(apt), "install", "-y", "whois"], timeout_s=600)
        if rc == 0:
            return True, "Installed whois via apt"
        return False, f"apt install whois failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"whois install failed: {e}"


def install_subfinder() -> tuple[bool, str]:
    """
    Best-effort install of subfinder.
    - Windows: winget install --id ProjectDiscovery.Subfinder -e
    - Linux: install via Go if available (not typically in apt repos)
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install subfinder manually"
            rc, out, err = run_cmd_safe(
                [str(winget), "install", "--id", "ProjectDiscovery.Subfinder", "-e", "--source", "winget"],
                timeout_s=600,
            )
            if rc == 0:
                return True, "Installed subfinder via winget"
            return False, f"winget install subfinder failed: {err.strip() or out.strip() or rc}"

        go = _which("go")
        if not go:
            return False, "Go not found; install subfinder manually or install Go then retry"
        rc, out, err = run_cmd_safe(
            [str(go), "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            timeout_s=900,
        )
        if rc == 0:
            return True, "Installed subfinder via go install (ensure GOPATH/bin is on PATH)"
        return False, f"go install subfinder failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"subfinder install failed: {e}"


def install_amass() -> tuple[bool, str]:
    """
    Best-effort install of amass.
    - Windows: winget install --id OWASP.Amass -e
    - Linux: install via Go if available (amass v4 module path)
    """
    system = platform_name()
    try:
        if system == "Windows":
            winget = _which("winget")
            if not winget:
                return False, "winget not found; install amass manually"
            rc, out, err = run_cmd_safe(
                [str(winget), "install", "--id", "OWASP.Amass", "-e", "--source", "winget"],
                timeout_s=600,
            )
            if rc == 0:
                return True, "Installed amass via winget"
            return False, f"winget install amass failed: {err.strip() or out.strip() or rc}"

        go = _which("go")
        if not go:
            return False, "Go not found; install amass manually or install Go then retry"
        rc, out, err = run_cmd_safe(
            [str(go), "install", "github.com/owasp-amass/amass/v4/...@latest"],
            timeout_s=900,
        )
        if rc == 0:
            return True, "Installed amass via go install (ensure GOPATH/bin is on PATH)"
        return False, f"go install amass failed: {err.strip() or out.strip() or rc}"
    except Exception as e:
        return False, f"amass install failed: {e}"

