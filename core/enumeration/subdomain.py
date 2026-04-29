from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import dns.resolver
import requests

from core.models import ScanConfig, ScanMode, SubdomainStrategy
from core.utils.crossplatform import install_amass, install_subfinder, run_cmd_safe
from core.utils.network import normalize_target, is_ip, is_domain


def _resolve_a(name: str) -> bool:
    try:
        ans = dns.resolver.resolve(name, "A", raise_on_no_answer=False)
        return bool(ans)
    except Exception:
        return False


def _load_wordlist(path: Path) -> list[str]:
    if not path.is_file():
        return []
    words: list[str] = []
    for line in path.read_text(encoding="utf8", errors="ignore").splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        if w not in words:
            words.append(w)
    return words


@dataclass(frozen=True)
class SubdomainOutput:
    subdomains: list[str]
    sources: dict[str, int]
    warnings: list[str] = None  # type: ignore[assignment]


def _bounded_bruteforce(
    domain: str,
    *,
    wordlist: Iterable[str],
    max_attempts: int = 50_000,
    max_found: int = 5_000,
    max_runtime_s: int = 120,
    cancel_event=None,
) -> tuple[list[str], dict[str, int]]:
    started = time.time()
    found: list[str] = []
    attempts = 0
    for w in wordlist:
        if cancel_event is not None and cancel_event.is_set():
            break
        if attempts >= max_attempts:
            break
        if (time.time() - started) > max_runtime_s:
            break
        attempts += 1
        host = f"{w}.{domain}".strip(".")
        if _resolve_a(host):
            if host not in found:
                found.append(host)
            if len(found) >= max_found:
                break
    found.sort()
    return found, {"bruteforce_attempts": attempts, "bruteforce_found": len(found)}


def _crtsh_passive(domain: str, *, timeout_s: int = 15, cancel_event=None) -> tuple[list[str], int]:
    """
    Best-effort passive enumeration via crt.sh.
    Endpoint returns JSON array; we only parse name_value fields.
    """
    if cancel_event is not None and cancel_event.is_set():
        return [], 0
    url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    try:
        r = requests.get(url, timeout=timeout_s, headers={"User-Agent": "boomStick"})
        if not r.ok or not r.text:
            return [], 0
        data = json.loads(r.text)
    except Exception:
        return [], 0
    out: list[str] = []
    for item in data if isinstance(data, list) else []:
        nv = item.get("name_value") if isinstance(item, dict) else None
        if not nv:
            continue
        for name in str(nv).splitlines():
            name = name.strip().lower().strip(".")
            if not name or "*" in name:
                continue
            if name.endswith("." + domain) or name == domain:
                if name not in out:
                    out.append(name)
        if cancel_event is not None and cancel_event.is_set():
            break
    out.sort()
    return out, len(out)


def _run_external_tool(tool: str, domain: str, *, timeout_s: int = 180) -> tuple[list[str], str | None]:
    """
    Execute a subdomain discovery tool if present in PATH.
    Returns (subdomains, warning)
    """
    # Note: we intentionally do not add tool location logic here; rely on PATH.
    if tool == "subfinder":
        argv = ["subfinder", "-silent", "-d", domain]
    elif tool == "amass":
        argv = ["amass", "enum", "-passive", "-d", domain]
    else:
        return [], f"Unknown external tool: {tool}"

    rc, out, err = run_cmd_safe(argv, timeout_s=timeout_s)
    if rc == 127:
        # Attempt install, then retry once.
        if tool == "subfinder":
            ok, msg = install_subfinder()
        elif tool == "amass":
            ok, msg = install_amass()
        else:
            ok, msg = False, f"Auto-install not supported for {tool}"
        if not ok:
            return [], f"{tool} not found; install failed: {msg}"
        rc, out, err = run_cmd_safe(argv, timeout_s=timeout_s)
        if rc == 127:
            return [], f"{tool} install reported success but executable is still not on PATH"
    if rc != 0 and not out:
        return [], f"{tool} failed: {err.strip() or rc}"
    subs: list[str] = []
    for line in (out or "").splitlines():
        s = line.strip().lower().strip(".")
        if not s:
            continue
        if s.endswith("." + domain) or s == domain:
            if s not in subs:
                subs.append(s)
    subs.sort()
    warn = err.strip() if err.strip() else None
    return subs, warn


def discover_subdomains(
    config: ScanConfig,
    *,
    data_dir: Path,
    user_wordlist: Path | None = None,
    cancel_event=None,
) -> SubdomainOutput:
    target = normalize_target(config.target)
    if is_ip(target) or not is_domain(target):
        return SubdomainOutput(subdomains=[], sources={}, warnings=["Subdomain discovery requires a domain target"])

    domain = target.strip(".").lower()
    warnings: list[str] = []
    sources: dict[str, int] = {}

    wl = _load_wordlist(data_dir / "subdomains.txt")
    if user_wordlist is not None:
        wl += _load_wordlist(user_wordlist)
    # stable unique
    seen: set[str] = set()
    wordlist: list[str] = []
    for w in wl:
        if w not in seen:
            seen.add(w)
            wordlist.append(w)

    strategy: SubdomainStrategy = config.subdomain_strategy
    found: list[str] = []

    if strategy == "bounded_bruteforce":
        found, s = _bounded_bruteforce(domain, wordlist=wordlist, cancel_event=cancel_event)
        sources.update(s)
    elif strategy == "passive_plus_bruteforce":
        passive, passive_n = _crtsh_passive(domain, cancel_event=cancel_event)
        sources["crtsh_found"] = passive_n
        bf, s = _bounded_bruteforce(domain, wordlist=wordlist, cancel_event=cancel_event)
        sources.update(s)
        found = sorted(set(passive) | set(bf))
    elif strategy == "external_tools_aggressive":
        if config.mode != ScanMode.LOUD:
            warnings.append("External tools strategy requires loud mode; falling back to passive+bruteforce")
            passive, passive_n = _crtsh_passive(domain, cancel_event=cancel_event)
            sources["crtsh_found"] = passive_n
            bf, s = _bounded_bruteforce(domain, wordlist=wordlist, cancel_event=cancel_event)
            sources.update(s)
            found = sorted(set(passive) | set(bf))
        else:
            subs: set[str] = set()
            for tool in ("subfinder", "amass"):
                tool_subs, warn = _run_external_tool(tool, domain)
                if warn:
                    warnings.append(warn)
                sources[f"{tool}_found"] = len(tool_subs)
                subs |= set(tool_subs)
            if not subs:
                warnings.append("No external tool results; falling back to passive+bruteforce")
                passive, passive_n = _crtsh_passive(domain, cancel_event=cancel_event)
                sources["crtsh_found"] = passive_n
                bf, s = _bounded_bruteforce(domain, wordlist=wordlist, cancel_event=cancel_event)
                sources.update(s)
                subs |= set(passive) | set(bf)
            found = sorted(subs)
    else:
        warnings.append(f"Unknown subdomain strategy: {strategy}")

    return SubdomainOutput(subdomains=found, sources=sources, warnings=warnings)

