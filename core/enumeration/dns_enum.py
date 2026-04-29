from __future__ import annotations

from dataclasses import dataclass

import dns.resolver

from core.models import ScanConfig, ScanMode
from core.utils.crossplatform import detect_tools, install_dig, run_cmd_safe
from core.utils.network import normalize_target, is_ip


DNS_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT")


def _resolve(rrtype: str, name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, rrtype, raise_on_no_answer=False)
    except Exception:
        return []
    out: list[str] = []
    if not answers:
        return out
    for rdata in answers:
        s = str(rdata).strip()
        if s and s not in out:
            out.append(s)
    return out


@dataclass(frozen=True)
class DnsEnumOutput:
    records: dict[str, list[str]]
    raw_dig: str | None = None
    warnings: list[str] = None  # type: ignore[assignment]


def dns_enumerate(config: ScanConfig, *, cancel_event=None) -> DnsEnumOutput:
    target = normalize_target(config.target)
    if is_ip(target):
        return DnsEnumOutput(records={}, raw_dig=None, warnings=["DNS enumeration skipped for IP targets"])

    records: dict[str, list[str]] = {}
    for rr in DNS_TYPES:
        if cancel_event is not None and cancel_event.is_set():
            break
        records[rr] = _resolve(rr, target)

    raw_dig: str | None = None
    warnings: list[str] = []
    if config.mode == ScanMode.LOUD:
        tools = detect_tools()
        if tools.dig is None:
            ok, msg = install_dig()
            warnings.append(msg)
            if ok:
                tools = detect_tools()
            if tools.dig is None:
                if ok:
                    warnings.append(
                        "dig install reported success but dig.exe was not found. Try restarting your shell, or set BOOMSTICK_DIG to the full path of dig.exe."
                    )
                warnings.append("dig not found; skipping loud DNS gather")
        else:
            argv = [str(tools.dig), target, "ANY", "+noall", "+answer"]
            rc, out, err = run_cmd_safe(argv, timeout_s=30)
            raw_dig = out.strip() if out else None
            if rc != 0:
                warnings.append(f"dig failed: {err.strip() or rc}")

    return DnsEnumOutput(records=records, raw_dig=raw_dig, warnings=warnings)

