from __future__ import annotations

from datetime import datetime
from typing import Any


def _fmt_dt(s: str | None) -> str:
    if not s:
        return "-"
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s


def format_summary(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines = [
        "== Summary ==",
        f"Target: {summary.get('target', '-')}",
        f"Started: {_fmt_dt(summary.get('started_at'))}",
        f"Finished: {_fmt_dt(summary.get('finished_at'))}",
        f"Duration (s): {summary.get('duration_s', '-')}",
        "",
        f"Open ports: {summary.get('open_ports', 0)}",
        f"Subdomains: {summary.get('subdomains', 0)}",
        f"Findings: {summary.get('findings', 0)}",
        f"CVEs: {summary.get('cves', 0)}",
        "",
        f"Warnings: {summary.get('warnings', 0)}",
        f"Errors: {summary.get('errors', 0)}",
    ]
    return "\n".join(lines).strip() + "\n"


def format_enumeration(result: dict[str, Any]) -> str:
    enum = result.get("enumeration") or {}
    lines: list[str] = ["== Enumeration =="]

    ips = enum.get("resolved_ips") or []
    if ips:
        lines += ["", "Resolved IPs:", *[f"- {ip}" for ip in ips]]

    dns_records = enum.get("dns_records") or {}
    if dns_records:
        lines.append("")
        lines.append("DNS records:")
        for rrtype, values in dns_records.items():
            if not values:
                continue
            lines.append(f"- {rrtype}:")
            for v in values:
                lines.append(f"  - {v}")

    zt = enum.get("zone_transfer") or {}
    if zt:
        lines.append("")
        lines.append("Zone transfer (AXFR):")
        lines.append(f"- Apex: {zt.get('apex', '-')}")
        lines.append(f"- Nodes (zone): {zt.get('discovered_nodes_total', 0)}")
        lines.append(f"- RDATA rows (approx): {zt.get('rdata_rows', 0)}")
        for a in (zt.get("attempts") or [])[:15]:
            ns = a.get("nameserver", "?")
            where = a.get("where") or "-"
            ok = a.get("ok")
            lines.append(f"- NS {ns} @ {where} ok={ok}")
            if not ok and a.get("error"):
                lines.append(f"    {str(a.get('error'))[:200]}")
        names = zt.get("discovered_names") or []
        if names:
            lines.append(f"- Names ({len(names)}):")
            for n in names[:100]:
                lines.append(f"  - {n}")
            if len(names) > 100:
                lines.append(f"  ... truncated ({len(names) - 100} more)")

    subs = enum.get("subdomains") or []
    if subs:
        lines += ["", f"Subdomains ({len(subs)}):", *[f"- {s}" for s in subs[:200]]]
        if len(subs) > 200:
            lines.append(f"... truncated ({len(subs) - 200} more)")

    ports = enum.get("open_ports") or []
    if ports:
        lines.append("")
        lines.append("Open ports:")
        for s in ports:
            port = s.get("port")
            proto = s.get("proto", "tcp")
            name = s.get("name") or "unknown"
            product = s.get("product") or ""
            version = s.get("version") or ""
            extra = " ".join([x for x in [name, product, version] if x]).strip()
            lines.append(f"- {port}/{proto} open  {extra}".rstrip())

    tr = enum.get("traceroute") or []
    if tr:
        lines.append("")
        lines.append("Traceroute:")
        for hop in tr[:50]:
            hop_n = hop.get("hop")
            raw = hop.get("raw") or hop.get("note") or hop.get("ip") or ""
            lines.append(f"- {hop_n}: {raw}".strip())

    return "\n".join(lines).strip() + "\n"


def format_vulnerabilities(result: dict[str, Any]) -> str:
    vuln = result.get("vulnerabilities") or {}
    findings = vuln.get("findings") or []
    cves = vuln.get("cves") or []

    lines: list[str] = ["== Vulnerabilities =="]
    if not findings and not cves:
        lines.append("\nNo findings.\n")
        return "\n".join(lines)

    if findings:
        lines.append("")
        lines.append(f"Findings ({len(findings)}):")
        for f in findings:
            sev = f.get("severity", "info")
            title = f.get("title", "Finding")
            url = f.get("url")
            param = f.get("parameter")
            lines.append(f"- [{sev}] {title}")
            if url:
                lines.append(f"  URL: {url}")
            if param:
                lines.append(f"  Parameter: {param}")
            desc = f.get("description")
            if desc:
                lines.append(f"  Description: {desc}")
            rec = f.get("recommendation")
            if rec:
                lines.append(f"  Recommendation: {rec}")
            ev = f.get("evidence")
            if ev:
                lines.append(f"  Evidence: {ev}")

    if cves:
        lines.append("")
        lines.append(f"CVEs ({len(cves)}):")
        for c in cves[:50]:
            cve = c.get("cve")
            summary = c.get("summary")
            url = c.get("url")
            lines.append(f"- {cve}")
            if summary:
                lines.append(f"  {summary}")
            if url:
                lines.append(f"  {url}")
        if len(cves) > 50:
            lines.append(f"... truncated ({len(cves) - 50} more)")

    return "\n".join(lines).strip() + "\n"

