from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from typing import Any


CVE_OPERATOR_BLURB = (
    "Match confidence estimates how well a CVE applies to the observed service fingerprint; "
    "CVSS (NVD) is severity only and does not measure exploit likelihood."
)


def build_cve_section_lines(
    cves: list[dict[str, Any]],
    *,
    hide_low_band: bool = False,
    max_rows: int = 200,
) -> tuple[list[str], int]:
    """
    Group CVE rows by match-confidence band for display/export.

    Returns ``(lines, n_low_hidden)`` where ``n_low_hidden`` is how many Low-band
    rows were omitted when ``hide_low_band`` is True.
    """
    by_band: dict[str, list[dict[str, Any]]] = {"high": [], "medium": [], "low": []}
    for c in cves:
        b = str(c.get("confidence_band") or "low").lower()
        if b not in by_band:
            b = "low"
        by_band[b].append(c)
    for b in by_band:
        by_band[b].sort(
            key=lambda x: (-int(x.get("confidence_score") or 0), -float(x.get("score") or 0)),
        )
    n_low = len(by_band["low"])
    n_hidden = n_low if hide_low_band else 0

    lines: list[str] = []
    bands_order = ("high", "medium", "low")
    shown = 0
    for band in bands_order:
        if hide_low_band and band == "low":
            continue
        chunk = by_band[band]
        if not chunk:
            continue
        label = band.capitalize()
        lines.append(f"[{label} confidence — {len(chunk)}]")
        for c in chunk:
            if shown >= max_rows:
                break
            cve = c.get("cve")
            summary_txt = c.get("summary")
            url = c.get("url")
            cs = c.get("confidence_score")
            cb = c.get("confidence_band")
            cvss = c.get("score")
            lines.append(f"- {cve}")
            if cs is not None and cb:
                lines.append(
                    f"  Match confidence: {cs}/100 ({str(cb).lower()}) — CVSS (NVD): "
                    f"{cvss if cvss is not None else 'n/a'}"
                )
            reasons = c.get("confidence_reasons") or []
            for r in reasons[:4]:
                lines.append(f"  • {r}")
            match = c.get("match") or {}
            svc = c.get("service") or {}
            if match.get("query"):
                lines.append(f"  Matched query: {match.get('query')}")
            if svc.get("port") or svc.get("name"):
                lines.append(
                    "  Service: "
                    f"{svc.get('port')}/{(svc.get('proto') or 'tcp')} "
                    f"{svc.get('name') or ''} {svc.get('product') or ''} {svc.get('version') or ''}".strip()
                )
            cpes = svc.get("cpes") or match.get("cpes") or []
            if cpes:
                lines.append("  CPEs:")
                for cp in cpes[:5]:
                    lines.append(f"    - {cp}")
            if summary_txt:
                lines.append(f"  {str(summary_txt)[:240]}")
            if url:
                lines.append(f"  {url}")
            shown += 1
        if shown >= max_rows:
            break
    if len(cves) > max_rows:
        lines.append(f"... truncated CVE rows ({len(cves) - max_rows} more)")
    return lines, n_hidden


def format_cves_csv(cves: list[dict[str, Any]]) -> str:
    """Flatten CVE hit dicts (offline checker shape) for spreadsheets."""
    buf = StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(
        [
            "cve",
            "cvss_score",
            "confidence_score",
            "confidence_band",
            "published",
            "modified",
            "match_query",
            "service_port",
            "service_proto",
            "service_name",
            "service_product",
            "service_version",
            "service_cpes",
            "confidence_reasons",
            "summary",
            "url",
            "source",
        ]
    )
    for c in cves:
        svc = c.get("service") or {}
        match = c.get("match") or {}
        cpes = svc.get("cpes") or match.get("cpes") or []
        reasons = c.get("confidence_reasons") or []
        w.writerow(
            [
                c.get("cve"),
                c.get("score"),
                c.get("confidence_score"),
                c.get("confidence_band"),
                c.get("published"),
                c.get("modified"),
                match.get("query"),
                svc.get("port"),
                svc.get("proto"),
                svc.get("name"),
                svc.get("product"),
                svc.get("version"),
                " ".join(str(x) for x in cpes) if cpes else "",
                " | ".join(str(r) for r in reasons if r is not None),
                c.get("summary"),
                c.get("url"),
                c.get("source"),
            ]
        )
    return buf.getvalue()


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
        lines.append(CVE_OPERATOR_BLURB)
        lines.append("")
        sec_lines, _ = build_cve_section_lines(cves, hide_low_band=False, max_rows=50)
        lines.extend(sec_lines)

    return "\n".join(lines).strip() + "\n"

