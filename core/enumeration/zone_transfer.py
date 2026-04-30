from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import dns.name
import dns.query
import dns.resolver
import dns.zone

from core.models import ScanConfig
from core.utils.network import normalize_target


def _ns_hosts(dns_records: dict[str, list[str]]) -> list[str]:
    raw = dns_records.get("NS") or []
    out: list[str] = []
    for ns in raw:
        s = str(ns).strip().rstrip(".")
        if s and s not in out:
            out.append(s)
    return out


def _resolve_ns_ip(ns_hostname: str) -> tuple[str | None, str | None]:
    """
    dns.query.xfr requires an address for *where* (not all versions resolve hostnames).
    Try A then AAAA.
    """
    host = ns_hostname.strip().rstrip(".")
    last_err: str | None = None
    for rrtype in ("A", "AAAA"):
        try:
            ans = dns.resolver.resolve(host, rrtype, raise_on_no_answer=False)
            if ans:
                return str(ans[0]).strip(), None
        except Exception as e:
            last_err = str(e)
            continue
    return None, last_err or "no A/AAAA records"


def _zone_discovered_names(z: dns.zone.Zone, *, max_names: int) -> tuple[list[str], int]:
    names: list[str] = []
    for node_name in z.nodes.keys():
        fqdn = node_name.to_text().rstrip(".")
        if fqdn and fqdn not in names:
            names.append(fqdn)
        if len(names) >= max_names:
            break
    names.sort()
    total_nodes = len(z.nodes)
    return names, total_nodes


def _count_rdatas(z: dns.zone.Zone) -> int:
    n = 0
    try:
        for _ in z.iterate_rdatas():
            n += 1
    except Exception:
        pass
    return n


@dataclass(frozen=True)
class ZoneTransferOutput:
    apex: str
    attempts: list[dict[str, Any]]
    discovered_names: list[str]
    discovered_nodes_total: int
    rdata_rows: int
    warnings: list[str] = field(default_factory=list)


def zone_transfer_scan(
    config: ScanConfig,
    *,
    dns_records: dict[str, list[str]],
    cancel_event=None,
) -> ZoneTransferOutput:
    apex = normalize_target(config.target)
    timeout_s = float(getattr(config, "zone_transfer_timeout_s", 10.0) or 10.0)
    lifetime_s = getattr(config, "zone_transfer_lifetime_s", 60.0)
    max_names = int(getattr(config, "zone_transfer_max_names", 5000) or 5000)

    attempts: list[dict[str, Any]] = []
    warnings: list[str] = []
    discovered: list[str] = []
    discovered_nodes_total = 0
    rdata_rows = 0

    ns_list = _ns_hosts(dns_records)
    if not ns_list:
        warnings.append("Zone transfer skipped: no NS records (run DNS enumeration first)")
        return ZoneTransferOutput(
            apex=apex,
            attempts=[],
            discovered_names=[],
            discovered_nodes_total=0,
            rdata_rows=0,
            warnings=warnings,
        )

    zone_name = dns.name.from_text(apex)

    for ns_host in ns_list:
        if cancel_event is not None and cancel_event.is_set():
            warnings.append("Zone transfer cancelled")
            break

        where, res_err = _resolve_ns_ip(ns_host)
        rec: dict[str, Any] = {
            "nameserver": ns_host,
            "where": where,
            "ok": False,
        }
        if not where:
            rec["error"] = res_err or "could not resolve nameserver"
            attempts.append(rec)
            continue

        try:
            xfr_gen = dns.query.xfr(
                where,
                zone_name,
                timeout=timeout_s,
                lifetime=lifetime_s,
                relativize=False,
            )
            z = dns.zone.from_xfr(xfr_gen, relativize=False)
        except Exception as e:
            rec["error"] = str(e)
            attempts.append(rec)
            continue

        names, nodes_total = _zone_discovered_names(z, max_names=max_names)
        rdatas = _count_rdatas(z)
        rec["ok"] = True
        rec["names_returned"] = len(names)
        rec["nodes_total"] = nodes_total
        rec["rdatas"] = rdatas
        attempts.append(rec)

        discovered_nodes_total = nodes_total
        rdata_rows = rdatas
        for n in names:
            if len(discovered) >= max_names:
                break
            if n not in discovered:
                discovered.append(n)
        discovered.sort()
        if len(names) >= max_names:
            warnings.append(f"Zone transfer name list truncated at {max_names} (large zone)")
        # One successful AXFR is enough; further NS attempts are usually redundant.
        break

    if not any(a.get("ok") for a in attempts):
        warnings.append(
            "Zone transfer failed or refused on all NS candidates "
            "(misconfiguration is common; TSIG keys are not supported here)"
        )

    return ZoneTransferOutput(
        apex=apex,
        attempts=attempts,
        discovered_names=discovered,
        discovered_nodes_total=discovered_nodes_total,
        rdata_rows=rdata_rows,
        warnings=warnings,
    )
