from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from core.enumeration.dns_enum import dns_enumerate
from core.enumeration.port_scan import port_scan
from core.enumeration.subdomain import discover_subdomains
from core.enumeration.traceroute import traceroute
from core.models import EnumerationReport, ScanConfig, ScanMode, ScanResult, ScanScope
from core.utils.network import build_base_urls, is_domain, is_ip, normalize_target, resolve_host
from core.vulnerability.cve_checker import query_offline_nvd_for_services
from core.vulnerability.web_vuln import crawl_and_test
from core.vulnerability.zap_scanner import zap_scan


@dataclass(frozen=True)
class ScanStep:
    name: str
    run: Callable[[ScanResult], dict[str, Any]]


def build_plan(
    config: ScanConfig,
    *,
    project_root: Path,
    cancel_event=None,
) -> list[ScanStep]:
    target = normalize_target(config.target)
    data_dir = project_root / "data"

    do_enum = config.scope in (ScanScope.ENUM, ScanScope.BOTH)
    do_vuln = config.scope in (ScanScope.VULN, ScanScope.BOTH)

    steps: list[ScanStep] = []

    def step_resolve_ips(result: ScanResult) -> dict[str, Any]:
        if is_ip(target):
            result.enumeration.resolved_ips = [target]
            return {"resolved_ips": result.enumeration.resolved_ips}
        ips = resolve_host(target)
        result.enumeration.resolved_ips = ips
        return {"resolved_ips": ips}

    steps.append(ScanStep(name="Resolve", run=step_resolve_ips))

    if do_enum and is_domain(target):
        steps.append(
            ScanStep(
                name="DNS",
                run=lambda result: _run_dns(config, result, cancel_event=cancel_event),
            )
        )
        steps.append(
            ScanStep(
                name="Subdomains",
                run=lambda result: _run_subdomains(
                    config,
                    result,
                    data_dir=data_dir,
                    cancel_event=cancel_event,
                ),
            )
        )

    if do_enum:
        steps.append(
            ScanStep(
                name="Ports",
                run=lambda result: _run_ports(config, result, cancel_event=cancel_event),
            )
        )
        if getattr(config, "enable_traceroute", True):
            steps.append(
                ScanStep(
                    name="Traceroute",
                    run=lambda result: _run_traceroute(config, result, cancel_event=cancel_event),
                )
            )

    if do_vuln:
        steps.append(
            ScanStep(
                name="WebVuln",
                run=lambda result: _run_web_vuln(config, result, cancel_event=cancel_event),
            )
        )
        steps.append(
            ScanStep(
                name="CVE",
                run=lambda result: _run_cve(config, result, cancel_event=cancel_event),
            )
        )

    return steps


def _run_dns(config: ScanConfig, result: ScanResult, *, cancel_event=None) -> dict[str, Any]:
    out = dns_enumerate(config, cancel_event=cancel_event)
    result.enumeration.dns_records = out.records
    if out.raw_dig:
        result.enumeration.raw_tool_output["dig"] = out.raw_dig
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"dns_records": out.records}


def _run_subdomains(
    config: ScanConfig,
    result: ScanResult,
    *,
    data_dir: Path,
    cancel_event=None,
) -> dict[str, Any]:
    out = discover_subdomains(config, data_dir=data_dir, cancel_event=cancel_event)
    result.enumeration.subdomains = out.subdomains
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"subdomains": out.subdomains, "sources": out.sources}


def _run_ports(config: ScanConfig, result: ScanResult, *, cancel_event=None) -> dict[str, Any]:
    out = port_scan(config, cancel_event=cancel_event)
    result.enumeration.open_ports = out.services
    if out.raw_nmap_xml:
        result.enumeration.raw_tool_output["nmap_xml"] = out.raw_nmap_xml
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"open_ports": [s.__dict__ for s in out.services]}


def _run_traceroute(config: ScanConfig, result: ScanResult, *, cancel_event=None) -> dict[str, Any]:
    open_ports = [s.port for s in result.enumeration.open_ports if s.state == "open"]
    out = traceroute(config, open_ports=open_ports, cancel_event=cancel_event)
    result.enumeration.traceroute = out.hops
    if out.raw:
        result.enumeration.raw_tool_output["traceroute"] = out.raw
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"traceroute": out.hops}


def _looks_like_web(services_ports: list[int]) -> bool:
    s = set(services_ports)
    return bool({80, 443, 8080, 8443} & s)


def _run_web_vuln(config: ScanConfig, result: ScanResult, *, cancel_event=None) -> dict[str, Any]:
    target = normalize_target(config.target)
    if is_ip(target):
        host = target
    else:
        host = target

    ports = [s.port for s in result.enumeration.open_ports if s.state == "open"]
    if ports and not _looks_like_web(ports):
        # No web-like ports found: skip quietly
        return {"skipped": "no_web_ports"}

    base_urls = build_base_urls(host, ports=ports if ports else None)
    if config.mode == ScanMode.LOUD:
        zap_out = zap_scan(
            config,
            base_urls=base_urls,
            scan_type=config.zap_scan_type,
            cancel_event=cancel_event,
        )
        result.vulnerabilities.findings.extend(zap_out.findings)
        if zap_out.warnings:
            result.warnings.extend(zap_out.warnings)
        return {"findings": [f.__dict__ for f in zap_out.findings], "engine": "owasp_zap"}

    out = crawl_and_test(config, base_urls=base_urls, cancel_event=cancel_event)
    result.vulnerabilities.findings.extend(out.findings)
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"findings": [f.__dict__ for f in out.findings], "scanned_urls": out.scanned_urls, "engine": "builtin"}


def _run_cve(config: ScanConfig, result: ScanResult, *, cancel_event=None) -> dict[str, Any]:
    if not result.enumeration.open_ports:
        return {"skipped": "no_services"}
    out = query_offline_nvd_for_services(
        result.enumeration.open_ports,
        project_root=Path(__file__).resolve().parents[1],
        cancel_event=cancel_event,
    )
    result.vulnerabilities.cves.extend(out.cves)
    if out.warnings:
        result.warnings.extend(out.warnings)
    return {"cves": out.cves}

