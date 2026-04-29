from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterable

from core.models import ScanConfig, ScanMode, Service
from core.utils.crossplatform import detect_tools, install_nmap, run_cmd_safe
from core.utils.network import normalize_target, resolve_host


async def _probe_tcp(host: str, port: int, timeout_s: float) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout_s)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def quiet_port_scan(
    host: str,
    ports: Iterable[int],
    *,
    timeout_s: float,
    concurrency: int,
    cancel_event=None,
) -> list[Service]:
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    out: list[Service] = []

    async def run_one(p: int) -> None:
        if cancel_event is not None and cancel_event.is_set():
            return
        async with sem:
            if cancel_event is not None and cancel_event.is_set():
                return
            ok = await _probe_tcp(host, int(p), timeout_s)
            if ok:
                out.append(Service(port=int(p), proto="tcp", state="open"))

    tasks = [asyncio.create_task(run_one(int(p))) for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)
    out.sort(key=lambda s: s.port)
    return out


def _parse_nmap_xml(xml_text: str) -> list[Service]:
    services: list[Service] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            proto = port_el.get("protocol", "tcp")
            portid = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue
            svc_el = port_el.find("service")
            name = svc_el.get("name") if svc_el is not None else None
            product = svc_el.get("product") if svc_el is not None else None
            version = svc_el.get("version") if svc_el is not None else None
            cpes: list[str] = []
            if svc_el is not None:
                for cpe_el in svc_el.findall("cpe"):
                    if cpe_el.text:
                        c = cpe_el.text.strip()
                        if c and c not in cpes:
                            cpes.append(c)
            services.append(
                Service(
                    port=portid,
                    proto="udp" if proto == "udp" else "tcp",
                    state="open",
                    name=name,
                    product=product,
                    version=version,
                    cpes=cpes,
                )
            )
    services.sort(key=lambda s: (s.proto, s.port))
    return services


@dataclass(frozen=True)
class PortScanOutput:
    services: list[Service]
    raw_nmap_xml: str | None = None
    warnings: list[str] = None  # type: ignore[assignment]


def loud_nmap_scan(target: str, ports: Iterable[int] | None = None) -> PortScanOutput:
    tools = detect_tools()
    if tools.nmap is None:
        ok, msg = install_nmap()
        warnings: list[str] = []
        if ok:
            warnings.append(msg)
            tools = detect_tools()
        if tools.nmap is None:
            warnings.append("nmap not found; skipping loud scan")
            return PortScanOutput(services=[], raw_nmap_xml=None, warnings=warnings)

    # -Pn to skip host discovery (more consistent), -sV for versions, -oX - for XML to stdout
    argv = [str(tools.nmap), "-Pn", "-sV", "-oX", "-"]
    if ports is not None:
        argv += ["-p", ",".join(str(int(p)) for p in ports)]
    argv.append(target)

    rc, out, err = run_cmd_safe(argv, timeout_s=180)
    if rc != 0 and not out:
        return PortScanOutput(services=[], raw_nmap_xml=None, warnings=[f"nmap failed: {err.strip() or rc}"])
    try:
        services = _parse_nmap_xml(out)
    except Exception as e:
        return PortScanOutput(services=[], raw_nmap_xml=out, warnings=[f"Failed to parse nmap XML: {e}"])
    warn: list[str] = []
    if err.strip():
        warn.append(err.strip())
    return PortScanOutput(services=services, raw_nmap_xml=out, warnings=warn)


def port_scan(config: ScanConfig, *, cancel_event=None) -> PortScanOutput:
    """
    Returns open TCP ports and basic service info when available.
    Quiet mode uses TCP connect probes to a small port list.
    Loud mode uses nmap (if found) and parses XML.
    """
    target = normalize_target(config.target)

    # Prefer scanning resolved IP for domains in quiet mode to avoid inconsistent vhost behavior.
    scan_host = target
    if config.mode == ScanMode.QUIET and not target.replace(".", "").isdigit():
        ips = resolve_host(target)
        if ips:
            scan_host = ips[0]

    if config.mode == ScanMode.LOUD:
        return loud_nmap_scan(target, ports=config.common_ports)

    services = asyncio.run(
        quiet_port_scan(
            scan_host,
            config.common_ports,
            timeout_s=float(config.port_timeout_s),
            concurrency=int(config.port_concurrency),
            cancel_event=cancel_event,
        )
    )
    return PortScanOutput(services=services, raw_nmap_xml=None, warnings=[])

