from __future__ import annotations

import platform
import re
import socket
from dataclasses import dataclass
from typing import Iterable

from core.models import ScanConfig, ScanMode
from core.utils.crossplatform import detect_tools, install_traceroute, platform_name, run_cmd_safe
from core.utils.network import normalize_target


@dataclass(frozen=True)
class TracerouteOutput:
    hops: list[dict]
    raw: str | None = None
    warnings: list[str] = None  # type: ignore[assignment]


_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _parse_system_traceroute(text: str) -> list[dict]:
    hops: list[dict] = []
    for line in (text or "").splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop_n = int(m.group(1))
        rest = m.group(2).strip()
        hops.append({"hop": hop_n, "raw": rest})
    return hops


def loud_traceroute(target: str, *, timeout_s: int = 90) -> TracerouteOutput:
    tools = detect_tools()
    if tools.traceroute is None:
        ok, msg = install_traceroute()
        warnings: list[str] = []
        if ok:
            warnings.append(msg)
            tools = detect_tools()
        if tools.traceroute is None:
            warnings.append("traceroute/tracert not found")
            return TracerouteOutput(hops=[], raw=None, warnings=warnings)

    system = platform_name()
    exe = str(tools.traceroute)
    if system == "Windows":
        argv = [exe, "-d", target]  # -d: no DNS lookup (faster)
    else:
        # traceroute or tracepath
        if exe.lower().endswith("tracepath"):
            argv = [exe, target]
        else:
            argv = [exe, "-n", target]

    try:
        rc, out, err = run_cmd_safe(argv, timeout_s=int(timeout_s))
    except Exception as e:
        # Treat as warning to avoid failing the whole scan (many networks block traceroute).
        return TracerouteOutput(hops=[], raw=None, warnings=[f"traceroute failed: {e}"])
    if rc != 0 and not out:
        return TracerouteOutput(hops=[], raw=None, warnings=[f"traceroute failed: {err.strip() or rc}"])
    return TracerouteOutput(hops=_parse_system_traceroute(out), raw=out, warnings=[w for w in [err.strip()] if w])


def quiet_tcp_hop_inference(target: str, port: int, *, max_hops: int = 20, timeout_s: float = 1.5) -> TracerouteOutput:
    """
    Best-effort, Python-only hop inference using increasing IP_TTL and observing errors.
    This is intentionally conservative: many networks block required ICMP responses.
    """
    hops: list[dict] = []
    try:
        dest_ip = socket.gethostbyname(target)
    except Exception:
        return TracerouteOutput(hops=[], raw=None, warnings=["Failed to resolve target for traceroute"])

    warnings: list[str] = []
    for ttl in range(1, max_hops + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            s.settimeout(timeout_s)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.connect((dest_ip, int(port)))
            s.close()
            hops.append({"hop": ttl, "ip": dest_ip, "note": "reached"})
            break
        except socket.timeout:
            hops.append({"hop": ttl, "ip": None, "note": "timeout"})
        except OSError as e:
            # Windows/Linux differ in error signaling; we record best-effort.
            hops.append({"hop": ttl, "ip": None, "note": f"oserror:{e.errno}"})
        finally:
            try:
                s.close()
            except Exception:
                pass

    if not hops:
        warnings.append("Traceroute unavailable in quiet mode on this network/OS")
    return TracerouteOutput(hops=hops, raw=None, warnings=warnings)


def traceroute(config: ScanConfig, *, open_ports: Iterable[int] = (), cancel_event=None) -> TracerouteOutput:
    target = normalize_target(config.target)
    if config.mode == ScanMode.LOUD:
        out = loud_traceroute(target, timeout_s=int(config.traceroute_timeout_s))
        # Normalize timeouts into warnings, never hard errors.
        if out.warnings:
            return out
        return out

    # Quiet mode: pick a likely-open port
    ports = list(int(p) for p in open_ports)
    for preferred in (443, 80):
        if preferred in ports:
            return quiet_tcp_hop_inference(target, preferred)
    if ports:
        return quiet_tcp_hop_inference(target, ports[0])
    # no known open ports yet; attempt 443
    return quiet_tcp_hop_inference(target, 443)

