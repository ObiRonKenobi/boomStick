from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def is_domain(target: str) -> bool:
    t = target.strip()
    if t.startswith(("http://", "https://")):
        t = urlparse(t).hostname or ""
    t = t.strip(".")
    return bool(_HOST_RE.match(t))


def normalize_target(target: str) -> str:
    t = target.strip()
    if t.startswith(("http://", "https://")):
        host = urlparse(t).hostname
        return host or t
    return t


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    ips: list[str] = []
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ips.append(sockaddr[0])
        elif family == socket.AF_INET6:
            ips.append(sockaddr[0])
    # stable unique
    out: list[str] = []
    for ip in ips:
        if ip not in out:
            out.append(ip)
    return out


def build_base_urls(host: str, ports: Iterable[int] | None = None) -> list[str]:
    """
    Prefer https on 443 / 8443, else http on 80 / 8080.
    If ports is None, return default schemes.
    """
    if ports is None:
        return [f"https://{host}", f"http://{host}"]
    ports_set = set(int(p) for p in ports)
    urls: list[str] = []
    if 443 in ports_set:
        urls.append(f"https://{host}")
    if 8443 in ports_set:
        urls.append(f"https://{host}:8443")
    if 80 in ports_set:
        urls.append(f"http://{host}")
    if 8080 in ports_set:
        urls.append(f"http://{host}:8080")
    if not urls:
        urls = [f"https://{host}", f"http://{host}"]
    return urls


@dataclass(frozen=True)
class UrlScope:
    host: str

    def contains(self, url: str) -> bool:
        try:
            p = urlparse(url)
        except Exception:
            return False
        return (p.hostname or "").lower().strip(".") == self.host.lower().strip(".")

