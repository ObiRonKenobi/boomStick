from __future__ import annotations

import dns.resolver

from core.models import ScanConfig


def resolver_from_config(config: ScanConfig) -> dns.resolver.Resolver | None:
    """
    When dns_nameservers is non-empty, return a Resolver using those IPs and dns_nameserver_port.
    Otherwise None (caller should use dns.resolver.resolve default path).
    """
    ns = getattr(config, "dns_nameservers", None) or ()
    if not ns:
        return None
    port = int(getattr(config, "dns_nameserver_port", 53) or 53)
    r = dns.resolver.Resolver()
    r.nameservers = list(ns)
    r.nameserver_ports = {ip: port for ip in ns}
    return r


def resolve_rr(config: ScanConfig, qname: str, rdtype: str):
    """Resolve using optional test/custom nameservers from ScanConfig."""
    r = resolver_from_config(config)
    if r is not None:
        return r.resolve(qname, rdtype, raise_on_no_answer=False)
    return dns.resolver.resolve(qname, rdtype, raise_on_no_answer=False)
