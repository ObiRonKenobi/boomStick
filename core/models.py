from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class ScanMode(str, Enum):
    QUIET = "quiet"
    LOUD = "loud"


class ScanScope(str, Enum):
    ENUM = "enum"
    VULN = "vuln"
    BOTH = "both"


SubdomainStrategy = Literal[
    "bounded_bruteforce",
    "passive_plus_bruteforce",
    "external_tools_aggressive",
]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ScanConfig:
    target: str
    mode: ScanMode = ScanMode.QUIET
    scope: ScanScope = ScanScope.BOTH
    subdomain_strategy: SubdomainStrategy = "bounded_bruteforce"

    # Safety / throttles
    max_pages: int = 50
    crawl_depth: int = 2
    http_timeout_s: int = 10

    # Enumeration defaults
    port_timeout_s: float = 1.0
    port_concurrency: int = 200
    common_ports: tuple[int, ...] = (
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        465,
        587,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        2376,
        2483,
        2484,
        3000,
        3306,
        3389,
        5000,
        5432,
        5672,
        5900,
        5985,
        5986,
        6379,
        8000,
        8080,
        8443,
        9000,
        9200,
        27017,
    )


@dataclass
class Service:
    port: int
    proto: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "closed", "filtered", "unknown"] = "unknown"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None

    def display_name(self) -> str:
        bits = [self.name or "unknown"]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits).strip()


@dataclass
class EnumerationReport:
    resolved_ips: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[Service] = field(default_factory=list)
    traceroute: list[dict[str, Any]] = field(default_factory=list)  # hop dicts
    raw_tool_output: dict[str, str] = field(default_factory=dict)  # e.g. whois/dig/nmap raw


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    recommendation: str
    evidence: str | None = None
    url: str | None = None
    parameter: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnReport:
    findings: list[Finding] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)  # {cve, score?, summary, url, msf?}


@dataclass
class ScanResult:
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    enumeration: EnumerationReport = field(default_factory=EnumerationReport)
    vulnerabilities: VulnReport = field(default_factory=VulnReport)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc)

    def duration_s(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_s": self.duration_s(),
            "open_ports": len(self.enumeration.open_ports),
            "subdomains": len(self.enumeration.subdomains),
            "findings": len(self.vulnerabilities.findings),
            "cves": len(self.vulnerabilities.cves),
            "warnings": len(self.warnings),
            "errors": len(self.errors),
        }

