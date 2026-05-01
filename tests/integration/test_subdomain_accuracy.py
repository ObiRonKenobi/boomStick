from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.enumeration.subdomain import discover_subdomains
from core.models import ScanConfig, ScanMode


@pytest.mark.integration
@pytest.mark.accuracy_id("subdomain/bruteforce")
def test_bruteforce_finds_expected_hosts() -> None:
    port = int(os.environ.get("TEST_DNS_PORT", "5353"))
    data_dir = Path(__file__).resolve().parents[1] / "fixtures" / "data"

    cfg = ScanConfig(
        target="boomstick.test",
        mode=ScanMode.QUIET,
        subdomain_strategy="bounded_bruteforce",
        dns_nameservers=("127.0.0.1",),
        dns_nameserver_port=port,
    )
    out = discover_subdomains(cfg, data_dir=data_dir)
    found = set(out.subdomains)
    assert "www.boomstick.test" in found
    assert "api.boomstick.test" in found
