from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.enumeration.dns_enum import dns_enumerate
from core.models import ScanConfig, ScanMode
from tests.harness.compare import compare_dns_records


@pytest.mark.integration
@pytest.mark.accuracy_id("dns/basic_records")
def test_dns_records_match_golden() -> None:
    apex = "boomstick.test"
    port = int(os.environ.get("TEST_DNS_PORT", "5353"))
    golden_path = Path(__file__).resolve().parents[1] / "golden" / "dns_boomstick_test.json"
    golden = json.loads(golden_path.read_text(encoding="utf8"))

    cfg = ScanConfig(
        target=apex,
        mode=ScanMode.QUIET,
        dns_nameservers=("127.0.0.1",),
        dns_nameserver_port=port,
    )
    out = dns_enumerate(cfg)

    # Compare only RR types present in golden (dnsmasq stub may omit NS/SOA).
    gold_types = set(golden["records"].keys())
    actual_filtered = {k: v for k, v in out.records.items() if k in gold_types}
    detail = compare_dns_records(actual_filtered, golden["records"])

    assert detail["ok"], detail
