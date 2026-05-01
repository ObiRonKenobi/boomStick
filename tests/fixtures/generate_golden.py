#!/usr/bin/env python3
"""
Generate golden JSON fixtures from declarative inputs (offline).

Usage:
  python tests/fixtures/generate_golden.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLD = ROOT / "tests" / "golden"


def main() -> None:
    GOLD.mkdir(parents=True, exist_ok=True)
    dns = {
        "apex": "boomstick.test",
        "records": {
            "A": ["127.0.0.1"],
            "TXT": ["boomstick-accuracy-v1"],
            "MX": ["10 mail.boomstick.test"],
        },
    }
    (GOLD / "dns_boomstick_test.json").write_text(json.dumps(dns, indent=2) + "\n", encoding="utf8")

    web = {
        "paths": ["/", "/page2", "/page3", "/formpage"],
        "disallowed_paths": ["/disallowed/secret"],
    }
    (GOLD / "web_static_paths.json").write_text(json.dumps(web, indent=2) + "\n", encoding="utf8")
    print("Wrote golden files under tests/golden/")


if __name__ == "__main__":
    main()
