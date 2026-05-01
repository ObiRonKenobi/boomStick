#!/usr/bin/env python3
"""
Promote normalized \"actual\" outputs to golden fixtures after human review.

Usage:
  python tools/update_golden.py --source tests/golden/candidate_dns.json --dest tests/golden/dns_boomstick_test.json --i-understand
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Promote golden harness fixtures")
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--dest", type=Path, required=True)
    ap.add_argument("--i-understand", action="store_true", help="Confirm intentional overwrite")
    args = ap.parse_args()
    if not args.i_understand:
        raise SystemExit("Refusing to write without --i-understand")

    args.dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.source, args.dest)
    sidecar = args.dest.with_suffix(args.dest.suffix + ".sha256")
    sidecar.write_text(_sha256(args.dest) + "\n", encoding="utf8")
    print(f"Updated {args.dest} (+ checksum {sidecar})")


if __name__ == "__main__":
    main()
