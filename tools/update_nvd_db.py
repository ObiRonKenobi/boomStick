from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.vulnerability.nvd_offline import open_db, upsert_cve


FEEDS_20 = {
    "recent": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
}

def _year_feed_url(year: int) -> str:
    return f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{int(year)}.json.gz"


def _pick_summary(cve: dict[str, Any]) -> str | None:
    descs = cve.get("descriptions") or []
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _pick_score(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics") or {}
    # Prefer CVSS v3.1, then v3.0, then v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m0 = arr[0] if isinstance(arr, list) else None
        if not isinstance(m0, dict):
            continue
        cvss = m0.get("cvssData") or {}
        s = cvss.get("baseScore")
        if s is not None:
            try:
                return float(s)
            except Exception:
                return None
    return None


def _extract_cpes(v: dict[str, Any]) -> list[str]:
    """
    Extract CPE match criteria strings from NVD 2.0 vulnerability object.
    """
    cpes: list[str] = []
    cve = v.get("cve") if isinstance(v, dict) else None
    if not isinstance(cve, dict):
        return cpes
    confs = cve.get("configurations") or []
    for conf in confs if isinstance(confs, list) else []:
        nodes = conf.get("nodes") or []
        for node in nodes if isinstance(nodes, list) else []:
            matches = node.get("cpeMatch") or []
            for m in matches if isinstance(matches, list) else []:
                crit = m.get("criteria")
                if crit and crit not in cpes:
                    cpes.append(str(crit))
    return cpes


def _download(url: str) -> bytes:
    r = requests.get(url, timeout=120, headers={"User-Agent": "boomStick"})
    r.raise_for_status()
    return r.content


def update_db(db_path: Path, feeds: list[str]) -> None:
    conn = open_db(db_path)
    try:
        for feed in feeds:
            url = FEEDS_20.get(feed)
            if not url:
                # allow year feeds like "2026"
                try:
                    y = int(feed)
                    if y < 2002 or y > 3000:
                        raise ValueError()
                    url = _year_feed_url(y)
                except Exception:
                    raise SystemExit(f"Unknown feed: {feed}") from None
            print(f"[boomStick] Downloading {feed} feed…", file=sys.stderr)
            gz = _download(url)
            raw = gzip.decompress(gz)
            data = json.loads(raw.decode("utf8", errors="ignore"))
            vulns = data.get("vulnerabilities") or []
            print(f"[boomStick] Parsing {len(vulns)} CVEs…", file=sys.stderr)

            with conn:
                for v in vulns:
                    cve = v.get("cve") if isinstance(v, dict) else None
                    if not isinstance(cve, dict):
                        continue
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    published = cve.get("published")
                    modified = cve.get("lastModified")
                    summary = _pick_summary(cve)
                    score = _pick_score(cve)
                    cpes = _extract_cpes(v)
                    # Build searchable text: CVE id + summary + CPE criteria strings.
                    search_text = " ".join([str(cve_id), summary or "", " ".join(cpes)]).strip() or None
                    upsert_cve(
                        conn,
                        cve_id=str(cve_id),
                        published=str(published) if published else None,
                        modified=str(modified) if modified else None,
                        score=score,
                        summary=summary,
                        text=search_text,
                        raw_json=v,
                    )

            print(f"[boomStick] Updated from {feed}.", file=sys.stderr)
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Update boomStick offline NVD SQLite database.")
    p.add_argument("--db", default=str(Path("data") / "nvd.sqlite"), help="Path to SQLite db (default: data/nvd.sqlite)")
    p.add_argument(
        "--feeds",
        nargs="+",
        default=["recent", "modified"],
        help="Feeds to ingest: recent/modified and/or year numbers (e.g. 2026 2025). Default: recent modified",
    )
    args = p.parse_args()
    db_path = Path(args.db)
    start = datetime.now()
    update_db(db_path, list(args.feeds))
    dur = (datetime.now() - start).total_seconds()
    print(f"[boomStick] Done. DB at {db_path} (took {dur:.1f}s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

