from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse


def normalize_url(u: str) -> str:
    """Strip fragments; lowercase host; stable query ordering."""
    p = urlparse(u.strip())
    if not p.scheme or not p.netloc:
        return u.strip()
    host = (p.hostname or "").lower()
    netloc = host
    if p.port and not (
        (p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)
    ):
        netloc = f"{host}:{p.port}"
    if p.username or p.password:
        auth = f"{p.username or ''}:{p.password or ''}@"
        netloc = auth + netloc
    qs = sorted(parse_qsl(p.query, keep_blank_values=True), key=lambda x: (x[0], x[1]))
    from urllib.parse import urlencode

    q = urlencode(qs, doseq=True)
    return urlunparse((p.scheme.lower(), netloc, p.path or "", p.params, q, ""))


def multiset(xs: list[str]) -> Counter[str]:
    return Counter(xs)


def prf1(expected: set[str], actual: set[str]) -> dict[str, float | int]:
    tp = len(expected & actual)
    fp = len(actual - expected)
    fn = len(expected - actual)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _norm_rr(s: str) -> str:
    s = s.strip().rstrip(".")
    return s


def compare_dns_records(
    actual: dict[str, list[str]],
    golden: dict[str, list[str]],
    *,
    normalize_txt: bool = True,
) -> dict[str, Any]:
    """Per RR-type set compare; TXT values optionally stripped of quotes."""
    per_type: dict[str, Any] = {}
    all_types = set(actual.keys()) | set(golden.keys())
    ok = True
    for rrtype in sorted(all_types):
        ag = [_norm_rr(x) for x in list(golden.get(rrtype, []))]
        aa = [_norm_rr(x) for x in list(actual.get(rrtype, []))]
        if normalize_txt and rrtype.upper() == "TXT":
            ag = [_strip_txt_quotes(x) for x in ag]
            aa = [_strip_txt_quotes(x) for x in aa]
        sg, sa = set(ag), set(aa)
        per_type[rrtype] = {
            "expected_only": sorted(sg - sa),
            "actual_only": sorted(sa - sg),
            "match": sg == sa,
        }
        if sg != sa:
            ok = False
    return {"ok": ok, "by_type": per_type}


def _strip_txt_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def compare_url_sets(
    expected: list[str],
    actual: list[str],
    *,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or {"min_precision": 0.99, "min_recall": 0.99}
    es = {normalize_url(u) for u in expected}
    ac = {normalize_url(u) for u in actual}
    metrics = prf1(es, ac)
    ok = (
        metrics["precision"] >= thresholds["min_precision"]
        and metrics["recall"] >= thresholds["min_recall"]
    )
    return {
        "ok": ok,
        "metrics": metrics,
        "expected_only": sorted(es - ac),
        "actual_only": sorted(ac - es),
    }


def compare_results(
    actual: dict[str, Any],
    golden: dict[str, Any],
    *,
    category: str,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Dispatch comparator by harness category key."""
    if category == "dns_records":
        inner = compare_dns_records(actual.get("records") or {}, golden.get("records") or {})
        return {"ok": inner["ok"], "category": category, "detail": inner}
    if category == "urls":
        detail = compare_url_sets(
            golden.get("urls") or [],
            actual.get("urls") or [],
            thresholds=thresholds,
        )
        return {"ok": detail["ok"], "category": category, "detail": detail}
    raise ValueError(f"Unknown category: {category}")
