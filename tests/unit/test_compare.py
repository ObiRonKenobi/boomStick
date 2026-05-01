from __future__ import annotations

from tests.harness.compare import compare_dns_records, normalize_url, prf1


def test_prf1_perfect() -> None:
    m = prf1({"a", "b"}, {"a", "b"})
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0


def test_prf1_partial() -> None:
    m = prf1({"a", "b"}, {"a"})
    assert m["recall"] == 0.5
    assert m["precision"] == 1.0


def test_normalize_url_strips_fragment() -> None:
    assert normalize_url("http://Example.com:80/foo#x") == normalize_url("http://example.com/foo")


def test_compare_dns_txt_quotes() -> None:
    actual = {"TXT": ['"hello"'], "A": ["1.1.1.1"]}
    golden = {"TXT": ["hello"], "A": ["1.1.1.1"]}
    r = compare_dns_records(actual, golden)
    assert r["ok"]
