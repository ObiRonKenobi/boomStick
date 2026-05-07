"""Capture lightweight HTTP response headers per destination port (CVE corroboration)."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests


def merge_http_response_headers(by_port: dict[int, dict[str, str]], resp: requests.Response) -> None:
    """Merge first-seen Server / X-Powered-By per destination port (final URL after redirects)."""
    try:
        purl = urlparse(resp.url)
        scheme = (purl.scheme or "http").lower()
        if not purl.hostname:
            return
        port = purl.port
        if port is None:
            port = 443 if scheme == "https" else 80
        slot = by_port.setdefault(int(port), {})
        srv = (resp.headers.get("Server") or "").strip()
        if srv and "server" not in slot:
            slot["server"] = srv[:256]
        xpb = (resp.headers.get("X-Powered-By") or "").strip()
        if xpb and "x_powered_by" not in slot:
            slot["x_powered_by"] = xpb[:128]
    except Exception:
        return


def probe_http_fingerprints_by_port(
    base_urls: list[str],
    *,
    timeout_s: float = 10.0,
    cancel_event: Any = None,
    user_agent: str = "boomStick",
) -> dict[int, dict[str, str]]:
    """
    Issue GET (follow redirects) per URL and aggregate headers by destination port.
    Used when full crawl/ZAP does not populate fingerprints (e.g. LOUD mode bootstrap probe).
    """
    out: dict[int, dict[str, str]] = {}
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    for u in base_urls:
        if cancel_event is not None and cancel_event.is_set():
            break
        if not (u or "").strip():
            continue
        try:
            r = session.get(u.strip(), timeout=timeout_s, allow_redirects=True)
            merge_http_response_headers(out, r)
        except Exception:
            continue
    return out
