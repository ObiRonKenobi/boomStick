from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests


@dataclass(frozen=True)
class RobotsPolicy:
    base_url: str
    rp: urllib.robotparser.RobotFileParser
    fetched_at: float

    def allowed(self, url: str, user_agent: str = "boomStick") -> bool:
        try:
            return self.rp.can_fetch(user_agent, url)
        except Exception:
            return False


def fetch_robots(base_url: str, *, timeout_s: int = 10) -> RobotsPolicy:
    """
    Fetch and parse robots.txt for a given base URL (scheme+host+optional port).
    If fetch fails, we default to allowing crawling (common practice), but the caller
    should still enforce strict same-host scoping.
    """
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(robots_url)
    try:
        r = requests.get(
            robots_url,
            timeout=timeout_s,
            headers={"User-Agent": "boomStick"},
            allow_redirects=True,
        )
        if r.ok and r.text:
            rp.parse(r.text.splitlines())
        else:
            rp.parse([])
    except Exception:
        rp.parse([])
    return RobotsPolicy(base_url=base_url, rp=rp, fetched_at=time.time())


def same_host(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.hostname or "").lower() == (pb.hostname or "").lower()

