"""HTTP fetching. Anything ending in .onion goes through Tor. Clearnet goes direct
unless force_tor is set (useful when you do not want the collector's AWS IP seen)."""
from __future__ import annotations

import dataclasses
import logging

import httpx
from bs4 import BeautifulSoup

from .config import settings

log = logging.getLogger(__name__)


@dataclasses.dataclass
class FetchResult:
    url: str
    status: int
    content: bytes
    headers: dict
    text: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.error


def is_onion(url: str) -> bool:
    host = httpx.URL(url).host or ""
    return host.endswith(".onion")


def _client(use_tor: bool, timeout: int | None = None, cookies: str = "") -> httpx.Client:
    headers = {"User-Agent": settings.user_agent, "Accept-Language": "en-US,en;q=0.8"}
    if cookies:
        # Raw Cookie header the team copied from an authenticated browser session.
        headers["Cookie"] = cookies
    kwargs: dict = {"timeout": timeout or settings.request_timeout, "headers": headers, "follow_redirects": True}
    if use_tor:
        kwargs["proxy"] = settings.tor_proxy
        # Tor circuits are slow; onion services slower. Give them room.
        kwargs["timeout"] = httpx.Timeout(timeout or max(settings.request_timeout, 90), connect=60)
    return httpx.Client(**kwargs)


def fetch(url: str, force_tor: bool = False, timeout: int | None = None, cookies: str = "") -> FetchResult:
    use_tor = force_tor or is_onion(url)
    try:
        with _client(use_tor, timeout, cookies) as c:
            r = c.get(url)
        body = r.content
        return FetchResult(
            url=str(r.url),
            status=r.status_code,
            content=body,
            headers={k: v for k, v in r.headers.items()},
            text=r.text if "text" in r.headers.get("content-type", "text") else "",
        )
    except Exception as e:  # noqa: BLE001
        log.warning("fetch failed %s: %s", url, e)
        return FetchResult(url=url, status=0, content=b"", headers={}, text="", error=str(e))


def fetch_json(url: str, headers: dict | None = None, force_tor: bool = False):
    use_tor = force_tor or is_onion(url)
    with _client(use_tor) as c:
        r = c.get(url, headers=headers or {})
        r.raise_for_status()
        return r.json()


def html_to_text(html: str) -> str:
    """Visible text only. Scripts, styles and nav chrome stripped."""
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001
        soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    text = soup.get_text("\n")
    lines = [ln.strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def soup_of(html: str):
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # noqa: BLE001
        return BeautifulSoup(html, "html.parser")


def select_text(node, selector: str) -> str:
    """First match's visible text for a CSS selector, or empty string."""
    if not selector:
        return ""
    for sel in [s.strip() for s in selector.split(",")]:
        try:
            el = node.select_one(sel)
        except Exception:  # noqa: BLE001
            continue
        if el:
            return el.get_text(" ", strip=True)
    return ""


def select_href(node, selector: str) -> str:
    if not selector:
        return ""
    for sel in [s.strip() for s in selector.split(",")]:
        try:
            el = node.select_one(sel)
        except Exception:  # noqa: BLE001
            continue
        if el and el.get("href"):
            return el["href"]
    return ""


def absolute(base: str, href: str) -> str:
    if not href:
        return ""
    return str(httpx.URL(base).join(href))


def tor_check() -> dict:
    """Confirms the Tor SOCKS proxy is up and exiting through Tor."""
    try:
        with _client(True, 45) as c:
            r = c.get("https://check.torproject.org/api/ip")
            return r.json()
    except Exception as e:  # noqa: BLE001
        return {"IsTor": False, "error": str(e)}
