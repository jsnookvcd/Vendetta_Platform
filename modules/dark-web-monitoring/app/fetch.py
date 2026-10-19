"""HTTP fetching. Anything ending in .onion goes through Tor. Clearnet goes direct
unless force_tor is set (useful when you do not want the collector's AWS IP seen).

Every request passes check_url first, and again on every redirect hop, so a
hostile page cannot point the collector at the docker network, the EC2
metadata service or a non-http scheme. Responses are streamed under a byte cap
(FETCH_MAX_BYTES) and a wall-clock deadline (FETCH_DEADLINE_SECONDS) so a large
or trickling response cannot exhaust memory or hold a job forever."""
from __future__ import annotations

import dataclasses
import ipaddress
import logging
import re
import socket
import time

import httpx
from bs4 import BeautifulSoup

from .config import settings

log = logging.getLogger(__name__)

MAX_REDIRECTS = 5
TOR_DEADLINE_SECONDS = 180
CLEARNET_DEADLINE_SECONDS = 60
_BLOCKED_SUFFIXES = (".internal", ".local", ".localhost")
# Dotted or bare numeric hosts that are not canonical IPv4 (127.1, 0x7f.1,
# 2130706433). Resolvers expand these to addresses, so they are refused outright.
_NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]*|[0-9]*))*")
_monotonic = time.monotonic  # replaced in tests


@dataclasses.dataclass
class FetchResult:
    url: str
    status: int
    content: bytes
    headers: dict
    text: str
    error: str = ""
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.error


def is_onion(url: str) -> bool:
    try:
        host = httpx.URL(url).host or ""
    except Exception:  # noqa: BLE001
        return False
    return host.lower().rstrip(".").endswith(".onion")


def _blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def check_url(url: str) -> str:
    """Empty string when the URL may be fetched, otherwise the reason it is
    refused. Hosts are checked as written; nothing is resolved here, so onion and
    Tor-routed names never touch local DNS. Onion hosts are always allowed (they
    are always fetched through Tor)."""
    try:
        u = httpx.URL(url)
    except Exception as e:  # noqa: BLE001
        return f"invalid URL: {e}"
    if u.scheme not in ("http", "https"):
        return f"scheme {u.scheme or '(none)'!r} is not allowed"
    host = (u.host or "").lower().rstrip(".")
    if not host:
        return "URL has no host"
    if host.endswith(".onion"):
        return ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return f"address {host} is internal" if _blocked_ip(ip) else ""
    if _NUMERIC_HOST.fullmatch(host):
        return f"numeric host {host} is not allowed"
    if "." not in host:
        return f"single-label host {host} is not allowed"
    if host.endswith(_BLOCKED_SUFFIXES):
        return f"internal host {host} is not allowed"
    return ""


def check_resolved(url: str) -> str:
    """For a direct clearnet hop only: resolve the host and refuse it when any
    address it resolves to is internal, so a public name pointed at a private or
    metadata address cannot be fetched from the host. Tor-routed hops are never
    resolved locally. A name that does not resolve is left for the request itself
    to fail. The request resolves again when it connects, so a name that changes
    its answer between the two lookups is not covered; the Tor default for
    clearnet (CLEARNET_VIA_TOR) is the stronger control."""
    host = (httpx.URL(url).host or "").rstrip(".")
    try:
        ipaddress.ip_address(host)
        return ""  # literal addresses were already checked by check_url
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return ""
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            continue
        if _blocked_ip(ip):
            return f"host {host} resolves to internal address {ip}"
    return ""


def _refused(url: str, reason: str) -> FetchResult:
    log.warning("fetch refused %s: %s", url, reason)
    return FetchResult(url=url, status=0, content=b"", headers={}, text="", error=f"refused: {reason}")


def deadline_for(use_tor: bool) -> int:
    if settings.fetch_deadline_seconds > 0:
        return settings.fetch_deadline_seconds
    return TOR_DEADLINE_SECONDS if use_tor else CLEARNET_DEADLINE_SECONDS


def _client(use_tor: bool, timeout: int | None = None, cookies: str = "") -> httpx.Client:
    headers = {"User-Agent": settings.user_agent, "Accept-Language": "en-US,en;q=0.8"}
    if cookies:
        # Raw Cookie header the team copied from an authenticated browser session.
        headers["Cookie"] = cookies
    kwargs: dict = {"timeout": timeout or settings.request_timeout, "headers": headers, "follow_redirects": False}
    if use_tor:
        kwargs["proxy"] = settings.tor_proxy
        # Tor circuits are slow; onion services slower. Give them room.
        kwargs["timeout"] = httpx.Timeout(timeout or max(settings.request_timeout, 90), connect=60)
    return httpx.Client(**kwargs)


def _get(url: str, force_tor: bool = False, timeout: int | None = None, cookies: str = "",
         headers: dict | None = None) -> FetchResult:
    """The one fetch path: guard, manual redirects, byte cap and deadline."""
    reason = check_url(url)
    if reason:
        return _refused(url, reason)
    tor = force_tor or is_onion(url)
    cap = max(1, settings.fetch_max_bytes)
    deadline = _monotonic() + deadline_for(tor)
    first_host = httpx.URL(url).host
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        hop_tor = tor or is_onion(current)
        if not hop_tor:
            reason = check_resolved(current)
            if reason:
                return _refused(current, reason)
        # The session cookie belongs to the source's own host and is never sent elsewhere.
        hop_cookies = cookies if httpx.URL(current).host == first_host else ""
        with _client(hop_tor, timeout, hop_cookies) as c:
            with c.stream("GET", current, headers=headers or {}, follow_redirects=False) as r:
                if r.is_redirect and r.headers.get("location"):
                    nxt = str(r.url.join(r.headers["location"]))
                    reason = check_url(nxt)
                    if reason:
                        return _refused(nxt, f"redirect from {current}: {reason}")
                    current = nxt
                    if _monotonic() > deadline:
                        return FetchResult(url=current, status=0, content=b"", headers={}, text="",
                                           error=f"deadline of {deadline_for(tor)}s exceeded")
                    continue
                buf = bytearray()
                truncated = False
                error = ""
                for chunk in r.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) >= cap:
                        truncated = len(buf) > cap
                        del buf[cap:]
                        if truncated:
                            break
                    if _monotonic() > deadline:
                        error = f"deadline of {deadline_for(tor)}s exceeded"
                        break
                body = bytes(buf)
                ctype = r.headers.get("content-type", "text")
                text = body.decode(r.encoding or "utf-8", errors="replace") if "text" in ctype else ""
                return FetchResult(url=str(r.url), status=r.status_code, content=body,
                                   headers={k: v for k, v in r.headers.items()}, text=text,
                                   error=error, truncated=truncated)
    return FetchResult(url=current, status=0, content=b"", headers={}, text="",
                       error=f"more than {MAX_REDIRECTS} redirects")


def fetch(url: str, force_tor: bool = False, timeout: int | None = None, cookies: str = "") -> FetchResult:
    try:
        return _get(url, force_tor=force_tor, timeout=timeout, cookies=cookies)
    except Exception as e:  # noqa: BLE001
        log.warning("fetch failed %s: %s", url, e)
        return FetchResult(url=url, status=0, content=b"", headers={}, text="", error=str(e))


def fetch_json(url: str, headers: dict | None = None, force_tor: bool = False):
    """JSON body of a URL under the same guard, byte cap and deadline as fetch.
    Raises httpx.HTTPError on a refusal, a failed request, a non-2xx status or a
    truncated body."""
    res = _get(url, force_tor=force_tor, headers=headers)
    if res.error:
        raise httpx.HTTPError(f"{url}: {res.error}")
    if not 200 <= res.status < 300:
        raise httpx.HTTPError(f"{url}: HTTP {res.status}")
    if res.truncated:
        raise httpx.HTTPError(f"{url}: response larger than FETCH_MAX_BYTES ({settings.fetch_max_bytes})")
    import json

    return json.loads(res.content)


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
    """href resolved against base, or an empty string when either is malformed."""
    if not href:
        return ""
    try:
        return str(httpx.URL(base).join(href))
    except Exception:  # noqa: BLE001
        return ""


def same_host(source_url: str, link: str) -> bool:
    """True when link is an http(s) URL on exactly the source's own host. Crawlers
    only follow links taken from fetched content when this holds."""
    try:
        a, b = httpx.URL(source_url), httpx.URL(link)
    except Exception:  # noqa: BLE001
        return False
    return bool(a.host) and b.scheme in ("http", "https") and a.host.lower() == (b.host or "").lower()


def tor_check() -> dict:
    """Confirms the Tor SOCKS proxy is up and exiting through Tor."""
    try:
        with _client(True, 45) as c:
            r = c.get("https://check.torproject.org/api/ip")
            return r.json()
    except Exception as e:  # noqa: BLE001
        return {"IsTor": False, "error": str(e)}
