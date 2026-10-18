"""Security review fixes in app/fetch.py: the URL guard on the first request and
every redirect hop, Tor stickiness across redirects, the response byte cap and
the per-request deadline. No test touches the network: fetch._client is
replaced with an httpx client over MockTransport that records each hop."""
import httpx
import pytest

from app import fetch
from app.config import settings

ONION = "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"


class Hops:
    """Records (url, use_tor, cookie) per request and answers from a handler."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def install(self, monkeypatch):
        real = httpx.Client

        def fake_client(use_tor, timeout=None, cookies=""):
            def h(request):
                self.calls.append((str(request.url), use_tor, cookies))
                return self.handler(request)
            return real(transport=httpx.MockTransport(h), timeout=5)

        monkeypatch.setattr(fetch, "_client", fake_client)
        return self


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/",
    "http://10.0.0.5/",
    "http://172.16.1.1/",
    "http://192.168.1.1/",
    "http://[::1]/",
    "http://[fd00::1]/",
    "http://[fe80::1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://0.0.0.0/",
    "http://platform:8000/api/clients",
    "http://db:5432/",
    "http://sabine/",
    "http://localhost/",
    "http://metadata.google.internal/",
    "http://printer.local/",
    "http://127.1/",
    "http://2130706433/",
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/",
])
def test_guard_refuses_internal_and_non_http_urls_without_a_request(monkeypatch, url):
    hops = Hops(lambda r: httpx.Response(200, text="secret")).install(monkeypatch)
    res = fetch.fetch(url)
    assert not res.ok and res.error.startswith("refused") and hops.calls == []
    res = fetch.fetch(url, force_tor=True)
    assert not res.ok and hops.calls == []
    with pytest.raises(httpx.HTTPError):
        fetch.fetch_json(url)
    assert hops.calls == []


@pytest.mark.parametrize("url", ["https://example.com/a", ONION + "/", "http://8.8.8.8/", "http://[2606:4700::1111]/"])
def test_guard_allows_public_and_onion_urls(monkeypatch, url):
    hops = Hops(lambda r: httpx.Response(200, text="hello", headers={"content-type": "text/html"})).install(monkeypatch)
    res = fetch.fetch(url)
    assert res.ok and res.text == "hello" and len(hops.calls) == 1
    assert hops.calls[0][1] is url.startswith(ONION)  # onion always on Tor, clearnet direct


def test_redirect_to_internal_host_is_refused(monkeypatch):
    def handler(r):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/iam/"})
    hops = Hops(handler).install(monkeypatch)
    res = fetch.fetch("https://example.com/start")
    assert not res.ok and "refused" in res.error and "169.254.169.254" in res.error
    assert [c[0] for c in hops.calls] == ["https://example.com/start"]


def test_redirect_to_single_label_docker_name_is_refused(monkeypatch):
    hops = Hops(lambda r: httpx.Response(301, headers={"location": "http://platform:8000/admin"})).install(monkeypatch)
    res = fetch.fetch(ONION + "/")
    assert "refused" in res.error and len(hops.calls) == 1


def test_redirects_are_followed_manually_and_stay_on_tor(monkeypatch):
    def handler(r):
        if r.url.host.endswith(".onion"):
            return httpx.Response(302, headers={"location": "https://example.com/landing"})
        if r.url.path == "/landing":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, text="done", headers={"content-type": "text/plain"})
    hops = Hops(handler).install(monkeypatch)
    res = fetch.fetch(ONION + "/", cookies="sid=1")
    assert res.ok and res.text == "done" and res.url == "https://example.com/final"
    assert [c[1] for c in hops.calls] == [True, True, True]
    # The source's cookie is only sent to the source's own host.
    assert [c[2] for c in hops.calls] == ["sid=1", "", ""]


def test_redirect_loop_stops_after_five_hops(monkeypatch):
    hops = Hops(lambda r: httpx.Response(302, headers={"location": "https://example.com/again"})).install(monkeypatch)
    res = fetch.fetch("https://example.com/")
    assert not res.ok and "redirects" in res.error and len(hops.calls) == fetch.MAX_REDIRECTS + 1


def test_body_is_capped_and_marked_truncated(monkeypatch):
    monkeypatch.setattr(settings, "fetch_max_bytes", 1000)
    Hops(lambda r: httpx.Response(200, content=b"a" * 50_000, headers={"content-type": "text/html"})).install(monkeypatch)
    res = fetch.fetch("https://example.com/big")
    assert res.ok and res.truncated and len(res.content) == 1000 and len(res.text) == 1000
    small = Hops(lambda r: httpx.Response(200, content=b"a" * 1000)).install(monkeypatch)
    assert not fetch.fetch("https://example.com/exact").truncated and small.calls


def test_trickling_server_hits_the_deadline(monkeypatch):
    clock = {"t": 0.0}

    def now():
        clock["t"] += 10
        return clock["t"]

    def trickle():
        for _ in range(10_000):
            yield b"x"

    monkeypatch.setattr(fetch, "_monotonic", now)
    Hops(lambda r: httpx.Response(200, content=trickle(), headers={"content-type": "text/plain"})).install(monkeypatch)
    res = fetch.fetch("https://example.com/slow")
    assert not res.ok and "deadline of 60s" in res.error and len(res.content) < 10
    clock["t"] = 0.0
    res = fetch.fetch(ONION + "/slow")
    assert "deadline of 180s" in res.error and len(res.content) < 20
    monkeypatch.setattr(settings, "fetch_deadline_seconds", 30)
    clock["t"] = 0.0
    assert "deadline of 30s" in fetch.fetch(ONION + "/slow").error


def test_fetch_json_uses_the_same_limits(monkeypatch):
    monkeypatch.setattr(settings, "fetch_max_bytes", 100)
    Hops(lambda r: httpx.Response(200, json=[{"post_title": "x" * 500}])).install(monkeypatch)
    with pytest.raises(httpx.HTTPError, match="FETCH_MAX_BYTES"):
        fetch.fetch_json("https://example.com/posts.json")
    monkeypatch.setattr(settings, "fetch_max_bytes", 10_000)
    assert fetch.fetch_json("https://example.com/posts.json")[0]["post_title"].startswith("x")
    Hops(lambda r: httpx.Response(302, headers={"location": "http://10.0.0.1/"})).install(monkeypatch)
    with pytest.raises(httpx.HTTPError, match="refused"):
        fetch.fetch_json("https://example.com/posts.json")
