"""A direct clearnet fetch refuses a public name that resolves to an internal
address; a Tor-routed fetch never resolves locally."""
import socket

import httpx

from app import fetch as F


def _fake_dns(addr):
    def gai(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]
    return gai


def test_direct_fetch_refuses_name_resolving_to_metadata(monkeypatch):
    monkeypatch.setattr(F.socket, "getaddrinfo", _fake_dns("169.254.169.254"))
    called = []
    monkeypatch.setattr(F, "_client", lambda *a, **k: called.append(1) or httpx.Client())
    r = F.fetch("https://rebind.example.com/latest/meta-data/", force_tor=False)
    assert r.error.startswith("refused:") and "169.254.169.254" in r.error
    assert not called


def test_direct_fetch_refuses_name_resolving_to_private(monkeypatch):
    monkeypatch.setattr(F.socket, "getaddrinfo", _fake_dns("10.0.3.7"))
    r = F.fetch("http://internal-looking.example.net/", force_tor=False)
    assert "resolves to internal address 10.0.3.7" in r.error


def test_tor_fetch_never_resolves_locally(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("local DNS lookup on a Tor-routed fetch")
    monkeypatch.setattr(F.socket, "getaddrinfo", boom)

    def handler(request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    monkeypatch.setattr(F, "_client", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler)))
    r = F.fetch("https://public.example.org/", force_tor=True)
    assert r.ok and r.text == "ok"


def test_public_resolution_is_allowed(monkeypatch):
    monkeypatch.setattr(F.socket, "getaddrinfo", _fake_dns("93.184.216.34"))

    def handler(request):
        return httpx.Response(200, text="fine", headers={"content-type": "text/plain"})

    monkeypatch.setattr(F, "_client", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler)))
    r = F.fetch("https://example.com/", force_tor=False)
    assert r.ok and r.text == "fine"
