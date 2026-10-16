"""The board (kiosk) and the spoken voice: token-gated read-only screen, her line
per cycle, server-rendered audio cached by hash, browser mode with no server
rendering, and no decision possible from the board."""
import httpx
import pytest

from app import brain, voice
from app.config import settings
from app.db import SessionLocal, Speech

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)


def test_board_requires_kiosk_token_or_session(client, world, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "kiosk_token", "wall-secret")
    assert client.get("/board", follow_redirects=False).status_code == 302  # to /login, as every console page
    assert client.get("/api/board").status_code == 401
    assert client.get("/board", params={"k": "wrong"}, follow_redirects=False).status_code == 302
    r = client.get("/board", params={"k": "wall-secret"})
    assert r.status_code == 200 and "SABINE" in r.text and "sabine_board" in r.headers.get("set-cookie", "")
    # the cookie now carries it
    assert client.get("/api/board").status_code == 200
    # a staff session sees the board too, without the token
    anon = client.__class__(client.app)
    anon.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    assert anon.get("/board").status_code == 200


def test_board_payload_carries_her_line_and_the_picture(client, world, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "kiosk_token", "wall-secret")
    client.get("/board", params={"k": "wall-secret"})
    before = client.get("/api/board").json()
    assert before["line"] == "Waiting for my first cycle." and before["stats"]["open"] == 0
    brain.cycle(SessionLocal())
    d = client.get("/api/board").json()
    assert d["stats"]["open"] > 0 and d["queue"] and d["pending"]
    assert "waiting on one of you" in d["line"]
    assert d["modules"]["dark-web-monitoring"]["ok"] is True
    assert d["last_cycle"]["ok"] is True and d["speak"] == "browser"
    # the board has no decision routes: a kiosk cookie cannot approve anything
    pid = d["pending"] and SessionLocal().query(__import__("app.db", fromlist=["Proposal"]).Proposal).filter_by(status="pending").first().id
    assert client.post(f"/proposals/{pid}/decide", data={"approve": "true"}, follow_redirects=False).status_code in (302, 401)
    assert SessionLocal().get(__import__("app.db", fromlist=["Proposal"]).Proposal, pid).status == "pending"


def test_cycle_line_variants(monkeypatch):
    from app import narrative
    monkeypatch.setattr(settings, "persona", "sabine")
    assert "waiting on one of you" in narrative.cycle_line({"open": 4, "pending": 2}, {"executed": 1, "seen": {}})
    assert "Nothing open" in narrative.cycle_line({"open": 0, "pending": 0}, {"executed": 0, "seen": {}})
    assert "cannot see penetration-testing" in narrative.cycle_line({"open": 1, "pending": 0}, {"executed": 0, "seen": {"module:penetration-testing": False}})
    monkeypatch.setattr(settings, "persona", "plain")
    assert narrative.cycle_line({"open": 4, "pending": 2}, {"executed": 1, "seen": {}}).startswith("4 open")


def test_speak_browser_mode_renders_nothing_server_side(client, fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "tts_provider", "browser")
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    r = client.post("/api/speak", json={"text": "Morning."})
    assert r.status_code == 200 and r.json() == {"provider": "browser", "url": None}
    assert SessionLocal().query(Speech).count() == 0


def test_speak_elevenlabs_renders_once_and_caches(client, fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "tts_provider", "elevenlabs")
    monkeypatch.setattr(settings, "elevenlabs_api_key", "k")
    monkeypatch.setattr(settings, "elevenlabs_voice_id", "voice123")
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.url.host, req.url.path, req.headers.get("xi-api-key")))
        return httpx.Response(200, content=b"ID3fakeaudio", headers={"content-type": "audio/mpeg"})
    voice.set_transport(httpx.MockTransport(handler))
    try:
        client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
        r = client.post("/api/speak", json={"text": "Coffee first, then come find me."})
        assert r.status_code == 200 and r.json()["provider"] == "elevenlabs"
        url = r.json()["url"]
        assert calls == [("api.elevenlabs.io", "/v1/text-to-speech/voice123", "k")]
        audio = client.get(url)
        assert audio.status_code == 200 and audio.content == b"ID3fakeaudio" and audio.headers["content-type"].startswith("audio/mpeg")
        # same sentence again: served from the cache, no second render
        r2 = client.post("/api/speak", json={"text": "Coffee first, then come find me."})
        assert r2.json()["url"] == url and len(calls) == 1
        assert SessionLocal().query(Speech).count() == 1
        # unconfigured provider falls back to browser rather than failing
        monkeypatch.setattr(settings, "elevenlabs_voice_id", "")
        assert voice.provider() == "browser"
    finally:
        voice.set_transport(None)


def test_speak_azure_and_render_failure(client, fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "tts_provider", "azure")
    monkeypatch.setattr(settings, "azure_speech_key", "k")
    monkeypatch.setattr(settings, "azure_speech_region", "eastus")
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["host"] = req.url.host
        seen["ssml"] = req.content.decode()
        return httpx.Response(500)
    voice.set_transport(httpx.MockTransport(handler))
    try:
        client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
        r = client.post("/api/speak", json={"text": "A <test> & more"})
        assert r.status_code == 200 and r.json()["url"] is None  # failure degrades to no audio
        assert seen["host"] == "eastus.tts.speech.microsoft.com" and "&lt;test&gt; &amp; more" in seen["ssml"]
        assert settings.azure_speech_voice in seen["ssml"]
    finally:
        voice.set_transport(None)


def test_speak_requires_auth_and_text(client, fresh_db):
    assert client.post("/api/speak", json={"text": "hi"}).status_code == 401
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    assert client.post("/api/speak", json={"text": ""}).status_code == 400
