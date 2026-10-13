"""Wiring a tool in through the app: credentials are saved encrypted, tested live on
save, and take effect without a redeploy. Stored credentials override the
environment; a blank secret keeps the stored one; disconnect falls back to env."""
import json

from sqlalchemy import text

from app import creds, preflight
from app.db import SessionLocal, ToolCredential, engine
from app.preflight import Result


def _ok(tool):
    return lambda tools=None: [Result(t, True, True, "3 clients visible") for t in (tools or [tool])]


def _fail(tool):
    return lambda tools=None: [Result(t, False, True, "invalid API token") for t in (tools or [tool])]


def test_connect_saves_encrypted_and_marks_connected(admin, monkeypatch):
    monkeypatch.setattr(preflight, "run", _ok("superops"))
    r = admin.post("/integrations/superops",
                   data={"api_token": "live-token-xyz", "subdomain": "vendetta"},
                   follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/integrations?connected=superops"

    # stored, and ciphertext at rest
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT data FROM tool_credentials WHERE tool='superops'")).scalar()
    assert raw and raw.startswith("enc:v1:") and "live-token-xyz" not in raw
    # decrypts back and overrides the env default
    assert creds.resolve("superops")["api_token"] == "live-token-xyz"
    row = SessionLocal().get(ToolCredential, "superops")
    assert row.connected is True and "3 clients" in row.last_detail

    page = admin.get("/integrations").text
    assert "CONNECTED" in page


def test_test_failure_saves_but_marks_not_connected(admin, monkeypatch):
    monkeypatch.setattr(preflight, "run", _fail("huntress"))
    r = admin.post("/integrations/huntress",
                   data={"api_key": "k", "api_secret": "s"}, follow_redirects=False)
    assert r.headers["location"] == "/integrations?testfail=huntress"
    row = SessionLocal().get(ToolCredential, "huntress")
    assert row is not None and row.connected is False and "invalid API token" in row.last_detail
    # credentials were still saved
    assert creds.resolve("huntress")["api_key"] == "k"


def test_missing_required_field_is_rejected(admin, monkeypatch):
    monkeypatch.setattr(preflight, "run", _ok("sentinelone"))
    # Clear the env default so the blank api_token is genuinely missing.
    from app.config import settings
    monkeypatch.setattr(settings, "sentinelone_api_token", "")
    r = admin.post("/integrations/sentinelone",
                   data={"url": "https://x.sentinelone.net"},  # api_token missing
                   follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().get(ToolCredential, "sentinelone") is None  # nothing saved


def test_blank_secret_keeps_the_stored_value(admin, monkeypatch):
    monkeypatch.setattr(preflight, "run", _ok("acronis"))
    admin.post("/integrations/acronis",
               data={"dc_url": "https://us5-cloud.acronis.com", "client_id": "ac", "client_secret": "secret-1"})
    # resave with a changed non-secret and a blank secret: secret must persist
    admin.post("/integrations/acronis",
               data={"dc_url": "https://us5-cloud.acronis.com", "client_id": "ac2", "client_secret": ""})
    vals = creds.resolve("acronis")
    assert vals["client_id"] == "ac2" and vals["client_secret"] == "secret-1"


def test_disconnect_falls_back_to_env(admin, monkeypatch):
    monkeypatch.setattr(preflight, "run", _ok("superops"))
    admin.post("/integrations/superops", data={"api_token": "stored-tok", "subdomain": "stored-sub"})
    assert creds.resolve("superops")["api_token"] == "stored-tok"
    admin.post("/integrations/superops/disconnect", follow_redirects=False)
    assert SessionLocal().get(ToolCredential, "superops") is None
    # conftest sets SUPEROPS_API_TOKEN="t" in the env, so resolve falls back to it
    assert creds.resolve("superops")["api_token"] == "t"


def test_resolve_prefers_stored_over_env(fresh_db):
    # env has SUPEROPS_API_TOKEN="t"; a stored value wins
    assert creds.resolve("superops")["api_token"] == "t"
    creds.save("superops", {"api_token": "stored", "subdomain": "sub"}, "tester")
    assert creds.resolve("superops")["api_token"] == "stored"
    assert creds.configured("superops") is True
