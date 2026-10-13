"""In-app Entra SSO config: stored-over-env resolution, secret encrypted at rest, a
live verify that checks tenant discovery and client credentials, and the save+verify
route flow."""
import httpx
from sqlalchemy import text

from app import sso
from app.db import SessionLocal, SsoConfig, engine


DISC = {"token_endpoint": "https://login.microsoftonline.com/t/oauth2/v2.0/token"}


def _transport(token_status=200, disc_status=200, token_body=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("openid-configuration"):
            return httpx.Response(disc_status, json=DISC if disc_status == 200 else {})
        return httpx.Response(token_status, json=token_body if token_body is not None
                              else ({"access_token": "x"} if token_status == 200 else
                                    {"error": "invalid_client", "error_description": "bad secret"}))
    return httpx.MockTransport(handler)


def test_resolve_prefers_stored_over_env(fresh_db):
    sso.save({"tenant_id": "tid", "client_id": "cid", "client_secret": "sec",
              "internal_email_domains": "vendettacd.io", "admin_emails": "ceo@vendettacd.io"}, "admin")
    cfg = sso.resolve()
    assert cfg["tenant_id"] == "tid" and cfg["client_id"] == "cid"
    assert cfg["configured"] and cfg["source"] == "stored"
    assert sso.enabled() is True


def test_secret_is_encrypted_at_rest(fresh_db):
    sso.save({"tenant_id": "t", "client_id": "c", "client_secret": "super-secret-value"}, "admin")
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT client_secret FROM sso_config WHERE id='default'")).scalar()
    assert raw and raw.startswith("enc:v1:") and "super-secret-value" not in raw
    assert sso.resolve()["client_secret"] == "super-secret-value"


def test_blank_secret_keeps_stored(fresh_db):
    sso.save({"tenant_id": "t", "client_id": "c", "client_secret": "keep-me"}, "admin")
    sso.save({"tenant_id": "t2", "client_id": "c2", "client_secret": ""}, "admin")
    cfg = sso.resolve()
    assert cfg["tenant_id"] == "t2" and cfg["client_secret"] == "keep-me"


def test_verify_ok(fresh_db):
    ok, detail = sso.test({"tenant_id": "t", "client_id": "c", "client_secret": "s"},
                          transport=_transport(token_status=200))
    assert ok and "valid" in detail


def test_verify_reports_bad_credentials(fresh_db):
    ok, detail = sso.test({"tenant_id": "t", "client_id": "c", "client_secret": "wrong"},
                          transport=_transport(token_status=401))
    assert not ok and "bad secret" in detail


def test_verify_reports_bad_tenant(fresh_db):
    ok, detail = sso.test({"tenant_id": "nope", "client_id": "c", "client_secret": "s"},
                          transport=_transport(disc_status=404))
    assert not ok and "tenant discovery failed" in detail


def test_verify_requires_all_three(fresh_db):
    ok, detail = sso.test({"tenant_id": "t", "client_id": "", "client_secret": "s"})
    assert not ok and "required" in detail


def test_save_route_saves_and_verifies(admin, monkeypatch):
    monkeypatch.setattr(sso, "test", lambda cfg=None, transport=None: (True, "tenant reachable and client credentials valid"))
    r = admin.post("/settings/sso", data={
        "tenant_id": "tid", "client_id": "cid", "client_secret": "sec",
        "internal_email_domains": "vendettacd.io", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/settings/sso?ok=1"
    row = SessionLocal().get(SsoConfig, "default")
    assert row.tenant_id == "tid" and row.enabled is True and "valid" in row.last_detail
    assert sso.enabled() is True
    assert "ENABLED" in admin.get("/settings/sso").text


def test_save_route_marks_testfail(admin, monkeypatch):
    monkeypatch.setattr(sso, "test", lambda cfg=None, transport=None: (False, "client credentials rejected: bad secret"))
    r = admin.post("/settings/sso", data={
        "tenant_id": "tid", "client_id": "cid", "client_secret": "sec", "enabled": "true"},
        follow_redirects=False)
    assert r.headers["location"] == "/settings/sso?testfail=1"
    # saved despite failing test
    assert SessionLocal().get(SsoConfig, "default").tenant_id == "tid"
