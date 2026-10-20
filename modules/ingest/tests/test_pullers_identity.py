"""Puller tests for the Okta System Log and the Google Workspace Reports API."""
import base64
import datetime as dt
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.connectors import ConnectorError
from test_pullers_common import NOW, Router, about_24h_before_now, assert_secret_free, form, make, run

# ---------------------------------------------------------------- Okta
OKTA = "https://acme.okta.com/api/v1/logs"
OKTA_TOKEN = "00aBcD-SSWS-SECRET-1234567890xyz"
OKTA_CFG = {"okta_domain": "acme.okta.com"}
OKTA_CREDS = {"api_token": OKTA_TOKEN}


def okta_ev(u, published):
    return {"uuid": u, "published": published, "eventType": "user.session.start"}


def link(url):
    return {"Link": f'<{url}>; rel="next"'}


def test_okta_pages_follow_link_until_empty():
    p2 = "https://acme.okta.com/api/v1/logs?after=1760000000000_1&sortOrder=ASCENDING&limit=1000"
    p3 = "https://acme.okta.com/api/v1/logs?after=1760000000000_2&sortOrder=ASCENDING&limit=1000"
    r = Router().add("GET", OKTA,
                     httpx.Response(200, json=[okta_ev("u1", "2026-10-19T09:00:00.000Z"),
                                               okta_ev("u2", "2026-10-19T09:05:00.000Z")], headers=link(p2)),
                     httpx.Response(200, json=[okta_ev("u3", "2026-10-19T10:00:00.000Z")], headers=link(p3)),
                     httpx.Response(200, json=[], headers=link(p3)))
    pages = run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r, cursor={"since": "2026-10-19T08:00:00+00:00"}))
    assert [len(rows) for rows, _ in pages] == [2, 1]
    assert pages[0][1] == {"since": "2026-10-19T09:05:00+00:00"}
    assert pages[1][1] == {"since": "2026-10-19T10:00:00+00:00"}
    assert r.calls[0].headers["authorization"] == f"SSWS {OKTA_TOKEN}"
    assert r.calls[0].url.params["since"] == "2026-10-19T08:00:00.000Z"
    assert r.calls[0].url.params["sortOrder"] == "ASCENDING"
    assert r.calls[1].url.params["after"] == "1760000000000_1"
    assert len(r.calls) == 3


def test_okta_first_run_looks_back_24h():
    r = Router().add("GET", OKTA, httpx.Response(200, json=[]))
    assert run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r)) == []
    assert about_24h_before_now(r.calls[0].url.params["since"], slack_minutes=0)


def test_okta_401_is_secret_free():
    r = Router().add("GET", OKTA, httpx.Response(401, json={"errorCode": "E0000011", "errorSummary": "Invalid token provided"}))
    with pytest.raises(ConnectorError) as e:
        run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r))
    assert_secret_free(e.value, OKTA_TOKEN)


def test_okta_429_then_success():
    r = Router().add("GET", OKTA, httpx.Response(429, headers={"Retry-After": "1", "X-Rate-Limit-Remaining": "0"}),
                     httpx.Response(200, json=[okta_ev("u1", "2026-10-19T09:00:00.000Z")]))
    assert len(run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r))) == 1
    assert len(r.calls) == 2


@pytest.mark.parametrize("nxt", ["https://evil.example/api/v1/logs?after=1", "https://acme.okta.com.evil.example/api/v1/logs",
                                 "http://acme.okta.com/api/v1/logs?after=1", "https://other.okta.com/api/v1/logs"])
def test_okta_foreign_next_link_refused(nxt):
    r = Router().add("GET", OKTA, httpx.Response(200, json=[okta_ev("u1", "2026-10-19T09:00:00.000Z")], headers=link(nxt)))
    with pytest.raises(ConnectorError):
        run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r))
    assert all(c.url.host == "acme.okta.com" for c in r.calls)


def test_okta_repeated_next_link_stops():
    same = "https://acme.okta.com/api/v1/logs?after=1"
    r = Router().add("GET", OKTA, httpx.Response(200, json=[okta_ev("u1", "2026-10-19T09:00:00.000Z")], headers=link(same)))
    pages = run(make("okta_system_log", OKTA_CFG, OKTA_CREDS, r))
    assert len(pages) == 2 and len(r.calls) == 2


@pytest.mark.parametrize("domain", ["acme.example.com", "acme.okta.com.evil.example", "http://acme.okta.com",
                                    "acme.okta.com/path", "acme.okta.com:8443", "okta.com", "", "acme okta.com",
                                    "user@acme.okta.com"])
def test_okta_invalid_domain(domain):
    r = Router()
    with pytest.raises(ConnectorError):
        run(make("okta_system_log", {"okta_domain": domain}, OKTA_CREDS, r))
    assert r.calls == []


@pytest.mark.parametrize("domain", ["acme.oktapreview.com", "https://acme.okta-emea.com/", "ACME.okta.com"])
def test_okta_valid_domains(domain):
    r = Router()
    host = domain.replace("https://", "").rstrip("/").lower()
    r.add("GET", f"https://{host}/api/v1/logs", httpx.Response(200, json=[]))
    run(make("okta_system_log", {"okta_domain": domain}, OKTA_CREDS, r))
    assert r.calls[0].url.host == host


# ---------------------------------------------------------------- Google Workspace
TOKEN_URL = "https://oauth2.googleapis.com/token"
LOGIN = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()).decode()
SA = {"type": "service_account", "project_id": "vendetta-ingest-test", "private_key_id": "0123456789abcdef",
      "private_key": PEM, "client_email": "ingest-reader@vendetta-ingest-test.iam.gserviceaccount.com",
      "client_id": "100000000000000000001", "token_uri": "https://evil.example/token"}
G_CREDS = {"service_account_json": json.dumps(SA)}
G_CFG = {"admin_email": "admin@acme.example", "applications": "login", "window_minutes": "720", "lag_minutes": "0"}


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def g_token():
    return httpx.Response(200, json={"access_token": "ya29.google-token", "expires_in": 3599, "token_type": "Bearer"})


def g_act(uq, t):
    return {"id": {"time": t, "uniqueQualifier": uq, "applicationName": "login", "customerId": "C0"},
            "events": [{"type": "login", "name": "login_success"}]}


def test_google_jwt_assertion_is_signed_and_scoped():
    r = Router().add("POST", TOKEN_URL, g_token()).add("GET", LOGIN, httpx.Response(200, json={}))
    run(make("google_workspace", G_CFG, G_CREDS, r))
    tok = r.to("oauth2.googleapis.com")[0]
    assert str(tok.url) == TOKEN_URL  # the key file's token_uri is not followed
    f = form(tok)
    assert f["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    head, claims, sig = f["assertion"].split(".")
    header = json.loads(_unb64(head))
    body = json.loads(_unb64(claims))
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "0123456789abcdef"}
    assert body == {"iss": SA["client_email"], "sub": "admin@acme.example",
                    "scope": "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                    "aud": TOKEN_URL, "iat": int(NOW.timestamp()), "exp": int(NOW.timestamp()) + 3600}
    _KEY.public_key().verify(_unb64(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())


def test_google_two_pages_then_next_window_cursor_advances():
    r = Router().add("POST", TOKEN_URL, g_token())
    r.add("GET", LOGIN,
          httpx.Response(200, json={"items": [g_act("1", "2026-10-18T23:00:00.000Z"), g_act("2", "2026-10-18T20:00:00.000Z")],
                                    "nextPageToken": "A:1760000000000:-1:login:-1"}),
          httpx.Response(200, json={"items": [g_act("3", "2026-10-18T13:00:00.000Z")]}),
          httpx.Response(200, json={"kind": "admin#reports#activities"}))
    pages = run(make("google_workspace", G_CFG, G_CREDS, r))
    assert [len(rows) for rows, _ in pages] == [2, 1, 0]
    w1_end = (NOW - dt.timedelta(hours=12)).isoformat()
    assert pages[0][1] == {"since": {}}
    assert pages[1][1] == {"since": {"login": w1_end}}
    assert pages[2][1] == {"since": {"login": NOW.isoformat()}}
    calls = r.to("admin.googleapis.com")
    assert calls[0].headers["authorization"] == "Bearer ya29.google-token"
    assert calls[0].url.params["startTime"] == "2026-10-18T12:00:00.000Z"
    assert calls[0].url.params["endTime"] == "2026-10-19T00:00:00.000Z"
    assert calls[1].url.params["pageToken"] == "A:1760000000000:-1:login:-1"
    assert calls[2].url.params["startTime"] == "2026-10-19T00:00:00.000Z"
    assert "pageToken" not in calls[2].url.params


def test_google_first_run_looks_back_24h_and_respects_lag():
    r = Router().add("POST", TOKEN_URL, g_token()).add("GET", LOGIN, httpx.Response(200, json={}))
    run(make("google_workspace", {**G_CFG, "lag_minutes": "15", "window_minutes": "1440"}, G_CREDS, r))
    calls = r.to("admin.googleapis.com")
    assert about_24h_before_now(calls[0].url.params["startTime"], slack_minutes=0)
    assert calls[-1].url.params["endTime"] == "2026-10-19T11:45:00.000Z"


def test_google_default_applications():
    r = Router().add("POST", TOKEN_URL, g_token())
    for app in ("login", "admin", "token", "drive"):
        r.add("GET", f"https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}",
              httpx.Response(200, json={}))
    run(make("google_workspace", {"admin_email": "admin@acme.example", "window_minutes": "1440"}, G_CREDS, r))
    apps = {c.url.path.rsplit("/", 1)[1] for c in r.to("admin.googleapis.com")}
    assert apps == {"login", "admin", "token", "drive"}


def test_google_401_is_secret_free():
    r = Router().add("POST", TOKEN_URL, httpx.Response(401, json={"error": "unauthorized_client",
                                                                  "error_description": "Client is unauthorized"}))
    with pytest.raises(ConnectorError) as e:
        run(make("google_workspace", G_CFG, G_CREDS, r))
    body = PEM.split("-----")[2].strip().splitlines()[1]
    assert_secret_free(e.value, body, "PRIVATE KEY", G_CREDS["service_account_json"][:40])


def test_google_429_then_success():
    r = Router().add("POST", TOKEN_URL, g_token())
    r.add("GET", LOGIN, httpx.Response(429, headers={"Retry-After": "1"}),
          httpx.Response(200, json={"items": [g_act("1", "2026-10-18T13:00:00.000Z")]}),
          httpx.Response(200, json={}))
    pages = run(make("google_workspace", G_CFG, G_CREDS, r))
    assert [len(rows) for rows, _ in pages] == [1, 0]
    assert len(r.to("admin.googleapis.com")) == 3


@pytest.mark.parametrize("cfg,creds", [
    ({"applications": "login,evil"}, None),
    ({"admin_email": "not-an-email"}, None),
    ({"admin_email": "a b@acme.example"}, None),
    ({"window_minutes": "0"}, None),
    ({"lag_minutes": "later"}, None),
    ({}, {"service_account_json": "{not json"}),
    ({}, {"service_account_json": json.dumps({"client_email": "x@y"})}),
    ({}, {"service_account_json": json.dumps({**SA, "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"})}),
])
def test_google_invalid_config_or_key(cfg, creds):
    r = Router()
    with pytest.raises(ConnectorError) as e:
        run(make("google_workspace", {**G_CFG, **cfg}, creds or G_CREDS, r))
    assert r.calls == []
    assert_secret_free(e.value, "PRIVATE KEY", "{not json")
