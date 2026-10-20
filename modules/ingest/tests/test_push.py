"""The push door: per-connector authentication, replay window, size limits,
envelopes, and refusals that do not reveal which connector ids exist."""
import json
import time

from sqlalchemy import select

from app.config import settings
from app.db import Event, SessionLocal
from helpers import make_client, make_connector, push, signed, signin


def _setup():
    c = make_client()
    return make_connector(c)


def test_hmac_push_is_accepted_and_counted(client):
    conn = _setup()
    r = push(client, conn, [signin(1), signin(2), signin(2)])
    assert r.status_code == 202
    assert r.json() == {"accepted": True, "received": 3, "stored": 2, "duplicates": 1, "rejected": 0,
                        "skipped": 0}


def test_bearer_secret_is_accepted(client):
    conn = _setup()
    r = client.post(f"/api/ingest/{conn.id}", json=[signin(1)],
                    headers={"Authorization": "Bearer push-secret-123"})
    assert r.status_code == 202 and r.json()["stored"] == 1


def test_wrong_secret_stale_timestamp_and_unknown_ids_all_look_the_same(client):
    conn = _setup()
    body = json.dumps([signin(1)]).encode()
    wrong = client.post(f"/api/ingest/{conn.id}", content=body, headers=signed(body, "not-the-secret"))
    stale = client.post(f"/api/ingest/{conn.id}", content=body,
                        headers=signed(body, "push-secret-123", ts=int(time.time()) - 3600))
    unknown = client.post("/api/ingest/0123456789abcdef0123456789abcdef", content=body,
                          headers=signed(body, "push-secret-123"))
    bearer_wrong = client.post(f"/api/ingest/{conn.id}", content=body, headers={"Authorization": "Bearer nope"})
    tampered_headers = signed(body, "push-secret-123")
    tampered = client.post(f"/api/ingest/{conn.id}", content=body.replace(b"alice", b"mallory"),
                           headers=tampered_headers)
    for r in (wrong, stale, unknown, bearer_wrong, tampered):
        assert r.status_code == 404
    assert SessionLocal().execute(select(Event)).first() is None


def test_staff_session_and_api_token_cannot_push(admin):
    conn = _setup()
    from helpers import bearer
    assert admin.post(f"/api/ingest/{conn.id}", json=[signin(1)]).status_code == 404
    assert admin.post(f"/api/ingest/{conn.id}", json=[signin(1)], headers=bearer()).status_code == 404


def test_disabled_connector_refuses(client):
    conn = make_connector(make_client(), enabled=False)
    assert push(client, conn, [signin(1)]).status_code == 404


def test_size_and_count_limits(client, monkeypatch):
    conn = _setup()
    monkeypatch.setattr(settings, "max_push_bytes", 4000)
    big = [signin(i, note="x" * 500) for i in range(10)]
    assert push(client, conn, big).status_code == 413
    monkeypatch.setattr(settings, "max_push_bytes", 5_000_000)
    monkeypatch.setattr(settings, "max_push_records", 3)
    assert push(client, conn, [signin(i) for i in range(4)]).status_code == 413


def test_non_json_body_is_400(client):
    conn = _setup()
    body = b"not json"
    assert client.post(f"/api/ingest/{conn.id}", content=body,
                       headers=signed(body, "push-secret-123")).status_code == 400


def test_envelopes_are_unwrapped(client):
    c = make_client()
    entra = make_connector(c)
    diag = {"records": [{"time": "x", "category": "SignInLogs", "properties": signin(7)}]}
    assert push(client, entra, diag).json()["stored"] == 1
    okta = make_connector(c, source="okta_system_log", secret="okta-secret")
    hook = {"data": {"events": [{"uuid": "okta-1", "published": "2026-10-19T12:00:00.000Z",
                                 "eventType": "user.session.start", "outcome": {"result": "SUCCESS"},
                                 "actor": {"alternateId": "bob@acme.example", "type": "User"},
                                 "client": {"ipAddress": "198.51.100.4"}}]}}
    r = push(client, okta, hook, secret="okta-secret")
    assert r.status_code == 202 and r.json()["stored"] == 1, r.json()


def test_okta_verification_challenge_needs_the_secret(client):
    conn = make_connector(make_client(), source="okta_system_log", secret="okta-secret")
    ok = client.get(f"/api/ingest/{conn.id}", headers={"Authorization": "Bearer okta-secret",
                                                       "x-okta-verification-challenge": "abc123"})
    assert ok.status_code == 200 and ok.json() == {"verification": "abc123"}
    assert client.get(f"/api/ingest/{conn.id}", headers={"x-okta-verification-challenge": "abc"}).status_code == 404
