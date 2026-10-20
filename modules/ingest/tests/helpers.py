"""Shared builders: clients, connectors, sessions, and mock transports."""
import hashlib
import hmac
import json
import time

import httpx

from app import auth
from app.db import Client, Connector, SessionLocal, User


def make_client(name="Acme Corp", pid="plat-acme", domains="acme.example", portal=True, execs="", active=True):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=portal, portal_domains=domains,
               executive_emails=execs, active=active)
    db.add(c)
    db.commit()
    db.close()
    return c


def make_connector(client, source="entra_signins", secret="push-secret-123", enabled=True, config=None,
                   credentials=""):
    db = SessionLocal()
    c = Connector(client_id=client.id, source=source, name=f"{client.name} {source}", enabled=enabled,
                  webhook_secret=secret, config=config or {}, credentials=credentials)
    db.add(c)
    db.commit()
    db.close()
    return c


def signin(i=0, user="alice@acme.example", ip="203.0.113.10", ok=True, at="2026-10-19T12:00:00Z", **extra):
    r = {"id": f"si-{i}", "createdDateTime": at, "userPrincipalName": user, "userId": f"u-{user}",
         "appDisplayName": "Office 365", "ipAddress": ip,
         "status": {"errorCode": 0} if ok else {"errorCode": 50126, "failureReason": "Invalid password"},
         "location": {"countryOrRegion": "US", "city": "Scranton"}}
    r.update(extra)
    return r


def as_user(tc, email, role="analyst", client_id=None):
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role=role, client_id=client_id, source="platform"))
            db.commit()
    finally:
        db.close()
    tc.cookies.set(auth.COOKIE, auth.make_session(email))


def bearer(actor=None):
    h = {"Authorization": f"Bearer {auth.api_token()}"}
    if actor:
        h["X-Vendetta-Actor"] = actor
    return h


def signed(body: bytes, secret: str, ts: int | None = None) -> dict:
    ts = int(time.time()) if ts is None else ts
    sig = hmac.new(secret.encode(), str(ts).encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Vendetta-Timestamp": str(ts), "X-Vendetta-Signature": f"sha256={sig}",
            "Content-Type": "application/json"}


def push(tc, connector, records, secret="push-secret-123"):
    body = json.dumps(records).encode()
    return tc.post(f"/api/ingest/{connector.id}", content=body, headers=signed(body, secret))


def hub_transport(captured, case="VCD-IR-2026-901"):
    def handler(req: httpx.Request) -> httpx.Response:
        payload = json.loads(req.content)
        captured.setdefault("payloads", []).append(payload)
        captured["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={"case_id": payload.get("case_ref") or case, "linked": bool(payload.get("case_ref"))})
    return httpx.MockTransport(handler)


def route(monkeypatch, module, transport):
    real = httpx.Client
    monkeypatch.setattr(module.httpx, "Client",
                        lambda *a, **k: real(*a, **{**k, "transport": k.get("transport") or transport}))
