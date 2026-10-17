"""Shared builders: clients, managed-services-shaped signals, a mock managed-services."""
import datetime as dt
import itertools
import json

import httpx

from app import auth
from app.db import Client, SessionLocal, User

_seq = itertools.count(1)


def make_client(name="Acme Corp", pid="plat-acme", domains="acme.example", portal=True, execs=""):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=portal, portal_domains=domains,
               executive_emails=execs)
    db.add(c)
    db.commit()
    db.close()
    return c


def finding(pid="plat-acme", client="Acme Corp", tool="sentinelone", kind="threat", severity="high",
            title="Ransomware behavior detected", host="ACME-WS01", at=None, fid=None, status="new"):
    """One managed-services finding, exactly as its /api/findings serves it."""
    at = at or dt.datetime.now(dt.timezone.utc)
    fid = fid or f"ms{next(_seq):05d}"
    return {
        "id": fid, "module": "managed-services", "platform": "Vendetta Platform",
        "subject": {"client_id": "msc1", "platform_client_id": pid, "client": client, "case_ref": ""},
        "type": kind, "reason": tool, "severity": severity, "status": status, "title": title,
        "matched": host, "source_group": tool, "url": "", "published_at": at.isoformat(),
        "created_at": at.isoformat(), "analyst_notes": "", "evidence": [],
        "workstream": "Scoping and Containment", "copilot": None,
    }


def ms_transport(findings, captured=None, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured["path"] = req.url.path
            captured["params"] = dict(req.url.params)
            captured["auth"] = req.headers.get("authorization")
        return httpx.Response(status, json=findings)
    return httpx.MockTransport(handler)


def hub_transport(captured, case="VCD-IR-2026-901", linked=None):
    def handler(req: httpx.Request) -> httpx.Response:
        payload = json.loads(req.content)
        captured.setdefault("payloads", []).append(payload)
        captured["path"] = req.url.path
        captured["auth"] = req.headers.get("authorization")
        is_linked = bool(payload.get("case_ref")) if linked is None else linked
        return httpx.Response(200, json={"case_id": payload.get("case_ref") or case, "id": "hubid",
                                         "linked": is_linked})
    return httpx.MockTransport(handler)


def route(monkeypatch, module, transport):
    """Point a module's outbound httpx.Client at a mock."""
    real = httpx.Client
    monkeypatch.setattr(module.httpx, "Client",
                        lambda *a, **k: real(*a, **{**k, "transport": k.get("transport") or transport}))


def ingest(findings, now=None):
    """Store signals and run the engine over them, no network."""
    from app import detect
    db = SessionLocal()
    try:
        detect.upsert_signals(db, findings)
        db.commit()
        return detect.run(db, pull=False, now=now)
    finally:
        db.close()


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
