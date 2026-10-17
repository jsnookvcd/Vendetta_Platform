"""The exposure report over the service API, for the Slack responder. The bridge
token plus a named, rostered person reads it; the module's ordinary token is its
own actor; nobody else reads it."""
import datetime as dt

import pytest

from app import auth
from app.config import settings
from app.db import AuditLog, Client, Hit, Item, SessionLocal, User, WatchTerm

BRIDGE = "dw-bridge"


@pytest.fixture()
def seeded(client, monkeypatch):
    monkeypatch.setattr(settings, "bridge_token", BRIDGE)
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", platform_client_id="plat-rb")
    db.add(c)
    db.add_all([User(email="dan@vendettacd.io", role="analyst", source="platform"),
                User(email="vic@vendettacd.io", role="viewer", source="platform")])
    db.flush()
    t = WatchTerm(client_id=c.id, term="riverbendcu.org", kind="domain", severity="high")
    db.add(t)
    it = Item(kind="credential", title="Infostealer log", url="", group_name="", content_hash="h1")
    it2 = Item(kind="victim", title="Riverbend Credit Union", url="http://leak.onion/rb", group_name="akira", content_hash="h2")
    db.add_all([it, it2])
    db.flush()
    db.add_all([Hit(client_id=c.id, item_id=it.id, term_id=t.id, reason="credential", severity="high",
                    matched_text="jsmith@riverbendcu.org", created_at=dt.datetime.now(dt.timezone.utc)),
                Hit(client_id=c.id, item_id=it2.id, term_id=t.id, reason="term", severity="critical",
                    matched_text="Riverbend Credit Union", created_at=dt.datetime.now(dt.timezone.utc))])
    db.commit()
    return client


def _h(person="dan@vendettacd.io", token=BRIDGE):
    h = {"Authorization": f"Bearer {token}", "X-Vendetta-Actor": "slack"}
    if person:
        h["X-Vendetta-On-Behalf-Of"] = person
    return h


def test_report_json_through_the_bridge(seeded):
    r = seeded.get("/api/clients/platform/plat-rb/report?days=30", headers=_h())
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["client"] == "Riverbend Credit Union" and d["total"] == 2
    assert d["credential_count"] == 1 and d["credentials"][0]["matched"] == "jsmith@riverbendcu.org"
    assert d["leak_posts"][0]["group"] == "akira" and d["actions"]
    row = SessionLocal().query(AuditLog).filter_by(action="report.api").one()
    assert row.actor == "dan@vendettacd.io via slack"


def test_viewer_may_read_but_strangers_and_no_person_may_not(seeded):
    assert seeded.get("/api/clients/platform/plat-rb/report", headers=_h("vic@vendettacd.io")).status_code == 200
    for who in ("", "stranger@vendettacd.io"):
        assert seeded.get("/api/clients/platform/plat-rb/report", headers=_h(who)).status_code == 403, who
    assert seeded.get("/api/clients/platform/plat-rb/report").status_code in (401, 403)


def test_module_token_is_its_own_actor_and_unknown_client_404(seeded):
    r = seeded.get("/api/clients/platform/plat-rb/report", headers=_h("jordan@vendettacd.io", token=auth.api_token()))
    assert r.status_code == 200
    assert SessionLocal().query(AuditLog).filter_by(action="report.api").one().actor == "api:slack"
    assert seeded.get("/api/clients/platform/nope/report", headers=_h()).status_code == 404


def test_pdf_route_is_guarded(seeded):
    assert seeded.get("/api/clients/platform/plat-rb/report.pdf", headers=_h("stranger@vendettacd.io")).status_code == 403
    r = seeded.get("/api/clients/platform/plat-rb/report.pdf", headers=_h())
    assert r.status_code in (200, 501)  # 501 where the PDF engine is not installed
    if r.status_code == 200:
        assert r.headers["content-type"] == "application/pdf"
