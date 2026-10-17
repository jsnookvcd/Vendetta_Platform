"""POST /api/oncall/page: SABINE pages the on-call responder through the same
SNS and Teams delivery a new case uses. Service API only, audit-logged, and it
answers {"sent": {}} when no channel is configured."""
from app import auth, notify
from app.config import settings
from app.db import AuditLog, SessionLocal

BODY = {"title": "Critical MDR investigation unacknowledged 22m: Ransomware on WS01", "body": "Commitment is 15 minutes.",
        "link": "https://mdr.example/investigations/i1", "severity": "critical", "platform_client_id": "plat-rb",
        "client": "Riverbend Credit Union", "source_module": "mdr", "source_ref": "mdr:i1"}


def _bearer(actor: str = "sabine"):
    return {"Authorization": f"Bearer {auth.api_token()}", "X-Vendetta-Actor": actor}


def test_page_with_nothing_configured_returns_empty_and_audits(client, monkeypatch):
    monkeypatch.setattr(settings, "teams_webhook_url", "")
    monkeypatch.setattr(settings, "sns_topic_arn", "")
    r = client.post("/api/oncall/page", json=BODY, headers=_bearer())
    assert r.status_code == 200 and r.json() == {"sent": {}}
    row = SessionLocal().query(AuditLog).filter_by(action="oncall.page").one()
    assert row.actor == "api:sabine" and "mdr:mdr:i1" in row.detail and "sent=none" in row.detail and "plat-rb" in row.detail


def test_page_goes_through_teams_with_the_link(client, monkeypatch):
    seen = {}

    class _Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, json, timeout):
        seen["url"], seen["card"] = url, json
        return _Resp()
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    monkeypatch.setattr(settings, "teams_webhook_url", "https://example.invalid/hook")
    monkeypatch.setattr(settings, "sns_topic_arn", "")
    r = client.post("/api/oncall/page", json=BODY, headers=_bearer())
    assert r.json() == {"sent": {"teams": "sent"}}
    content = seen["card"]["attachments"][0]["content"]
    assert content["body"][0]["text"].startswith("[CRITICAL] Critical MDR investigation unacknowledged")
    assert "Client: Riverbend Credit Union" in content["body"][1]["text"] and "Ref: mdr:i1" in content["body"][1]["text"]
    assert content["actions"][0]["url"] == BODY["link"]
    assert "sent=teams" in SessionLocal().query(AuditLog).filter_by(action="oncall.page").one().detail


def test_page_validates_and_requires_the_service_token(client, monkeypatch):
    monkeypatch.setattr(settings, "teams_webhook_url", "")
    monkeypatch.setattr(settings, "sns_topic_arn", "")
    assert client.post("/api/oncall/page", json=BODY).status_code == 401
    assert client.post("/api/oncall/page", json={**BODY, "title": " "}, headers=_bearer()).status_code == 400
    # a link that is not http(s) is dropped rather than put on a card
    r = client.post("/api/oncall/page", json={**BODY, "link": "javascript:alert(1)"}, headers=_bearer())
    assert r.status_code == 200 and r.json() == {"sent": {}}


def test_page_new_case_uses_the_generic_page(fresh_db, monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "page", lambda title, body, link="", link_label="Open": calls.append((title, link, link_label)) or {"x": 1})
    from app.db import Client, open_case
    db = SessionLocal()
    c = Client(name="Alpha")
    db.add(c)
    db.commit()
    case = open_case(db, c, "x", severity="high")
    assert notify.page_new_case(case) == {"x": 1}
    assert calls[0][0].startswith("[HIGH] ") and calls[0][2] == "Open case"
