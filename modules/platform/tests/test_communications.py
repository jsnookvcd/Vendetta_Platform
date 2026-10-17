"""Communications: SABINE drafts through the service API (idempotent), one person
approves (the account lead or a platform admin, never a viewer or another
analyst), approval publishes and emails the executives through notify.send when
mail is configured, mail never fails an approval, and discard is final."""
import datetime as dt

import pytest

from app import journey, notify
from app.db import Communication, SessionLocal
from helpers import bearer, make_client, sign_in_as


@pytest.fixture()
def outbox():
    sent = []
    notify.use_sender(lambda to, subject, body: sent.append((to, subject, body)) or "fake")
    yield sent
    notify.use_sender(None)


def _draft(client, pid, **body):
    payload = {"kind": "posture_review", "title": "October posture review", "subject": "Your October review",
               "body_md": "## Summary\n\n- **2** critical findings closed\n- MFA rollout on track",
               "source_ref": "review:x:2026-10", **body}
    return client.post(f"/api/platform/clients/{pid}/communications", json=payload, headers=bearer("sabine"))


def _client(admin, **kw):
    kw.setdefault("executive_emails", "ceo@riverbendcu.org, CFO@riverbendcu.org")
    kw.setdefault("account_lead", "dan@vendettacd.io")
    return make_client(admin, **kw)


def test_draft_is_idempotent_and_listed_newest_first(admin):
    c = _client(admin)
    r = _draft(admin, c.id)
    assert r.json()["created"] is True
    first = r.json()["id"]
    assert _draft(admin, c.id, title="changed").json() == {"id": first, "created": False}
    second = _draft(admin, c.id, kind="outreach", title="Deliverable waiting", source_ref="outreach:d1").json()["id"]
    db = SessionLocal()
    db.get(Communication, first).created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    db.commit()
    items = admin.get(f"/api/platform/clients/{c.id}/communications", headers=bearer()).json()["items"]
    assert [i["id"] for i in items] == [second, first]
    assert set(items[0]) == {"id", "kind", "title", "subject", "body_md", "status", "source", "source_ref",
                             "created_at", "decided_by", "decided_at", "sent_detail", "published"}
    assert items[1]["status"] == "draft" and items[1]["source"] == "sabine" and items[1]["published"] is False


def test_draft_validation(admin):
    c = _client(admin)
    assert _draft(admin, c.id, kind="newsletter").status_code == 400
    assert _draft(admin, c.id, title="").status_code == 400
    assert _draft(admin, "nope").status_code == 404
    assert admin.get("/api/platform/clients/nope/communications", headers=bearer()).status_code == 404


def test_admin_approval_publishes_and_emails_executives(admin, outbox):
    c = _client(admin)
    mid = _draft(admin, c.id).json()["id"]
    r = admin.post(f"/clients/{c.id}/communications/{mid}/approve",
                   data={"title": "October posture review", "subject": "Your October security review",
                         "body_md": "Edited body before approval."}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    m = SessionLocal().get(Communication, mid)
    assert m.status == "sent" and m.published is True and m.decided_by == "admin" and m.decided_at
    assert m.body_md == "Edited body before approval."
    assert sorted(t for t, _, _ in outbox) == ["ceo@riverbendcu.org", "cfo@riverbendcu.org"]
    assert all(s == "Your October security review" for _, s, _ in outbox)
    assert "Edited body before approval." in outbox[0][2] and "—" not in outbox[0][2]
    assert "ceo@riverbendcu.org: sent (fake)" in m.sent_detail
    # approval is one-time
    r = admin.post(f"/clients/{c.id}/communications/{mid}/approve", follow_redirects=False)
    assert "err=" in r.headers["location"] and len(outbox) == 2


def test_portal_link_in_email_when_public_url_set(admin, outbox, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "public_url", "https://platform.vendettacd.io")
    c = _client(admin)
    mid = _draft(admin, c.id).json()["id"]
    admin.post(f"/clients/{c.id}/communications/{mid}/approve")
    assert f"https://platform.vendettacd.io/portal/communications/{mid}" in outbox[0][2]


def test_account_lead_approves_other_analyst_and_viewer_cannot(client, admin, outbox):
    c = _client(admin)
    mid = _draft(admin, c.id).json()["id"]
    # an analyst who is not the lead
    sign_in_as(client, "kenedi@vendettacd.io", "analyst")
    assert client.get(f"/clients/{c.id}/communications/{mid}").status_code == 200
    for action in ("approve", "edit", "discard"):
        assert client.post(f"/clients/{c.id}/communications/{mid}/{action}").status_code == 403
    # a viewer, even one named as the lead, cannot approve
    sign_in_as(client, "dan@vendettacd.io", "viewer")
    r = client.post(f"/clients/{c.id}/communications/{mid}/approve")
    assert r.status_code == 403
    assert SessionLocal().get(Communication, mid).status == "draft" and outbox == []
    # the lead as an analyst approves
    sign_in_as(client, "dan@vendettacd.io", "analyst")
    client.post(f"/clients/{c.id}/communications/{mid}/approve")
    m = SessionLocal().get(Communication, mid)
    assert m.status == "sent" and m.decided_by == "dan@vendettacd.io" and len(outbox) == 2


def test_no_smtp_publishes_without_mail(admin):
    assert not notify.can_send()
    c = _client(admin)
    mid = _draft(admin, c.id).json()["id"]
    admin.post(f"/clients/{c.id}/communications/{mid}/approve")
    m = SessionLocal().get(Communication, mid)
    assert m.status == "approved" and m.published and "SMTP not configured" in m.sent_detail


def test_no_executive_emails_publishes_only(admin, outbox):
    c = _client(admin, executive_emails="")
    mid = _draft(admin, c.id).json()["id"]
    admin.post(f"/clients/{c.id}/communications/{mid}/approve")
    m = SessionLocal().get(Communication, mid)
    assert m.status == "approved" and m.published and "no executive emails" in m.sent_detail and outbox == []


def test_mail_failure_never_fails_approval(admin):
    def boom(to, subject, body):
        raise ConnectionError("mail host down")
    notify.use_sender(boom)
    try:
        c = _client(admin)
        mid = _draft(admin, c.id).json()["id"]
        r = admin.post(f"/clients/{c.id}/communications/{mid}/approve", follow_redirects=False)
    finally:
        notify.use_sender(None)
    assert r.status_code == 302
    m = SessionLocal().get(Communication, mid)
    assert m.status == "approved" and m.published and "failed: ConnectionError" in m.sent_detail


def test_edit_and_discard_are_final(admin, outbox):
    c = _client(admin)
    mid = _draft(admin, c.id).json()["id"]
    admin.post(f"/clients/{c.id}/communications/{mid}/edit", data={"title": "Renamed", "subject": "", "body_md": "x"})
    m = SessionLocal().get(Communication, mid)
    assert m.title == "Renamed" and m.subject == "Your October review" and m.body_md == "x"
    admin.post(f"/clients/{c.id}/communications/{mid}/discard")
    m = SessionLocal().get(Communication, mid)
    assert m.status == "discarded" and m.decided_by == "admin" and not m.published
    r = admin.post(f"/clients/{c.id}/communications/{mid}/approve", follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = admin.post(f"/clients/{c.id}/communications/{mid}/edit", data={"title": "again"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert SessionLocal().get(Communication, mid).status == "discarded" and outbox == []
    # SABINE re-posting the same source_ref does not resurrect it
    assert _draft(admin, c.id).json() == {"id": mid, "created": False}


def test_staff_draft_from_client_page(admin):
    c = _client(admin)
    r = admin.post(f"/clients/{c.id}/communications", data={"kind": "outreach", "title": "Check-in",
                                                            "body_md": "Hello"}, follow_redirects=False)
    assert r.headers["location"].startswith(f"/clients/{c.id}/communications/")
    m = SessionLocal().query(Communication).filter_by(client_id=c.id).one()
    assert m.source == "staff" and m.status == "draft" and m.subject == "Check-in"


def test_inbox_lists_drafts_across_clients(admin):
    a = _client(admin)
    b = make_client(admin, "Cedar Valley")
    keep = _draft(admin, a.id).json()["id"]
    _draft(admin, b.id, title="Cedar outreach", kind="outreach", source_ref="o:1")
    done = _draft(admin, b.id, title="Already approved", source_ref="o:2").json()["id"]
    admin.post(f"/clients/{b.id}/communications/{done}/approve")
    page = admin.get("/communications").text
    drafts_section = page.split("Recently decided")[0]
    assert "October posture review" in drafts_section and "Cedar outreach" in drafts_section
    assert "Already approved" not in drafts_section and "Already approved" in page
    assert f"/clients/{a.id}/communications/{keep}" in page
    assert "yours to approve" in page  # the break-glass admin may approve everything


def test_markdown_is_escaped(admin):
    html = journey.render_md("# Title\n\n<script>alert(1)</script> **bold** and *it*\n\n1. one\n2. two")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<strong>bold</strong>" in html and "<em>it</em>" in html and "<ol><li>one</li>" in html
    c = _client(admin)
    mid = _draft(admin, c.id, body_md="<img src=x onerror=alert(1)>").json()["id"]
    page = admin.get(f"/clients/{c.id}/communications/{mid}").text
    assert "<img src=x" not in page
