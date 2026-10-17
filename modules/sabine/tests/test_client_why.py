"""The client brief's "What SABINE did on your account" section, and the
redaction every client-facing line goes through: no other client, no Vendetta
person, no host that is not the client's own, no console link, no token."""
from app import brain, executor, redact
from app.config import settings
from app.db import Brief, Proposal, SessionLocal

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)

RB = {"id": "plat-rb", "name": "Riverbend Credit Union"}
HP = {"id": "plat-hp", "name": "Harbor Point"}
CTX = {"others": ["Harbor Point", "Muhlenberg College"], "people": ["Dan Baker", "Jordan", "dan@vendettacd.io"],
       "own_hosts": {"ws01", "jdoe@riverbendcu.org", "riverbendcu.org"}}


def test_redact_for_client_rules():
    r = lambda t: redact.redact_for_client(t, RB, CTX)  # noqa: E731
    assert r("Harbor Point also has this; so does Muhlenberg.") == "another client also has this; so does another client."
    assert r("Lead: Dan Baker. Jordan will call; dan@vendettacd.io knows.") == "Lead: your Vendetta team. your Vendetta team will call; your Vendetta team knows."
    assert r("Ransomware on WS01 and lateral movement to SRV02 and fs01.harbor.local") == "Ransomware on WS01 and lateral movement to [host] and [host]"
    assert r("credential jdoe@riverbendcu.org leaked; see https://msp.example/alerts/al1") == "credential jdoe@riverbendcu.org leaked; see [link]"
    assert r("other victim bob@othercorp.com") == "other victim [address]"
    assert r("token=abc123 Bearer eyJhbGciOi.payload 0123456789abcdef0123456789abcdef") == "token [redacted] [redacted] [redacted]"
    assert r("OpenSSL < 3.0.14 at 2 a.m., see notes.md and VCD-IR-2026-790") == "OpenSSL < 3.0.14 at 2 a.m., see notes.md and VCD-IR-2026-790"
    assert r("") == "" and redact.redact_for_client("Dan at https://x.y", RB) == "Dan at [link]"  # no context: generic rules only
    assert r("Riverbend Credit Union is fine") == "Riverbend Credit Union is fine"  # the client's own name stays


def test_client_context_from_the_picture(world):  # noqa: F811
    from app import perception
    db = SessionLocal()
    perception.observe(db)
    ctx = redact.client_context(db, RB)
    assert ctx["others"] == ["Harbor Point"]
    assert {"Dan", "Idle", "Jordan", "dan@vendettacd.io"} <= set(ctx["people"])
    assert {"ws01", "srv02", "fs01", "jdoe@riverbendcu.org", "riverbendcu.org"} <= ctx["own_hosts"]
    assert "openssl < 3.0.14" not in ctx["own_hosts"]


def test_brief_carries_what_sabine_did_and_never_leaks(world):  # noqa: F811
    db = SessionLocal()
    brain.cycle(db)
    # a human-approved action for Harbor Point too
    e = db.query(Proposal).filter_by(key="escalate_finding:dark-web-monitoring:dw1").one()
    brain.decide(db, e, "dan@vendettacd.io", True)
    for p in db.query(Proposal).filter_by(action="client_brief").all():
        p.status = "expired"  # let the next cycle write fresh briefs
    db.commit()
    brain.cycle(db)
    briefs = {b.client: b for b in db.query(Brief).filter_by(kind="client-brief").order_by(Brief.created_at).all()}
    rb, hp = briefs["Riverbend Credit Union"].body_md, briefs["Harbor Point"].body_md
    assert "## What SABINE did on your account" in rb and "## What SABINE did on your account" in hp
    # Riverbend: the correlation note, the copilot item, the acceptance nudge, the escalation a responder approved
    assert "Note related findings across modules" in rb and "Nudge a deliverable" in rb
    assert "Escalate a finding into an IR case" in rb and "Information Security Policy v1" in rb
    # Harbor Point: the quiet case, the overdue remediation and the engagement past its end
    assert "Nudge an IR case" in hp and "Flag a vulnerability past its remediation SLA" in hp and "Tabletop 2026" in hp
    for other, body in (("Harbor Point", rb), ("Riverbend", hp)):
        assert other not in body, other
    for who in ("Dan", "Idle", "Jordan", "vendettacd.io"):
        assert who not in rb and who not in hp, who
    assert "WS01" in rb and "WS01" not in hp and "SRV02" not in hp and "FS01" not in hp
    assert "https://" not in rb and "https://" not in hp
    assert "VCD-IR-2026-790" in hp  # the client's own case number is theirs to see
    # the briefs themselves and the daily summary are not listed as actions
    assert "Write a client brief" not in rb and "Write the daily summary" not in rb
    acts = executor.client_actions(db, RB)
    assert all(a["by"] in ("SABINE", "a Vendetta responder") for a in acts)
    assert any(a["by"] == "a Vendetta responder" and a["what"].startswith("Escalate") for a in acts)
    # outside the window nothing is listed
    assert executor.client_actions(db, RB, days=0) == [] or all(a["at"] >= str(db.query(Proposal).first().created_at.date()) for a in executor.client_actions(db, RB, days=0))
    assert settings.client_brief_window_days == 7


def test_model_facts_carry_the_section_redacted(world, monkeypatch):  # noqa: F811
    """With a model configured, the facts it receives already carry the redacted
    section and no case lead, and the model's own output is scrubbed too."""
    from app import narrative
    seen = []

    def fake(prompt, max_tokens=900, audience="internal", system_text=None):
        seen.append((audience, prompt))
        return "Harbor Point is in good hands with Dan. What SABINE did on your account: see the list."
    monkeypatch.setattr(settings, "anthropic_api_key", "k")
    monkeypatch.setattr(narrative, "_complete", fake)
    db = SessionLocal()
    brain.cycle(db)
    b = db.query(Brief).filter_by(kind="client-brief", client="Riverbend Credit Union").one()
    assert b.source == "llm"
    prompt = next(p for a, p in seen if a == "client" and "'client': 'Riverbend Credit Union'" in p)
    assert "what_sabine_did" in prompt and "'lead'" not in prompt and "Harbor Point" not in prompt and "Dan" not in prompt
    assert "another client is in good hands with your Vendetta team" in b.body_md
