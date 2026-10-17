"""Phase 4 coverage: starter watch terms on provisioning, backfill on new terms
through the worker, readiness for clients without terms, and the not-configured
reasons of the optional connectors. No test touches the network; the control
plane and the paste index are replaced with httpx.MockTransport or fakes."""
import datetime as dt
import importlib.util

import httpx
import pytest

from app import backfill, connectors, provision, readiness, watchterms, worker
from app.collectors import pastes
from app.config import settings
from app.db import AutoTermTombstone, BackfillRequest, Client, Hit, Item, SessionLocal, Source, WatchTerm, utcnow

ROSTER = {"module": "dark-web-monitoring", "clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "industry": "credit union",
     "portal_domains": "riverbendcu.org", "modules": ["dark-web-monitoring"]},
    {"id": "plat-hp", "name": "Harbor Point Logistics, LLC", "industry": "transport",
     "portal_domains": "", "modules": ["dark-web-monitoring"]},
]}


def _roster(**over):
    rb = {**ROSTER["clients"][0], **over}
    return {"clients": [rb, ROSTER["clients"][1]]}


def _transport(roster=ROSTER):
    return httpx.MockTransport(lambda req: httpx.Response(200, json=roster))


def _pull(monkeypatch, roster=ROSTER):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")
    db = SessionLocal()
    try:
        return provision.pull(db, transport=_transport(roster))
    finally:
        db.close()


def _terms(pid):
    db = SessionLocal()
    try:
        c = db.query(Client).filter_by(platform_client_id=pid).one()
        return c.id, {(t.term, t.kind): t for t in db.query(WatchTerm).filter_by(client_id=c.id)}
    finally:
        db.close()


def _requests():
    db = SessionLocal()
    try:
        return db.query(BackfillRequest).order_by(BackfillRequest.requested_at).all()
    finally:
        db.close()


def _item(title, days_ago, kind="victim", body=""):
    db = SessionLocal()
    try:
        when = utcnow() - dt.timedelta(days=days_ago)
        it = Item(kind=kind, title=title, body=body, group_name="akira", published_at=when, collected_at=when,
                  content_hash=Item.make_hash(title, str(days_ago)))
        db.add(it)
        db.commit()
        return it.id
    finally:
        db.close()


def _hits(cid):
    db = SessionLocal()
    try:
        return db.query(Hit).filter_by(client_id=cid).all()
    finally:
        db.close()


# ---------------------------------------------------------------- name variants
def test_suffix_stripping():
    s = watchterms.strip_suffixes
    assert s("Riverbend Credit Union") == "Riverbend"
    assert s("Keystone Federal Credit Union") == "Keystone"
    assert s("Penn FCU") == "Penn"
    assert s("Acme, Inc.") == "Acme"
    assert s("Widgets L.L.C.") == "Widgets"
    assert s("Northwind Corporation") == "Northwind"
    assert s("Contoso Corp") == "Contoso"
    assert s("Fabrikam Co.") == "Fabrikam"
    assert s("Tailspin Ltd") == "Tailspin"
    assert s("Smith & Co") == "Smith"
    assert s("Juniper Bank, N.A.") == "Juniper"
    assert s("Costco") == "Costco"            # suffixes only match whole trailing words
    assert s("Harbor Point Logistics") == "Harbor Point Logistics"


def test_starter_terms_skip_short_and_generic_variants():
    st = watchterms.starter_terms
    assert st("Riverbend Credit Union", "riverbendcu.org, @WWW.RiverbendCU.org") == [
        ("riverbendcu.org", "domain"), ("riverbendcu.org", "email_domain"),
        ("Riverbend Credit Union", "brand"), ("Riverbend", "brand")]
    assert st("ABC Corp", "") == [("ABC Corp", "brand")]                       # "ABC" is under 4 characters
    assert st("First National Bank", "") == []                                 # every word is generic
    assert st("Community Credit Union", "") == []
    assert st("Acme, Inc.", "") == [("Acme, Inc", "brand"), ("Acme", "brand")]  # matcher-safe punctuation
    assert st("Harbor Point Logistics", "not-a-domain") == [("Harbor Point Logistics", "brand")]


# ---------------------------------------------------------------- provisioning
def test_auto_terms_on_create(fresh_db, monkeypatch):
    summ = _pull(monkeypatch)
    rb_id, rb = _terms("plat-rb")
    assert set(rb) == {("riverbendcu.org", "domain"), ("riverbendcu.org", "email_domain"),
                       ("Riverbend Credit Union", "brand"), ("Riverbend", "brand")}
    assert all(t.source == "auto" and t.enabled for t in rb.values())
    hp_id, hp = _terms("plat-hp")
    assert set(hp) == {("Harbor Point Logistics, LLC", "brand"), ("Harbor Point Logistics", "brand")}
    assert summ["terms_added"] == 6
    # one backfill per client, limited to the new terms, run later by the worker
    reqs = _requests()
    assert {r.payload["client_id"] for r in reqs} == {rb_id, hp_id}
    assert all(r.status == "pending" and r.payload["days"] == 365 for r in reqs)
    assert sorted(next(r for r in reqs if r.payload["client_id"] == rb_id).payload["term_ids"]) == \
        sorted(t.id for t in rb.values())


def test_auto_terms_on_update_add_only_what_is_missing(fresh_db, monkeypatch):
    _pull(monkeypatch)
    # a second identical pull adds nothing and queues nothing new
    db = SessionLocal()
    for r in db.query(BackfillRequest):
        r.status = "done"
    db.commit()
    db.close()
    assert _pull(monkeypatch)["terms_added"] == 0
    assert all(r.status == "done" for r in _requests())
    # the platform adds a domain: only its two terms are added
    summ = _pull(monkeypatch, _roster(portal_domains="riverbendcu.org, rbcu.com"))
    assert summ["terms_added"] == 2
    rb_id, rb = _terms("plat-rb")
    assert {("rbcu.com", "domain"), ("rbcu.com", "email_domain")} <= set(rb)
    assert len(rb) == 6
    pending = [r for r in _requests() if r.status == "pending"]
    assert len(pending) == 1 and len(pending[0].payload["term_ids"]) == 2


def test_analyst_terms_never_deleted_or_altered(fresh_db, monkeypatch):
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union")
    db.add(c)
    db.commit()
    db.add_all([
        WatchTerm(client_id=c.id, term="RiverbendCU.org", kind="domain", severity="critical", enabled=False),
        WatchTerm(client_id=c.id, term="riverbend", kind="brand", severity="low"),
        WatchTerm(client_id=c.id, term="Jane Doe", kind="person", severity="high"),
    ])
    db.commit()
    cid = c.id
    db.close()
    _pull(monkeypatch)
    _, terms = _terms("plat-rb")
    # same text and kind already present (any case, even disabled): left exactly as is
    dom = terms[("RiverbendCU.org", "domain")]
    assert (dom.severity, dom.enabled, dom.source) == ("critical", False, "analyst")
    assert terms[("riverbend", "brand")].severity == "low"
    assert ("riverbendcu.org", "domain") not in terms and ("Riverbend", "brand") not in terms
    assert terms[("Jane Doe", "person")].source == "analyst"
    # only the genuinely missing starter terms were added
    assert {k for k, t in terms.items() if t.source == "auto"} == {
        ("riverbendcu.org", "email_domain"), ("Riverbend Credit Union", "brand")}
    # the platform drops the domain: nothing is deleted
    _pull(monkeypatch, _roster(portal_domains=""))
    _, after = _terms("plat-rb")
    assert set(after) == set(terms)
    assert cid


def test_deleted_auto_term_is_not_re_added(admin, monkeypatch):
    _pull(monkeypatch)
    cid, terms = _terms("plat-rb")
    t = terms[("Riverbend", "brand")]
    r = admin.post(f"/clients/{cid}/terms/{t.id}/delete", follow_redirects=False)
    assert r.status_code == 302
    db = SessionLocal()
    tomb = db.query(AutoTermTombstone).filter_by(client_id=cid).one()
    assert (tomb.term, tomb.kind) == ("riverbend", "brand")
    db.close()
    assert _pull(monkeypatch)["terms_added"] == 0
    _, after = _terms("plat-rb")
    assert ("Riverbend", "brand") not in after and len(after) == 3
    # deleting an analyst term leaves no tombstone
    admin.post(f"/clients/{cid}/terms", data={"term": "Riverbend Mortgage", "kind": "brand", "severity": "medium"})
    _, after = _terms("plat-rb")
    admin.post(f"/clients/{cid}/terms/{after[('Riverbend Mortgage', 'brand')].id}/delete")
    db = SessionLocal()
    assert db.query(AutoTermTombstone).filter_by(client_id=cid).count() == 1
    db.close()
    page = admin.get(f"/clients/{cid}").text
    assert "Removed auto terms" in page and "riverbend" in page


# ---------------------------------------------------------------- backfill
def test_backfill_queued_on_provision_and_run_by_worker(fresh_db, monkeypatch):
    recent = _item("Riverbend Credit Union", days_ago=200)
    _item("Riverbend Credit Union (old leak)", days_ago=400)        # outside 365 days
    _item("Unrelated Manufacturing Inc", days_ago=30)
    _pull(monkeypatch)
    rb_id, _ = _terms("plat-rb")
    assert _hits(rb_id) == []                                        # nothing matched inline
    assert worker.poll_backfills() == 2
    hits = _hits(rb_id)
    assert {h.item_id for h in hits} == {recent}
    assert all(h.severity == "high" for h in hits)                   # victim posts are at least high
    req = next(r for r in _requests() if r.payload["client_id"] == rb_id)
    assert req.status == "done" and req.result["hits_new"] == len(hits) and req.result["items_scanned"] == 2
    # draining again is a no-op; re-running the backfill creates no duplicates
    assert worker.poll_backfills() == 0
    db = SessionLocal()
    assert backfill.run_backfill(db, rb_id)["hits_new"] == 0
    db.close()


def test_analyst_terms_queue_backfill_and_client_page_shows_result(admin):
    db = SessionLocal()
    c = Client(name="Northwind Traders")
    db.add(c)
    db.commit()
    cid = c.id
    db.close()
    item = _item("northwind.example leaked by akira", days_ago=90, kind="post")
    admin.post(f"/clients/{cid}/terms", data={"term": "northwind.example", "kind": "domain", "severity": "medium"})
    assert _hits(cid) == []
    reqs = _requests()
    assert len(reqs) == 1 and reqs[0].payload["client_id"] == cid and len(reqs[0].payload["term_ids"]) == 1
    db = SessionLocal()
    assert db.query(WatchTerm).filter_by(client_id=cid).one().source == "analyst"
    db.close()
    assert "queued for the collector worker" in admin.get(f"/clients/{cid}").text
    worker.poll_backfills()
    assert [h.item_id for h in _hits(cid)] == [item]
    page = admin.get(f"/clients/{cid}").text
    assert "Last backfill" in page and "created 1 new hits" in page
    assert ">analyst<" in page


def test_manual_backfill_route_queues_full_pass(admin):
    db = SessionLocal()
    c = Client(name="Contoso Ltd")
    db.add(c)
    db.commit()
    db.add(WatchTerm(client_id=c.id, term="Contoso", kind="brand"))
    db.commit()
    cid = c.id
    db.close()
    _item("Contoso data posted", days_ago=100)
    r = admin.post(f"/clients/{cid}/backfill", data={"days": "365"}, follow_redirects=False)
    assert r.status_code == 302 and _hits(cid) == []
    req = _requests()[0]
    assert req.payload["term_ids"] is None and req.payload["include_iab"] is True
    worker.poll_backfills()
    assert len(_hits(cid)) == 1


def test_queue_merges_into_pending_request(fresh_db):
    db = SessionLocal()
    c = Client(name="Fabrikam")
    db.add(c)
    db.commit()
    backfill.queue(db, c.id, ["a"], reason="starter terms")
    backfill.queue(db, c.id, ["b"], reason="terms added", days=30)
    reqs = _requests()
    assert len(reqs) == 1
    assert reqs[0].payload["term_ids"] == ["a", "b"] and reqs[0].payload["days"] == 365
    assert reqs[0].payload["reason"] == "starter terms, terms added"
    backfill.queue(db, c.id, None)
    assert _requests()[0].payload["term_ids"] is None
    db.close()


def test_scheduler_drains_backfills():
    jobs = {j.id: j for j in worker.build_scheduler().get_jobs()}
    assert "backfill_requests" in jobs and jobs["backfill_requests"].next_run_time is not None


# ---------------------------------------------------------------- readiness
def test_readiness_warns_on_active_client_without_terms(fresh_db):
    db = SessionLocal()
    bare = Client(name="Harbor Point Logistics")
    paused = Client(name="Paused Co", active=False)
    db.add_all([bare, paused])
    db.commit()
    integ = readiness.integrations()
    assert {"kind", "configured", "tor", "worker_heartbeat_age_seconds", "connectors"} <= set(integ)
    assert integ["watch_terms"]["ok"] is False and integ["watch_terms"]["clients_without_terms"] == 1
    assert integ["watch_terms"]["clients"] == [{"id": bare.id, "name": "Harbor Point Logistics"}]
    assert any("Harbor Point Logistics" in w for w in integ["warnings"])
    # a disabled term does not count
    db.add(WatchTerm(client_id=bare.id, term="harborpoint.example", kind="domain", enabled=False))
    db.commit()
    assert readiness.integrations()["watch_terms"]["ok"] is False
    db.add(WatchTerm(client_id=bare.id, term="Harbor Point", kind="brand"))
    db.commit()
    integ = readiness.integrations()
    assert integ["watch_terms"]["ok"] is True and integ["warnings"] == []
    db.close()


# ---------------------------------------------------------------- optional connectors
def _reason(key):
    db = SessionLocal()
    try:
        return connectors.get(key).configured(db)
    finally:
        db.close()


def _with_terms():
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union")
    db.add(c)
    db.commit()
    db.add(WatchTerm(client_id=c.id, term="riverbendcu.org", kind="domain"))
    db.commit()
    db.close()


def test_telegram_reasons(fresh_db, monkeypatch, tmp_path):
    for k in ("telegram_api_id", "telegram_api_hash", "telegram_channels"):
        monkeypatch.setattr(settings, k, "")
    ok, why = _reason("telegram")
    assert not ok and why == "needs TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_CHANNELS"
    monkeypatch.setattr(settings, "telegram_api_id", "123")
    monkeypatch.setattr(settings, "telegram_api_hash", "hash")
    monkeypatch.setattr(settings, "telegram_channels", "somechannel")
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda n, *a: None if n == "telethon" else real(n, *a))
    assert _reason("telegram") == (False, "telethon is not installed")
    monkeypatch.setattr(importlib.util, "find_spec", lambda n, *a: object() if n == "telethon" else real(n, *a))
    session = tmp_path / "tg.session"
    monkeypatch.setattr(settings, "telegram_session_path", str(session))
    ok, why = _reason("telegram")
    assert not ok and why.startswith(f"missing Telegram session file at {session}") and "telegram_login.py" in why
    session.write_bytes(b"x")
    assert _reason("telegram") == (True, "")


def test_telethon_pinned_in_requirements():
    import os

    req = open(os.path.join(os.path.dirname(__file__), "..", "requirements.txt")).read().splitlines()
    assert any(line.startswith("telethon==") for line in req)


def test_hibp_reason(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "")
    assert _reason("hibp") == (False, "needs HIBP_API_KEY")


def test_pastes_reasons(fresh_db, monkeypatch):
    ok, why = _reason("pastes")
    assert settings.pastes_enabled is False
    assert not ok and why.startswith("PASTES_ENABLED is false") and "psbdmp" in why
    monkeypatch.setattr(settings, "pastes_enabled", True)
    monkeypatch.setattr(settings, "paste_source", "nosuch")
    ok, why = _reason("pastes")
    assert not ok and "PASTE_SOURCE 'nosuch'" in why
    monkeypatch.setattr(settings, "paste_source", "psbdmp")
    assert _reason("pastes") == (False, "no domain, email_domain, brand or keyword watch terms")
    _with_terms()
    assert _reason("pastes") == (True, "paste source: psbdmp paste index")


def test_paste_collector_uses_the_source_interface(fresh_db):
    _with_terms()

    class FakeSource:
        key, name, url = "fake", "fake paste index", "https://paste.example/api"

        def search(self, term):
            return [pastes.PasteHit("p1", "https://paste.example/p1", "", {"time": "2026-10-01"})]

        def fetch(self, hit):
            return "dump: admin@riverbendcu.org:Winter2026!"

    db = SessionLocal()
    out = pastes.run(db, source=FakeSource(), pause=0)
    db.close()
    assert out["ok"] is True and out["terms"] == 1
    db = SessionLocal()
    it = db.query(Item).filter_by(kind="paste").one()
    assert it.external_id == "fake:p1" and db.query(Source).filter_by(kind="paste").one().name == "fake paste index"
    hit = db.query(Hit).one()
    assert hit.reason == "credential"
    db.close()


def test_psbdmp_source_against_mock_transport():
    def handler(req):
        if "/search/" in req.url.path:
            return httpx.Response(200, json={"data": [{"id": "AbC123", "text": "snippet", "time": "t"}]})
        return httpx.Response(200, json={"data": "full dump"})

    src = pastes.PsbdmpSource(transport=httpx.MockTransport(handler))
    hits = src.search("riverbendcu.org")
    assert [h.paste_id for h in hits] == ["AbC123"] and hits[0].url == "https://pastebin.com/AbC123"
    assert src.fetch(hits[0]) == "full dump"
    refusing = pastes.PsbdmpSource(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    with pytest.raises(pastes.SourceRefused):
        refusing.search("x")


def test_forum_reasons(fresh_db, monkeypatch):
    profs = {"_example_forum": {"kind": "forum"}, "leakgroup": {"kind": "leak"}}
    monkeypatch.setattr(connectors.profiles, "all_profiles", lambda: profs)
    assert _reason("forum_crawl") == (False, "no forum profiles configured")
    profs["xss_board"] = {"kind": "forum", "thread_selector": "tr.thread"}
    ok, why = _reason("forum_crawl")
    assert not ok and why.startswith("no forum profiles configured") and "xss_board" in why
    db = SessionLocal()
    db.add(Source(name="XSS", kind="forum", url="http://xss.onion/", profile="xss_board"))
    db.commit()
    db.close()
    assert _reason("forum_crawl") == (True, "1 forum sources")


def test_connectors_page_shows_each_reason(admin, monkeypatch):
    for k in ("telegram_api_id", "telegram_api_hash", "telegram_channels", "hibp_api_key"):
        monkeypatch.setattr(settings, k, "")
    page = admin.get("/connectors").text
    assert "needs HIBP_API_KEY" in page
    assert "needs TELEGRAM_API_ID" in page
    assert "PASTES_ENABLED is false" in page
    assert "no forum profiles configured" in page
