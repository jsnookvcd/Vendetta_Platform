"""Free sources that need no key: the RansomLook victim feed and onion seeding
fallback, Hudson Rock infostealer exposure, the deepdarkCTI catalog and the
Telegram web preview collector.

No test touches the network. RansomLook is replaced with httpx.MockTransport
serving fixtures built from RansomLook's own API code (website/web/api/
genericapi.py and statsapi.py); Hudson Rock, deepdarkCTI and Telegram are
replaced with callables returning recorded bodies."""
import datetime as dt
import json
from pathlib import Path

import httpx
import pytest

from app import connectors, deepdarkcti, fetch, health, onion_sources, priority
from app import ransomlook as rlook
from app import ransomware_live as rl
from app.collectors import infostealers, leak_feeds, telegram_web
from app.config import settings
from app.db import Client, Hit, Item, SessionLocal, Source, WatchTerm
from app.fetch import FetchResult
from app.pipeline import ingest

FIX = Path(__file__).parent / "fixtures"
AKIRA = "akiraexamplefixtureaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
AKIRA_MIRROR = "akiramirrorfixturecccccccccccccccccccccccccccccccccccccccccc.onion"
AKIRA_DDC = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
MEDUSA = "medusaxko7jxtrojdkxo66j7ck4q5tgktf7uqsqyfry4ebnxlcbkccyd.onion"
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)


def _fx(name):
    return (FIX / name).read_text()


def _db():
    return SessionLocal()


class Upstream:
    def __init__(self):
        self.routes: dict = {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        h = self.routes.get(request.url.path)
        if h is None:
            return httpx.Response(404, json={"message": "not found"})
        if isinstance(h, list):
            h = h.pop(0) if len(h) > 1 else h[0]
        return h(request) if callable(h) else h

    @property
    def paths(self):
        return [r.url.path for r in self.requests]


@pytest.fixture()
def upstream(monkeypatch):
    up = Upstream()
    real = httpx.Client

    def fake_client(use_tor, timeout=None, cookies=""):
        return real(transport=httpx.MockTransport(up), timeout=5)

    monkeypatch.setattr(fetch, "_client", fake_client)
    return up


@pytest.fixture()
def free(monkeypatch):
    """No ransomware.live key, RansomLook on its public default."""
    monkeypatch.setattr(settings, "ransomware_live_api_key", "")
    monkeypatch.setattr(settings, "ransomlook_enabled", True)
    monkeypatch.setattr(settings, "ransomlook_url", "https://www.ransomlook.io")


def _client_with(db, name, terms):
    c = Client(name=name)
    db.add(c)
    db.commit()
    for term, kind in terms:
        db.add(WatchTerm(client_id=c.id, term=term, kind=kind, severity="medium"))
    db.commit()
    return c


def _rl_routes(up):
    up.routes["/api/last/2"] = httpx.Response(200, json=json.loads(_fx("ransomlook_last.json")))
    up.routes["/api/hot/365"] = httpx.Response(200, json=json.loads(_fx("ransomlook_hot.json")))
    up.routes["/api/group/akira"] = httpx.Response(200, json=json.loads(_fx("ransomlook_group_akira.json")))
    up.routes["/api/group/qilin"] = httpx.Response(200, json=[{"meta": None, "locations": []}, []])


# ---------------------------------------------------------------- RansomLook feed
def test_ransomlook_feed_ingests_victims_with_attribution_and_hits(fresh_db, free, upstream):
    _rl_routes(upstream)
    db = _db()
    try:
        c = _client_with(db, "Riverbend Credit Union", [("riverbendcu.org", "domain")])
        out = leak_feeds.run_ransomlook(db)
        assert out["ok"] is True and out["new"] == 2 and out["rows"] == 4 and out["provider"] == "ransomlook.io"
        assert upstream.paths == ["/api/last/2"]
        req = upstream.requests[0]
        assert req.url.host == "www.ransomlook.io" and "Vendetta" in req.headers["User-Agent"]
        assert "authorization" not in req.headers
        items = {i.title: i for i in db.query(Item).filter_by(kind="victim")}
        rb = items["akira: Riverbend Credit Union"]
        assert rb.url == f"http://{AKIRA}/d/riverbend"
        assert rb.meta["attribution"] == rlook.ATTRIBUTION and rb.meta["license"] == "CC-BY-4.0"
        assert rb.published_at == dt.datetime(2026, 10, 24, 18, 2, 11, 412907, tzinfo=dt.timezone.utc)
        assert items["qilin: Contoso Manufacturing"].url == ""  # relative link is not a post URL
        hit = db.query(Hit).filter_by(client_id=c.id).one()
        assert hit.item_id == rb.id and hit.severity == "high"
        src = db.query(Source).filter_by(kind="feed", url="https://www.ransomlook.io/api/last").one()
        assert src.last_ok is not None and src.meta["provider"] == "ransomlook.io"
        # A second run stores nothing new and calls once more.
        assert leak_feeds.run_ransomlook(db)["new"] == 0
    finally:
        db.close()


def test_ransomlook_and_ransomware_live_dedupe_the_same_victim(fresh_db, free, upstream):
    _rl_routes(upstream)
    db = _db()
    try:
        src = Source(name="ransomware.live recent victims", kind="feed",
                     url="https://api-pro.ransomware.live/victims/recent")
        db.add(src)
        db.commit()
        leak_feeds.ingest_victim(db, {"victim": "Riverbend Credit Union", "group": "Akira"}, src)
        out = leak_feeds.run_ransomlook(db)
        assert out["new"] == 1  # only Contoso is new
        assert db.query(Item).filter_by(kind="victim").count() == 2
    finally:
        db.close()


def test_ransomlook_client_errors(fresh_db, free, upstream):
    waits = []
    upstream.routes["/api/last/2"] = [httpx.Response(429, headers={"retry-after": "7"}),
                                      httpx.Response(200, json=[])]
    assert rlook.Client(sleep=waits.append).last_posts(2) == [] and waits == [7.0]
    upstream.routes["/api/last/3"] = httpx.Response(429)
    with pytest.raises(rlook.RateLimited):
        rlook.Client(sleep=lambda s: None).last_posts(3)
    upstream.routes["/api/last/4"] = httpx.Response(403)
    with pytest.raises(rl.AuthError):  # seeding catches the ransomware.live classes
        rlook.Client().last_posts(4)
    upstream.routes["/api/last/5"] = httpx.Response(200, json={"posts": []})
    with pytest.raises(rlook.SchemaDrift):
        rlook.Client().last_posts(5)
    upstream.routes["/api/last/6"] = httpx.Response(200, json=[{"title": "x"}])
    with pytest.raises(rlook.SchemaDrift):
        rlook.Client().last_posts(6)
    upstream.routes["/api/last/7"] = httpx.Response(200, content=b"[" + b'{"post_title":"x"},' * 5000 + b"{}]")
    with pytest.raises(rlook.TooLarge):
        rlook.Client(max_bytes=1000).last_posts(7)
    db = _db()
    try:
        upstream.routes["/api/last/2"] = httpx.Response(500)
        out = leak_feeds.run_ransomlook(db)
        assert out["ok"] is False and "HTTP 500" in out["error"]
    finally:
        db.close()


def test_ransomlook_off_never_calls(fresh_db, free, upstream, monkeypatch):
    monkeypatch.setattr(settings, "ransomlook_enabled", False)
    db = _db()
    try:
        assert leak_feeds.run_ransomlook(db)["ok"] is False
        ok, reason = connectors.get("ransomlook").configured(db)
        assert ok is False and "RANSOMLOOK_ENABLED=false" in reason
        assert onion_sources.seed(db)["ok"] is False
        assert connectors.get("ransomlook").probes() == []
    finally:
        db.close()
    assert upstream.requests == []


def test_self_hosted_instance_label_and_key(fresh_db, free, upstream, monkeypatch):
    monkeypatch.setattr(settings, "ransomlook_url", "http://ransomlook:8000/")
    monkeypatch.setattr(settings, "ransomlook_api_key", "PRIVATE-INSTANCE-KEY")
    upstream.routes["/api/last/2"] = httpx.Response(200, json=json.loads(_fx("ransomlook_last.json")))
    db = _db()
    try:
        out = leak_feeds.run_ransomlook(db)
        assert out["ok"] and out["provider"] == "ransomlook (self-hosted)"
        assert upstream.requests[0].url.host == "ransomlook"  # internal address allowed: operator config
        assert upstream.requests[0].headers["authorization"] == "PRIVATE-INSTANCE-KEY"
        ok, reason = connectors.get("ransomlook").configured(db)
        assert ok and "self-hosted instance at http://ransomlook:8000" in reason
        item = db.query(Item).filter_by(kind="victim").first()
        assert item.meta["provider"] == "ransomlook (self-hosted)" and "PRIVATE" not in json.dumps(item.meta)
    finally:
        db.close()


# ---------------------------------------------------------------- seeding fallback
def test_seeding_without_pro_key_uses_ransomlook(fresh_db, free, upstream):
    _rl_routes(upstream)
    db = _db()
    try:
        out = onion_sources.seed(db, now=NOW, sleep=lambda s: None)
        assert out["ok"] is True and out["provider"] == "ransomlook.io"
        assert upstream.paths[0] == "/api/hot/365"
        assert sorted(upstream.paths[1:]) == ["/api/group/akira", "/api/group/qilin"]
        srcs = {onion_sources.fqdn_of(s.url): s for s in db.query(Source).filter_by(kind="onion")}
        assert set(srcs) == {AKIRA, AKIRA_MIRROR}  # chat portal and clearnet mirror skipped
        live = srcs[AKIRA]
        assert live.enabled and live.group_name == "akira"
        assert live.meta["seeded_from"] == "ransomlook.io" and live.meta["license"] == "CC-BY-4.0"
        assert live.meta["group_lastseen"].startswith("2026-10-24")
        assert "screen" not in live.meta and "source" not in live.meta  # base64 never stored
        assert srcs[AKIRA_MIRROR].enabled is False
        assert srcs[AKIRA_MIRROR].meta["disabled"]["code"] == "unavailable"
        assert "ransomlook.io lists" in srcs[AKIRA_MIRROR].meta["disabled"]["detail"]
    finally:
        db.close()


def test_pro_key_still_wins_for_seeding(fresh_db, free, upstream, monkeypatch):
    monkeypatch.setattr(settings, "ransomware_live_api_key", "SECRET-PRO-KEY")
    upstream.routes["/groups"] = httpx.Response(200, json={"groups": []})
    db = _db()
    try:
        out = onion_sources.seed(db, now=NOW, sleep=lambda s: None)
        assert out["provider"] == "ransomware.live" and upstream.paths == ["/groups"]
        ok, reason = connectors.get("ransomware_live").configured(db)
        assert ok and reason == ""
    finally:
        db.close()


def test_ransomware_live_reason_mentions_fallback(fresh_db, free):
    db = _db()
    try:
        ok, reason = connectors.get("ransomware_live").configured(db)
        assert ok is False and "free PRO key from my.ransomware.live" in reason and "RansomLook covers" in reason
    finally:
        db.close()


def test_priority_counts_ransomlook_victims(fresh_db, free, upstream):
    _rl_routes(upstream)
    db = _db()
    try:
        leak_feeds.run_ransomlook(db)
        out = priority.compute(db, now=NOW)
        assert out["victims_considered"] == 2
    finally:
        db.close()


# ---------------------------------------------------------------- infostealers
def _hr(payload):
    calls = []

    def get_json(url):
        calls.append(url)
        if isinstance(payload, Exception):
            raise payload
        return payload(url) if callable(payload) else payload

    return get_json, calls


def test_infostealer_exposure_raises_a_credential_hit(fresh_db):
    db = _db()
    try:
        c = _client_with(db, "Riverbend Credit Union", [("riverbendcu.org", "domain"), ("RiverbendCU.org", "email_domain")])
        other = _client_with(db, "Email Only Co", [("emailonly.example", "email_domain")])
        get_json, calls = _hr(lambda url: json.loads(_fx("hudsonrock_domain.json")) if "riverbend" in url
                              else {"total": 0, "employees": 0, "users": 0, "third_parties": 0, "data": {}})
        out = infostealers.run(db, get_json=get_json, sleep=lambda s: None, now=NOW)
        assert out == {"ok": True, "domains_due": 2, "checked": 2, "exposed": 1, "new": 1}
        assert calls == [infostealers.domain_url("emailonly.example"), infostealers.domain_url("riverbendcu.org")]
        item = db.query(Item).filter_by(kind="stealer").one()
        assert "4 employee and 23 user machines" in item.title
        assert "riverbendcu.org" in item.body and "vpn.riverbendcu.org" in item.body
        assert "•" not in item.body and item.meta["counts"]["total"] == 27
        assert item.meta["employee_urls"] == [{"url": "https://vpn.riverbendcu.org/remote/login", "occurrence": 3}]
        hits = db.query(Hit).filter_by(client_id=c.id).all()
        assert {h.reason for h in hits} == {"credential"} and {h.severity for h in hits} == {"high"}
        assert len(hits) == 2  # domain and email_domain terms both match
        assert db.query(Hit).filter_by(client_id=other.id).count() == 0
        # Inside the recheck window nothing is asked again.
        get2, calls2 = _hr(lambda url: json.loads(_fx("hudsonrock_domain.json")) if "riverbend" in url
                           else {"total": 0, "employees": 0})
        assert infostealers.run(db, get_json=get2, sleep=lambda s: None, now=NOW + dt.timedelta(hours=2))["domains_due"] == 0
        assert calls2 == []
        # A day later the same counts store nothing new; changed counts do.
        later = NOW + dt.timedelta(hours=25)
        assert infostealers.run(db, get_json=get2, sleep=lambda s: None, now=later)["new"] == 0
        grown = json.loads(_fx("hudsonrock_domain.json")) | {"total": 30, "employees": 6}
        get3, _ = _hr(lambda url: grown if "riverbend" in url else {"total": 0})
        assert infostealers.run(db, get_json=get3, sleep=lambda s: None,
                                now=later + dt.timedelta(hours=25))["new"] == 1
        assert health.get_state(db, "infostealers:riverbendcu.org")["employees"] == 6
    finally:
        db.close()


def test_infostealer_rate_limit_stops_the_run_and_drift_is_reported(fresh_db):
    db = _db()
    try:
        _client_with(db, "A", [("a-example.com", "domain")])
        _client_with(db, "B", [("b-example.com", "domain")])
        get_json, calls = _hr(httpx.HTTPError("https://cavalier...: HTTP 429"))
        out = infostealers.run(db, get_json=get_json, sleep=lambda s: None, now=NOW)
        assert out["ok"] is False and len(calls) == 1 and "HTTP 429" in out["error"]
        assert health.get_state(db, "infostealers:a-example.com") is None  # retried next run
        get2, _ = _hr({"unexpected": True})
        out = infostealers.run(db, get_json=get2, sleep=lambda s: None, now=NOW)
        assert out["ok"] is False and "schema changed" in out["error"]
    finally:
        db.close()


def test_infostealer_connector_status(fresh_db, monkeypatch):
    db = _db()
    try:
        ok, reason = connectors.get("infostealers").configured(db)
        assert ok is False and reason == "no domain or email_domain watch terms"
        _client_with(db, "A", [("a-example.com", "domain")])
        assert connectors.get("infostealers").configured(db)[0] is True
        monkeypatch.setattr(settings, "infostealers_enabled", False)
        assert connectors.get("infostealers").configured(db)[0] is False
        assert infostealers.run(db)["ok"] is False
    finally:
        db.close()


# ---------------------------------------------------------------- deepdarkCTI
def _ddc_get(overrides=None):
    files = {
        "ransomware_gang.md": _fx("deepdarkcti_ransomware_gang.md"),
        "telegram_threat_actors.md": _fx("deepdarkcti_telegram_threat_actors.md"),
        "telegram_infostealer.md": _fx("deepdarkcti_telegram_infostealer.md"),
    }
    files.update(overrides or {})
    calls = []

    def get(url):
        calls.append(url)
        body = files.get(url.rsplit("/", 1)[1])
        if body is None:
            return FetchResult(url=url, status=404, content=b"", headers={}, text="")
        return FetchResult(url=url, status=200, content=body.encode(), headers={}, text=body)

    return get, calls


def test_deepdarkcti_parsers():
    sites = deepdarkcti.parse_ransomware(_fx("deepdarkcti_ransomware_gang.md"))
    assert [(s["group"], s["host"]) for s in sites] == [("Akira", AKIRA_DDC), ("Medusa", MEDUSA)]
    tg = deepdarkcti.parse_telegram(_fx("deepdarkcti_telegram_threat_actors.md"), "ta")
    assert [c["channel"] for c in tg] == ["leakbase_official", "initialaccess_hub"]


def test_deepdarkcti_seeds_onions_and_telegram_catalog(fresh_db):
    db = _db()
    try:
        feed = Source(name="RansomLook recent posts", kind="feed", url="https://www.ransomlook.io/api/last")
        db.add(feed)
        db.commit()
        ingest(db, kind="victim", title="akira: x", body="x", group_name="akira", source=feed,
               published_at=NOW - dt.timedelta(days=3), hash_parts=("victim", "akira", "x"))
        manual = Source(name="medusa", kind="onion", url=f"http://{MEDUSA}/", group_name="medusa", enabled=False,
                        meta={"seeded_from": "manual"})
        db.add(manual)
        db.commit()
        get, calls = _ddc_get()
        out = deepdarkcti.run(db, get=get, now=NOW)
        assert out["ok"] and out["onion_listed"] == 2 and out["onion_added"] == 1 and out["telegram_channels"] == 3
        assert calls[0] == "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
        akira = db.query(Source).filter_by(kind="onion", group_name="Akira").one()
        assert akira.enabled and akira.meta["seeded_from"] == "deepdarkcti"
        assert akira.meta["attribution"].startswith("deepdarkCTI")
        db.refresh(manual)
        assert manual.enabled is False and manual.meta["seeded_from"] == "manual"  # a person's choice wins
        cat = deepdarkcti.telegram_catalog(db)
        assert sorted(c["channel"].lower() for c in cat) == ["cloudlogs_free", "initialaccess_hub", "leakbase_official"]
        row = next(r for r in connectors.status(db) if r["key"] == "deepdarkcti")
        assert row["catalog"]["onion_listed"] == 2 and row["catalog"]["telegram_channels"] == 3
    finally:
        db.close()


def test_deepdarkcti_inactive_groups_start_disabled_then_enable(fresh_db):
    db = _db()
    try:
        get, _ = _ddc_get()
        deepdarkcti.run(db, get=get, now=NOW)
        medusa = db.query(Source).filter_by(kind="onion", group_name="Medusa").one()
        assert medusa.enabled is False and medusa.meta["disabled"]["code"] == "inactive"
        feed = Source(name="f", kind="feed", url="https://www.ransomlook.io/api/last")
        db.add(feed)
        db.commit()
        ingest(db, kind="victim", title="medusa: y", body="y", group_name="medusa", source=feed,
               published_at=NOW, hash_parts=("victim", "medusa", "y"))
        out = deepdarkcti.run(db, get=get, now=NOW + dt.timedelta(days=1))
        assert out["onion_enabled"] == 1
        db.refresh(medusa)
        assert medusa.enabled is True and "disabled" not in medusa.meta
    finally:
        db.close()


def test_deepdarkcti_partial_failure_keeps_previous_catalog(fresh_db):
    db = _db()
    try:
        get, _ = _ddc_get()
        deepdarkcti.run(db, get=get, now=NOW)
        get_bad, _ = _ddc_get({"telegram_threat_actors.md": None, "telegram_infostealer.md": None})
        out = deepdarkcti.run(db, get=get_bad, now=NOW)
        assert out["ok"] is True and "telegram_threat_actors.md" in out["error"]
        assert len(deepdarkcti.telegram_catalog(db)) == 3
    finally:
        db.close()


# ---------------------------------------------------------------- Telegram web preview
def _tg_get(html, status=200):
    calls = []

    def get(url):
        calls.append(url)
        return FetchResult(url=url, status=status, content=html.encode(), headers={}, text=html)

    return get, calls


def test_telegram_preview_parse():
    posts = telegram_web.parse(_fx("telegram_web_preview.html"), "leakbase_official")
    assert [p["id"] for p in posts] == [101, 102, 103]
    assert posts[1]["text"] == "" and "Selling VPN access" in posts[2]["text"]
    assert posts[2]["published"] == dt.datetime(2026, 10, 24, 21, 30, tzinfo=dt.timezone.utc)
    with pytest.raises(ValueError):
        telegram_web.parse("<html><body><p>Something else</p></body></html>", "x")
    assert telegram_web.parse('<div class="tgme_channel_info"></div>', "x") == []


def test_telegram_web_ingests_new_posts_once_and_redacts(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_channels", "@leakbase_official, https://t.me/s/bad name, x")
    monkeypatch.setattr(settings, "telegram_web_use_catalog", False)
    db = _db()
    try:
        c = _client_with(db, "Riverbend Credit Union", [("riverbendcu.org", "domain")])
        src = Source(name="Telegram @leakbase_official", kind="telegram", url="https://t.me/leakbase_official",
                     meta={"last_message_id": 101})
        db.add(src)
        db.commit()
        get, calls = _tg_get(_fx("telegram_web_preview.html"))
        out = telegram_web.run(db, get=get)
        assert calls == ["https://t.me/s/leakbase_official"]
        assert out["ok"] and out["new"] == 1 and out["channels"] == 1
        item = db.query(Item).filter_by(kind="message").one()
        assert item.external_id == "tg:leakbase_official:103" and item.url == "https://t.me/leakbase_official/103"
        assert "Summer2026!" not in item.body and "admin@riverbendcu.org" in item.body
        assert item.content_hash == Item.make_hash("tg", "leakbase_official", "103")  # same as telethon
        hit = db.query(Hit).filter_by(client_id=c.id).one()
        assert hit.reason == "credential"
        db.refresh(src)
        assert src.meta["last_message_id"] == 103 and src.last_ok is not None
        assert telegram_web.run(db, get=get)["new"] == 0
    finally:
        db.close()


def test_telegram_web_reports_layout_change_and_http_errors(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_channels", "chan_one,chan_two")
    monkeypatch.setattr(settings, "telegram_web_use_catalog", False)
    db = _db()
    try:
        get, _ = _tg_get("<html><body>Please open Telegram to view this post</body></html>")
        out = telegram_web.run(db, get=get)
        assert out["ok"] is False and "layout changed" in out["error"]
        get2, _ = _tg_get("", status=302)
        out = telegram_web.run(db, get=get2)
        assert out["ok"] is False and "HTTP 302" in out["error"]
    finally:
        db.close()


def test_telegram_web_rotates_through_the_catalog(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_channels", "mine_first")
    monkeypatch.setattr(settings, "telegram_web_max_channels_per_run", 3)
    db = _db()
    try:
        health.set_state(db, deepdarkcti.STATE_TELEGRAM, {"channels": [
            {"channel": n} for n in ("cat_aaaa", "cat_bbbb", "cat_cccc", "Mine_First", "bad name")]})
        get, calls = _tg_get('<div class="tgme_channel_info"></div>')
        telegram_web.run(db, get=get)
        assert calls == ["https://t.me/s/mine_first", "https://t.me/s/cat_aaaa", "https://t.me/s/cat_bbbb"]
        calls.clear()
        telegram_web.run(db, get=get)
        assert calls == ["https://t.me/s/mine_first", "https://t.me/s/cat_cccc", "https://t.me/s/cat_aaaa"]
        ok, reason = connectors.get("telegram_web").configured(db)
        assert ok and "1 configured and 3 catalog channels" in reason  # duplicate and invalid names dropped
    finally:
        db.close()


def test_telegram_web_with_no_channels(fresh_db, monkeypatch):
    monkeypatch.setattr(settings, "telegram_channels", "")
    db = _db()
    try:
        assert connectors.get("telegram_web").configured(db)[0] is False
        assert telegram_web.run(db, get=lambda u: pytest.fail("no fetch expected"))["channels"] == 0
    finally:
        db.close()


# ---------------------------------------------------------------- console
def test_connectors_page_lists_free_sources(admin, free):
    r = admin.get("/connectors")
    assert r.status_code == 200
    for name in ("RansomLook victims", "Infostealer exposure (Hudson Rock)", "deepdarkCTI catalog",
                 "Telegram public channels (web preview)"):
        assert name in r.text
    assert "CC BY 4.0" in r.text
