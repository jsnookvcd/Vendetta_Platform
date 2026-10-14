"""Cross-client correlation: indicator extraction, and campaigns formed only when
an indicator is seen on two or more distinct clients."""
import datetime as dt

from app import indicators
from app.db import Alert, Client, Indicator, SessionLocal


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _types(found):
    return {(t, v) for t, v, _ in found}


def test_extract_pulls_structured_and_freetext_indicators():
    a = {"title": "Beacon to 203.0.113.9", "severity": "high",
         "detail": "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 seen",
         "raw": {"domain": "evil-c2.net", "indicators": [{"type": "ip", "value": "198.51.100.5"}]}}
    found = _types(indicators.extract(a))
    assert ("ip", "203.0.113.9") in found
    assert ("ip", "198.51.100.5") in found
    assert ("domain", "evil-c2.net") in found
    assert ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in found
    # a signature is always derived from the title, host stripped off
    assert any(t == "signature" for t, _ in found)


def test_private_ips_and_vendor_domains_are_ignored():
    a = {"title": "Internal scan", "detail": "from 192.168.1.10 via sentinelone.net", "raw": {}}
    found = _types(indicators.extract(a))
    assert not any(t == "ip" for t, _ in found)
    assert not any(v == "sentinelone.net" for t, v in found if t == "domain")


def test_signature_normalizes_host_suffix():
    assert indicators._norm_signature("Mimikatz on WS01") == "mimikatz"
    assert indicators._norm_signature("Mimikatz on WS42") == "mimikatz"


def _client(db, name):
    c = Client(name=name); db.add(c); db.flush(); return c


def _alert(db, c, ext, title, sev="high", raw=None, status="open"):
    a = Alert(client_id=c.id, tool="sentinelone", external_id=ext, severity=sev, title=title,
              status=status, received_at=_now(), raw=raw or {})
    db.add(a); db.flush()
    indicators.sync_for_alert(db, a)
    return a


def test_shared_indicator_across_two_clients_is_a_campaign(fresh_db):
    db = SessionLocal()
    c1, c2, c3 = _client(db, "Alpha"), _client(db, "Bravo"), _client(db, "Charlie")
    _alert(db, c1, "a1", "C2 callout", raw={"ip": "203.0.113.50"})
    _alert(db, c2, "a2", "Odd traffic", raw={"ip": "203.0.113.50"})
    _alert(db, c3, "a3", "Unrelated", raw={"ip": "203.0.113.99"})  # only one client
    db.commit()
    camps = indicators.correlate(db)
    ip_camps = [g for g in camps if g["itype"] == "ip"]
    assert len(ip_camps) == 1
    g = ip_camps[0]
    assert g["value"] == "203.0.113.50" and g["n_clients"] == 2
    assert {n for _, n in g["client_list"]} == {"Alpha", "Bravo"}


def test_signature_correlation_across_clients(fresh_db):
    db = SessionLocal()
    c1, c2 = _client(db, "One"), _client(db, "Two")
    _alert(db, c1, "s1", "Mimikatz on WS01", sev="critical")
    _alert(db, c2, "s2", "Mimikatz on SRV9", sev="high")
    db.commit()
    camps = indicators.correlate(db)
    sig = [g for g in camps if g["itype"] == "signature"]
    assert len(sig) == 1
    assert sig[0]["n_clients"] == 2 and sig[0]["severity"] == "critical"  # worst severity wins


def test_single_client_indicator_is_not_a_campaign(fresh_db):
    db = SessionLocal()
    c1 = _client(db, "Solo")
    _alert(db, c1, "x1", "Beacon", raw={"ip": "203.0.113.7"})
    _alert(db, c1, "x2", "Beacon again", raw={"ip": "203.0.113.7"})  # same client twice
    db.commit()
    assert [g for g in indicators.correlate(db) if g["itype"] == "ip"] == []


def test_backfill_and_campaigns_page(admin):
    db = SessionLocal()
    c1 = Client(name="Pine"); c2 = Client(name="Oak"); db.add_all([c1, c2]); db.flush()
    db.add(Alert(client_id=c1.id, tool="crowdstrike", external_id="p1", severity="high",
                 title="Phish kit", status="open", received_at=_now(), raw={"domain": "badlogin-portal.com"}))
    db.add(Alert(client_id=c2.id, tool="huntress", external_id="o1", severity="medium",
                 title="Phish kit", status="open", received_at=_now(), raw={"domain": "badlogin-portal.com"}))
    db.commit()
    n = indicators.backfill(db)
    assert n >= 2 and SessionLocal().query(Indicator).count() > 0
    page = admin.get("/campaigns")
    assert page.status_code == 200 and "badlogin-portal.com" in page.text
    assert "Pine" in page.text and "Oak" in page.text
