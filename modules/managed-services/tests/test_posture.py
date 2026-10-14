"""Pre-incident posture: each risk category fires on the right condition, from data
the module already holds, and the posture page renders."""
import datetime as dt

from app import posture
from app.db import Alert, Client, Device, SessionLocal


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _cats(items):
    return {it["category"] for it in items}


def test_coverage_gap_when_tool_mapped_but_no_devices(fresh_db):
    db = SessionLocal()
    c = Client(name="Gap Co", sentinelone_site_ids="111", huntress_org_id="h1")
    db.add(c); db.commit()
    items = posture.scan(db)
    gaps = [it for it in items if it["category"] == "coverage-gap"]
    assert len(gaps) == 1 and gaps[0]["severity"] == "risk"
    assert "SentinelOne" in gaps[0]["detail"] and "Huntress" in gaps[0]["detail"]


def test_endpoints_dark_offline_and_stale(fresh_db):
    db = SessionLocal()
    c = Client(name="Dark Co", sentinelone_site_ids="111"); db.add(c); db.flush()
    db.add(Device(client_id=c.id, tool="sentinelone", external_id="d1", hostname="OK-01",
                  status="online", last_seen=_now(), synced_at=_now()))
    db.add(Device(client_id=c.id, tool="sentinelone", external_id="d2", hostname="OFF-01",
                  status="offline", last_seen=_now() - dt.timedelta(days=10), synced_at=_now()))
    db.commit()
    items = posture.scan(db)
    dark = [it for it in items if it["category"] == "endpoints-dark"]
    assert len(dark) == 1 and dark[0]["severity"] == "risk"  # 10 days > stale window
    assert "1 of 2" in dark[0]["detail"]


def test_backup_risk_from_open_failure(fresh_db):
    db = SessionLocal()
    c = Client(name="Backup Co", acronis_tenant_id="ac1"); db.add(c); db.flush()
    # a reporting workload so it is not a coverage gap
    db.add(Device(client_id=c.id, tool="acronis", external_id="w1", hostname="FS-01",
                  status="online", last_seen=_now(), synced_at=_now()))
    db.add(Alert(client_id=c.id, tool="acronis", external_id="b1", kind="backup", severity="medium",
                 title="Backup job failed", status="open", received_at=_now()))
    db.commit()
    items = posture.scan(db)
    br = [it for it in items if it["category"] == "backup-risk"]
    assert len(br) == 1 and br[0]["severity"] == "risk"


def test_stale_telemetry_when_sync_is_old(fresh_db):
    db = SessionLocal()
    c = Client(name="Stale Co", sentinelone_site_ids="111"); db.add(c); db.flush()
    db.add(Device(client_id=c.id, tool="sentinelone", external_id="d1", hostname="WS-01",
                  status="online", last_seen=_now(), synced_at=_now() - dt.timedelta(hours=48)))
    db.commit()
    items = posture.scan(db)
    assert "stale-telemetry" in _cats(items)
    # and not a coverage gap, since a device is present
    assert "coverage-gap" not in _cats(items)


def test_isolation_review_after_window(fresh_db):
    db = SessionLocal()
    c = Client(name="Iso Co", sentinelone_site_ids="111"); db.add(c); db.flush()
    db.add(Device(client_id=c.id, tool="sentinelone", external_id="d1", hostname="HR-01",
                  status="isolated", last_seen=_now() - dt.timedelta(hours=48),
                  synced_at=_now() - dt.timedelta(hours=48)))
    db.commit()
    items = posture.scan(db)
    iso = [it for it in items if it["category"] == "isolation-review"]
    assert len(iso) == 1 and "HR-01" in iso[0]["headline"]


def test_healthy_client_has_no_posture_items(fresh_db):
    db = SessionLocal()
    c = Client(name="Healthy Co", sentinelone_site_ids="111"); db.add(c); db.flush()
    db.add(Device(client_id=c.id, tool="sentinelone", external_id="d1", hostname="WS-01",
                  status="online", last_seen=_now(), synced_at=_now()))
    db.commit()
    assert posture.scan(db) == []


def test_summary_and_grouping_and_page(admin):
    db = SessionLocal()
    c = Client(name="Mixed Co", sentinelone_site_ids="111", acronis_tenant_id="ac1"); db.add(c); db.commit()
    items = posture.scan(db)
    s = posture.summarize(items)
    assert s["total"] == len(items) and s["risk"] >= 1
    g = posture.grouped(items)
    assert all(grp["items"] for grp in g)
    page = admin.get("/posture")
    assert page.status_code == 200 and "Pre-incident posture" in page.text
