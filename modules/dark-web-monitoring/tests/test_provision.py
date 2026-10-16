"""Dark web pulling its roster from the platform, without clobbering its own
onboarding data (watch terms, the IAB profile, case_ref)."""
import httpx
import pytest

from app import provision
from app.config import settings
from app.db import Client, SessionLocal, WatchTerm

ROSTER = {"module": "dark-web-monitoring", "clients": [
    {"id": "plat-rb", "name": "Riverbend Credit Union", "industry": "credit union",
     "portal_domains": "riverbendcu.org", "modules": ["dark-web-monitoring"]},
    {"id": "plat-hp", "name": "Harbor Point Logistics", "industry": "transport",
     "portal_domains": "", "modules": ["dark-web-monitoring"]},
]}


def _transport(roster=ROSTER, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params["module"] == "dark-web-monitoring"
        return httpx.Response(status, json=roster)
    return httpx.MockTransport(handler)


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "platform_url", "https://platform.local")
    monkeypatch.setattr(settings, "platform_token", "ptok")


def test_pull_upserts_and_sets_managed_kind(fresh_db, monkeypatch):
    _configure(monkeypatch)
    summ = provision.pull(SessionLocal(), transport=_transport())
    assert {k: summ[k] for k in ("roster", "added", "updated", "deactivated")} == {"roster": 2, "added": 2, "updated": 0, "deactivated": 0}
    rb = SessionLocal().query(Client).filter_by(platform_client_id="plat-rb").one()
    assert rb.kind == "managed" and rb.portal_enabled and rb.industry == "credit union"


def test_pull_preserves_onboarding_data(fresh_db, monkeypatch):
    _configure(monkeypatch)
    db = SessionLocal()
    c = Client(name="Riverbend Credit Union", case_ref="VCD-IR-2026-781", industry="bank",
               country="USA", revenue_min_musd=200)
    db.add(c); db.commit()
    db.add(WatchTerm(client_id=c.id, term="riverbendcu.org", kind="domain", severity="high")); db.commit()
    provision.pull(SessionLocal(), transport=_transport())
    db = SessionLocal()
    c2 = db.query(Client).filter_by(platform_client_id="plat-rb").one()
    assert c2.id == c.id                       # adopted by name
    assert c2.case_ref == "VCD-IR-2026-781"    # IR ref untouched
    assert c2.industry == "bank" and c2.country == "USA" and c2.revenue_min_musd == 200  # profile untouched
    assert db.query(WatchTerm).filter_by(client_id=c.id).count() == 1  # watch terms kept
    assert c2.portal_domains == "riverbendcu.org"  # platform-owned field updated


def test_pull_deactivates_dropped(fresh_db, monkeypatch):
    _configure(monkeypatch)
    provision.pull(SessionLocal(), transport=_transport())
    summ = provision.pull(SessionLocal(), transport=_transport({"clients": [ROSTER["clients"][0]]}))
    assert summ["deactivated"] == 1
    assert SessionLocal().query(Client).filter_by(platform_client_id="plat-hp").one().active is False


def test_pull_errors_typed(fresh_db, monkeypatch):
    _configure(monkeypatch)
    with pytest.raises(provision.ProvisionError, match="token"):
        provision.pull(SessionLocal(), transport=_transport(status=403))
