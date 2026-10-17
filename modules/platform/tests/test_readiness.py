"""Go-live readiness aggregation: module manifests plus the control plane roll up
into one checklist, with blocking items (unreachable, disabled, default secret)
separated from hardening items (SSO unverified, derived keys)."""
from types import SimpleNamespace

from app import readiness
from app.config import settings


def _mod(key, status="in-progress", base_url="http://m"):
    return SimpleNamespace(key=key, display_name=key.title(), status=status, base_url=base_url)


def _ready_probe():
    return {"reachable": True, "enabled": True, "readiness": {
        "sso": {"configured": True, "enabled": True, "verified": True, "source": "stored"},
        "keys": {"signing_applicable": True, "signing_dedicated": True, "encryption_dedicated": True},
        "integrations": {"kind": "response-tools", "wired": 2, "total": 3},
    }}


def test_fully_configured_module_has_no_blocking_items(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "a-real-secret")
    monkeypatch.setattr(settings, "encryption_key", "a-real-enc-key")
    m = _mod("managed-services")
    rep = readiness.assess([m], {"managed-services": _ready_probe()})
    mod = rep["modules"][0]
    assert mod["fail"] == 0 and mod["ready"] is True
    # SSO verified and dedicated keys all count as ok, not warn.
    assert all(c["state"] == "ok" for c in mod["checks"])


def test_unreachable_and_disabled_modules_block_go_live(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "a-real-secret")
    down = _mod("down")
    off = _mod("off")
    ov = {"down": {"reachable": False, "detail": "timeout"},
          "off": {"reachable": True, "enabled": False, "readiness": {}}}
    rep = readiness.assess([down, off], ov)
    assert rep["ready"] is False
    by = {r["key"]: r for r in rep["modules"]}
    assert by["down"]["fail"] >= 1
    assert any(c["label"] == "Enabled" and c["state"] == "fail" for c in by["off"]["checks"])


def test_derived_keys_and_unverified_sso_are_hardening_not_blocking(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "a-real-secret")
    monkeypatch.setattr(settings, "encryption_key", "a-real-enc-key")
    probe = {"reachable": True, "enabled": True, "readiness": {
        "sso": {"configured": True, "enabled": True, "verified": False, "source": "stored"},
        "keys": {"signing_applicable": True, "signing_dedicated": False, "encryption_dedicated": False},
        "integrations": {"kind": "manual-entry"}}}
    rep = readiness.assess([_mod("vuln")], {"vuln": probe})
    mod = rep["modules"][0]
    assert mod["fail"] == 0 and mod["warn"] >= 3 and mod["ready"] is True


def test_default_secret_key_blocks_the_control_plane(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "change-me")
    rep = readiness.assess([], {})
    assert rep["control_plane"]["fail"] >= 1
    assert rep["ready"] is False
    assert any(c["label"].startswith("Platform secret") and c["state"] == "fail"
               for c in rep["control_plane"]["checks"])


def test_planned_modules_are_not_graded(monkeypatch):
    monkeypatch.setattr(settings, "secret_key", "a-real-secret")
    rep = readiness.assess([_mod("future", status="planned", base_url="")], {})
    assert rep["modules"] == []


def test_readiness_screen_and_api_render(admin):
    assert admin.get("/readiness").status_code == 200
    body = admin.get("/api/platform/readiness",
                     headers={"Authorization": f"Bearer {__import__('app.auth', fromlist=['api_token']).api_token()}"}).json()
    assert "summary" in body and "control_plane" in body and "modules" in body


def test_office_of_special_projects_is_probed_by_engagements(monkeypatch):
    """The OSP serves engagements rather than findings; the probe reads its count
    from /api/engagements so the readiness screen can mark it reachable."""
    import httpx

    from app import aggregate

    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        if req.url.path == "/api/module":
            return httpx.Response(200, json={"module": "professional-services", "enabled": True, "readiness": {}})
        if req.url.path == "/api/engagements":
            return httpx.Response(200, json=[{"id": "e1", "status": "active"}, {"id": "e2", "status": "scoping"}])
        return httpx.Response(404)
    m = SimpleNamespace(key="professional-services", display_name="Office of Special Projects",
                        status="in-progress", base_url="http://professional-services:8000", api_token="t")
    res = aggregate.probe_module(m, transport=httpx.MockTransport(handler), force=True)
    assert res["reachable"] and res["open"] == 2 and res["critical"] == 0 and res["label"] == "open engagements"
    assert "/api/engagements" in calls
    monkeypatch.setattr(settings, "secret_key", "a-real-secret")
    rep = readiness.assess([m], {"professional-services": res})
    assert any(c["label"] == "Reachable" and c["state"] == "ok" for c in rep["modules"][0]["checks"])


def _cp(label):
    rep = readiness.assess([], {})
    return next((c for c in rep["control_plane"]["checks"] if c["label"] == label), None)


def test_portal_client_without_account_lead_warns(admin):
    from helpers import add_staff, make_client

    assert _cp("Portal clients have an account lead") is None  # no portal clients, nothing to say
    c = make_client(admin, "Alpha", portal_domains="alpha.example", portal_enabled="true")
    chk = _cp("Portal clients have an account lead")
    assert chk["state"] == "warn" and "Alpha" in chk["detail"]
    # a client without the portal on is not graded
    make_client(admin, "Bravo")
    add_staff("dan@vendettacd.io")
    admin.post(f"/clients/{c.id}/edit", data={"active": "true", "portal_domains": "alpha.example",
                                              "account_lead": "dan@vendettacd.io"})
    assert _cp("Portal clients have an account lead")["state"] == "ok"


def test_stale_communication_drafts_warn(admin):
    import datetime as dt

    from app.db import Communication, SessionLocal
    from helpers import bearer, make_client

    c = make_client(admin)
    r = admin.post(f"/api/platform/clients/{c.id}/communications",
                   json={"kind": "outreach", "title": "Fresh", "source_ref": "a"}, headers=bearer())
    assert _cp("Communications drafts")["state"] == "ok"
    db = SessionLocal()
    db.get(Communication, r.json()["id"]).created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=8)
    db.commit()
    chk = _cp("Communications drafts")
    assert chk["state"] == "warn" and "1 draft(s) waiting more than 7 days" in chk["detail"]
    # once a person decides it, the warning clears
    admin.post(f"/clients/{c.id}/communications/{r.json()['id']}/discard")
    assert _cp("Communications drafts")["state"] == "ok"
