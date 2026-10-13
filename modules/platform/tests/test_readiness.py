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
