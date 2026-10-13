"""Go-live readiness: one checklist that rolls up every module's self-reported
readiness (from its /api/module manifest, captured by the probe) together with the
control plane's own posture. An operator reads this one screen before flipping a
client live instead of checking each module by hand.

Each check has a state: ok (ready), warn (works, but hardening recommended before
production) or fail (blocks go-live). A module or the platform is "ready" when it
has no fails. SSO must be verified (tested), not merely saved, to count as ok.
"""
from __future__ import annotations

import datetime as dt

from .config import settings
from . import sso


def _chk(label: str, state: str, detail: str = "") -> dict:
    return {"label": label, "state": state, "detail": detail}


def _module_checks(module, probe: dict) -> list[dict]:
    checks: list[dict] = []
    if not module.base_url:
        checks.append(_chk("Reachable", "fail", "no base URL registered"))
        return checks
    if not probe.get("reachable"):
        checks.append(_chk("Reachable", "fail", probe.get("detail") or "no response"))
        return checks
    checks.append(_chk("Reachable", "ok", "manifest responding"))

    if probe.get("enabled") is False:
        checks.append(_chk("Enabled", "fail", "module reports disabled"))
    else:
        checks.append(_chk("Enabled", "ok"))

    r = probe.get("readiness") or {}
    s = r.get("sso") or {}
    if s.get("verified"):
        checks.append(_chk("SSO verified", "ok", f"source: {s.get('source', '?')}"))
    elif s.get("configured"):
        checks.append(_chk("SSO verified", "warn", "configured but last test did not pass"))
    else:
        checks.append(_chk("SSO verified", "warn", "not configured"))

    keys = r.get("keys") or {}
    if keys.get("signing_applicable"):
        checks.append(_chk("Signing key dedicated", "ok" if keys.get("signing_dedicated") else "warn",
                           "" if keys.get("signing_dedicated") else "derived from secret_key; set a dedicated key"))
    checks.append(_chk("Encryption key dedicated", "ok" if keys.get("encryption_dedicated") else "warn",
                       "" if keys.get("encryption_dedicated") else "derived from secret_key; set a dedicated key"))

    integ = r.get("integrations") or {}
    if integ.get("kind") == "response-tools":
        n, total = integ.get("wired", 0), integ.get("total", 0)
        checks.append(_chk("Response tools wired", "ok" if n else "warn", f"{n} of {total} connected"))
    elif integ.get("kind"):
        checks.append(_chk("Integrations", "ok", integ.get("kind").replace("-", " ")))
    return checks


def _control_plane_checks(modules, ov) -> list[dict]:
    checks: list[dict] = []
    checks.append(_chk("Platform secret key set", "fail" if settings.secret_key == "change-me" else "ok",
                       "still the default 'change-me'" if settings.secret_key == "change-me" else ""))
    enc = bool((getattr(settings, "encryption_key", "") or "").strip())
    checks.append(_chk("Token encryption key dedicated", "ok" if enc else "warn",
                       "" if enc else "derived from secret_key; set ENCRYPTION_KEY"))
    st = sso.status()
    if st["verified"]:
        checks.append(_chk("Platform SSO verified", "ok", f"source: {st['source']}"))
    elif st["configured"]:
        checks.append(_chk("Platform SSO verified", "warn", "configured but last test did not pass"))
    else:
        checks.append(_chk("Platform SSO verified", "warn", "not configured"))

    live = [m for m in modules if m.status in ("production", "in-progress")]
    missing = [m.display_name for m in live if not m.base_url]
    if missing:
        checks.append(_chk("Live modules registered", "warn",
                           f"{len(missing)} without a base URL: {', '.join(missing)}"))
    else:
        checks.append(_chk("Live modules registered", "ok", f"{len(live)} active modules"))
    return checks


def _score(checks: list[dict]) -> tuple[int, int, int]:
    ok = sum(1 for c in checks if c["state"] == "ok")
    warn = sum(1 for c in checks if c["state"] == "warn")
    fail = sum(1 for c in checks if c["state"] == "fail")
    return ok, warn, fail


def assess(modules, ov: dict) -> dict:
    """Build the full readiness report from the module list and the probe overview."""
    mod_reports = []
    all_checks: list[dict] = []
    for m in modules:
        if m.status == "planned":
            continue
        checks = _module_checks(m, ov.get(m.key, {}))
        ok, warn, fail = _score(checks)
        mod_reports.append({
            "key": m.key, "display_name": m.display_name, "status": m.status,
            "checks": checks, "ok": ok, "warn": warn, "fail": fail,
            "ready": fail == 0,
        })
        all_checks += checks

    cp_checks = _control_plane_checks(modules, ov)
    cp_ok, cp_warn, cp_fail = _score(cp_checks)
    all_checks += cp_checks

    ok, warn, fail = _score(all_checks)
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc),
        "ready": fail == 0,
        "summary": {"ok": ok, "warn": warn, "fail": fail,
                    "modules_ready": sum(1 for r in mod_reports if r["ready"]),
                    "modules_total": len(mod_reports)},
        "control_plane": {"checks": cp_checks, "ok": cp_ok, "warn": cp_warn, "fail": cp_fail,
                          "ready": cp_fail == 0},
        "modules": mod_reports,
    }
