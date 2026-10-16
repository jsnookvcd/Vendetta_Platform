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

    post = r.get("posture") or {}
    if post:
        if post.get("secret_placeholder"):
            checks.append(_chk("Secret key set", "fail", "module is running on a placeholder SECRET_KEY"))
        else:
            checks.append(_chk("Secret key set", "ok"))
        if post.get("admin_login_possible") or s.get("verified"):
            checks.append(_chk("Sign-in possible", "ok",
                               "SSO verified" if s.get("verified") else "local admin password set"))
        else:
            checks.append(_chk("Sign-in possible", "fail",
                               "no ADMIN_PASSWORD_HASH and SSO not verified: nobody can log in"))
        checks.append(_chk("Service token dedicated", "ok" if post.get("api_token_dedicated") else "warn",
                           "" if post.get("api_token_dedicated") else "derived from secret_key; set API_TOKEN"))
        pub = post.get("public_url") or ""
        if pub.startswith("https://") and not post.get("cookie_secure"):
            checks.append(_chk("Secure cookies", "warn", "served over https but COOKIE_SECURE is false"))
        elif pub.startswith("https://"):
            checks.append(_chk("Secure cookies", "ok"))
        if post.get("actions_readonly") is not None:
            checks.append(_chk("Tool actions", "ok" if post["actions_readonly"] else "warn",
                               "read-only: no action can touch a client host" if post["actions_readonly"]
                               else "LIVE: isolate, contain and quarantine will fire against real hosts"))

    plat = r.get("platform") or {}
    if plat:
        if not plat.get("configured"):
            checks.append(_chk("Roster from platform", "fail", "PLATFORM_URL not set; clients will not provision"))
        elif not plat.get("token_set"):
            checks.append(_chk("Roster from platform", "fail", "PLATFORM_TOKEN not set"))
        elif plat.get("last_ok") is True:
            checks.append(_chk("Roster from platform", "ok", f"last pull {plat.get('last_at', '')[:16]}"))
        elif plat.get("last_ok") is False:
            checks.append(_chk("Roster from platform", "fail", f"last pull failed: {plat.get('last_detail')}"))
        else:
            checks.append(_chk("Roster from platform", "warn", "configured, no pull has run yet"))

        st = plat.get("staff") or {}
        if st.get("last_ok") is False:
            checks.append(_chk("Staff roster", "warn", f"last staff pull failed: {st.get('last_detail')}"))
        elif st.get("governs") and not st.get("count"):
            checks.append(_chk("Staff roster", "warn", "roster governs but nobody is granted this module"))
        elif st.get("governs"):
            checks.append(_chk("Staff roster", "ok", f"{st.get('count')} person(s) granted; roster governs sign-in"))

    if module.key != "incident-response" and "hub_configured" in r:
        if r.get("hub_configured") and r.get("hub_token_set"):
            checks.append(_chk("Escalation to IR hub", "ok"))
        elif r.get("hub_configured"):
            checks.append(_chk("Escalation to IR hub", "warn", "PLATFORM_HUB_TOKEN not set; escalations will be refused"))
        else:
            checks.append(_chk("Escalation to IR hub", "warn", "PLATFORM_HUB_URL not set; findings cannot escalate"))

    integ = r.get("integrations") or {}
    if integ.get("kind") == "response-tools":
        n, total = integ.get("wired", 0), integ.get("total", 0)
        checks.append(_chk("Response tools wired", "ok" if n else "warn", f"{n} of {total} connected"))
    elif integ.get("kind") == "agent":
        n = len(integ.get("reach") or [])
        if integ.get("last_cycle_ok") is False:
            checks.append(_chk("SABINE cycle", "warn", f"last cycle failed: {integ.get('last_cycle_detail')}"))
        elif n < 2:
            checks.append(_chk("SABINE reach", "warn", "MODULE_DIRECTORY reaches fewer than two modules"))
        else:
            checks.append(_chk("SABINE reach", "ok", f"{n} modules, narrative: {integ.get('narrative')}"))
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
    if (settings.admin_password_hash or "").strip() or sso.status()["verified"]:
        checks.append(_chk("Sign-in possible", "ok"))
    else:
        checks.append(_chk("Sign-in possible", "fail", "no ADMIN_PASSWORD_HASH and SSO not verified"))
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
    from . import directory

    if directory.env_directory():
        checks.append(_chk("Deployment directory", "ok", f"{len(directory.env_directory())} module(s) rendered"))
    else:
        checks.append(_chk("Deployment directory", "warn", "MODULE_DIRECTORY not set; endpoints entered by hand"))
    failed = [k for k, v in directory.LAST_PUSH.items() if not v.get("ok")]
    if failed:
        checks.append(_chk("Roster push", "warn", f"last push failed for: {', '.join(failed)}"))
    elif directory.LAST_PUSH:
        checks.append(_chk("Roster push", "ok", f"{len(directory.LAST_PUSH)} module(s) reached"))
    from . import staff as staff_mod
    from .db import SessionLocal

    db = SessionLocal()
    try:
        n = len(staff_mod.roster_all(db))
        admins = sum(1 for p in staff_mod.roster_all(db) if p["active"] and p["platform_role"] == "admin")
    finally:
        db.close()
    if n == 0:
        checks.append(_chk("Staff roster", "warn", "nobody onboarded; any internal-domain account signs in as analyst"))
    elif admins == 0:
        checks.append(_chk("Staff roster", "warn", f"{n} onboarded but no active platform admin"))
    else:
        checks.append(_chk("Staff roster", "ok", f"{n} onboarded, {admins} admin(s); roster governs sign-in"))
    checks.append(_chk("Public URL set", "ok" if settings.public_url else "warn",
                       "" if settings.public_url else "PUBLIC_URL unset; modules cannot link back here"))
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
