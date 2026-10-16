"""MARLOW's link to the control plane for its own console access: who may sign in
here and at what level comes from the platform staff roster, exactly as in every
other module. MARLOW does not keep a client roster of its own; it reads the client
directory live through perception."""
from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .config import settings

log = logging.getLogger(__name__)
MODULE_KEY = "marlow"


class ProvisionError(Exception):
    pass


def configured() -> bool:
    return bool(settings.platform_url)


def pull(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
    return pull_staff(db, transport)


def state() -> dict:
    return {"configured": configured(), "token_set": bool(settings.platform_token),
            "interval_seconds": settings.provision_interval_seconds, "staff": staff_state(),
            "last_ok": STAFF["ok"], "last_at": STAFF["at"].isoformat() if STAFF["at"] else None,
            "last_detail": STAFF["detail"]}


def start_scheduler(session_factory) -> None:
    import threading
    import time

    if not configured() or settings.provision_interval_seconds <= 0:
        return

    def _loop():
        time.sleep(5)
        while True:
            db = session_factory()
            try:
                pull(db)
            except Exception as e:  # noqa: BLE001
                log.warning("staff pull failed: %s", e)
            finally:
                db.close()
            time.sleep(settings.provision_interval_seconds)

    threading.Thread(target=_loop, name="platform-pull", daemon=True).start()


# ---------------------------------------------------------------- staff roster
# The control plane is the system of record for Vendetta's own people and their
# access level per module. This module pulls GET /api/platform/staff?module=<key>
# alongside the client roster and mirrors it into its users table (source
# "platform"), and SSO sign-in asks the roster live, so onboarding or deactivating
# someone on the platform takes effect here within seconds.
STAFF: dict = {"governs": None, "count": 0, "at": None, "ok": None, "detail": "never run"}
_STAFF_CACHE: dict = {"at": 0.0, "body": None}


def _staff_fetch(transport: httpx.BaseTransport | None = None, timeout: float = 20.0) -> dict:
    headers = {"Authorization": f"Bearer {settings.platform_token}"} if settings.platform_token else {}
    url = f"{settings.platform_url.rstrip('/')}/api/platform/staff"
    try:
        with httpx.Client(timeout=timeout, transport=transport, headers=headers) as http:
            r = http.get(url, params={"module": MODULE_KEY})
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"platform unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise ProvisionError("platform rejected the token")
    if r.status_code == 404:
        raise ProvisionError("platform has no staff roster (older control plane)")
    if r.status_code != 200:
        raise ProvisionError(f"platform HTTP {r.status_code}")
    return r.json()


def _apply_staff(db: Session, body: dict) -> dict:
    from .db import User

    roster = body.get("staff") or []
    seen = set()
    added = updated = 0
    for entry in roster:
        email = (entry.get("email") or "").strip().lower()
        if not email or entry.get("role") not in ("admin", "analyst"):
            continue
        seen.add(email)
        u = db.query(User).filter_by(email=email).one_or_none()
        if u is None:
            u = User(email=email, source="platform")
            db.add(u)
            added += 1
        else:
            updated += 1
        u.source = "platform"
        u.name = entry.get("name") or u.name
        u.role = entry["role"]
        u.client_id = None
        u.active = True
        cfg = entry.get("config") or {}
        if hasattr(u, "can_act"):
            u.can_act = bool(cfg.get("can_act", True))
        if hasattr(u, "can_approve"):
            u.can_approve = bool(cfg.get("can_approve", False))
    deactivated = 0
    for u in db.query(User).filter(User.source == "platform", User.active.is_(True)).all():
        if u.email not in seen:
            u.active = False
            deactivated += 1
    db.commit()
    return {"staff": len(roster), "staff_added": added, "staff_updated": updated, "staff_deactivated": deactivated}


def pull_staff(db: Session, transport: httpx.BaseTransport | None = None) -> dict:
    """Mirror the staff roster for this module. Raises ProvisionError when the
    control plane cannot be reached; records the outcome either way."""
    import datetime as _dt
    import time as _time

    if not configured():
        raise ProvisionError("PLATFORM_URL not set")
    try:
        body = _staff_fetch(transport)
    except ProvisionError as e:
        STAFF.update(at=_dt.datetime.now(_dt.timezone.utc), ok=False, detail=str(e))
        raise
    summary = _apply_staff(db, body)
    _STAFF_CACHE.update(at=_time.time(), body=body)
    STAFF.update(governs=bool(body.get("governs")), count=summary["staff"],
                 at=_dt.datetime.now(_dt.timezone.utc), ok=True, detail="ok")
    log.info("staff pull: %s", summary)
    return summary


def staff_decision(email: str, db: Session | None = None,
                   transport: httpx.BaseTransport | None = None) -> tuple[str, str, dict]:
    """Who may sign in, asked at SSO time. Returns (verdict, role, config):

    - ("admit", role, config): the platform roster lists this person for this module;
    - ("deny", "", {}): a roster governs and this person is not on it, or is deactivated;
    - ("unknown", "", {}): no control plane, or no roster yet; the module's own
      domain and allowlist rules apply as before.

    Asks the control plane live (cached for a minute) so a change there is honored
    on the next sign-in; if the control plane is unreachable, falls back to the
    mirrored users table so a known person can still get in during an outage."""
    import time as _time

    email = (email or "").strip().lower()
    if not configured():
        return "unknown", "", {}
    body = None
    if _STAFF_CACHE["body"] is not None and _time.time() - _STAFF_CACHE["at"] < 60:
        body = _STAFF_CACHE["body"]
    else:
        try:
            body = _staff_fetch(transport, timeout=6.0)
            _STAFF_CACHE.update(at=_time.time(), body=body)
            if db is not None:
                _apply_staff(db, body)
                STAFF.update(governs=bool(body.get("governs")), count=len(body.get("staff") or []))
        except ProvisionError as e:
            log.warning("staff decision: control plane unavailable (%s); using the mirrored roster", e)
    if body is not None:
        if not body.get("governs"):
            return "unknown", "", {}
        for entry in body.get("staff") or []:
            if (entry.get("email") or "").strip().lower() == email and entry.get("role") in ("admin", "analyst"):
                return "admit", entry["role"], dict(entry.get("config") or {})
        return "deny", "", {}
    # Offline fallback: the mirrored table.
    if db is None:
        return "unknown", "", {}
    from .db import User

    if db.query(User).filter(User.source == "platform").count() == 0:
        return "unknown", "", {}
    u = db.query(User).filter_by(email=email).one_or_none()
    if u and u.active and u.source == "platform":
        cfg = {k: getattr(u, k) for k in ("can_act", "can_approve") if hasattr(u, k)}
        return "admit", u.role, cfg
    return "deny", "", {}


def staff_state() -> dict:
    return {
        "governs": STAFF["governs"],
        "count": STAFF["count"],
        "last_ok": STAFF["ok"],
        "last_at": STAFF["at"].isoformat() if STAFF["at"] else None,
        "last_detail": STAFF["detail"],
    }
