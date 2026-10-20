"""Detection runs: pull signals from managed-services, feed the engine from the
database, and apply its plan (open investigations, attach signals, count
suppression hits).

managed-services serves its alerts in the shared finding shape at
GET {MANAGED_SERVICES_URL}/api/findings?status=all with Bearer MANAGED_SERVICES_TOKEN.
MDR keeps its own copy of each signal so an investigation's evidence survives an
alert being resolved or aged out upstream.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import engine as eng
from .config import INGEST_PREFIX, OPEN_STATUSES, SEV_RANK, TOOL_NAMES, settings
from .db import (Client, Counter, Investigation, InvestigationSignal, Rule, RuleOverride, Signal,
                 Suppression, record, utcnow)

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_ADVISORY_KEY = 880_801  # serializes detection runs across workers on one database

LAST: dict = {"at": None, "ok": None, "detail": "never run", "summary": None}


class DetectError(Exception):
    pass


def configured() -> bool:
    return bool(settings.managed_services_url or settings.ingest_url)


def _sources() -> list[tuple[str, str, str]]:
    """(name, base url, token) for every configured signal source."""
    out = []
    if settings.managed_services_url:
        out.append(("managed-services", settings.managed_services_url, settings.managed_services_token))
    if settings.ingest_url:
        out.append(("ingest", settings.ingest_url, settings.ingest_token))
    return out


def _fetch_one(name: str, base: str, token: str, transport: httpx.BaseTransport | None) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers["X-Vendetta-Actor"] = "mdr"
    url = f"{base.rstrip('/')}/api/findings"
    try:
        with httpx.Client(timeout=30.0, transport=transport, headers=headers) as http:
            r = http.get(url, params={"status": "all"})
    except Exception as e:  # noqa: BLE001
        raise DetectError(f"{name} unreachable: {type(e).__name__}") from e
    if r.status_code in (401, 403):
        raise DetectError(f"{name} rejected the token")
    if r.status_code != 200:
        raise DetectError(f"{name} HTTP {r.status_code}")
    body = r.json()
    if isinstance(body, dict):  # tolerate a wrapped list
        body = body.get("findings") or body.get("items") or []
    rows = body if isinstance(body, list) else []
    if name == "ingest":
        rows = [dict(f, id=INGEST_PREFIX + str(f.get("id") or "")) for f in rows if f.get("id")]
    else:
        # Only ingest signals may carry the ingest prefix, so no other source can
        # overwrite one.
        rows = [f for f in rows if not str(f.get("id") or "").startswith(INGEST_PREFIX)]
    # Ids are stored in 64 characters; refuse rather than truncate, because two long
    # ids sharing a prefix would otherwise merge into one signal.
    return [f for f in rows if 0 < len(str(f.get("id") or "")) <= 64]


def fetch_signals(transport: httpx.BaseTransport | None = None) -> list[dict]:
    """Read every finding from every configured source. One source failing does not
    stop the others; DetectError is raised only when every source failed."""
    if not configured():
        raise DetectError("no signal source set (MANAGED_SERVICES_URL or INGEST_URL)")
    rows: list[dict] = []
    errors: list[str] = []
    for name, base, token in _sources():
        try:
            rows.extend(_fetch_one(name, base, token, transport))
        except DetectError as e:
            errors.append(str(e))
            log.warning("signal source %s failed: %s", name, e)
    SOURCE_ERRORS[:] = errors
    if errors and len(errors) == len(_sources()):
        raise DetectError("; ".join(errors))
    return rows


SOURCE_ERRORS: list[str] = []


def _parse_ts(value) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    try:
        v = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)


def upsert_signals(db: Session, rows: list[dict]) -> dict:
    """Store or refresh signals. Returns counts. Signals for a client this module has
    not been provisioned with are kept with no client and never open anything."""
    clients = {c.platform_client_id: c for c in db.execute(
        select(Client).where(Client.platform_client_id != "")).scalars().all()}
    added = updated = unmapped = 0
    for f in rows:
        sid = str(f.get("id") or "").strip()
        if not sid:
            continue
        subject = f.get("subject") or {}
        pid = (subject.get("platform_client_id") or "").strip()
        c = clients.get(pid)
        occurred = _parse_ts(f.get("published_at")) or _parse_ts(f.get("created_at")) or utcnow()
        s = db.get(Signal, sid[:64])
        if s is None:
            s = Signal(id=sid[:64], occurred_at=occurred, first_seen_at=utcnow())
            db.add(s)
            added += 1
        else:
            updated += 1
        s.platform_client_id = pid
        s.client_id = c.id if (c and c.active) else None
        s.client_name = (subject.get("client") or (c.name if c else ""))[:200]
        s.tool = (f.get("reason") or "").lower()[:30]
        s.type = (f.get("type") or "").lower()[:30]
        sev = (f.get("severity") or "low").lower()
        s.severity = sev if sev in SEV_RANK and sev != "info" else "low"
        s.status = (f.get("status") or "new")[:20]
        s.title = (f.get("title") or "")[:600]
        s.host = (f.get("matched") or "")[:255]
        s.url = (f.get("url") or "")[:600]
        s.occurred_at = occurred
        s.copilot = f.get("copilot") if isinstance(f.get("copilot"), dict) else None
        if s.client_id is None:
            unmapped += 1
    db.flush()
    return {"signals": len(rows), "signals_added": added, "signals_updated": updated, "unmapped": unmapped}


def _next_number(db: Session, when: dt.datetime) -> str:
    year = when.year
    row = db.execute(select(Counter).where(Counter.year == year).with_for_update()).scalar_one_or_none()
    if row is None:
        row = Counter(year=year, n=0)
        db.add(row)
        db.flush()
    row.n += 1
    return f"MDR-{year}-{row.n:04d}"


def engine_inputs(db: Session, now: dt.datetime) -> dict:
    lookback = max(int(settings.detect_lookback_minutes or 1440), 1)
    rules = [eng.Rule.from_dict(r.as_dict()) for r in db.execute(select(Rule)).scalars().all()]
    # The engine needs enough history for the widest correlation window.
    widest = max([lookback] + [r.window_minutes for r in rules])
    since = now - dt.timedelta(minutes=widest)
    sigs = db.execute(select(Signal).where(Signal.client_id.isnot(None), Signal.occurred_at >= since)).scalars().all()
    pid_by_client = {c.id: c.platform_client_id for c in db.execute(select(Client)).scalars().all()}
    overrides = [eng.Override(o.rule_key, pid_by_client.get(o.client_id, ""), o.disabled, o.severity or "")
                 for o in db.execute(select(RuleOverride)).scalars().all()]
    sups = [eng.Suppression(s.id, s.platform_client_id, s.tool, s.title_contains, s.host, s.expires_at)
            for s in db.execute(select(Suppression).where(Suppression.expires_at > now)).scalars().all()]
    opens = [eng.OpenInvestigation(i.id, i.rule_key, i.platform_client_id, i.group_key)
             for i in db.execute(select(Investigation).where(Investigation.status.in_(OPEN_STATUSES))).scalars().all()]
    signal_ids = [s.id for s in sigs]
    linked = set()
    if signal_ids:
        linked = {(r, s) for r, s in db.execute(select(InvestigationSignal.rule_key, InvestigationSignal.signal_id)
                                                .where(InvestigationSignal.signal_id.in_(signal_ids))).all()}
    return {
        "signals": [eng.Signal(s.id, s.platform_client_id, s.client_name, s.tool, s.type, s.severity, s.title,
                               s.host, s.occurred_at) for s in sigs],
        "rules": rules, "overrides": overrides, "suppressions": sups, "open_investigations": opens,
        "linked": linked, "already_suppressed": {s.id for s in sigs if s.suppression_id},
        "lookback_minutes": lookback,
    }


def apply_plan(db: Session, plan: eng.Plan, now: dt.datetime) -> list[Investigation]:
    clients = {c.platform_client_id: c for c in db.execute(
        select(Client).where(Client.platform_client_id != "")).scalars().all()}
    opened: list[Investigation] = []
    for sid, sup_id in plan.suppressed.items():
        s = db.get(Signal, sid)
        sup = db.get(Suppression, sup_id)
        if s is not None and sup is not None and not s.suppression_id:
            s.suppression_id = sup.id
            sup.hits = (sup.hits or 0) + 1
    for o in plan.opens:
        c = clients.get(o.platform_client_id)
        if c is None:
            continue
        inv = Investigation(number=_next_number(db, now), client_id=c.id, platform_client_id=o.platform_client_id,
                            title=o.title, severity=o.severity, status="new", verdict="pending",
                            rule_key=o.rule_key, rule_version=o.rule_version, group_key=o.group_key[:255],
                            mitre=o.mitre, host=o.host[:255], first_signal_at=o.first_signal_at,
                            last_signal_at=o.last_signal_at, opened_at=now, response=o.response)
        db.add(inv)
        db.flush()
        for sid in o.signal_ids:
            db.add(InvestigationSignal(investigation_id=inv.id, signal_id=sid, rule_key=o.rule_key, attached_at=now))
        tools = sorted({TOOL_NAMES.get(s.tool, s.tool) for s in (db.get(Signal, x) for x in o.signal_ids) if s})
        record(db, inv, "opened", "mdr:engine",
               f"Rule {o.rule_key} v{o.rule_version} fired on {len(o.signal_ids)} signal(s) from {', '.join(tools)}.",
               {"rule": o.rule_key, "rule_version": o.rule_version, "signals": o.signal_ids,
                "mitre": o.mitre, "severity": o.severity, "group_key": o.group_key}, client_visible=True)
        opened.append(inv)
    for a in plan.attaches:
        inv = db.get(Investigation, a.investigation_id)
        if inv is None:
            continue
        have = {link.signal_id for link in inv.links}
        new = [sid for sid in a.signal_ids if sid not in have]
        if not new:
            continue
        for sid in new:
            db.add(InvestigationSignal(investigation_id=inv.id, signal_id=sid, rule_key=a.rule_key, attached_at=now))
            s = db.get(Signal, sid)
            if s and s.occurred_at > inv.last_signal_at:
                inv.last_signal_at = s.occurred_at
            if s and s.occurred_at < inv.first_signal_at:
                inv.first_signal_at = s.occurred_at
        record(db, inv, "signals_attached", "mdr:engine", f"{len(new)} new signal(s) attached.", {"signals": new})
    return opened


def run(db: Session, transport: httpx.BaseTransport | None = None, *, pull: bool = True,
        now: dt.datetime | None = None) -> dict:
    """One detection run. With pull=False the engine runs over what is already
    stored (used by tests and after a rule edit)."""
    now = now or utcnow()
    with _LOCK:
        try:
            summary: dict = {}
            if pull:
                summary.update(upsert_signals(db, fetch_signals(transport)))
            db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_KEY})
            inputs = engine_inputs(db, now)
            plan = eng.evaluate(inputs.pop("signals"), inputs.pop("rules"), now=now, **inputs)
            opened = apply_plan(db, plan, now)
            db.commit()
        except DetectError as e:
            db.rollback()
            LAST.update(at=utcnow(), ok=False, detail=str(e), summary=None)
            raise
        except Exception as e:  # noqa: BLE001
            db.rollback()
            LAST.update(at=utcnow(), ok=False, detail=f"{type(e).__name__}: {e}", summary=None)
            raise
    summary.update(plan.summary())
    summary["investigations"] = [i.number for i in opened]
    LAST.update(at=utcnow(), ok=True, detail="ok", summary=summary)
    log.info("detection run: %s", summary)
    return summary


def state() -> dict:
    return {
        "configured": configured(),
        "token_set": bool(settings.managed_services_token),
        "ingest_configured": bool(settings.ingest_url),
        "ingest_token_set": bool(settings.ingest_token),
        "source_errors": list(SOURCE_ERRORS),
        "public_url_set": bool(settings.managed_services_public_url),
        "interval_seconds": int(settings.detect_interval_seconds or 0),
        "last_ok": LAST["ok"],
        "last_at": LAST["at"].isoformat() if LAST["at"] else None,
        "last_detail": LAST["detail"],
        "last_summary": LAST["summary"],
    }


def start_scheduler(session_factory) -> None:
    """Run detection on an interval in a daemon thread. Idle when managed-services is
    not configured, the interval is 0, or the module is turned off."""
    import time

    interval = int(settings.detect_interval_seconds or 0)
    if not configured() or interval <= 0:
        return

    def _loop():
        time.sleep(10)
        while True:
            if settings.module_enabled:
                db = session_factory()
                try:
                    run(db)
                except Exception as e:  # noqa: BLE001
                    log.warning("scheduled detection run failed: %s", e)
                finally:
                    db.close()
            time.sleep(interval)

    threading.Thread(target=_loop, name="mdr-detect", daemon=True).start()
