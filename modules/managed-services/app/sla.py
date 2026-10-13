"""Service-level clocks for alerts.

Every alert runs two clocks against its client's SLA profile: acknowledge (time to
first human triage) and contain (time to first containment). The clock starts at
received_at. A responder sets acknowledged_at on first triage and contained_at on
first containment, so adherence is measured against when the work actually happened.

This module has no database or request dependency: it takes an alert-like object and
a profile name and returns plain dicts, so the dashboard, the portal and the tests
all read the same numbers.
"""
from __future__ import annotations

import datetime as dt

from .config import DEFAULT_SLA_PROFILE, SLA_PROFILES

# A phase is at risk once the time left falls to a quarter of its target or ten
# minutes, whichever is larger, so a short target still gives a usable warning.
AT_RISK_FRACTION = 0.25
AT_RISK_FLOOR_MINUTES = 10


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def targets(profile: str, severity: str) -> tuple[int | None, int | None]:
    """(acknowledge, contain) targets in minutes for a severity, or (None, None)."""
    prof = SLA_PROFILES.get(profile) or SLA_PROFILES[DEFAULT_SLA_PROFILE]
    return prof.get(severity, (None, None))


def governed(profile: str, severity: str) -> bool:
    """True when this severity carries at least one SLA target under this profile."""
    ack, contain = targets(profile, severity)
    return ack is not None or contain is not None


def _received(alert) -> dt.datetime:
    base = getattr(alert, "received_at", None) or getattr(alert, "synced_at", None) \
        or getattr(alert, "occurred_at", None)
    return base or _utcnow()


def _phase_state(remaining_s: float, target_min: int) -> str:
    if remaining_s <= 0:
        return "breached"
    window_min = max(target_min * AT_RISK_FRACTION, AT_RISK_FLOOR_MINUTES)
    if remaining_s <= window_min * 60:
        return "at_risk"
    return "on_track"


def live_status(alert, profile: str, now: dt.datetime | None = None) -> dict:
    """The governing clock for an open alert: the acknowledge phase until it is
    acknowledged, then the contain phase, then done. Returns phase, state
    (on_track | at_risk | breached | done | none), the deadline and seconds left."""
    now = now or _utcnow()
    sev = getattr(alert, "severity", "medium")
    ack_t, contain_t = targets(profile, sev)
    base = _received(alert)

    # Acknowledge phase.
    if ack_t is not None and getattr(alert, "acknowledged_at", None) is None \
            and getattr(alert, "status", "open") == "open":
        deadline = base + dt.timedelta(minutes=ack_t)
        remaining = (deadline - now).total_seconds()
        return {"phase": "ack", "state": _phase_state(remaining, ack_t),
                "deadline": deadline, "remaining_seconds": remaining, "target_minutes": ack_t}

    # Contain phase.
    if contain_t is not None and getattr(alert, "contained_at", None) is None \
            and getattr(alert, "status", "open") != "resolved":
        deadline = base + dt.timedelta(minutes=contain_t)
        remaining = (deadline - now).total_seconds()
        return {"phase": "contain", "state": _phase_state(remaining, contain_t),
                "deadline": deadline, "remaining_seconds": remaining, "target_minutes": contain_t}

    if not governed(profile, sev):
        return {"phase": "none", "state": "none", "deadline": None,
                "remaining_seconds": None, "target_minutes": None}
    return {"phase": "done", "state": "done", "deadline": None,
            "remaining_seconds": None, "target_minutes": None}


def _phase_adherence(done_at, target_min, base, now) -> tuple[str, float | None]:
    """(result, minutes_taken). result is met | missed | pending | na."""
    if target_min is None:
        return "na", None
    if done_at is not None:
        taken = (done_at - base).total_seconds() / 60.0
        return ("met" if taken <= target_min else "missed"), taken
    # Not yet done: pending while within target, missed once the deadline has passed.
    elapsed = (now - base).total_seconds() / 60.0
    if elapsed > target_min:
        return "missed", None
    return "pending", None


def adherence(alert, profile: str, now: dt.datetime | None = None) -> dict:
    """Did this alert meet its acknowledge and contain SLAs. Used for reporting and
    the client-facing adherence view."""
    now = now or _utcnow()
    sev = getattr(alert, "severity", "medium")
    ack_t, contain_t = targets(profile, sev)
    base = _received(alert)
    closed = getattr(alert, "status", "open") == "resolved"
    ack_done = getattr(alert, "acknowledged_at", None)
    contain_done = getattr(alert, "contained_at", None) or (
        getattr(alert, "updated_at", None) if closed else None)
    ack_res, ack_min = _phase_adherence(ack_done, ack_t, base, now)
    con_res, con_min = _phase_adherence(contain_done, contain_t, base, now)
    results = [r for r in (ack_res, con_res) if r in ("met", "missed")]
    overall = "na"
    if results:
        overall = "met" if all(r == "met" for r in results) else "missed"
    return {"ack": {"result": ack_res, "minutes": ack_min, "target": ack_t},
            "contain": {"result": con_res, "minutes": con_min, "target": contain_t},
            "overall": overall, "governed": governed(profile, sev)}


def summarize(alerts_with_profiles, now: dt.datetime | None = None) -> dict:
    """Roll a list of (alert, profile) into dashboard/portal counts: how many open
    clocks are at risk or breached, and the met-vs-total adherence rate."""
    now = now or _utcnow()
    at_risk = breached = on_track = 0
    met = missed = 0
    for alert, profile in alerts_with_profiles:
        if getattr(alert, "status", "open") != "resolved":
            st = live_status(alert, profile, now)["state"]
            if st == "at_risk":
                at_risk += 1
            elif st == "breached":
                breached += 1
            elif st == "on_track":
                on_track += 1
        ad = adherence(alert, profile, now)["overall"]
        if ad == "met":
            met += 1
        elif ad == "missed":
            missed += 1
    graded = met + missed
    rate = round(100.0 * met / graded, 1) if graded else None
    return {"at_risk": at_risk, "breached": breached, "on_track": on_track,
            "met": met, "missed": missed, "graded": graded, "adherence_rate": rate}


def response_stats(alerts_with_profiles, now: dt.datetime | None = None) -> dict:
    """Median acknowledge and contain times, in minutes, over the alerts where the
    work has actually happened. For the client-facing 'how fast did you respond' line."""
    now = now or _utcnow()
    acks: list[float] = []
    contains: list[float] = []
    for alert, profile in alerts_with_profiles:
        ad = adherence(alert, profile, now)
        if ad["ack"]["minutes"] is not None:
            acks.append(ad["ack"]["minutes"])
        if ad["contain"]["minutes"] is not None:
            contains.append(ad["contain"]["minutes"])

    def _median(xs: list[float]) -> float | None:
        if not xs:
            return None
        xs = sorted(xs)
        n = len(xs)
        mid = n // 2
        return xs[mid] if n % 2 else (xs[mid - 1] + xs[mid]) / 2.0

    return {"ack_median_min": _median(acks), "contain_median_min": _median(contains),
            "ack_count": len(acks), "contain_count": len(contains)}


def mark_acknowledged(alert, when: dt.datetime | None = None) -> None:
    if getattr(alert, "acknowledged_at", None) is None:
        alert.acknowledged_at = when or _utcnow()


def mark_contained(alert, when: dt.datetime | None = None) -> None:
    now = when or _utcnow()
    # Containing implies the alert has been seen, so backfill acknowledge too.
    mark_acknowledged(alert, now)
    if getattr(alert, "contained_at", None) is None:
        alert.contained_at = now


def humanize(seconds: float | None) -> str:
    """A compact duration like '2h 05m' or '8m' or 'overdue 14m' for a clock."""
    if seconds is None:
        return ""
    overdue = seconds < 0
    s = int(abs(seconds))
    h, rem = divmod(s, 3600)
    m, _ = divmod(rem, 60)
    if h:
        label = f"{h}h {m:02d}m"
    else:
        label = f"{m}m"
    return f"overdue {label}" if overdue else label
