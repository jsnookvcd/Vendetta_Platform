"""Mean Time to Trusted Action: how SABINE measures herself, from the ledger.

For a rolling window (7 and 30 days) the ledger's proposal, decision and action
rows give:

- auto and human latency: proposal raised to action carried out, median and
  p90, split by whether the action was automatic or a person approved it;
- proposals decided, and the approval rate among them;
- the autonomous share: the fraction of proposals raised in the window that
  SABINE closed herself, with no person involved.

A posture review or outreach email SABINE drafts on the platform is an automatic
action whose result is marked draft: a person still approves it before anything
reaches the client, so it is counted as drafted and left out of the automatic
latency and the autonomous share.

compute() is a pure function over ledger rows so it can be tested with
synthetic data; get() reads the ledger and caches the answer for a minute.
"""
from __future__ import annotations

import datetime as dt
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

WINDOWS = (7, 30)
_CACHE: dict = {"at": 0.0, "value": None}
_LOCK = threading.Lock()


def _pct(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile; None for no values."""
    if not values:
        return None
    xs = sorted(values)
    k = max(0, min(len(xs) - 1, int(round(q * len(xs) + 0.5)) - 1))
    return round(xs[k], 1)


def _ok(row: dict) -> bool:
    return bool(((row.get("detail") or {}).get("result") or {}).get("ok"))


def compute(rows: list[dict], now: dt.datetime | None = None, windows: tuple[int, ...] = WINDOWS) -> dict:
    """rows: [{at, kind, ref, summary, detail}] in any order. Returns
    {"windows": {days: {...}}, "computed_at": iso}."""
    now = now or dt.datetime.now(dt.timezone.utc)
    raised_at: dict[str, dt.datetime] = {}
    for r in rows:
        if r.get("kind") == "proposal" and r.get("ref"):
            raised_at.setdefault(r["ref"], r["at"])
    out = {}
    for days in windows:
        since = now - dt.timedelta(days=days)
        raised = sum(1 for r in rows if r.get("kind") == "proposal" and r["at"] >= since)
        auto, human = [], []
        auto_n = human_n = drafted = 0
        for r in rows:
            if r.get("kind") != "action" or r["at"] < since:
                continue
            how = (r.get("detail") or {}).get("autonomy")
            if how == "auto":
                auto_n += 1
            elif how == "approved":
                human_n += 1
            else:
                continue
            if not _ok(r) or r.get("ref") not in raised_at:
                continue
            if how == "auto" and ((r.get("detail") or {}).get("result") or {}).get("draft"):
                # A draft posted for a person to approve on the platform is not a
                # trusted action carried out: it neither times nor counts as closed.
                drafted += 1
                continue
            lat = (r["at"] - raised_at[r["ref"]]).total_seconds()
            (auto if how == "auto" else human).append(max(0.0, lat))
        approved = sum(1 for r in rows if r.get("kind") == "decision" and r["at"] >= since and (r.get("summary") or "").startswith("approved: "))
        rejected = sum(1 for r in rows if r.get("kind") == "decision" and r["at"] >= since and (r.get("summary") or "").startswith("rejected: "))
        decided = approved + rejected
        out[days] = {
            "days": days, "proposals_raised": raised,
            "auto": {"n": auto_n, "ok": len(auto), "median_s": _pct(auto, 0.5), "p90_s": _pct(auto, 0.9)},
            "human": {"n": human_n, "ok": len(human), "median_s": _pct(human, 0.5), "p90_s": _pct(human, 0.9)},
            "drafted": drafted,
            "decided": decided, "approved": approved, "rejected": rejected,
            "approval_rate": round(approved / decided, 3) if decided else None,
            "autonomous_share": round(min(1.0, len(auto) / raised), 3) if raised else None,
        }
    return {"windows": out, "computed_at": now.isoformat()}


def rows_from_ledger(db: Session, days: int = max(WINDOWS)) -> list[dict]:
    """Ledger rows that matter, reaching back past the window by the proposal
    TTL so an action late in its life still finds the row that raised it."""
    from .config import settings
    from .db import Ledger, utcnow

    since = utcnow() - dt.timedelta(days=days, hours=settings.proposal_ttl_hours)
    q = select(Ledger).where(Ledger.at >= since, Ledger.kind.in_(("proposal", "decision", "action"))).order_by(Ledger.chain_seq)
    return [{"at": r.at, "kind": r.kind, "ref": r.ref, "summary": r.summary, "detail": r.detail or {}}
            for r in db.execute(q).scalars().all()]


def get(db: Session, ttl: float = 60.0) -> dict:
    """The current metrics, cached for ttl seconds across callers."""
    with _LOCK:
        if _CACHE["value"] is not None and time.monotonic() - _CACHE["at"] < ttl:
            return _CACHE["value"]
        value = compute(rows_from_ledger(db))
        _CACHE.update(at=time.monotonic(), value=value)
        return value


def invalidate() -> None:
    with _LOCK:
        _CACHE.update(at=0.0, value=None)


def fmt_seconds(s: float | None) -> str:
    if s is None:
        return "n/a"
    if s < 60:
        return f"{int(s)}s"
    if s < 3600:
        return f"{int(s // 60)}m"
    if s < 86400:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"


def line(m: dict, days: int = 7) -> str:
    """One sentence of the numbers, for the daily summary and the board."""
    w = (m.get("windows") or {}).get(days) or (m.get("windows") or {}).get(str(days)) or {}
    if not w or not w.get("proposals_raised"):
        return f"No proposals in the last {days} days, so nothing to measure yet."
    rate = f"{int(round(100 * w['approval_rate']))}% approved" if w.get("approval_rate") is not None else "nothing decided"
    share = f"{int(round(100 * w['autonomous_share']))}% closed without a person" if w.get("autonomous_share") is not None else ""
    return (f"Trusted action over {days} days: {w['proposals_raised']} proposals raised; median time to action "
            f"{fmt_seconds(w['auto']['median_s'])} automatic (p90 {fmt_seconds(w['auto']['p90_s'])}) and "
            f"{fmt_seconds(w['human']['median_s'])} with a person (p90 {fmt_seconds(w['human']['p90_s'])}); "
            f"{w['decided']} decided, {rate}" + (f"; {share}" if share else "")
            + (f"; {w['drafted']} client drafts handed to a person on the platform" if w.get("drafted") else "") + ".")
