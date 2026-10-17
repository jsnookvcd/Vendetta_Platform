"""Detection and response timing.

- MTTD (mean time to detect, reported as median and p90): earliest signal occurred
  to investigation opened.
- MTTA (acknowledge): opened to acknowledged.
- MTTR (respond): opened to contained, or to closed when it was never contained.

The math is a pure function over plain records so it is tested without a database;
p90 is the nearest-rank percentile. An investigation still waiting on a step
contributes nothing to that step's figures.
"""
from __future__ import annotations

import datetime as dt
import math
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload


def _minutes(a: dt.datetime | None, b: dt.datetime | None) -> float | None:
    if not a or not b:
        return None
    return max((b - a).total_seconds() / 60.0, 0.0)


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile; None for no values."""
    if not values:
        return None
    vs = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(vs)))
    return vs[rank - 1]


def median(values: list[float]) -> float | None:
    if not values:
        return None
    vs = sorted(values)
    n = len(vs)
    mid = n // 2
    return vs[mid] if n % 2 else (vs[mid - 1] + vs[mid]) / 2.0


def _stat(values: list[float]) -> dict:
    def r(v):
        return None if v is None else round(v, 1)
    return {"median": r(median(values)), "p90": r(percentile(values, 90)), "count": len(values)}


def durations(rec: dict) -> dict:
    """rec carries first_signal_at, opened_at, acknowledged_at, contained_at, closed_at."""
    end = rec.get("contained_at") or rec.get("closed_at")
    return {"mttd": _minutes(rec.get("first_signal_at"), rec.get("opened_at")),
            "mtta": _minutes(rec.get("opened_at"), rec.get("acknowledged_at")),
            "mttr": _minutes(rec.get("opened_at"), end)}


def summarize(records: list[dict]) -> dict:
    buckets: dict[str, list[float]] = {"mttd": [], "mtta": [], "mttr": []}
    for rec in records:
        for k, v in durations(rec).items():
            if v is not None:
                buckets[k].append(v)
    return {"investigations": len(records), "mttd_minutes": _stat(buckets["mttd"]),
            "mtta_minutes": _stat(buckets["mtta"]), "mttr_minutes": _stat(buckets["mttr"])}


def compute(records: list[dict], window_days: int) -> dict:
    out = {"window_days": window_days, **summarize(records)}
    by: dict[str, list[dict]] = defaultdict(list)
    names: dict[str, str] = {}
    for rec in records:
        by[rec.get("platform_client_id") or ""].append(rec)
        names[rec.get("platform_client_id") or ""] = rec.get("client", "")
    out["by_client"] = [{"platform_client_id": pid, "client": names[pid], **summarize(rs)}
                        for pid, rs in sorted(by.items(), key=lambda kv: names[kv[0]].lower())]
    return out


def records(db: Session, days: int, platform_client_id: str = "", client_id: str = "",
            now: dt.datetime | None = None) -> list[dict]:
    from .db import Client, Investigation, utcnow

    now = now or utcnow()
    q = (select(Investigation).options(selectinload(Investigation.client))
         .where(Investigation.opened_at >= now - dt.timedelta(days=days)))
    if platform_client_id:
        q = q.join(Investigation.client).where(Client.platform_client_id == platform_client_id)
    if client_id:
        q = q.where(Investigation.client_id == client_id)
    return [{"platform_client_id": i.client.platform_client_id or "", "client": i.client.name,
             "first_signal_at": i.first_signal_at, "opened_at": i.opened_at,
             "acknowledged_at": i.acknowledged_at, "contained_at": i.contained_at, "closed_at": i.closed_at}
            for i in db.execute(q).scalars().all()]


def for_window(db: Session, days: int = 30, platform_client_id: str = "", client_id: str = "") -> dict:
    return compute(records(db, days, platform_client_id, client_id), days)


def fmt(minutes: float | None) -> str:
    """Human duration for the pages: 42s, 18m, 3.5h, 2.1d."""
    if minutes is None:
        return "n/a"
    if minutes < 1:
        return f"{round(minutes * 60)}s"
    if minutes < 90:
        return f"{round(minutes)}m"
    if minutes < 60 * 48:
        return f"{minutes / 60:.1f}h"
    return f"{minutes / 1440:.1f}d"
