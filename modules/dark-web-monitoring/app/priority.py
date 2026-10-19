"""Priority groups: which ransomware groups get direct, profiled crawls first.

The ranking reads the ransomware.live PRO victims this module has stored (feed
victim items) and counts each group's victims published in the last 90 days.
A victim counts for more when it matches an active client: WEIGHT_INDUSTRY when
its sector matches a client's industry and WEIGHT_COUNTRY when its country
matches a client's country. The top PRIORITY_GROUP_COUNT (25) groups by weighted
score are the computed list, refreshed daily by the worker.

An admin can pin a group (always a priority group, ahead of the computed list)
or exclude one (never a priority group) on the Priority Groups page. Pins and
exclusions survive every refresh."""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import Client, Item, PriorityGroup, Source, utcnow

log = logging.getLogger(__name__)

WINDOW_DAYS = 90
WEIGHT_INDUSTRY = 1.0
WEIGHT_COUNTRY = 0.5

# Client industry words mapped to fragments of ransomware.live sector names
# ("Financial Services", "Healthcare", "Education", "Manufacturing", ...).
SECTOR_ALIASES: dict[str, tuple[str, ...]] = {
    "credit union": ("financial",), "bank": ("financial",), "banking": ("financial",),
    "finance": ("financial",), "financial": ("financial",), "lender": ("financial",),
    "mortgage": ("financial",), "insurance": ("financial", "insurance"),
    "health": ("health",), "hospital": ("health",), "medical": ("health",), "clinic": ("health",),
    "education": ("education",), "college": ("education",), "university": ("education",), "school": ("education",),
    "manufactur": ("manufactur",), "industrial": ("manufactur", "industrial"),
    "government": ("government", "public sector"), "municipal": ("government", "public sector"),
    "legal": ("legal", "business services"), "law firm": ("legal", "business services"),
    "technology": ("technology",), "software": ("technology",), "msp": ("technology",),
    "construction": ("construction",), "retail": ("retail", "consumer"),
    "energy": ("energy",), "utility": ("energy", "utilit"), "transport": ("transport", "logistic"),
    "logistic": ("transport", "logistic"), "hospitality": ("hospitality",), "agricultur": ("agricultur",),
    "telecom": ("telecom",),
}

COUNTRY_ALIASES = {
    "usa": "US", "us": "US", "u.s.": "US", "u.s.a.": "US", "united states": "US", "united states of america": "US",
    "uk": "GB", "united kingdom": "GB", "great britain": "GB", "england": "GB", "canada": "CA",
    "bermuda": "BM", "australia": "AU", "germany": "DE", "france": "FR", "mexico": "MX",
}


def country_code(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    mapped = COUNTRY_ALIASES.get(v.lower())
    if mapped:
        return mapped
    return v.upper() if len(v) == 2 else ""


def sector_needles(industry: str) -> set[str]:
    ind = (industry or "").strip().lower()
    if not ind:
        return set()
    needles = {ind}
    for word, frags in SECTOR_ALIASES.items():
        if word in ind:
            needles.update(frags)
    return needles


def _victim_fields(it: Item) -> tuple[str, str]:
    meta = it.meta or {}
    raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}
    activity = meta.get("activity") or raw.get("activity") or raw.get("sector") or ""
    country = meta.get("country") or raw.get("country") or ""
    return str(activity).lower(), str(country).upper()


def compute(db: Session, now: dt.datetime | None = None) -> dict:
    now = now or utcnow()
    since = now - dt.timedelta(days=WINDOW_DAYS)
    clients = db.execute(select(Client).where(Client.active.is_(True))).scalars().all()
    needles: set[str] = set()
    countries: set[str] = set()
    for c in clients:
        needles |= sector_needles(c.industry)
        cc = country_code(c.country)
        if cc:
            countries.add(cc)
    when = func.coalesce(Item.published_at, Item.collected_at)
    items = db.execute(
        select(Item).join(Source, Item.source_id == Source.id)
        .where(Source.kind == "feed", Source.url.ilike("%ransomware.live%"), Item.kind == "victim",
               Item.group_name != "", when >= since)
    ).scalars().all()
    stats: dict[str, dict] = {}
    for it in items:
        key = it.group_name.strip().lower()
        activity, country = _victim_fields(it)
        ind = bool(needles and activity and any(n in activity for n in needles))
        ctry = bool(countries and country in countries)
        s = stats.setdefault(key, {"display": it.group_name.strip(), "victims": 0, "matched": 0, "score": 0.0})
        s["victims"] += 1
        s["matched"] += 1 if (ind or ctry) else 0
        s["score"] += 1.0 + (WEIGHT_INDUSTRY if ind else 0.0) + (WEIGHT_COUNTRY if ctry else 0.0)
    rows = {r.group_key: r for r in db.execute(select(PriorityGroup)).scalars()}
    for key, s in stats.items():
        row = rows.get(key)
        if row is None:
            row = PriorityGroup(group_key=key)
            db.add(row)
            rows[key] = row
        row.display_name = s["display"]
        row.victims_90d = s["victims"]
        row.matched_victims = s["matched"]
        row.score = round(s["score"], 2)
    for key, row in list(rows.items()):
        if key not in stats:
            row.victims_90d, row.matched_victims, row.score = 0, 0, 0.0
            if not (row.pinned or row.excluded):
                db.delete(row)
                del rows[key]
    ranked = sorted((r for r in rows.values() if not r.excluded and r.victims_90d > 0),
                    key=lambda r: (-r.score, -r.victims_90d, r.group_key))
    top = settings.priority_group_count
    for i, r in enumerate(ranked, start=1):
        r.rank = i
        r.computed = i <= top
    for r in rows.values():
        if r.excluded or r.victims_90d == 0:
            r.rank, r.computed = 0, False
        r.computed_at = now
    db.commit()
    summary = {"groups": len(rows), "computed": sum(1 for r in rows.values() if r.computed),
               "pinned": sum(1 for r in rows.values() if r.pinned), "victims_considered": len(items),
               "clients": len(clients)}
    log.info("priority groups: %s", summary)
    return summary


def priority_keys(db: Session) -> list[str]:
    """Pinned groups, then the computed list in rank order. Excluded groups never appear."""
    rows = db.execute(select(PriorityGroup).where(PriorityGroup.excluded.is_(False))).scalars().all()
    pinned = sorted((r for r in rows if r.pinned), key=lambda r: (r.rank or 10**6, r.group_key))
    computed = sorted((r for r in rows if r.computed and not r.pinned), key=lambda r: (r.rank, r.group_key))
    return [r.group_key for r in pinned + computed]


def set_flags(db: Session, group: str, actor: str, pinned: bool | None = None, excluded: bool | None = None) -> PriorityGroup:
    key = group.strip().lower()[:100]
    row = db.get(PriorityGroup, key)
    if row is None:
        row = PriorityGroup(group_key=key, display_name=group.strip()[:100])
        db.add(row)
    if pinned is not None:
        row.pinned = pinned
        if pinned:
            row.excluded = False
    if excluded is not None:
        row.excluded = excluded
        if excluded:
            row.pinned, row.computed, row.rank = False, False, 0
    row.updated_by = actor
    row.updated_at = utcnow()
    db.commit()
    return row


def page_rows(db: Session) -> list[dict]:
    """Rows for the Priority Groups page: priority groups first, then the rest."""
    from . import profile_store

    keys = priority_keys(db)
    order = {k: i for i, k in enumerate(keys)}
    rows = db.execute(select(PriorityGroup)).scalars().all()
    srcs = db.execute(select(Source).where(Source.kind == "onion")).scalars().all()
    by_group: dict[str, list[Source]] = {}
    for s in srcs:
        by_group.setdefault((s.group_name or "").lower(), []).append(s)
    out = []
    for r in sorted(rows, key=lambda r: (order.get(r.group_key, 10**6), -r.score, r.group_key)):
        gs = by_group.get(r.group_key, [])
        page = profile_store.latest_page(db, r.group_key)
        out.append({
            "row": r, "priority": r.group_key in order,
            "profile_state": profile_store.state_for_group(db, r.group_key),
            "sources_enabled": sum(1 for s in gs if s.enabled), "sources_total": len(gs),
            "latest_page_at": page.collected_at if page else None,
        })
    return out
