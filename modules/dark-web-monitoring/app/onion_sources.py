"""Onion leak-site sources: seeding, activity, disable rules and crawl order.

Seeding reads ransomware.live PRO group detail (GET /groups/{name}), whose
locations carry availability, instead of the archived ransomwatch groups.json.
Each seeded Source records in meta:

  seeded_from         "ransomware.live" (or "ransomwatch" for the old mirrors,
                      "manual" for ones a person added)
  seeded_at           when this module first registered it
  last_seen_in_feed   newest victim the live feed published for the group
  group_lastseen      the group's lastseen date from ransomware.live
  available, updated, lastscrape, type, captcha, seized  from the location
  disabled            {"code", "detail", "at"} when a rule turned it off

Disable rules (a person can re-enable any source on the Sources page):
  inactive   no feed activity for the group in ONION_INACTIVE_DAYS (180)
  failures   ONION_MAX_CONSECUTIVE_FAILURES (10) failed crawls in a row
Seeding re-enables a source that a rule or the ransomwatch migration turned off
when ransomware.live lists it as available for a group that is active again. A
source a person disabled stays off."""
from __future__ import annotations

import datetime as dt
import logging
import time
from typing import Callable

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import health
from . import ransomware_live as rl
from .config import settings
from .db import Item, Source, utcnow
from .fetch import FetchResult, fetch

log = logging.getLogger(__name__)

SEED_PAUSE_SECONDS = 1.0
MIGRATION_KEY = "migration:ransomwatch_mirrors_v1"
AUTO_REENABLE_CODES = ("ransomwatch_archive", "inactive", "unavailable")
SEED_LOCATION_TYPES = ("", "dls")


# ---------------------------------------------------------------- helpers
def fqdn_of(url: str) -> str:
    try:
        return (httpx.URL(url).host or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _iso(v: dt.datetime | None) -> str | None:
    return v.isoformat() if v else None


def parse_ts(v) -> dt.datetime | None:
    if not v:
        return None
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
    s = str(v).strip().replace(" ", "T", 1)
    try:
        out = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            out = dt.datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return out if out.tzinfo else out.replace(tzinfo=dt.timezone.utc)


def group_activity(db: Session) -> dict[str, dt.datetime]:
    """Newest published victim per group (lower-case key) across the feeds."""
    when = func.coalesce(Item.published_at, Item.collected_at)
    rows = db.execute(
        select(func.lower(Item.group_name), func.max(when))
        .join(Source, Item.source_id == Source.id)
        .where(Source.kind == "feed", Item.kind == "victim", Item.group_name != "")
        .group_by(func.lower(Item.group_name))
    ).all()
    return {g: parse_ts(t) for g, t in rows if g and t}


def last_activity(src: Source) -> dt.datetime | None:
    meta = src.meta or {}
    seen = [parse_ts(meta.get("last_seen_in_feed")), parse_ts(meta.get("group_lastseen"))]
    seen = [s for s in seen if s]
    return max(seen) if seen else None


def update_feed_activity(db: Session) -> int:
    """Copy each group's newest feed victim onto its onion sources as
    meta.last_seen_in_feed. Returns how many sources changed."""
    act = group_activity(db)
    n = 0
    for src in db.execute(select(Source).where(Source.kind == "onion")).scalars():
        seen = act.get((src.group_name or "").lower())
        if not seen:
            continue
        iso = seen.isoformat()
        if (src.meta or {}).get("last_seen_in_feed") != iso:
            src.meta = {**(src.meta or {}), "last_seen_in_feed": iso}
            n += 1
    db.commit()
    return n


def disable(src: Source, code: str, detail: str, now: dt.datetime | None = None) -> None:
    src.enabled = False
    src.meta = {**(src.meta or {}), "disabled": {"code": code, "detail": detail[:500], "at": (now or utcnow()).isoformat()}}


def disabled_reason(src: Source) -> dict | None:
    d = (src.meta or {}).get("disabled")
    return d if isinstance(d, dict) else None


def set_enabled_by_person(src: Source, enabled: bool, actor: str) -> None:
    """The Sources page toggle. Re-enabling clears the rule's reason and the
    failure streak and records who did it, so the inactivity rule leaves the
    source alone for another full window. Disabling records a manual reason that
    seeding never overrides."""
    now = utcnow()
    meta = dict(src.meta or {})
    if enabled:
        meta.pop("disabled", None)
        meta["reenabled_by"] = actor
        meta["reenabled_at"] = now.isoformat()
    else:
        meta["disabled"] = {"code": "manual", "detail": f"disabled by {actor}", "at": now.isoformat()}
    src.meta = meta
    src.enabled = enabled
    src.fail_count = 0


# ---------------------------------------------------------------- disable rules
def apply_disable_rules(db: Session, now: dt.datetime | None = None) -> dict:
    now = now or utcnow()
    window = dt.timedelta(days=settings.onion_inactive_days)
    max_fail = settings.onion_max_consecutive_failures
    out = {"failures": 0, "inactive": 0}
    for src in db.execute(select(Source).where(Source.kind == "onion", Source.enabled.is_(True))).scalars():
        meta = src.meta or {}
        if (src.fail_count or 0) >= max_fail:
            disable(src, "failures", f"{src.fail_count} consecutive failed crawls; last error: {src.last_error[:200]}", now)
            out["failures"] += 1
            continue
        if meta.get("seeded_from") == "manual":
            continue
        reenabled = parse_ts(meta.get("reenabled_at"))
        if reenabled and now - reenabled < window:
            continue
        seen = last_activity(src)
        if seen is not None:
            if now - seen > window:
                disable(src, "inactive", f"no feed activity for {src.group_name or 'this group'} since "
                        f"{seen.date().isoformat()} ({settings.onion_inactive_days} day limit)", now)
                out["inactive"] += 1
            continue
        seeded = parse_ts(meta.get("seeded_at")) or src.created_at
        if seeded and now - seeded > window:
            disable(src, "inactive", f"no feed activity recorded for {src.group_name or 'this group'} in "
                    f"{settings.onion_inactive_days} days since it was seeded", now)
            out["inactive"] += 1
    db.commit()
    if out["failures"] or out["inactive"]:
        log.info("onion disable rules: %s", out)
    return out


# ---------------------------------------------------------------- seeding
def _location_url(loc: dict) -> str:
    fqdn = (loc.get("fqdn") or "").strip().lower()
    slug = (loc.get("slug") or "").strip()
    if slug.startswith(("http://", "https://")) and fqdn and fqdn in slug.lower():
        return slug
    return f"http://{fqdn}/"


def _choose_groups(db: Session, listed: list[dict], limit: int, now: dt.datetime) -> list[str]:
    """Priority groups first, then groups active in the feed (newest first), then
    the remaining listed groups by victim count. Lower-case names, de-duplicated."""
    from . import priority  # local import: priority imports this module

    names = {(g.get("group") or "").lower(): g for g in listed if g.get("group")}
    chosen: list[str] = []

    def add(k: str) -> None:
        if k and k in names and k not in chosen and len(chosen) < limit:
            chosen.append(k)

    for k in priority.priority_keys(db):
        add(k)
    window = dt.timedelta(days=settings.onion_inactive_days)
    for k, seen in sorted(group_activity(db).items(), key=lambda kv: kv[1], reverse=True):
        if now - seen <= window:
            add(k)
    for g in sorted(listed, key=lambda g: int(g.get("victims") or 0), reverse=True):
        add((g.get("group") or "").lower())
    return chosen


def seed(db: Session, client: rl.Client | None = None, now: dt.datetime | None = None,
         sleep: Callable[[float], None] = time.sleep, limit: int | None = None) -> dict:
    """Register or refresh onion sources from ransomware.live PRO group locations.
    One call to /groups and one to /groups/{name} per chosen group per run."""
    now = now or utcnow()
    if not rl.configured():
        return {"ok": False, "added": 0, "error": rl.NOT_CONFIGURED}
    try:
        client = client or rl.Client(sleep=sleep)
        listed = client.groups()
    except rl.RansomwareLiveError as e:
        log.warning("onion seeding skipped: %s", e)
        return {"ok": False, "added": 0, "error": str(e)}
    limit = settings.onion_seed_group_limit if limit is None else limit
    chosen = _choose_groups(db, listed, limit, now)
    activity = group_activity(db)
    by_fqdn: dict[str, Source] = {}
    for s in db.execute(select(Source).where(Source.kind == "onion")).scalars():
        by_fqdn.setdefault(fqdn_of(s.url), s)
    added = refreshed = reenabled = skipped = 0
    errors: list[str] = []
    window = dt.timedelta(days=settings.onion_inactive_days)
    for i, key in enumerate(chosen):
        if i:
            sleep(SEED_PAUSE_SECONDS)
        try:
            detail = client.group(key)
        except (rl.AuthError, rl.RateLimited) as e:
            errors.append(str(e))
            break
        except rl.RansomwareLiveError as e:
            errors.append(str(e))
            continue
        display = detail.get("group") or key
        lastseen = parse_ts(detail.get("lastseen"))
        feed_seen = activity.get(key)
        active_at = max([t for t in (lastseen, feed_seen) if t], default=None)
        active = bool(active_at and now - active_at <= window)
        for loc in detail.get("locations") or []:
            if not isinstance(loc, dict):
                continue
            fqdn = (loc.get("fqdn") or "").strip().lower()
            if not fqdn.endswith(".onion"):
                continue
            if (str(loc.get("type") or "")).strip().lower() not in SEED_LOCATION_TYPES or loc.get("seized"):
                skipped += 1
                continue
            loc_meta = {k: loc.get(k) for k in ("available", "updated", "lastscrape", "type", "captcha", "seized")}
            src = by_fqdn.get(fqdn)
            if src is None:
                src = Source(name=f"{display} leak site", kind="onion", url=_location_url(loc), group_name=display,
                             enabled=True, meta={"seeded_from": "ransomware.live", "seeded_at": now.isoformat()})
                db.add(src)
                by_fqdn[fqdn] = src
                added += 1
                if loc.get("available") is False:
                    disable(src, "unavailable", "ransomware.live lists this location as unavailable", now)
            else:
                refreshed += 1
            meta = dict(src.meta or {})
            if meta.get("seeded_from") == "ransomwatch":
                meta["seeded_from"] = "ransomware.live"
                meta["previously_seeded_from"] = "ransomwatch"
                meta.setdefault("seeded_at", now.isoformat())
            meta.update(loc_meta)
            meta["listed_by_ransomware_live_at"] = now.isoformat()
            if lastseen:
                meta["group_lastseen"] = lastseen.isoformat()
            if feed_seen:
                meta["last_seen_in_feed"] = feed_seen.isoformat()
            src.meta = meta
            reason = disabled_reason(src)
            if (not src.enabled and reason and reason.get("code") in AUTO_REENABLE_CODES
                    and loc.get("available") is not False and active):
                meta = dict(src.meta)
                meta.pop("disabled", None)
                src.meta = meta
                src.enabled = True
                src.fail_count = 0
                reenabled += 1
        db.commit()
    rules = apply_disable_rules(db, now)
    summary = {"ok": not errors, "added": added, "refreshed": refreshed, "reenabled": reenabled,
               "skipped_locations": skipped, "groups_checked": len(chosen), "calls": len(client.calls),
               "disabled": rules}
    if errors:
        summary["error"] = "; ".join(errors)[:2000]
    log.info("onion seeding: %s", summary)
    return summary


# ---------------------------------------------------------------- startup migration
def migrate_ransomwatch_mirrors(db: Session) -> int:
    """Disable the onion mirrors seeded from the archived ransomwatch list and
    mark the ransomwatch feed archived. Rows are never deleted. Runs once: the
    result is recorded in worker_state so a mirror a person re-enables later is
    not turned off again at the next start."""
    if health.get_state(db, MIGRATION_KEY):
        return 0
    now = utcnow()
    n = 0
    for src in db.execute(select(Source).where(Source.kind == "onion")).scalars():
        if (src.meta or {}).get("seeded_from") == "ransomwatch" and src.enabled:
            disable(src, "ransomwatch_archive", "seeded from the ransomwatch archive, which stopped updating in "
                    "mid-2025; seeding re-enables it if ransomware.live lists it for an active group", now)
            n += 1
    from .collectors import leak_feeds

    for src in db.execute(select(Source).where(Source.kind == "feed", Source.url.ilike("%ransomwatch%"))).scalars():
        leak_feeds.mark_archived(db, src)
    db.commit()
    health.set_state(db, MIGRATION_KEY, {"at": now.isoformat(), "disabled": n})
    log.info("migration: disabled %d ransomwatch-seeded onion mirrors", n)
    return n


# ---------------------------------------------------------------- crawling
def crawl_order(db: Session, sources: list[Source]) -> list[tuple[Source, bool]]:
    """Priority groups first (in priority order), then the rest by group activity,
    newest first, then least recently successful. Returns (source, is_priority)."""
    from . import priority

    keys = priority.priority_keys(db)
    rank = {k: i for i, k in enumerate(keys)}
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

    def sort_key(s: Source):
        g = (s.group_name or "").lower()
        if g in rank:
            return (0, rank[g], 0.0, 0.0)
        act = last_activity(s) or epoch
        ok = s.last_ok or epoch
        return (1, 0, -act.timestamp(), ok.timestamp())

    ordered = sorted(sources, key=sort_key)
    return [(s, (s.group_name or "").lower() in rank) for s in ordered]


def fetch_onion(url: str, cookies: str = "") -> FetchResult:
    """Fetch over Tor. ransomware.live writes many onion slugs as https://; most
    onion services only speak http, so a failed https onion fetch retries as http."""
    res = fetch(url, force_tor=True, cookies=cookies)
    if not res.ok and url.startswith("https://") and fqdn_of(url).endswith(".onion"):
        alt = fetch("http://" + url[len("https://"):], force_tor=True, cookies=cookies)
        if alt.ok or alt.status:
            return alt
    return res
