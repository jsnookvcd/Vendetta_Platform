"""Ransomware leak site victim feeds from clearnet aggregators.

  ransomware.live   The live victim feed. PRO API only (app/ransomware_live.py):
                    without RANSOMWARE_LIVE_API_KEY the connector is not
                    configured and never calls the public v2 tier.
  ransomwatch       Archived upstream in mid-2025. Never scheduled. Kept only as
                    a one-time historical backfill an admin starts from the
                    Connectors page; its source is marked archived.

Onion source seeding moved to app/onion_sources.py and reads ransomware.live PRO
group locations instead of the ransomwatch archive."""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import ransomware_live as rl
from ..db import Source, utcnow
from ..fetch import fetch_json
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

RANSOMWATCH_POSTS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RANSOMWATCH_GROUPS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
RL_FEED_NAME = "ransomware.live recent victims"


def _rl_base() -> str:
    return rl.base_url()


def rl_headers() -> dict:
    return rl.headers()


def _parse_dt(v) -> dt.datetime | None:
    if not v:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(str(v)[:26], fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    try:
        v2 = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return v2 if v2.tzinfo else v2.replace(tzinfo=dt.timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def _get_source(db: Session, name: str, url: str) -> Source:
    src = db.execute(select(Source).where(Source.kind == "feed", Source.url == url)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind="feed", url=url)
        db.add(src)
        db.commit()
    return src


def ingest_victim(db: Session, v: dict, src: Source):
    """Store one ransomware.live victim row. The leak post URL (post_url or
    claim_url) is the item URL, which the capture queue fetches on a hit."""
    victim = rl.victim_name(v)
    group = rl.victim_group(v)
    desc = v.get("description") or ""
    website = v.get("website") or v.get("domain") or ""
    activity = v.get("activity") or v.get("sector") or ""
    country = v.get("country") or ""
    published = _parse_dt(v.get("attackdate") or v.get("published") or v.get("discovered"))
    body = "\n".join([f"Victim: {victim}", f"Website: {website}", f"Sector: {activity}", f"Country: {country}", "", desc])
    return ingest(
        db,
        kind="victim",
        title=f"{group}: {victim}",
        body=body,
        url=rl.victim_target_url(v),
        external_id=f"rl:{group}:{victim}",
        group_name=group,
        published_at=published,
        source=src,
        meta={"raw": v, "victim": victim, "activity": activity, "country": country,
              "discovered": v.get("discovered") or ""},
        hash_parts=("victim", group.lower(), victim.lower()),
    )


def run_ransomware_live(db: Session, client: rl.Client | None = None) -> dict:
    """Returns a run summary: {"ok", "new", "rows"} and "error" on failure. One
    call to /victims/recent per run."""
    if not rl.configured():
        return {"ok": False, "new": 0, "error": rl.NOT_CONFIGURED}
    url = f"{rl.base_url()}{rl.RECENT_VICTIMS}"
    src = _get_source(db, RL_FEED_NAME, url)
    try:
        client = client or rl.Client()
        rows = client.recent_victims()
    except rl.RansomwareLiveError as e:
        mark_source(db, src, False, str(e))
        return {"ok": False, "new": 0, "error": str(e)}
    n = 0
    for v in rows:
        if not rl.victim_name(v):
            continue
        item, _ = ingest_victim(db, v, src)
        n += 1 if item else 0
    mark_source(db, src, True)
    from .. import onion_sources  # local import: onion_sources imports this module

    onion_sources.update_feed_activity(db)
    log.info("ransomware.live: %d new victims from %d rows", n, len(rows))
    return {"ok": True, "new": n, "rows": len(rows)}


def run_ransomwatch_posts(db: Session) -> dict:
    """One-time historical backfill from the archived ransomwatch posts.json.
    Returns a run summary. The source is marked archived and disabled so it never
    counts as a live, healthy feed."""
    src = _get_source(db, "ransomwatch posts (archive)", RANSOMWATCH_POSTS)
    try:
        rows = fetch_json(RANSOMWATCH_POSTS)
    except Exception as e:  # noqa: BLE001
        mark_source(db, src, False, str(e))
        mark_archived(db, src)
        return {"ok": False, "new": 0, "error": str(e)}
    n = 0
    for v in rows:
        victim = v.get("post_title") or ""
        group = v.get("group_name") or ""
        item, _ = ingest(
            db,
            kind="victim",
            title=f"{group}: {victim}",
            body=f"Victim: {victim}\nGroup: {group}\nDiscovered: {v.get('discovered')}",
            external_id=f"rw:{group}:{victim}",
            group_name=group,
            published_at=_parse_dt(v.get("discovered")),
            source=src,
            meta={"raw": v, "victim": victim, "archive": "ransomwatch"},
            hash_parts=("victim", group.lower(), victim.lower()),
        )
        n += 1 if item else 0
    mark_source(db, src, True)
    mark_archived(db, src, backfilled=True)
    log.info("ransomwatch backfill: %d new victims", n)
    return {"ok": True, "new": n, "rows": len(rows)}


def mark_archived(db: Session, src: Source, backfilled: bool = False) -> None:
    meta = dict(src.meta or {})
    meta["archived"] = True
    meta["archived_reason"] = "ransomwatch was archived upstream in mid-2025 and produces no new victims"
    if backfilled:
        meta["backfilled_at"] = utcnow().isoformat()
    src.meta = meta
    src.enabled = False
    db.add(src)
    db.commit()


def seed_onion_sources(db: Session) -> int:
    """Compatibility wrapper. Seeding reads ransomware.live PRO group locations;
    see app/onion_sources.py."""
    from .. import onion_sources

    return onion_sources.seed(db).get("added", 0)


def run(db: Session) -> dict:
    """The live feed for scripts and manual use. ransomwatch is a backfill only."""
    return run_ransomware_live(db)
