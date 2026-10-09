"""Ransomware leak site victim feeds from clearnet aggregators.

Two free sources are used and merged:
  ransomware.live   JSON API of recent victims across tracked groups
  ransomwatch       GitHub-hosted posts.json and groups.json (also seeds our onion source list)

Both are community projects. Field names drift, so parsing is defensive. The onion
crawler (onion_crawl.py) is the primary source once sources are seeded; these feeds
catch groups we do not crawl directly and give published dates."""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Source
from ..fetch import fetch_json
from ..pipeline import ingest, mark_source

log = logging.getLogger(__name__)

def _rl_base() -> str:
    """PRO API (free key from my.ransomware.live, intended for business use) when a key is set,
    otherwise the public v2 endpoint, which is rate limited to one call per minute."""
    if settings.ransomware_live_base:
        return settings.ransomware_live_base.rstrip("/")
    return "https://api-pro.ransomware.live" if settings.ransomware_live_api_key else "https://api.ransomware.live/v2"


RANSOMWATCH_POSTS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RANSOMWATCH_GROUPS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"


def _parse_dt(v) -> dt.datetime | None:
    if not v:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(str(v)[:26], fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(str(v)).astimezone(dt.timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def _get_source(db: Session, name: str, url: str) -> Source:
    src = db.execute(select(Source).where(Source.kind == "feed", Source.url == url)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind="feed", url=url)
        db.add(src)
        db.commit()
    return src


def run_ransomware_live(db: Session) -> int:
    url = f"{_rl_base()}/recentvictims"
    src = _get_source(db, "ransomware.live recent victims", url)
    headers = {settings.ransomware_live_api_header: settings.ransomware_live_api_key} if settings.ransomware_live_api_key else {}
    try:
        data = fetch_json(url, headers=headers)
    except Exception as e:  # noqa: BLE001
        mark_source(db, src, False, str(e))
        return 0
    rows = data if isinstance(data, list) else data.get("victims") or data.get("data") or []
    n = 0
    for v in rows:
        victim = v.get("victim") or v.get("post_title") or v.get("title") or ""
        group = v.get("group") or v.get("group_name") or ""
        desc = v.get("description") or ""
        website = v.get("website") or v.get("domain") or ""
        activity = v.get("activity") or v.get("sector") or ""
        country = v.get("country") or ""
        published = _parse_dt(v.get("attackdate") or v.get("published") or v.get("discovered"))
        body = "\n".join(
            s for s in [f"Victim: {victim}", f"Website: {website}", f"Sector: {activity}", f"Country: {country}", "", desc] if s is not None
        )
        item, _ = ingest(
            db,
            kind="victim",
            title=f"{group}: {victim}",
            body=body,
            url=v.get("post_url") or v.get("claim_url") or "",
            external_id=f"rl:{group}:{victim}",
            group_name=group,
            published_at=published,
            source=src,
            meta={"raw": v},
            hash_parts=("victim", group.lower(), victim.lower()),
        )
        n += 1 if item else 0
    mark_source(db, src, True)
    log.info("ransomware.live: %d new victims", n)
    return n


def run_ransomwatch_posts(db: Session) -> int:
    src = _get_source(db, "ransomwatch posts", RANSOMWATCH_POSTS)
    try:
        rows = fetch_json(RANSOMWATCH_POSTS)
    except Exception as e:  # noqa: BLE001
        mark_source(db, src, False, str(e))
        return 0
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
            meta={"raw": v},
            hash_parts=("victim", group.lower(), victim.lower()),
        )
        n += 1 if item else 0
    mark_source(db, src, True)
    log.info("ransomwatch posts: %d new victims", n)
    return n


def _group_lists() -> list[tuple[str, list]]:
    """Group lists from ransomware.live (live) and ransomwatch (archived mid-2025, still a useful seed)."""
    out = []
    headers = {settings.ransomware_live_api_header: settings.ransomware_live_api_key} if settings.ransomware_live_api_key else {}
    for label, url, hdrs in [
        ("ransomware.live", f"{_rl_base()}/groups", headers),
        ("ransomwatch", RANSOMWATCH_GROUPS, {}),
    ]:
        try:
            data = fetch_json(url, headers=hdrs)
            groups = data if isinstance(data, list) else data.get("groups") or data.get("data") or []
            out.append((label, groups))
        except Exception as e:  # noqa: BLE001
            log.warning("%s group list fetch failed: %s", label, e)
    return out


def seed_onion_sources(db: Session) -> int:
    """Register every known onion mirror of every tracked group as a crawl source."""
    added = 0
    seen: set[str] = set(db.execute(select(Source.url).where(Source.kind == "onion")).scalars().all())
    for label, groups in _group_lists():
        for g in groups:
            name = g.get("name", "")
            for loc in g.get("locations", []) or []:
                if not isinstance(loc, dict):
                    continue
                fqdn = loc.get("fqdn") or ""
                if not fqdn.endswith(".onion"):
                    continue
                slug = loc.get("slug") or ""
                # slug is normally the full URL; fall back to building one from the fqdn.
                url = slug if slug.startswith("http") else f"http://{fqdn}{slug or '/'}"
                if url in seen:
                    continue
                seen.add(url)
                db.add(Source(
                    name=f"{name} leak site",
                    kind="onion",
                    url=url,
                    group_name=name,
                    enabled=bool(loc.get("enabled", True)),
                    meta={"seeded_from": label, "available": loc.get("available"), "updated": loc.get("updated")},
                ))
                added += 1
    db.commit()
    log.info("seeded %d onion sources", added)
    return added


def run(db: Session) -> None:
    run_ransomware_live(db)
    run_ransomwatch_posts(db)
