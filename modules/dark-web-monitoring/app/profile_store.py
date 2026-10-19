"""Leak-site parser profiles stored in the database, with the YAML files under
app/profiles as a fallback.

A profile is written on the host from the Priority Groups page: the editor
previews selectors against the newest stored index page for the group (a `page`
item whose meta carries the raw HTML) and shows the victims they would extract
before the profile is saved. Saving stores the selectors in parser_profiles and
points the group's onion sources at the profile.

Profile state:
  none     no profile for the group
  draft    saved, but no crawl has extracted an entry with it yet
  working  the last crawl extracted entries
  broken   it extracted entries before and the last crawl extracted none

Broken detection is tracked per source too (meta.profile_state), so a YAML
profile that stops matching is raised on the Connectors page as well."""
from __future__ import annotations

import datetime as dt
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import profiles
from .db import Item, ParserProfile, Source, utcnow
from .fetch import absolute, select_href, select_text, soup_of

SELECTOR_FIELDS = ("list_selector", "title_selector", "link_selector", "desc_selector", "date_selector",
                   "post_title_selector", "post_body_selector")
PREVIEW_LIMIT = 50


def profile_name_for(group_key: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", group_key.lower()).strip("-")[:80]
    return f"group-{slug or 'unnamed'}"


def get(db: Session | None, name: str) -> dict | None:
    """The profile dict the crawler uses: the database row when one exists,
    otherwise the YAML file of the same name."""
    if not name:
        return None
    if db is not None:
        row = db.get(ParserProfile, name)
        if row is not None:
            return {**(row.selectors or {}), "kind": row.kind, "name": row.name, "stored": "database"}
    prof = profiles.get(name)
    return {**prof, "stored": "yaml"} if prof else None


def for_group(db: Session, group_key: str) -> ParserProfile | None:
    row = db.get(ParserProfile, profile_name_for(group_key))
    if row is not None:
        return row
    return db.execute(select(ParserProfile).where(ParserProfile.group_key == group_key.lower())).scalars().first()


def yaml_for_group(group_key: str) -> dict | None:
    for name, prof in profiles.all_profiles().items():
        if name.startswith("_") or prof.get("kind") != "leak":
            continue
        if (str(prof.get("group") or "")).lower() == group_key.lower():
            return prof
    return None


def state_for_group(db: Session, group_key: str) -> str:
    row = for_group(db, group_key)
    if row is not None:
        return row.state
    if yaml_for_group(group_key):
        srcs = db.execute(select(Source).where(Source.kind == "onion")).scalars().all()
        states = [(s.meta or {}).get("profile_state") for s in srcs if (s.group_name or "").lower() == group_key.lower()]
        if "broken" in states:
            return "broken"
        return "working" if "working" in states else "draft"
    return "none"


def latest_page(db: Session, group_key: str) -> Item | None:
    """Newest stored index page for the group that kept its raw HTML."""
    rows = db.execute(
        select(Item).where(Item.kind == "page", func.lower(Item.group_name) == group_key.lower())
        .order_by(Item.collected_at.desc()).limit(10)
    ).scalars().all()
    for it in rows:
        if (it.meta or {}).get("html"):
            return it
    return None


def extract(html: str, prof: dict, base_url: str = "", limit: int | None = None) -> list[dict]:
    """Victim entries the profile's selectors find on an index page."""
    if not html or not prof.get("list_selector"):
        return []
    soup = soup_of(html)
    try:
        nodes = soup.select(prof["list_selector"])
    except Exception:  # noqa: BLE001
        return []
    out = []
    for node in nodes[: limit or len(nodes)]:
        href = select_href(node, prof.get("link_selector", ""))
        out.append({
            "victim": select_text(node, prof.get("title_selector", "")) or "(unnamed)",
            "desc": select_text(node, prof.get("desc_selector", ""))[:300],
            "date": select_text(node, prof.get("date_selector", "")),
            "link": absolute(base_url, href) if (href and base_url) else href,
        })
    return out


def clean_selectors(form: dict) -> dict:
    out = {k: (str(form.get(k) or "")).strip()[:500] for k in SELECTOR_FIELDS}
    try:
        out["max_posts_per_run"] = max(0, min(200, int(form.get("max_posts_per_run") or 40)))
    except (TypeError, ValueError):
        out["max_posts_per_run"] = 40
    return out


def save(db: Session, group_key: str, display: str, selectors: dict, actor: str, apply_to_sources: bool = True) -> ParserProfile:
    name = profile_name_for(group_key)
    row = db.get(ParserProfile, name)
    if row is None:
        row = ParserProfile(name=name, group_key=group_key.lower(), kind="leak")
        db.add(row)
    changed = (row.selectors or {}) != selectors
    row.selectors = {**selectors, "group": display}
    row.updated_by = actor
    row.updated_at = utcnow()
    if changed:
        # New selectors start over: they are a draft until a crawl extracts entries.
        row.state, row.last_entries, row.ever_extracted, row.broken_at = "draft", 0, 0, None
    if apply_to_sources:
        for s in db.execute(select(Source).where(Source.kind == "onion")).scalars():
            if (s.group_name or "").lower() == group_key.lower():
                s.profile = name
                meta = dict(s.meta or {})
                for k in ("profile_state", "profile_last_entries", "profile_ever_extracted", "profile_broken_at"):
                    meta.pop(k, None)
                s.meta = meta
    db.commit()
    return row


def record_crawl(db: Session, src: Source, prof_name: str, entries: int, now: dt.datetime | None = None) -> str:
    """Track what a profiled crawl extracted and return the resulting state."""
    now = now or utcnow()
    meta = dict(src.meta or {})
    ever = int(meta.get("profile_ever_extracted") or 0)
    if entries > 0:
        state = "working"
        meta.pop("profile_broken_at", None)
    elif ever > 0:
        state = "broken"
        meta.setdefault("profile_broken_at", now.isoformat())
    else:
        state = "draft"
    meta.update(profile_state=state, profile_last_entries=entries, profile_ever_extracted=max(ever, entries),
                profile_name=prof_name)
    src.meta = meta
    row = db.get(ParserProfile, prof_name)
    if row is not None:
        row.last_entries = entries
        row.last_crawled_at = now
        if entries > 0:
            row.state, row.ever_extracted, row.broken_at = "working", max(row.ever_extracted or 0, entries), None
        elif (row.ever_extracted or 0) > 0:
            row.state = "broken"
            row.broken_at = row.broken_at or now
    db.commit()
    return state


def broken_profiles(db: Session) -> list[dict]:
    """Profiles that extracted entries before and now extract none."""
    out: dict[str, dict] = {}
    for row in db.execute(select(ParserProfile).where(ParserProfile.state == "broken")).scalars():
        out[row.name] = {"profile": row.name, "group": row.group_key,
                         "since": row.broken_at.isoformat() if row.broken_at else None, "sources": []}
    for s in db.execute(select(Source).where(Source.kind == "onion", Source.enabled.is_(True))).scalars():
        meta = s.meta or {}
        if meta.get("profile_state") == "broken":
            name = meta.get("profile_name") or s.profile
            entry = out.setdefault(name, {"profile": name, "group": (s.group_name or "").lower(),
                                          "since": meta.get("profile_broken_at"), "sources": []})
            entry["sources"].append(s.name)
    return sorted(out.values(), key=lambda r: r["profile"])
