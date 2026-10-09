"""Parser profiles. A profile is a small YAML file describing how to read one kind
of site with CSS selectors, so the delivery team adds a new ransomware group or
forum by dropping in a file, not by writing Python.

Leak-site profile (kind: leak):
  list_selector      CSS selector for each victim entry on the index page
  title_selector     victim name within an entry (relative)
  link_selector      anchor to the victim's own post (relative); href is followed
  desc_selector      optional description within an entry
  date_selector      optional published date within an entry
  post_title_selector / post_body_selector  selectors on the followed post page

Forum profile (kind: forum):
  thread_selector    CSS selector for each thread row on a board page
  thread_link_selector  anchor to the thread (relative)
  thread_title_selector thread title (relative)
  page_param         query param for pagination (e.g. page); pages walked until max_pages
  post_selector      CSS selector for each message on a thread page
  author_selector / body_selector / date_selector  within a message

A profile with no selectors falls back to whole-page text, which is what the
generic onion crawler already does. Selectors only add structure."""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger(__name__)
PROFILE_DIR = Path(__file__).parent / "profiles"


@lru_cache(maxsize=1)
def _all() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not PROFILE_DIR.exists():
        return out
    for f in sorted(PROFILE_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text()) or {}
            data["name"] = f.stem
            out[f.stem] = data
        except Exception as e:  # noqa: BLE001
            log.error("bad profile %s: %s", f, e)
    return out


def get(name: str) -> dict | None:
    return _all().get(name)


def all_profiles() -> dict[str, dict]:
    return _all()


def reload() -> None:
    _all.cache_clear()
