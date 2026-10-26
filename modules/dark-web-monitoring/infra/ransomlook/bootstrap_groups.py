# SPDX-License-Identifier: GPL-3.0-or-later
"""Seed an empty RansomLook instance with groups and leak-site locations.

Runs inside the RansomLook container, against RansomLook's own code, so it is
licensed GPL-3.0-or-later like RansomLook itself. It reads a public instance's
open endpoints (no key): /api/hot/365 for the groups active in the last year and
/api/group/<name> for each group's locations, then registers every leak-site
location with RansomLook's own adder(). Chat, admin and clearnet locations are
skipped, and a group already in the local database is left untouched, so a
restart never overwrites what this instance has learned."""
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, "/opt/RansomLook")

from ransomlook import ransomlook  # noqa: E402
from ransomlook.default import DB_GROUPS  # noqa: E402

UA = "VendettaCyber-RansomLook-bootstrap/1 (+https://vendettacd.io)"


def get(url, limit=40 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f"{url}: response larger than {limit} bytes")
    return json.loads(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="base", default="https://www.ransomlook.io")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--pause", type=float, default=1.0)
    args = ap.parse_args()
    base = args.base.rstrip("/")
    added = skipped = failed = 0
    for row in get(f"{base}/api/hot/{args.days}").get("rows", []):
        name = str(row.get("group") or "").strip().lower()
        if not name:
            continue
        if ransomlook.checkexisting(name, DB_GROUPS):
            skipped += 1
            continue
        time.sleep(args.pause)
        try:
            data = get(f"{base}/api/group/{urllib.parse.quote(name, safe='')}")
        except Exception as e:  # noqa: BLE001
            print(f"[bootstrap] {name}: {e}")
            failed += 1
            continue
        locs = data[0].get("locations") if isinstance(data, list) and data and isinstance(data[0], dict) else []
        n = 0
        for loc in locs or []:
            slug = str(loc.get("slug") or "").strip()
            if not slug or ".onion" not in slug or loc.get("chat") or loc.get("admin"):
                continue
            ransomlook.adder(name, slug, DB_GROUPS, fs=bool(loc.get("fs")))
            n += 1
        if n:
            added += 1
    print(f"[bootstrap] groups added {added}, already present {skipped}, failed {failed}")


if __name__ == "__main__":
    main()
