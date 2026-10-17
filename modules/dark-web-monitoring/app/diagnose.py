"""Collector diagnosis for operators: `python -m app.diagnose` inside the worker
container.

Prints the worker heartbeat, the last recorded Tor check, the same connector table
as the Connectors page, and a live probe of each upstream (HTTP status and byte
count only). Header values, API keys and cookies are never printed.

Options:
  --no-probe   skip the live upstream probes (database only)
"""
from __future__ import annotations

import argparse
import sys
from typing import Callable, TextIO

import httpx

from . import connectors
from .config import settings
from .db import SessionLocal


def _http_get(probe: connectors.Probe) -> tuple[int, int]:
    kwargs: dict = {"timeout": 45, "follow_redirects": True,
                    "headers": {"User-Agent": settings.user_agent, **probe.headers}}
    if probe.tor:
        kwargs["proxy"] = settings.tor_proxy
    with httpx.Client(**kwargs) as c:
        r = c.get(probe.url)
        return r.status_code, len(r.content)


def _fmt_ts(v) -> str:
    return v.strftime("%Y-%m-%d %H:%M") if v else "never"


def _scrub(text: str) -> str:
    """Belt and braces: drop any configured secret that might appear in an error."""
    for secret in (settings.hibp_api_key, settings.ransomware_live_api_key, settings.telegram_api_hash):
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def _url_for_display(url: str) -> str:
    u = httpx.URL(url)
    return str(u.copy_with(query=None)) if u.query else url


def report(out: TextIO = sys.stdout, probe: bool = True,
           get: Callable[[connectors.Probe], tuple[int, int]] = _http_get) -> int:
    """Print the report. Returns a process exit code: 0 healthy, 1 when the worker
    or Tor is down or a configured connector failed."""
    db = SessionLocal()
    try:
        h = connectors.health_summary(db)
    finally:
        db.close()

    def w(line: str = "") -> None:
        out.write(_scrub(line) + "\n")

    age = h["heartbeat_age_seconds"]
    tor = h["tor"] or {}
    w("Vendetta Dark Web Monitoring: collector diagnosis")
    w(f"module_enabled: {settings.module_enabled}")
    w(f"worker heartbeat age: {'never' if age is None else f'{age}s'}")
    if tor:
        w(f"tor: is_tor={tor.get('is_tor')} reachable={tor.get('reachable')} exit_ip={tor.get('exit_ip') or '-'} "
          f"checked_at={tor.get('checked_at')} error={tor.get('error') or '-'}")
    else:
        w("tor: no check recorded")
    w("")
    cols = ("connector", "state", "configured", "last run", "last ok", "24h", "7d", "newest", "error / reason")
    w(" | ".join(cols))
    for r in h["connectors"]:
        newest = r["newest_published"].strftime("%Y-%m-%d") if r["newest_published"] else "none"
        note = r["error"] or r["reason"] or ""
        w(" | ".join([r["key"], r["state"], "yes" if r["configured"] else "no", _fmt_ts(r["last_run_at"]),
                      _fmt_ts(r["last_ok"]), str(r["items_24h"]), str(r["items_7d"]), newest, note[:160]]))
    if h["banner"]["level"]:
        w("")
        w(f"banner ({h['banner']['level']}): " + " ".join(h["banner"]["messages"]))

    if probe:
        w("")
        w("live upstream probes (status, bytes):")
        for c in connectors.CONNECTORS:
            for p in c.probes():
                try:
                    status, size = get(p)
                    w(f"  {c.key}: {status} {size}B {p.label} {_url_for_display(p.url)}{' via Tor' if p.tor else ''}")
                except Exception as e:  # noqa: BLE001
                    w(f"  {c.key}: ERR {type(e).__name__} {p.label} {_url_for_display(p.url)}{' via Tor' if p.tor else ''}")
    return 1 if h["banner"]["level"] == "red" or any(r["state"] == "fail" for r in h["connectors"]) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.diagnose", description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-probe", action="store_true", help="skip live upstream probes")
    args = ap.parse_args(argv)
    return report(probe=not args.no_probe)


if __name__ == "__main__":
    sys.exit(main())
