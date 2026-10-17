"""Who is talking. A Slack user id becomes a work email through users.info, and the
email is checked against the platform staff roster for the module the command
touches. The roster decides everything; a Slack workspace member who is not on it
cannot use the responder at all.

- incident-response grant: viewer reads cases, analyst or admin changes them.
- sabine grant: analyst or admin may ask SABINE and decide her proposals.

The roster is asked live with a one-minute cache. If the control plane cannot be
reached, the last roster this process saw is used so a responder is not locked
out mid-incident; if it has never been seen, everyone is refused (fail closed).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import time

from . import reach, slack
from .config import settings
from .db import SlackUser, utcnow

log = logging.getLogger(__name__)
WRITE_ROLES = ("analyst", "admin")
READ_ROLES = ("viewer", "analyst", "admin")
_ROSTER: dict[str, dict] = {}   # module -> {"at": float, "body": dict, "ok": bool, "detail": str}
USER_TTL = dt.timedelta(hours=1)


class Refused(Exception):
    """Raised with a sentence the person can read."""


@dataclasses.dataclass
class Person:
    slack_id: str
    email: str
    name: str
    roles: dict  # module -> role

    def role(self, module: str) -> str:
        return self.roles.get(module, "")

    def can_read(self, module: str = "incident-response") -> bool:
        return self.role(module) in READ_ROLES

    def can_write(self, module: str = "incident-response") -> bool:
        return self.role(module) in WRITE_ROLES

    @property
    def first(self) -> str:
        n = (self.name or self.email.split("@")[0]).split()[0]
        return n.split(".")[0].capitalize()


def _domain_ok(email: str) -> bool:
    domains = [d.strip().lower().lstrip("@") for d in (settings.internal_email_domains or "").split(",") if d.strip()]
    return bool(email) and (not domains or email.rsplit("@", 1)[-1].lower() in domains)


def slack_user(db, slack_id: str) -> SlackUser:
    """users.info, cached for an hour."""
    row = db.get(SlackUser, slack_id)
    if row is not None and row.email and utcnow() - row.fetched_at < USER_TTL:
        return row
    try:
        u = slack.call("users.info", user=slack_id)["user"]
    except slack.SlackError as e:
        if row is not None and row.email:
            return row  # Slack hiccup: the cached answer is better than refusing
        raise Refused("I could not look you up in Slack just now. Try again in a moment.") from e
    prof = u.get("profile") or {}
    if row is None:
        row = SlackUser(slack_id=slack_id)
        db.add(row)
    row.email = (prof.get("email") or "").strip().lower()
    row.name = prof.get("real_name") or u.get("real_name") or u.get("name") or ""
    row.is_bot = bool(u.get("is_bot")) or bool(u.get("deleted"))
    row.fetched_at = utcnow()
    db.commit()
    return row


def roster(module: str) -> dict | None:
    """The platform roster for one module, cached for a minute, last good on failure."""
    cached = _ROSTER.get(module)
    if cached and cached.get("ok") and time.time() - cached["at"] < 60:
        return cached["body"]
    r = reach.get("platform", "/api/platform/staff", params={"module": module}, timeout=6.0)
    if r["ok"] and isinstance(r["data"], dict):
        _ROSTER[module] = {"at": time.time(), "good_at": time.time(), "body": r["data"], "ok": True, "detail": "ok"}
        return r["data"]
    log.warning("staff roster for %s unavailable: %s", module, r["detail"])
    if cached and cached.get("body") is not None:
        cached.update(ok=False, detail=r["detail"])
        return cached["body"]
    _ROSTER[module] = {"at": time.time(), "body": None, "ok": False, "detail": r["detail"]}
    return None


STALE_WRITES_AFTER = 15 * 60


def stale(module: str) -> bool:
    """True when the roster for a module is a last-good copy older than fifteen
    minutes: reads continue through a control-plane outage, changes stop, so a
    person removed during the outage cannot keep acting on cases."""
    cached = _ROSTER.get(module)
    return bool(cached and not cached.get("ok") and cached.get("good_at") is not None
                and time.time() - cached["good_at"] > STALE_WRITES_AFTER)


def roster_state() -> dict:
    return {m: {"ok": v.get("ok"), "detail": v.get("detail"),
                "at": dt.datetime.fromtimestamp(v["at"], dt.timezone.utc).isoformat() if v.get("at") else "",
                "count": len((v.get("body") or {}).get("staff") or []),
                "governs": bool((v.get("body") or {}).get("governs"))} for m, v in _ROSTER.items()}


def role_for(email: str, module: str) -> str:
    body = roster(module)
    if not body or not body.get("governs"):
        return ""
    for entry in body.get("staff") or []:
        if (entry.get("email") or "").strip().lower() == email and entry.get("role") in READ_ROLES:
            return entry["role"]
    return ""


def resolve(db, slack_id: str, modules: tuple[str, ...] = ("incident-response",)) -> Person:
    """The person behind a Slack user id with their roles, or Refused."""
    u = slack_user(db, slack_id)
    if u.is_bot:
        raise Refused("Bots cannot work cases.")
    if not u.email:
        raise Refused("Your Slack profile has no email I can see, so I cannot match you to the staff roster.")
    if not _domain_ok(u.email):
        raise Refused("This responder is for Vendetta staff. Your Slack email is not on a Vendetta domain.")
    roles = {m: role_for(u.email, m) for m in modules}
    if not any(roles.values()):
        if roster(modules[0]) is None:
            raise Refused("I cannot reach the staff roster on the platform right now, so I cannot confirm your access.")
        raise Refused("You are not on the platform staff roster for this. A platform admin can onboard you on the Staff page.")
    return Person(slack_id=slack_id, email=u.email, name=u.name, roles=roles)


def lookup_by_email(email: str) -> str:
    """Slack user id for a work email, or ""."""
    d = slack.try_call("users.lookupByEmail", email=email)
    return (d or {}).get("user", {}).get("id", "")


def reset_cache() -> None:
    _ROSTER.clear()


