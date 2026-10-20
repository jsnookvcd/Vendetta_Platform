"""Small helpers shared by the wave 1 mappers.

The module name starts with an underscore so the mapper loader does not import it as
a source. Everything here is pure: no clock, no network, no tenant.
"""
from __future__ import annotations

import functools
import ipaddress
from typing import Any, Callable

from .. import ocsf


def guarded(fn: Callable[[dict], dict | None]) -> Callable[[dict], dict | None]:
    """Turn the accidental exceptions a malformed record causes (a string where an
    object was expected, a list where a number was) into ocsf.MappingError, so the
    pipeline rejects the record with a reason instead of counting a mapper bug."""

    @functools.wraps(fn)
    def wrapper(raw):
        if not isinstance(raw, dict):
            raise ocsf.MappingError("record is not a JSON object")
        try:
            ev = fn(raw)
        except ocsf.MappingError:
            raise
        except (AttributeError, TypeError, KeyError, ValueError, IndexError) as e:
            raise ocsf.MappingError(f"malformed record ({type(e).__name__})") from None
        if ev is not None:
            # ocsf.event tests a value for emptiness before pruning it, so {"user": {}}
            # survives as {}. Drop those so the stored event carries only real values.
            for k in [k for k, v in ev.items() if v == {} or v == []]:
                del ev[k]
        return ev

    return wrapper


def obj(v: Any, what: str = "") -> dict:
    """The value as a dict. None and missing become {}; any other type is malformed."""
    if v is None:
        return {}
    if isinstance(v, dict):
        return v
    raise ocsf.MappingError(f"{what or 'field'} is not an object")


def lst(v: Any, what: str = "") -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    raise ocsf.MappingError(f"{what or 'field'} is not a list")


def text(v: Any) -> str | None:
    if v is None or isinstance(v, (dict, list)):
        return None
    s = str(v).strip()
    return s or None


def require(r: dict, *keys: str) -> None:
    missing = [k for k in keys if r.get(k) in (None, "")]
    if missing:
        raise ocsf.MappingError(f"record has no {', '.join(missing)}")


def ip(v: Any) -> str | None:
    """A bare IP address, or None. Accepts "1.2.3.4", "1.2.3.4:443", "[2001:db8::1]:443"
    and bare IPv6. Anything that does not parse (a service name, "AWS Internal") is None."""
    s = text(v)
    if not s:
        return None
    if s.startswith("["):
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def basename(path: Any) -> str | None:
    s = text(path)
    if not s:
        return None
    return s.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def attack(technique_id: Any, technique_name: Any = None, tactic_id: Any = None, tactic_name: Any = None) -> dict | None:
    """One OCSF attack object, or None when there is no technique id."""
    tid = text(technique_id)
    if not tid:
        return None
    return ocsf.prune({"technique": {"uid": tid, "name": text(technique_name)},
                       "tactic": {"uid": text(tactic_id), "name": text(tactic_name)}})


def dedupe_attacks(items: list) -> list:
    out, seen = [], set()
    for a in items:
        if not a:
            continue
        key = ((a.get("technique") or {}).get("uid"), (a.get("tactic") or {}).get("uid"))
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def finding_activity(created: Any, updated: Any, closed: bool) -> int:
    """Detection finding activity: Close when the vendor closed it, Update when it
    changed after it was created, otherwise Create."""
    if closed:
        return 3
    c, u = ocsf.to_epoch_ms(created), ocsf.to_epoch_ms(updated)
    if c is not None and u is not None and u > c:
        return 2
    return 1


def version_uid(record_id: Any, version: Any) -> str:
    """Dedupe key for a detection that the vendor updates in place: the id plus the
    vendor's last-updated stamp, so a status change is stored as a new event while a
    repeat of the same version in an overlapping window is dropped."""
    rid = text(record_id) or ""
    if not rid:
        return ""
    v = text(version)
    return f"{rid}:{v}" if v else rid
