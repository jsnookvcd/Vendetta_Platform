"""Okta: System Log events (GET /api/v1/logs).

One record is one LogEvent. The class follows eventType:

- user.session.start: authentication Logon; user.session.end: authentication Logoff.
- user.authentication.auth_via_mfa, user.mfa.okta_verify.deny_push and
  system.push.send_factor_verify_push: authentication, with the factor outcome in
  unmapped.mfa_result.
- user.account.privilege.grant / revoke: user_access.
- user.account.*, user.lifecycle.* and user.mfa.factor.*: account_change.
- group.user_membership.add / remove: group_management.
- application.*, policy.*, system.* and everything else: api_activity, with the
  activity taken from the verb at the end of the event type when there is one.

`actor` becomes actor.user. `target[]` entries of type User become the event's
user; groups become the group; everything else is listed under resources.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import guarded, ip, lst, obj, require, text

VENDOR, PRODUCT = "Okta", "Okta Identity Cloud"

_MFA = {
    "user.authentication.auth_via_mfa": 1,
    "user.mfa.okta_verify.deny_push": 99,
    "system.push.send_factor_verify_push": 99,
}
_ACCOUNT = {
    "user.account.lock": 9, "user.account.lock.limit": 9, "user.account.unlock": 2,
    "user.account.unlock_by_admin": 2, "user.account.update_password": 3, "user.account.reset_password": 4,
    "user.lifecycle.create": 1, "user.lifecycle.activate": 2, "user.lifecycle.reactivate": 2,
    "user.lifecycle.unsuspend": 2, "user.lifecycle.deactivate": 5, "user.lifecycle.suspend": 5,
    "user.lifecycle.delete.initiated": 6, "user.lifecycle.delete.completed": 6,
    "user.mfa.factor.activate": 10, "user.mfa.factor.deactivate": 11, "user.mfa.factor.reset_all": 11,
    "user.mfa.factor.suspend": 11,
}
_VERB = {"create": 1, "add": 1, "read": 2, "update": 3, "activate": 3, "deactivate": 3, "change": 3,
         "delete": 4, "remove": 4}
_OKTA_SEV = {"DEBUG": 1, "INFO": 1, "WARN": 2, "ERROR": 3}


def _status(result: str | None) -> int | None:
    r = (result or "").upper()
    if r in ("SUCCESS", "ALLOW"):
        return 1
    if r in ("FAILURE", "DENY"):
        return 2
    if r in ("SKIPPED", "CHALLENGE", "UNKNOWN"):
        return 99
    return None


def _okta_user(a: dict) -> dict:
    alt = text(a.get("alternateId"))
    return ocsf.user(name=alt or text(a.get("displayName")), uid=text(a.get("id")),
                     email=alt if alt and "@" in alt else None, type_=text(a.get("type")))


def _classify(event_type: str) -> tuple[str, int]:
    et = event_type.lower()
    if et == "user.session.start":
        return "authentication", 1
    if et == "user.session.end":
        return "authentication", 2
    if et in _MFA:
        return "authentication", _MFA[et]
    if et == "user.account.privilege.grant":
        return "user_access", 1
    if et == "user.account.privilege.revoke":
        return "user_access", 2
    if et.startswith(("user.account.", "user.lifecycle.", "user.mfa.factor.")):
        return "account_change", _ACCOUNT.get(et, 99)
    if et == "group.user_membership.add":
        return "group_management", 3
    if et == "group.user_membership.remove":
        return "group_management", 4
    if et.startswith(("application.", "policy.", "system.")):
        return "api_activity", _VERB.get(et.rsplit(".", 1)[-1], 99)
    return "api_activity", 99


@guarded
def _log(r: dict) -> dict | None:
    require(r, "uuid", "eventType", "published")
    et = str(r["eventType"])
    cls, aid = _classify(et)
    actor = obj(r.get("actor"), "actor")
    client = obj(r.get("client"), "client")
    geo = obj(client.get("geographicalContext"), "geographicalContext")
    gl = obj(geo.get("geolocation"))
    ua = obj(client.get("userAgent"))
    outcome = obj(r.get("outcome"), "outcome")
    result = text(outcome.get("result"))
    auth_ctx = obj(r.get("authenticationContext"), "authenticationContext")
    sec = obj(r.get("securityContext"))
    debug = obj(obj(r.get("debugContext")).get("debugData"))
    targets = [obj(t, "target") for t in lst(r.get("target"), "target")]
    t_users = [t for t in targets if (text(t.get("type")) or "").lower() == "user"]
    t_groups = [t for t in targets if (text(t.get("type")) or "").lower() in ("usergroup", "group")]
    others = [t for t in targets if t not in t_users and t not in t_groups]
    status = _status(result)

    sev = _OKTA_SEV.get((text(r.get("severity")) or "INFO").upper(), 1)
    if cls == "authentication" and status == 2:
        sev = max(sev, 2)
    if et == "user.mfa.okta_verify.deny_push":
        sev = max(sev, 3)  # a user rejecting a push they did not start is an MFA fatigue signal
    if cls == "user_access" and aid == 1:
        sev = max(sev, 3)
    if text(debug.get("threatSuspected")) == "true" or text(debug.get("risk")) and "HIGH" in str(debug.get("risk")):
        sev = max(sev, 3)

    attrs: dict = {
        "actor": {"user": _okta_user(actor), "app_name": text(client.get("id"))},
        "src_endpoint": ocsf.endpoint(ip=ip(client.get("ipAddress")), location=ocsf.location(
            country=text(geo.get("country")), city=text(geo.get("city")), region=text(geo.get("state")),
            lat=gl.get("lat"), lon=gl.get("lon"))),
        "http_request": {"user_agent": text(ua.get("rawUserAgent"))},
    }
    unmapped = {
        "event_type": et, "legacy_event_type": text(r.get("legacyEventType")),
        "outcome_reason": text(outcome.get("reason")),
        "transaction_id": text(obj(r.get("transaction")).get("id")),
        "external_session_id": text(auth_ctx.get("externalSessionId")),
        "zone": text(client.get("zone")), "device": text(client.get("device")),
        "os": text(ua.get("os")), "browser": text(ua.get("browser")),
        "isp": text(sec.get("isp")), "as_org": text(sec.get("asOrg")), "is_proxy": sec.get("isProxy"),
        "request_uri": text(debug.get("requestUri")), "behaviors": text(debug.get("behaviors")),
        "risk": text(debug.get("risk")),
    }
    if cls == "authentication":
        attrs["user"] = _okta_user(t_users[0]) if t_users and et != "user.session.start" else _okta_user(actor)
        attrs["auth_protocol"] = text(auth_ctx.get("authenticationProvider"))
        attrs["is_mfa"] = True if et in _MFA else None
        unmapped.update({"credential_type": text(auth_ctx.get("credentialType")),
                         "credential_provider": text(auth_ctx.get("credentialProvider")),
                         "auth_interface": text(auth_ctx.get("interface")),
                         "auth_step": auth_ctx.get("authenticationStep")})
        if et in _MFA:
            unmapped["mfa_result"] = result
            unmapped["mfa_factor"] = text(debug.get("factor")) or text(auth_ctx.get("credentialType"))
    else:
        attrs["user"] = _okta_user(t_users[0]) if t_users else None
    if cls == "group_management" and t_groups:
        attrs["group"] = {"name": text(t_groups[0].get("displayName")), "uid": text(t_groups[0].get("id"))}
    if cls == "user_access":
        priv = text(debug.get("privilegeGranted")) if aid == 1 else text(debug.get("privilegeRevoked"))
        attrs["privileges"] = [p.strip() for p in priv.split(",") if p.strip()] if priv else None
    if cls == "api_activity":
        attrs["api"] = {"operation": et, "service": {"name": "Okta"}}
    attrs["resources"] = [ocsf.prune({"name": text(t.get("displayName")) or text(t.get("alternateId")),
                                      "uid": text(t.get("id")), "type": text(t.get("type"))})
                          for t in (others if cls != "api_activity" else targets)] or None
    return ocsf.event(cls, aid, time=r.get("published"), product=PRODUCT, vendor=VENDOR, uid=r.get("uuid"),
                      severity=sev, status_id=status, message=text(r.get("displayMessage")) or et,
                      status_detail=text(outcome.get("reason")), unmapped=ocsf.prune(unmapped), **attrs)


register(Mapper(
    key="okta_system_log", name="Okta System Log", vendor=VENDOR, product=PRODUCT, family="identity",
    classes=("authentication", "account_change", "group_management", "user_access", "api_activity"),
    map=_log, uid=lambda r: str(r.get("uuid") or ""), doors=("pull", "push")))
