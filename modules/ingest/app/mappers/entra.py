"""Microsoft Entra ID: sign-in logs and directory audit logs (Microsoft Graph).

Sign-ins come from GET /auditLogs/signIns, audits from GET /auditLogs/directoryAudits.
Both arrive as Graph JSON objects; the same objects arrive through Event Hubs
diagnostic export inside `records[].properties`, which the push door unwraps first.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register

PRODUCT, VENDOR = "Entra ID", "Microsoft"

# Graph riskLevelAggregated / riskLevelDuringSignIn words to OCSF severity.
_RISK = {"high": 4, "medium": 3, "low": 2, "none": 1, "hidden": 1}


def _signin(r: dict) -> dict | None:
    status = r.get("status") or {}
    code = status.get("errorCode")
    ok = code in (0, "0", None)
    loc = r.get("location") or {}
    geo = loc.get("geoCoordinates") or {}
    dev = r.get("deviceDetail") or {}
    risk = (r.get("riskLevelDuringSignIn") or r.get("riskLevelAggregated") or "none").lower()
    sev = _RISK.get(risk, 1)
    if not ok and sev < 2:
        sev = 2
    mfa = (r.get("mfaDetail") or {}).get("authMethod") or ""
    return ocsf.event(
        "authentication", 1, time=r.get("createdDateTime"), product=PRODUCT, vendor=VENDOR, uid=r.get("id"),
        severity=sev, status_id=1 if ok else 2,
        message=f"Sign-in {'succeeded' if ok else 'failed'} for {r.get('userPrincipalName') or 'unknown user'}"
                f" to {r.get('appDisplayName') or 'an application'}",
        status_code=str(code) if code not in (None, 0, "0") else None,
        status_detail=status.get("failureReason") if not ok else None,
        is_mfa=bool(mfa) or (r.get("authenticationRequirement") == "multiFactorAuthentication"),
        user=ocsf.user(name=r.get("userPrincipalName"), uid=r.get("userId"), email=r.get("userPrincipalName"),
                       type_=r.get("userType")),
        actor={"user": ocsf.user(name=r.get("userPrincipalName"), uid=r.get("userId"),
                                 email=r.get("userPrincipalName")),
               "app_name": r.get("appDisplayName")},
        src_endpoint=ocsf.endpoint(ip=r.get("ipAddress"), location=ocsf.location(
            country=loc.get("countryOrRegion"), city=loc.get("city"), region=loc.get("state"),
            lat=geo.get("latitude"), lon=geo.get("longitude"))),
        device=ocsf.device(hostname=dev.get("displayName"), uid=dev.get("deviceId"),
                           os_name=dev.get("operatingSystem")),
        service={"name": r.get("resourceDisplayName"), "uid": r.get("resourceId")},
        http_request={"user_agent": r.get("userAgent")},
        unmapped=ocsf.prune({"risk_level": risk, "risk_state": r.get("riskState"),
                             "conditional_access_status": r.get("conditionalAccessStatus"),
                             "client_app": r.get("clientAppUsed"), "app_id": r.get("appId"),
                             "auth_method": mfa, "is_interactive": r.get("isInteractive"),
                             "correlation_id": r.get("correlationId")}),
    )


register(Mapper(
    key="entra_signins", name="Entra ID sign-ins", vendor=VENDOR, product=PRODUCT, family="identity",
    classes=("authentication",), map=_signin, uid=lambda r: str(r.get("id") or ""), doors=("pull", "push")))


# Directory audit activityDisplayName prefixes to OCSF classes and activities.
_AUDIT = [
    ("Add member to role", "user_access", 1),
    ("Remove member from role", "user_access", 2),
    ("Add eligible member to role", "user_access", 1),
    ("Add member to group", "group_management", 3),
    ("Remove member from group", "group_management", 4),
    ("Add group", "group_management", 6),
    ("Delete group", "group_management", 5),
    ("Add user", "account_change", 1),
    ("Delete user", "account_change", 6),
    ("Disable account", "account_change", 5),
    ("Enable account", "account_change", 2),
    ("Reset user password", "account_change", 4),
    ("Change user password", "account_change", 3),
    ("Reset password", "account_change", 4),
    ("Change password", "account_change", 3),
    ("User registered security info", "account_change", 10),
    ("User deleted security info", "account_change", 11),
    ("Consent to application", "authorize_session", 1),
    ("Add app role assignment", "authorize_session", 1),
    ("Add delegated permission grant", "authorize_session", 1),
    ("Add service principal credentials", "api_activity", 1),
    ("Update application", "api_activity", 3),
    ("Add application", "api_activity", 1),
    ("Add service principal", "api_activity", 1),
    ("Update conditional access policy", "api_activity", 3),
    ("Delete conditional access policy", "api_activity", 4),
    ("Add conditional access policy", "api_activity", 1),
    ("Set federation settings on domain", "api_activity", 3),
    ("Set domain authentication", "api_activity", 3),
]


def _audit(r: dict) -> dict | None:
    act = r.get("activityDisplayName") or ""
    cls, aid = "api_activity", 99
    for prefix, c, a in _AUDIT:
        if act.lower().startswith(prefix.lower()):
            cls, aid = c, a
            break
    by = r.get("initiatedBy") or {}
    by_user = by.get("user") or {}
    by_app = by.get("app") or {}
    targets = r.get("targetResources") or []
    tgt = targets[0] if targets else {}
    ok = (r.get("result") or "success").lower() == "success"
    props = []
    for t in targets:
        for mp in t.get("modifiedProperties") or []:
            props.append({"name": mp.get("displayName"), "old": mp.get("oldValue"), "new": mp.get("newValue")})
    target_user = ocsf.user(name=tgt.get("userPrincipalName") or tgt.get("displayName"), uid=tgt.get("id"),
                            type_=tgt.get("type")) if tgt else None
    attrs = {
        "actor": {"user": ocsf.user(name=by_user.get("userPrincipalName") or by_app.get("displayName"),
                                    uid=by_user.get("id") or by_app.get("servicePrincipalId"),
                                    email=by_user.get("userPrincipalName")),
                  "app_name": by_app.get("displayName")},
        "src_endpoint": ocsf.endpoint(ip=by_user.get("ipAddress")),
        "api": {"operation": act, "service": {"name": r.get("loggedByService") or "Core Directory"}},
        "unmapped": ocsf.prune({"category": r.get("category"), "correlation_id": r.get("correlationId"),
                                "targets": [ocsf.prune({"type": t.get("type"), "id": t.get("id"),
                                                        "name": t.get("displayName") or t.get("userPrincipalName")})
                                            for t in targets],
                                "modified_properties": props[:20]}),
    }
    if cls in ("account_change", "user_access", "group_management"):
        attrs["user"] = target_user
    if cls == "group_management":
        grp = next((t for t in targets if (t.get("type") or "").lower() == "group"), None)
        if grp:
            attrs["group"] = {"name": grp.get("displayName"), "uid": grp.get("id")}
    if cls == "user_access":
        role = next((p for p in props if (p.get("name") or "") in ("Role.DisplayName", "Role.TemplateId")), None)
        attrs["privileges"] = [str(role["new"]).strip('"')] if role and role.get("new") else None
    if cls == "api_activity":
        attrs["resources"] = [ocsf.prune({"name": t.get("displayName"), "uid": t.get("id"), "type": t.get("type")})
                              for t in targets] or None
    sev = 1
    if cls == "user_access" and aid == 1:
        sev = 3
    return ocsf.event(cls, aid, time=r.get("activityDateTime"), product=PRODUCT, vendor=VENDOR, uid=r.get("id"),
                      severity=sev, status_id=1 if ok else 2, message=act, **attrs)


register(Mapper(
    key="entra_audit", name="Entra ID directory audit", vendor=VENDOR, product=PRODUCT, family="identity",
    classes=("account_change", "user_access", "group_management", "authorize_session", "api_activity"),
    map=_audit, uid=lambda r: str(r.get("id") or ""), doors=("pull", "push")))
