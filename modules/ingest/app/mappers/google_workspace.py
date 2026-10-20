"""Google Workspace: Admin SDK Reports API activities (login, admin, token, drive).

One record is one activity resource from
GET /admin/reports/v1/activity/users/all/applications/{application}. An activity
can carry several entries in `events[]`; for login, token and most drive activity
there is one, and for admin activity the first entry names the action taken. This
mapper maps the first event and keeps the names of any further events under
unmapped.other_events, so one vendor record stays one leaf of a receipt.

The dedupe id is id.uniqueQualifier plus id.time, because Google documents that
uniqueQualifier alone can repeat across activities.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import guarded, ip, lst, obj, require, text

VENDOR, PRODUCT = "Google", "Google Workspace"

_LOGIN = {"login_success": (1, 1), "login_failure": (1, 2), "suspicious_login": (1, 99),
          "suspicious_login_less_secure_app": (1, 99), "suspicious_programmatic_login": (1, 99),
          "logout": (2, 1), "login_challenge": (99, None), "login_verification": (99, None),
          "gov_attack_warning": (99, None)}
_DRIVE = {"view": 2, "preview": 2, "download": 7, "print": 7, "copy": 1, "create": 1, "upload": 1,
          "edit": 3, "rename": 3, "move": 3, "delete": 4, "trash": 4, "untrash": 3,
          "change_user_access": 8, "change_document_visibility": 8, "change_document_access_scope": 8,
          "change_acl_editors": 8, "shared_drive_membership_change": 8}
_ADMIN_VERB = {"CREATE": 1, "ADD": 1, "ASSIGN": 1, "GRANT": 1, "CHANGE": 3, "UPDATE": 3, "EDIT": 3, "TOGGLE": 3,
               "SET": 3, "ENABLE": 3, "DISABLE": 3, "SUSPEND": 3, "UNSUSPEND": 3, "RENAME": 3, "MOVE": 3,
               "DELETE": 4, "REMOVE": 4, "REVOKE": 4, "VIEW": 2, "DOWNLOAD": 2}


def _params(ev: dict) -> dict:
    out: dict = {}
    for p in lst(ev.get("parameters"), "parameters"):
        p = obj(p, "parameter")
        name = text(p.get("name"))
        if not name:
            continue
        for k in ("value", "boolValue", "intValue", "multiValue", "multiIntValue"):
            if k in p:
                out[name] = p[k]
                break
    return out


@guarded
def _activity(r: dict) -> dict | None:
    rid = obj(r.get("id"), "id")
    require(rid, "time", "applicationName")
    events = [obj(e, "event") for e in lst(r.get("events"), "events")]
    if not events:
        raise ocsf.MappingError("activity has no events")
    ev = events[0]
    name = text(ev.get("name")) or ""
    params = _params(ev)
    app = str(rid["applicationName"]).lower()
    actor = obj(r.get("actor"), "actor")
    email = text(actor.get("email"))
    actor_user = ocsf.user(name=email or text(actor.get("key")), uid=text(actor.get("profileId")), email=email,
                           type_=text(actor.get("callerType")))
    common = dict(time=rid["time"], product=PRODUCT, vendor=VENDOR,
                  uid=_uid(r) or None, actor={"user": actor_user},
                  src_endpoint=ocsf.endpoint(ip=ip(r.get("ipAddress"))))
    unmapped = {"application": app, "event_type": text(ev.get("type")), "event_name": name,
                "customer_id": text(rid.get("customerId")), "parameters": params or None,
                "other_events": [text(e.get("name")) for e in events[1:]] or None,
                "owner_domain": text(r.get("ownerDomain"))}

    if app == "login":
        aid, status = _LOGIN.get(name, (99, None))
        if name == "login_success" and params.get("is_suspicious") is True:
            status, sev = 1, 4
        elif name.startswith("suspicious") or name == "gov_attack_warning":
            sev = 4
        elif status == 2:
            sev = 2
        else:
            sev = 1
        if name == "login_failure":
            unmapped["failure_type"] = text(params.get("login_failure_type"))
        challenge = params.get("login_challenge_method")
        is_mfa = None
        if isinstance(challenge, list):
            is_mfa = any(str(c).lower() not in ("password", "none") for c in challenge) or None
        return ocsf.event("authentication", aid, severity=sev, status_id=status,
                          message=f"{name} for {email or 'unknown user'}",
                          user=ocsf.user(name=email, email=email, uid=text(actor.get("profileId"))),
                          is_mfa=is_mfa, auth_protocol=text(params.get("login_type")),
                          unmapped=ocsf.prune(unmapped), **common)
    if app == "admin":
        if name in ("ASSIGN_ROLE", "UNASSIGN_ROLE"):
            target = text(params.get("USER_EMAIL"))
            role = text(params.get("ROLE_NAME"))
            grant = name == "ASSIGN_ROLE"
            return ocsf.event("user_access", 1 if grant else 2, severity=3 if grant else 1,
                              message=f"{name} {role or ''} to {target or 'a user'}",
                              user=ocsf.user(name=target, email=target), privileges=[role] if role else None,
                              unmapped=ocsf.prune(unmapped), **common)
        aid = _ADMIN_VERB.get(name.split("_", 1)[0], 99)
        return ocsf.event("api_activity", aid, severity=1, message=name,
                          api={"operation": name, "service": {"name": "Admin console"}},
                          resources=[ocsf.prune({"name": text(params.get("USER_EMAIL")) or text(params.get("GROUP_EMAIL"))
                                                 or text(params.get("SETTING_NAME")), "type": text(ev.get("type"))})],
                          unmapped=ocsf.prune(unmapped), **common)
    if app == "token":
        scopes = params.get("scope")
        scopes = [str(s) for s in scopes] if isinstance(scopes, list) else ([str(scopes)] if scopes else [])
        aid = 1 if name == "authorize" else 99
        sev = 1
        if aid == 1 and any(s.endswith(("/auth/gmail.readonly", "mail.google.com/", "/auth/drive")) for s in scopes):
            sev = 2  # broad mailbox or drive grants to a third-party app are worth a look
        unmapped.update({"client_id": text(params.get("client_id")), "app_name": text(params.get("app_name")),
                         "client_type": text(params.get("client_type"))})
        return ocsf.event("authorize_session", aid, severity=sev,
                          message=f"{name} {params.get('app_name') or params.get('client_id') or ''}".strip(),
                          user=actor_user, privileges=scopes[:50] or None,
                          unmapped=ocsf.prune(unmapped), **common)
    if app == "drive":
        aid = _DRIVE.get(name, 99)
        vis = (text(params.get("visibility")) or "").lower()
        sev = 3 if aid == 8 and vis in ("people_with_link", "public_on_the_web") else 1
        unmapped.update({"visibility": vis or None, "target_user": text(params.get("target_user")),
                         "owner": text(params.get("owner"))})
        return ocsf.event("web_resources_activity", aid, severity=sev,
                          message=f"{name} {params.get('doc_title') or ''}".strip(),
                          web_resources=[ocsf.prune({"name": text(params.get("doc_title")),
                                                     "uid": text(params.get("doc_id")),
                                                     "type": text(params.get("doc_type"))})],
                          unmapped=ocsf.prune(unmapped), **common)
    return ocsf.event("api_activity", 99, severity=1, message=name or app,
                      api={"operation": name, "service": {"name": app}}, unmapped=ocsf.prune(unmapped), **common)


def _uid(r: dict) -> str:
    rid = r.get("id") if isinstance(r.get("id"), dict) else {}
    if not rid.get("uniqueQualifier") or not rid.get("time"):
        return ""
    return f"{rid['uniqueQualifier']}:{rid['time']}"


register(Mapper(
    key="google_workspace", name="Google Workspace audit", vendor=VENDOR, product=PRODUCT, family="saas",
    classes=("authentication", "api_activity", "user_access", "authorize_session", "web_resources_activity"),
    map=_activity, uid=_uid, doors=("pull", "push")))
