"""Microsoft 365 unified audit log (Office 365 Management Activity API).

One record is one audit record from a content blob (Audit.Exchange,
Audit.AzureActiveDirectory, Audit.SharePoint, Audit.General). Every record carries
the common schema (Id, CreationTime, Operation, Workload, UserId, ClientIP,
ResultStatus); the rest depends on the workload.

Exchange admin cmdlets (New-InboxRule, Set-Mailbox, ...) carry their arguments in
`Parameters` as [{Name, Value}]; Outlook clients that change rules through
UpdateInboxRules carry them in `OperationProperties`. Both are kept under
unmapped.parameters as a name to value dict, because forwarding and delete rules
are the most common business email compromise persistence and the detection rules
read them there.

CreationTime has no zone designator; the API documents it as UTC.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import guarded, ip, lst, obj, require, text

VENDOR, PRODUCT = "Microsoft", "Microsoft 365"

_WEB = {
    "MailItemsAccessed": 2, "FileAccessed": 2, "FileDownloaded": 2, "FilePreviewed": 2,
    "FileDeleted": 4, "FileRecycled": 4, "FileUploaded": 1, "FileModified": 3,
    "SharingSet": 8, "AnonymousLinkCreated": 8, "SharingInvitationCreated": 8, "CompanyLinkCreated": 8,
}
_RULES = {"New-InboxRule": 1, "Set-InboxRule": 3, "UpdateInboxRules": 3, "Enable-InboxRule": 3,
          "Remove-InboxRule": 4, "Disable-InboxRule": 3}
_RULE_RISK = ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "MoveToFolder",
              "MarkAsRead", "SoftDeleteMessage")
_VERB = {"New": 1, "Add": 1, "Get": 2, "Set": 3, "Update": 3, "Enable": 3, "Disable": 3, "Remove": 4}


def _params(r: dict) -> dict:
    out: dict = {}
    for key in ("Parameters", "OperationProperties"):
        for p in lst(r.get(key), key):
            p = obj(p, key)
            name = text(p.get("Name"))
            if name and name not in out:
                v = p.get("Value")
                out[name] = v if isinstance(v, (str, int, float, bool)) or v is None else str(v)
    return out


def _status(r: dict) -> int | None:
    s = (text(r.get("ResultStatus")) or "").lower()
    if s in ("succeeded", "success", "true", "partiallysucceeded"):
        return 1
    if s in ("failed", "failure", "false"):
        return 2
    return None


def _verb_activity(op: str) -> int:
    head = op.split("-", 1)[0] if "-" in op else ""
    return _VERB.get(head, 99)


@guarded
def _audit(r: dict) -> dict | None:
    require(r, "Id", "CreationTime", "Operation")
    op = str(r["Operation"])
    params = _params(r)
    status = _status(r)
    src_ip = ip(r.get("ClientIP")) or ip(r.get("ClientIPAddress")) or ip(r.get("ActorIpAddress"))
    user_id = text(r.get("UserId"))
    actor = {"user": ocsf.user(name=user_id, uid=text(r.get("UserKey")),
                               email=user_id if user_id and "@" in user_id else None),
             "app_name": text(r.get("ClientInfoString")) or text(r.get("ApplicationId"))}
    workload = text(r.get("Workload"))
    common = dict(time=r.get("CreationTime"), product=PRODUCT, vendor=VENDOR, uid=r.get("Id"), status_id=status,
                  actor=actor, src_endpoint=ocsf.endpoint(ip=src_ip),
                  http_request={"user_agent": text(r.get("UserAgent"))})
    unmapped = {"record_type": r.get("RecordType"), "workload": workload, "organization_id": text(r.get("OrganizationId")),
                "user_type": r.get("UserType"), "result_status": text(r.get("ResultStatus")),
                "object_id": text(r.get("ObjectId")), "parameters": params or None}

    if op in _RULES:
        risky = sorted(k for k in params if k in _RULE_RISK and str(params[k]).strip().lower() not in ("", "false"))
        if op == "UpdateInboxRules":
            # Outlook clients put the actions in RuleActions; look for the same words there.
            actions = str(params.get("RuleActions") or "")
            risky += [w for w in ("Forward", "Redirect", "Delete", "Move") if w in actions and w not in risky]
        unmapped["rule_risk"] = risky or None
        return ocsf.event("api_activity", _RULES[op], severity=3 if risky else 1,
                          message=f"{op} on {r.get('ObjectId') or user_id or 'a mailbox'}",
                          api={"operation": op, "service": {"name": workload}},
                          resources=[ocsf.prune({"name": text(params.get("Name")) or text(params.get("RuleName"))
                                                 or text(r.get("ObjectId")), "type": "InboxRule"})],
                          unmapped=ocsf.prune(unmapped), **common)
    if op == "Set-Mailbox":
        fwd = text(params.get("ForwardingSmtpAddress")) or text(params.get("ForwardingAddress"))
        unmapped["forwarding"] = fwd
        return ocsf.event("api_activity", 3, severity=3 if fwd else 1,
                          message=f"Set-Mailbox on {r.get('ObjectId') or 'a mailbox'}"
                                  + (f" forwarding to {fwd}" if fwd else ""),
                          api={"operation": op, "service": {"name": workload}},
                          resources=[ocsf.prune({"name": text(r.get("ObjectId")) or text(params.get("Identity")),
                                                 "type": "Mailbox"})],
                          unmapped=ocsf.prune(unmapped), **common)
    if op in ("Add-MailboxPermission", "Remove-MailboxPermission", "Add-RecipientPermission"):
        rights = text(params.get("AccessRights"))
        grantee = text(params.get("User")) or text(params.get("Trustee"))
        return ocsf.event("user_access", 2 if op.startswith("Remove") else 1,
                          severity=3 if rights and "FullAccess" in rights and not op.startswith("Remove") else 1,
                          message=f"{op} {rights or ''} for {grantee or 'a user'} on {r.get('ObjectId') or 'a mailbox'}",
                          user=ocsf.user(name=grantee), privileges=[rights] if rights else None,
                          resources=[ocsf.prune({"name": text(r.get("ObjectId")) or text(params.get("Identity")),
                                                 "type": "Mailbox"})],
                          unmapped=ocsf.prune(unmapped), **common)
    if op in _WEB:
        url = text(r.get("ObjectId")) if str(r.get("ObjectId") or "").startswith("http") else None
        resources = [ocsf.prune({"name": text(r.get("SourceFileName")) or text(r.get("ObjectId")),
                                 "type": text(r.get("ItemType")), "url_string": url,
                                 "uid": text(r.get("ListItemUniqueId"))})]
        if op == "MailItemsAccessed":
            folders = lst(r.get("Folders"), "Folders")
            unmapped["mailbox_owner"] = text(r.get("MailboxOwnerUPN"))
            unmapped["folders"] = [text(obj(f).get("Path")) for f in folders][:20] or None
            unmapped["items_accessed"] = sum(len(lst(obj(f).get("FolderItems"))) for f in folders) or None
            resources = [ocsf.prune({"name": text(r.get("MailboxOwnerUPN")), "type": "Mailbox"})]
        unmapped.update({"site_url": text(r.get("SiteUrl")), "relative_url": text(r.get("SourceRelativeUrl")),
                         "target_user": text(r.get("TargetUserOrGroupName")),
                         "event_data": text(r.get("EventData"))})
        sev = 2 if op == "AnonymousLinkCreated" else 1
        return ocsf.event("web_resources_activity", _WEB[op], severity=sev,
                          message=f"{op} {resources[0].get('name') or ''}".strip(),
                          web_resources=resources, unmapped=ocsf.prune(unmapped), **common)
    if op in ("UserLoggedIn", "UserLoginFailed"):
        ok = op == "UserLoggedIn"
        ext = {}
        for p in lst(r.get("ExtendedProperties"), "ExtendedProperties"):
            p = obj(p)
            if text(p.get("Name")):
                ext[str(p["Name"])] = p.get("Value")
        unmapped.update({"logon_error": text(r.get("LogonError")), "application_id": text(r.get("ApplicationId")),
                         "request_type": text(ext.get("RequestType")),
                         "result_status_detail": text(ext.get("ResultStatusDetail"))})
        common["status_id"] = 1 if ok else 2
        common["http_request"] = {"user_agent": text(ext.get("UserAgent")) or text(r.get("UserAgent"))}
        return ocsf.event("authentication", 1, severity=1 if ok else 2,
                          message=f"{op} {user_id or ''}".strip(),
                          user=ocsf.user(name=user_id, email=user_id if user_id and "@" in user_id else None),
                          status_detail=text(r.get("LogonError")), unmapped=ocsf.prune(unmapped), **common)
    return ocsf.event("api_activity", _verb_activity(op), severity=1, message=op,
                      api={"operation": op, "service": {"name": workload}},
                      resources=[ocsf.prune({"name": text(r.get("ObjectId"))})] if text(r.get("ObjectId")) else None,
                      unmapped=ocsf.prune(unmapped), **common)


register(Mapper(
    key="m365_audit", name="Microsoft 365 unified audit log", vendor=VENDOR, product=PRODUCT, family="saas",
    classes=("api_activity", "user_access", "web_resources_activity", "authentication"),
    map=_audit, uid=lambda r: str(r.get("Id") or ""), doors=("pull", "push")))
