"""Amazon Web Services: CloudTrail records and GuardDuty findings.

cloudtrail takes one CloudTrail record. CloudTrail log files in S3 hold a
{"Records": [...]} array; the bucket door splits it so each record is one leaf.
EventBridge deliveries of CloudTrail events put the record in `detail`, which is
unwrapped here as well.

guardduty takes one finding, either bare (S3 export, GetFindings) or inside the
EventBridge envelope ({"source": "aws.guardduty", "detail": {...}}). GuardDuty's
EventBridge and S3 export shapes use camelCase keys and the SDK shape uses
PascalCase; both are read.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import finding_activity, guarded, ip, lst, obj, require, text, version_uid

VENDOR = "AWS"

# Verb prefixes of an API action to the API Activity activity id.
_VERBS = [
    (("Create", "Put", "Run", "Start", "Attach", "Add"), 1),
    (("Get", "List", "Describe", "Lookup"), 2),
    (("Update", "Modify", "Set", "Stop", "Detach", "Enable", "Disable"), 3),
    (("Delete", "Remove", "Terminate"), 4),
]
# Actions that blind or weaken logging and detection. Raised to medium; the Sigma
# rules decide whether any of them becomes a detection.
_SENSITIVE = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs",
              "DeleteDetector", "DisassociateFromMasterAccount", "UpdateDetector", "DeleteLogGroup",
              "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "CreateAccessKey", "CreateLoginProfile",
              "UpdateLoginProfile", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
              "DisableKey", "ScheduleKeyDeletion", "LeaveOrganization"}
_DENIED = ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation", "AccessDeniedException")


def verb_activity(name: str) -> int:
    for prefixes, aid in _VERBS:
        for p in prefixes:
            # Match on a word boundary: "Get" in GetObject, not in "Getaway".
            if name.startswith(p) and (len(name) == len(p) or name[len(p)].isupper()):
                return aid
    return 99


def _identity(ui: dict) -> tuple[dict, dict]:
    ctx = obj(ui.get("sessionContext"), "sessionContext")
    issuer = obj(ctx.get("sessionIssuer"), "sessionIssuer")
    attrs = obj(ctx.get("attributes"), "attributes")
    typ = text(ui.get("type"))
    if typ == "AssumedRole":
        name = text(issuer.get("userName")) or text(ui.get("principalId"))
    elif typ == "Root":
        name = "root"
    else:
        name = text(ui.get("userName")) or text(ui.get("invokedBy")) or text(ui.get("principalId"))
    usr = ocsf.prune({**ocsf.user(name=name, uid=text(ui.get("arn")), type_=typ),
                      "uid_alt": text(ui.get("principalId")), "credential_uid": text(ui.get("accessKeyId")),
                      "account": {"uid": text(ui.get("accountId")), "type": "AWS Account"}})
    session = ocsf.prune({"issuer": text(issuer.get("arn")),
                          "is_mfa": {"true": True, "false": False}.get(str(attrs.get("mfaAuthenticated")).lower()),
                          "created_time": ocsf.to_epoch_ms(attrs.get("creationDate")) if attrs.get("creationDate")
                          else None})
    return usr, session


@guarded
def _trail(r: dict) -> dict | None:
    if isinstance(r.get("detail"), dict) and r.get("detail-type"):
        r = r["detail"]
    require(r, "eventTime", "eventName", "eventSource")
    name = str(r["eventName"])
    ui = obj(r.get("userIdentity"), "userIdentity")
    usr, session = _identity(ui)
    err = text(r.get("errorCode"))
    raw_src = text(r.get("sourceIPAddress"))
    src_ip = ip(raw_src)
    region = text(r.get("awsRegion"))
    account = text(r.get("recipientAccountId")) or text(ui.get("accountId"))
    common = dict(time=r["eventTime"], product="CloudTrail", vendor=VENDOR, uid=text(r.get("eventID")),
                  actor={"user": usr, "session": session or None, "invoked_by": text(ui.get("invokedBy"))},
                  src_endpoint=ocsf.endpoint(ip=src_ip) or (
                      {"svc_name": raw_src} if raw_src else None),
                  http_request={"user_agent": text(r.get("userAgent"))},
                  cloud=ocsf.cloud(provider="AWS", account=account, region=region))
    resources = [ocsf.prune({"uid": text(x.get("ARN")), "type": text(x.get("type")),
                             "owner": {"account": {"uid": text(x.get("accountId"))}}})
                 for x in (obj(x, "resource") for x in lst(r.get("resources"), "resources"))] or None
    unmapped = {"event_type": text(r.get("eventType")), "event_category": text(r.get("eventCategory")),
                "read_only": r.get("readOnly"), "management_event": r.get("managementEvent"),
                "request_id": text(r.get("requestID")), "error_message": text(r.get("errorMessage")),
                "source_ip_address": raw_src if raw_src and not src_ip else None,
                "shared_event_id": text(r.get("sharedEventID")), "vpc_endpoint_id": text(r.get("vpcEndpointId")),
                "tls_version": text(obj(r.get("tlsDetails")).get("tlsVersion"))}

    if name == "ConsoleLogin":
        extra = obj(r.get("additionalEventData"), "additionalEventData")
        resp = obj(r.get("responseElements"), "responseElements")
        result = text(resp.get("ConsoleLogin"))
        ok = result == "Success" if result else not err
        mfa = text(extra.get("MFAUsed"))
        sev = 1
        if not ok:
            sev = 2
        if text(ui.get("type")) == "Root":
            sev = 3
        unmapped.update({"mfa_used": mfa, "login_to": text(extra.get("LoginTo")),
                         "mobile_version": text(extra.get("MobileVersion"))})
        return ocsf.event("authentication", 1, severity=sev, status_id=1 if ok else 2,
                          message=f"Console login {'succeeded' if ok else 'failed'} for {usr.get('name') or 'unknown'}",
                          user=usr, is_mfa={"Yes": True, "No": False}.get(mfa or ""),
                          status_detail=text(r.get("errorMessage")),
                          service={"name": "AWS Management Console"},
                          unmapped=ocsf.prune(unmapped), **common)

    sev = 1
    if err and err in _DENIED:
        sev = 2
    if name in _SENSITIVE or text(ui.get("type")) == "Root":
        sev = 3
    return ocsf.event("api_activity", verb_activity(name), severity=sev, status_id=2 if err else 1,
                      status_code=err, message=f"{name} on {r.get('eventSource')}" + (f" ({err})" if err else ""),
                      api={"operation": name, "service": {"name": text(r.get("eventSource"))},
                           "request": {"uid": text(r.get("requestID"))}},
                      resources=resources, unmapped=ocsf.prune(unmapped), **common)


register(Mapper(
    key="cloudtrail", name="AWS CloudTrail", vendor=VENDOR, product="CloudTrail", family="cloud",
    classes=("api_activity", "authentication"), map=_trail,
    uid=lambda r: str((r.get("detail") if isinstance(r.get("detail"), dict) else r).get("eventID") or ""),
    doors=("bucket", "push")))


# ---------------------------------------------------------------- GuardDuty
def _g(d, key: str):
    """Read camelCase or PascalCase."""
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    return d.get(key[:1].upper() + key[1:])


def _gd(d, key: str) -> dict:
    return obj(_g(d, key), key)


def gd_severity(n) -> int:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return 0
    if v >= 9:
        return 5
    if v >= 7:
        return 4
    if v >= 4:
        return 3
    return 2


def _remote(action: dict) -> tuple[dict, dict | None, str]:
    """(remote ip details, port details, action type) from Service.Action."""
    kind = text(_g(action, "actionType")) or ""
    for key in ("awsApiCallAction", "networkConnectionAction", "kubernetesApiCallAction", "rdsLoginAttemptAction"):
        a = _gd(action, key)
        if a:
            return _gd(a, "remoteIpDetails"), a, kind
    probe = _gd(action, "portProbeAction")
    if probe:
        details = [obj(x) for x in lst(_g(probe, "portProbeDetails"))]
        if details:
            return _gd(details[0], "remoteIpDetails"), details[0], kind
    return {}, None, kind


def _finding_of(r: dict) -> dict:
    if isinstance(r.get("detail"), dict) and (r.get("source") == "aws.guardduty" or r.get("detail-type")):
        return r["detail"]
    return r


@guarded
def _finding(r: dict) -> dict | None:
    f = _finding_of(r)
    fid, ftype = text(_g(f, "id")), text(_g(f, "type"))
    if not fid or not ftype:
        raise ocsf.MappingError("finding has no id or type")
    sev = gd_severity(_g(f, "severity"))
    res = _gd(f, "resource")
    svc = _gd(f, "service")
    action = _gd(svc, "action")
    remote, act_detail, act_type = _remote(action)
    inst = _gd(res, "instanceDetails")
    nics = [obj(n) for n in lst(_g(inst, "networkInterfaces"))]
    nic = nics[0] if nics else {}
    key = _gd(res, "accessKeyDetails")
    country = _gd(remote, "country")
    city = _gd(remote, "city")
    geo = _gd(remote, "geoLocation")
    created, updated = _g(f, "createdAt"), _g(f, "updatedAt")
    archived = bool(_g(svc, "archived"))
    aid = finding_activity(created, updated, archived)
    title = text(_g(f, "title")) or ftype
    api_call = _gd(action, "awsApiCallAction")
    dns = _gd(action, "dnsRequestAction")
    local_port = _gd(act_detail, "localPortDetails") if act_detail else {}
    remote_port = _gd(act_detail, "remotePortDetails") if act_detail else {}
    return ocsf.event(
        "detection_finding", aid, time=updated if aid in (2, 3) and updated else created, product="GuardDuty",
        vendor=VENDOR, uid=fid, severity=sev, message=text(_g(f, "description")) or title,
        finding_info=ocsf.finding_info(
            title, uid=fid, desc=text(_g(f, "description")), types=[ftype],
            src_url=None, created=created),
        device=ocsf.device(hostname=text(_g(nic, "privateDnsName")), uid=text(_g(inst, "instanceId")),
                           ip=ip(_g(nic, "privateIpAddress")), os_name=text(_g(inst, "platform")),
                           type_=text(_g(inst, "instanceType"))) if inst else None,
        actor={"user": ocsf.prune({**ocsf.user(name=text(_g(key, "userName")), uid=text(_g(key, "principalId")),
                                               type_=text(_g(key, "userType"))),
                                   "credential_uid": text(_g(key, "accessKeyId"))})} if key else None,
        src_endpoint=ocsf.endpoint(
            ip=ip(_g(remote, "ipAddressV4")) or ip(_g(remote, "ipAddressV6")), port=_g(remote_port, "port"),
            location=ocsf.location(country=text(_g(country, "countryName")), city=text(_g(city, "cityName")),
                                   lat=_g(geo, "lat"), lon=_g(geo, "lon"))),
        dst_endpoint=ocsf.endpoint(port=_g(local_port, "port")),
        cloud=ocsf.cloud(provider="AWS", account=text(_g(f, "accountId")), region=text(_g(f, "region"))),
        api={"operation": text(_g(api_call, "api")), "service": {"name": text(_g(api_call, "serviceName"))}}
        if api_call else None,
        query={"hostname": text(_g(dns, "domain"))} if dns else None,
        resources=[ocsf.prune({"type": text(_g(res, "resourceType")),
                               "uid": text(_g(inst, "instanceId")) or text(_g(key, "accessKeyId"))
                               or text(_g(f, "arn"))})],
        unmapped=ocsf.prune({
            "finding_type": ftype, "severity_score": _g(f, "severity"), "arn": text(_g(f, "arn")),
            "action_type": act_type, "count": _g(svc, "count"), "archived": archived,
            "detector_id": text(_g(svc, "detectorId")), "resource_role": text(_g(svc, "resourceRole")),
            "first_seen": text(_g(svc, "eventFirstSeen")), "last_seen": text(_g(svc, "eventLastSeen")),
            "remote_org": text(_g(_gd(remote, "organization"), "asnOrg")),
            "threat_purpose": ftype.split(":", 1)[0] if ":" in ftype else None,
        }),
    )


def _gd_uid(r: dict) -> str:
    f = _finding_of(r) if isinstance(r, dict) else {}
    return version_uid(_g(f, "id"), _g(f, "updatedAt"))


register(Mapper(
    key="guardduty", name="Amazon GuardDuty findings", vendor=VENDOR, product="GuardDuty", family="cloud",
    classes=("detection_finding",), map=_finding, uid=_gd_uid, doors=("push", "bucket"), detection=True))
