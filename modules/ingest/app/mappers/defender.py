"""Microsoft Defender XDR alerts from Microsoft Graph (GET /security/alerts_v2).

One record is one alert resource. `evidence[]` is polymorphic by `@odata.type`:
device evidence gives the host, user evidence the account, process and file
evidence the process. Alerts from every Defender product (Endpoint, Office 365,
Identity, Cloud Apps, Entra ID Protection) arrive through this one API, named by
`serviceSource`.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import attack, dedupe_attacks, finding_activity, guarded, ip, lst, obj, require, text, version_uid

VENDOR, PRODUCT = "Microsoft", "Defender XDR"

_SEV = {"informational": 1, "low": 2, "medium": 3, "high": 4, "unknownfuturevalue": 0}


def _kind(e: dict) -> str:
    return (text(e.get("@odata.type")) or "").rsplit(".", 1)[-1]


def _account(a: dict) -> dict:
    upn = text(a.get("userPrincipalName"))
    return ocsf.user(name=upn or text(a.get("accountName")), uid=text(a.get("azureAdUserId")) or text(a.get("userSid")),
                     email=upn, domain=text(a.get("domainName")))


@guarded
def _alert(r: dict) -> dict | None:
    require(r, "id")
    evidence = [obj(e, "evidence") for e in lst(r.get("evidence"), "evidence")]
    dev = next((e for e in evidence if _kind(e) == "deviceEvidence"), {})
    usr = next((e for e in evidence if _kind(e) == "userEvidence"), {})
    prc = next((e for e in evidence if _kind(e) == "processEvidence"), {})
    ips = [ip(e.get("ipAddress")) for e in evidence if _kind(e) == "ipEvidence"]
    status = (text(r.get("status")) or "").lower()
    created, updated = r.get("createdDateTime"), r.get("lastUpdateDateTime")
    aid = finding_activity(created, updated, status == "resolved")
    when = (r.get("resolvedDateTime") or updated) if aid == 3 else (updated if aid == 2 else created)
    title = text(r.get("title")) or "Defender alert"
    process = None
    if prc:
        img = obj(prc.get("imageFile"), "imageFile")
        pimg = obj(prc.get("parentProcessImageFile"), "parentProcessImageFile")
        parent = ocsf.process(name=text(pimg.get("fileName")), path=text(pimg.get("filePath")),
                              pid=prc.get("parentProcessId"), sha256=text(pimg.get("sha256")))
        process = ocsf.process(name=text(img.get("fileName")), path=text(img.get("filePath")),
                               cmd_line=text(prc.get("processCommandLine")), pid=prc.get("processId"),
                               sha256=text(img.get("sha256")), md5=text(img.get("md5")),
                               user_=_account(obj(prc.get("userAccount"))) or None, parent=parent or None)
    user_obj = _account(obj(usr.get("userAccount"), "userAccount")) if usr else None
    if not user_obj and prc:
        user_obj = _account(obj(prc.get("userAccount"))) or None
    techniques = [attack(t) for t in lst(r.get("mitreTechniques"), "mitreTechniques")]
    return ocsf.event(
        "detection_finding", aid, time=when, product=PRODUCT, vendor=VENDOR, uid=r.get("id"),
        severity=_SEV.get((text(r.get("severity")) or "").lower(), 0),
        message=text(r.get("description")) or title,
        finding_info=ocsf.finding_info(
            title, uid=text(r.get("id")), desc=text(r.get("description")),
            types=[t for t in (text(r.get("category")), text(r.get("threatFamilyName"))) if t],
            attacks=dedupe_attacks(techniques), src_url=text(r.get("alertWebUrl")), created=created),
        device=ocsf.device(hostname=text(dev.get("deviceDnsName")) or text(dev.get("hostName")),
                           uid=text(dev.get("mdeDeviceId")) or text(dev.get("azureAdDeviceId")),
                           os_name=text(dev.get("osPlatform")),
                           ip=next((ip(i.get("ipAddress") if isinstance(i, dict) else i)
                                    for i in lst(dev.get("ipInterfaces")) if i), None)) if dev else None,
        actor={"user": user_obj},
        process=process or None,
        src_endpoint=ocsf.endpoint(ip=next((i for i in ips if i), None)),
        unmapped=ocsf.prune({
            "status": text(r.get("status")), "classification": text(r.get("classification")),
            "determination": text(r.get("determination")), "category": text(r.get("category")),
            "service_source": text(r.get("serviceSource")), "detection_source": text(r.get("detectionSource")),
            "detector_id": text(r.get("detectorId")), "provider_alert_id": text(r.get("providerAlertId")),
            "incident_id": text(r.get("incidentId")), "incident_url": text(r.get("incidentWebUrl")),
            "threat": text(r.get("threatDisplayName")), "actor_display_name": text(r.get("actorDisplayName")),
            "assigned_to": text(r.get("assignedTo")),
            "first_activity": text(r.get("firstActivityDateTime")),
            "last_activity": text(r.get("lastActivityDateTime")),
            "evidence_types": sorted({_kind(e) for e in evidence if _kind(e)}),
        }),
    )


register(Mapper(
    key="defender_alerts", name="Microsoft Defender XDR alerts", vendor=VENDOR, product=PRODUCT, family="edr",
    classes=("detection_finding",), map=_alert,
    uid=lambda r: version_uid(r.get("id"), r.get("lastUpdateDateTime")),
    doors=("pull", "push"), detection=True))
