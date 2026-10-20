"""SentinelOne Singularity: threats from Management API v2.1 (GET /web/api/v2.1/threats).

One record is one entry of the response's `data` array: `threatInfo` describes the
threat, `agentRealtimeInfo` and `agentDetectionInfo` describe the endpoint at the
time of the request and at detection, and `indicators[].tactics[].techniques[]`
carry ATT&CK technique ids when the engine supplied them.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import attack, basename, dedupe_attacks, guarded, ip, lst, obj, require, text

VENDOR, PRODUCT = "SentinelOne", "Singularity"


def _severity(ti: dict) -> int:
    conf = (text(ti.get("confidenceLevel")) or "").lower()
    mit = (text(ti.get("mitigationStatus")) or "").lower()
    verdict = (text(ti.get("analystVerdict")) or "").lower()
    if verdict == "false_positive" or mit == "marked_as_benign":
        return 1
    if conf == "malicious":
        # Malicious and still active on the endpoint is the case the SOC must act on now.
        return 5 if mit in ("not_mitigated", "active") else 4
    if conf == "suspicious":
        return 3
    return 2


@guarded
def _threat(r: dict) -> dict | None:
    require(r, "id")
    ti = obj(r.get("threatInfo"), "threatInfo")
    rt = obj(r.get("agentRealtimeInfo"), "agentRealtimeInfo")
    det = obj(r.get("agentDetectionInfo"), "agentDetectionInfo")
    created = ti.get("createdAt") or ti.get("identifiedAt") or r.get("createdAt")
    updated = ti.get("updatedAt") or r.get("updatedAt")
    incident = (text(ti.get("incidentStatus")) or "").lower()
    aid = 3 if incident == "resolved" else 1
    attacks = []
    for ind in lst(r.get("indicators"), "indicators"):
        for tac in lst(obj(ind).get("tactics"), "tactics"):
            tac = obj(tac)
            for tech in lst(tac.get("techniques"), "techniques"):
                tech = obj(tech)
                # The technique id sits in `name` ("T1055"); the tactic is named, not numbered.
                attacks.append(attack(tech.get("name"), None, None, tac.get("name")))
    proc_name = text(ti.get("originatorProcess"))
    file_path = text(ti.get("filePath"))
    title = text(ti.get("threatName")) or basename(file_path) or "SentinelOne threat"
    host = text(rt.get("agentComputerName")) or text(det.get("agentComputerName"))
    user_name = text(ti.get("processUser")) or text(det.get("agentLastLoggedInUserName"))
    actions = []
    for m in lst(r.get("mitigationStatus"), "mitigationStatus"):
        m = obj(m)
        actions.append(ocsf.prune({"action": text(m.get("action")), "status": text(m.get("status")),
                                   "at": text(m.get("mitigationEndedAt") or m.get("lastUpdate"))}))
    return ocsf.event(
        "detection_finding", aid, time=updated if aid == 3 and updated else created, product=PRODUCT,
        vendor=VENDOR, uid=r.get("id"), severity=_severity(ti),
        message=f"{title} on {host or 'unknown endpoint'} ({ti.get('mitigationStatus') or 'status unknown'})",
        finding_info=ocsf.finding_info(
            title, uid=text(ti.get("threatId")) or text(r.get("id")),
            desc=text(ti.get("classification")),
            types=[t for t in (text(ti.get("classification")), text(ti.get("detectionType"))) if t],
            attacks=dedupe_attacks(attacks), created=created),
        device=ocsf.device(hostname=host, ip=ip(det.get("agentIpV4")), uid=text(rt.get("agentId")),
                           os_name=text(rt.get("agentOsName")) or text(det.get("agentOsName")),
                           type_=text(rt.get("agentMachineType"))),
        actor={"user": ocsf.user(name=user_name, domain=text(det.get("agentDomain")) or text(rt.get("agentDomain")))},
        process=ocsf.process(name=proc_name, cmd_line=text(ti.get("maliciousProcessArguments"))) or None,
        file={"name": text(ti.get("fileDisplayName")) or basename(file_path), "path": file_path,
              "hashes": [h for h in (
                  {"algorithm_id": 3, "algorithm": "SHA-256", "value": text(ti.get("sha256"))},
                  {"algorithm_id": 2, "algorithm": "SHA-1", "value": text(ti.get("sha1"))},
                  {"algorithm_id": 1, "algorithm": "MD5", "value": text(ti.get("md5"))}) if h["value"]]},
        src_endpoint=ocsf.endpoint(ip=ip(det.get("externalIp"))),
        unmapped=ocsf.prune({
            "confidence": text(ti.get("confidenceLevel")), "classification": text(ti.get("classification")),
            "mitigation_status": text(ti.get("mitigationStatus")), "incident_status": text(ti.get("incidentStatus")),
            "analyst_verdict": text(ti.get("analystVerdict")), "engines": ti.get("engines"),
            "initiated_by": text(ti.get("initiatedBy")), "storyline": text(ti.get("storyline")),
            "mitigated_preemptively": ti.get("mitigatedPreemptively"),
            "mitigation_mode": text(det.get("agentMitigationMode")),
            "site": text(rt.get("siteName")) or text(det.get("siteName")),
            "account": text(rt.get("accountName")), "group": text(rt.get("groupName")),
            "agent_version": text(rt.get("agentVersion")), "mitigation_actions": actions,
        }),
    )


register(Mapper(
    key="sentinelone_threats", name="SentinelOne threats", vendor=VENDOR, product=PRODUCT, family="edr",
    classes=("detection_finding",), map=_threat, uid=lambda r: str(r.get("id") or ""),
    doors=("pull", "push"), detection=True))
