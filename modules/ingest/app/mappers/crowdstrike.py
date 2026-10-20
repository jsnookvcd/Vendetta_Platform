"""CrowdStrike Falcon: Alerts API v2 detections and Falcon Data Replicator events.

crowdstrike_alerts takes one alert entity as POST /alerts/entities/alerts/v2 returns
it (the same shape the combined endpoint returns). Endpoint detections (product
"epp") carry the process fields at the top level; identity and cloud alerts carry
fewer of them, and every field below is optional except composite_id and a time.

crowdstrike_fdr takes one FDR event (one JSON line of an FDR batch file in the
customer's or CrowdStrike's bucket). FDR events identify the host by `aid`;
`ComputerName` is present on some event types and is used when it is. Only the
event types listed in _FDR are mapped; every other event_simpleName is skipped.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import (attack, basename, dedupe_attacks, finding_activity, guarded, ip, obj, require, text,
                    version_uid)

VENDOR, PRODUCT = "CrowdStrike", "Falcon"


def _alert_severity(r: dict) -> int:
    word = (text(r.get("severity_name")) or "").lower()
    if word in ocsf.SEVERITY_FROM_WORD:
        return ocsf.SEVERITY_FROM_WORD[word]
    try:
        n = int(r.get("severity") or 0)
    except (TypeError, ValueError):
        return 0
    # Falcon's 1 to 100 scale: Informational 10, Low 30, Medium 50, High 70, Critical 90.
    if n >= 80:
        return 5
    if n >= 60:
        return 4
    if n >= 40:
        return 3
    if n >= 20:
        return 2
    return 1 if n > 0 else 0


def _proc(d: dict, user_name=None, parent=None) -> dict:
    return ocsf.process(name=text(d.get("filename")) or basename(d.get("filepath")), path=text(d.get("filepath")),
                        cmd_line=text(d.get("cmdline")), pid=d.get("process_id") or d.get("local_process_id"),
                        uid=text(d.get("process_graph_id")), sha256=text(d.get("sha256")), md5=text(d.get("md5")),
                        user_=ocsf.user(name=user_name) if user_name else None, parent=parent)


@guarded
def _alert(r: dict) -> dict | None:
    require(r, "composite_id")
    dev = obj(r.get("device"), "device")
    parent_d = obj(r.get("parent_details"), "parent_details")
    grand_d = obj(r.get("grandparent_details"), "grandparent_details")
    status = (text(r.get("status")) or "").lower()
    created, updated = r.get("created_timestamp") or r.get("timestamp"), r.get("updated_timestamp")
    aid = finding_activity(created, updated, status == "closed")
    when = updated if aid in (2, 3) and updated else created
    grand = _proc(grand_d) if grand_d else None
    parent = _proc(parent_d, user_name=text(parent_d.get("user_name")), parent=grand) if parent_d else None
    user_name = text(r.get("user_name"))
    proc = _proc(r, user_name=user_name, parent=parent)
    attacks = [attack(r.get("technique_id"), r.get("technique"), r.get("tactic_id"), r.get("tactic"))]
    for m in r.get("mitre_attack") or []:  # some alert types carry a list as well
        if isinstance(m, dict):
            attacks.append(attack(m.get("technique_id"), m.get("technique"), m.get("tactic_id"), m.get("tactic")))
    title = text(r.get("display_name")) or text(r.get("name")) or text(r.get("scenario")) or "Falcon alert"
    sev = _alert_severity(r)
    return ocsf.event(
        "detection_finding", aid, time=when, product=PRODUCT, vendor=VENDOR, uid=r.get("composite_id"),
        severity=sev, message=text(r.get("description")) or title,
        finding_info=ocsf.finding_info(
            title, uid=text(r.get("composite_id")), desc=text(r.get("description")),
            types=[t for t in (text(r.get("type")), text(r.get("product"))) if t],
            attacks=dedupe_attacks(attacks), src_url=text(r.get("falcon_host_link")), created=created),
        device=ocsf.device(hostname=text(dev.get("hostname")), ip=ip(dev.get("local_ip")),
                           uid=text(dev.get("device_id")) or text(r.get("agent_id")),
                           os_name=text(dev.get("platform_name")), type_=text(dev.get("product_type_desc"))),
        actor={"user": ocsf.user(name=user_name, uid=text(r.get("user_id")),
                                 email=text(r.get("user_principal")) if "@" in str(r.get("user_principal") or "")
                                 else None, domain=text(dev.get("machine_domain"))),
               "process": parent},
        process=proc if (proc.get("name") or proc.get("cmd_line")) else None,
        src_endpoint=ocsf.endpoint(ip=ip(dev.get("external_ip"))),
        unmapped=ocsf.prune({
            "status": status, "confidence": r.get("confidence"), "severity_score": r.get("severity"),
            "objective": text(r.get("objective")), "pattern_id": r.get("pattern_id"),
            "scenario": text(r.get("scenario")), "aggregate_id": text(r.get("aggregate_id")),
            "alert_id": text(r.get("id")), "cid": text(r.get("cid")),
            "disposition": text(r.get("pattern_disposition_description")),
            "assigned_to": text(r.get("assigned_to_name")), "tags": r.get("tags"),
            "os_version": text(dev.get("os_version")), "mac": text(dev.get("mac_address")),
        }),
    )


register(Mapper(
    key="crowdstrike_alerts", name="CrowdStrike Falcon alerts", vendor=VENDOR, product=PRODUCT, family="edr",
    classes=("detection_finding",), map=_alert,
    uid=lambda r: version_uid(r.get("composite_id"), r.get("updated_timestamp")),
    doors=("pull", "push"), detection=True))


# ---------------------------------------------------------------- FDR
_PROCESS = {"ProcessRollup2", "SyntheticProcessRollup2"}
_LOGON = {"UserLogon": 1, "UserLogonFailed2": 2}


def _fdr_device(r: dict) -> dict:
    return ocsf.device(hostname=text(r.get("ComputerName")), uid=text(r.get("aid")), ip=ip(r.get("aip")),
                       os_name=text(r.get("event_platform")))


@guarded
def _fdr(r: dict) -> dict | None:
    name = text(r.get("event_simpleName"))
    if not name:
        raise ocsf.MappingError("record has no event_simpleName")
    if name not in _PROCESS and name not in _LOGON and name not in ("DnsRequest", "NetworkConnectIP4"):
        return None
    when = r.get("timestamp")
    common = dict(time=when, product=PRODUCT, vendor=VENDOR, uid=text(r.get("id")), device=_fdr_device(r))
    left = {"cid": text(r.get("cid")), "event_simpleName": name, "aid": text(r.get("aid")),
            "context_process_id": text(r.get("ContextProcessId"))}
    if name in _PROCESS:
        user_name = text(r.get("UserName"))
        usr = ocsf.user(name=user_name, uid=text(r.get("UserSid")))
        parent = ocsf.process(name=text(r.get("ParentBaseFileName")), uid=text(r.get("ParentProcessId")))
        image = text(r.get("ImageFileName"))
        proc = ocsf.process(name=basename(image), path=image, cmd_line=text(r.get("CommandLine")),
                            pid=r.get("RawProcessId"), uid=text(r.get("TargetProcessId")),
                            sha256=text(r.get("SHA256HashData")), md5=text(r.get("MD5HashData")),
                            user_=usr or None, parent=parent or None)
        if not proc.get("name") and not proc.get("cmd_line"):
            raise ocsf.MappingError("process event has no ImageFileName or CommandLine")
        return ocsf.event("process_activity", 1, severity=1, message=f"{basename(image) or 'process'} launched",
                          process=proc, actor={"user": usr, "process": parent},
                          unmapped=ocsf.prune({**left, "integrity_level": r.get("IntegrityLevel"),
                                               "token_type": r.get("TokenType")}), **common)
    if name == "DnsRequest":
        domain = text(r.get("DomainName"))
        if not domain:
            raise ocsf.MappingError("DnsRequest has no DomainName")
        return ocsf.event("dns_activity", 1, severity=1, message=f"DNS query {domain}",
                          query={"hostname": domain, "type": text(r.get("RequestType"))},
                          src_endpoint=ocsf.endpoint(hostname=text(r.get("ComputerName")), uid=text(r.get("aid"))),
                          unmapped=ocsf.prune(left), **common)
    if name == "NetworkConnectIP4":
        remote = ip(r.get("RemoteAddressIP4"))
        if not remote:
            raise ocsf.MappingError("NetworkConnectIP4 has no RemoteAddressIP4")
        proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(str(r.get("Protocol") or ""), text(r.get("Protocol")))
        return ocsf.event("network_activity", 1, severity=1, message=f"connection to {remote}:{r.get('RemotePort')}",
                          src_endpoint=ocsf.endpoint(ip=ip(r.get("LocalAddressIP4")), port=r.get("LocalPort"),
                                                     hostname=text(r.get("ComputerName")), uid=text(r.get("aid"))),
                          dst_endpoint=ocsf.endpoint(ip=remote, port=r.get("RemotePort")),
                          connection_info={"protocol_name": proto,
                                           "direction_id": {"0": 2, "1": 1}.get(
                                               str(r.get("ConnectionDirection") or ""))},
                          unmapped=ocsf.prune(left), **common)
    # UserLogon, UserLogonFailed2
    status = _LOGON[name]
    user_name = text(r.get("UserName"))
    return ocsf.event("authentication", 1, severity=1 if status == 1 else 2, status_id=status,
                      message=f"logon {'succeeded' if status == 1 else 'failed'} for {user_name or 'unknown user'}",
                      user=ocsf.user(name=user_name, uid=text(r.get("UserSid")), domain=text(r.get("LogonDomain"))),
                      logon_type_id=int(r["LogonType"]) if str(r.get("LogonType") or "").isdigit() else None,
                      src_endpoint=ocsf.endpoint(ip=ip(r.get("RemoteAddressIP4"))),
                      dst_endpoint=ocsf.endpoint(hostname=text(r.get("ComputerName")), uid=text(r.get("aid"))),
                      status_code=text(r.get("Status")) if status == 2 else None,
                      unmapped=ocsf.prune({**left, "sub_status": text(r.get("SubStatus")),
                                           "logon_server": text(r.get("LogonServer"))}),
                      **common)


register(Mapper(
    key="crowdstrike_fdr", name="CrowdStrike Falcon Data Replicator", vendor=VENDOR, product=PRODUCT,
    family="edr", classes=("process_activity", "dns_activity", "network_activity", "authentication"),
    map=_fdr, uid=lambda r: str(r.get("id") or ""), doors=("bucket",)))
