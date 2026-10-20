"""Huntress: incident reports (GET https://api.huntress.io/v1/incident_reports).

One record is one entry of the response's `incident_reports` array. Huntress
incident reports are SOC-reviewed and already carry a severity of low, high or
critical. The report names the agent and organization by id; the host name is not
a documented field of the incident report object, so it is read from `hostname`
or the nested `agent` object only when Huntress includes one. Field names follow
the public v1 API reference as known in 2026; `indicator_types`, `indicator_counts`
and `remediations` in particular should be checked against a live tenant.
"""
from __future__ import annotations

from .. import ocsf
from . import Mapper, register
from ._util import finding_activity, guarded, lst, obj, require, text, version_uid

VENDOR, PRODUCT = "Huntress", "Managed EDR"

_CLOSED = {"closed", "dismissed", "auto_remediated"}


@guarded
def _incident(r: dict) -> dict | None:
    require(r, "id")
    agent = obj(r.get("agent"), "agent")
    status = (text(r.get("status")) or "").lower()
    created = r.get("sent_at") or r.get("created_at")
    updated = r.get("status_updated_at") or r.get("updated_at")
    aid = finding_activity(created, updated, status in _CLOSED)
    when = (r.get("closed_at") or updated) if aid == 3 else (updated if aid == 2 else created)
    title = text(r.get("subject")) or text(r.get("summary")) or "Huntress incident report"
    sev = ocsf.severity_id(text(r.get("severity")) or "medium")
    remediations = []
    for rem in lst(r.get("remediations"), "remediations"):
        rem = obj(rem)
        remediations.append(ocsf.prune({"type": text(rem.get("type")), "status": text(rem.get("status")),
                                        "details": text(rem.get("details") or rem.get("description"))}))
    return ocsf.event(
        "detection_finding", aid, time=when, product=PRODUCT, vendor=VENDOR, uid=r.get("id"), severity=sev,
        message=text(r.get("summary")) or title,
        finding_info=ocsf.finding_info(
            title, uid=text(r.get("id")), desc=text(r.get("summary")),
            types=[str(t) for t in lst(r.get("indicator_types"), "indicator_types") if t], created=created),
        device=ocsf.device(hostname=text(r.get("hostname")) or text(agent.get("hostname")),
                           uid=text(r.get("agent_id")) or text(agent.get("id")),
                           os_name=text(r.get("platform")) or text(agent.get("platform"))),
        unmapped=ocsf.prune({
            "status": status, "organization_id": text(r.get("organization_id")),
            "indicator_counts": r.get("indicator_counts"), "remediations": remediations,
            "body": (text(r.get("body")) or "")[:4000], "closed_at": text(r.get("closed_at")),
        }),
    )


register(Mapper(
    key="huntress_incidents", name="Huntress incident reports", vendor=VENDOR, product=PRODUCT, family="edr",
    classes=("detection_finding",), map=_incident,
    uid=lambda r: version_uid(r.get("id"), r.get("status_updated_at") or r.get("updated_at")),
    doors=("pull", "push"), detection=True))
