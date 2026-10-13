"""Action dispatcher: every button a tech can press on an alert or a device, in
one catalog, routed to the right connector, and always logged.

Each action records an ActionLog row with the result. Actions marked shared are
written client_visible with plain-language wording, which is what the portal's
"actions taken" feed shows. Tool failures come back as a readable message on the
alert page, never a stack trace, and the log row says failed."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from . import connectors, hub, sla
from .config import settings
from .connectors import ConnectorError
from .db import ActionLog, Alert, Device

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    shared: bool = False     # written to the client-visible actions feed
    danger: bool = False     # rendered as a destructive button
    needs_comment: bool = False


# Alert-level actions, per tool. Module-level triage (acknowledge, resolve here,
# publish, escalate) is handled in main.py and applies to every tool.
ALERT_ACTIONS: dict[str, list[Action]] = {
    "sentinelone": [
        Action("s1_kill", "Kill process", shared=True, danger=True),
        Action("s1_quarantine", "Quarantine threat", shared=True, danger=True),
        Action("s1_remediate", "Remediate", shared=True, danger=True),
        Action("s1_resolve_tp", "Resolve as true positive"),
        Action("s1_resolve_fp", "Resolve as false positive"),
    ],
    "crowdstrike": [
        Action("cs_in_progress", "Mark in progress in Falcon"),
        Action("cs_close", "Close in Falcon"),
    ],
    "huntress": [
        Action("h_approve", "Approve all remediations", shared=True, danger=True),
        Action("h_reject", "Reject remediations", needs_comment=True),
        Action("h_resolve", "Resolve report"),
    ],
    "acronis": [
        Action("a_run_backup", "Run backup now", shared=True),
        Action("a_dismiss", "Dismiss in Acronis"),
    ],
    "superops": [
        Action("so_resolve", "Resolve in SuperOps"),
        Action("so_ticket", "Create SuperOps ticket"),
    ],
}

# Device-level actions (on the alert's device, or from the client's device table).
DEVICE_ACTIONS: dict[str, list[Action]] = {
    "sentinelone": [
        Action("s1_disconnect", "Isolate from network", shared=True, danger=True),
        Action("s1_reconnect", "Reconnect to network", shared=True),
    ],
    "crowdstrike": [
        Action("cs_contain", "Network contain", shared=True, danger=True),
        Action("cs_lift", "Lift containment", shared=True),
    ],
    "huntress": [
        Action("h_isolate", "Isolate host", shared=True, danger=True),
        Action("h_release", "Release isolation", shared=True),
    ],
}

_ALL = {a.id: a for acts in list(ALERT_ACTIONS.values()) + list(DEVICE_ACTIONS.values()) for a in acts}


def _blocked(action: "Action", confirm: bool, *, can_act: bool = True, approved: bool = True) -> str:
    """Refusal reason for an action, or "" when it may run. Read-only mode blocks
    every tool write; the actor must be allowed to run actions; destructive actions
    also need an explicit confirm and an authorized approver."""
    if settings.actions_readonly:
        return "read-only mode is on: tool actions are disabled while this client is being validated"
    if not can_act:
        return "you do not have permission to run response actions"
    if action.danger and not confirm:
        return "needs confirmation"
    if action.danger and not approved:
        return "a destructive action needs approval from an authorized responder"
    return ""


def spec(action_id: str) -> Action | None:
    return _ALL.get(action_id)


def _portal_text(action: Action, alert: Alert | None, device: Device | None) -> str:
    host = (device.hostname if device else "") or (alert.device.hostname if alert and alert.device else "")
    subject = f" on {host}" if host else ""
    texts = {
        "s1_kill": f"Malicious process terminated{subject}.",
        "s1_quarantine": f"Threat quarantined{subject}.",
        "s1_remediate": f"Threat remediation started{subject}.",
        "s1_disconnect": f"Host isolated from the network{subject} pending investigation.",
        "s1_reconnect": f"Host restored to the network{subject}.",
        "cs_contain": f"Host network-contained{subject} pending investigation.",
        "cs_lift": f"Network containment lifted{subject}.",
        "h_approve": f"Approved remediation plan{subject}; cleanup is running.",
        "h_isolate": f"Host isolated{subject} pending investigation.",
        "h_release": f"Host isolation released{subject}.",
        "a_run_backup": f"Backup re-run started{subject}.",
    }
    return texts.get(action.id, f"{action.label}{subject}.")


def _ref(alert_or_device, client) -> str:
    return client.tool_ref(alert_or_device.tool)


def run_alert_action(db: Session, alert: Alert, action_id: str, actor: str, comment: str = "",
                     confirm: bool = False, can_act: bool = True, approver: str = "") -> tuple[bool, str]:
    action = _ALL.get(action_id)
    if not action or action not in ALERT_ACTIONS.get(alert.tool, []):
        return False, "that action does not apply to this alert"
    blocked = _blocked(action, confirm, can_act=can_act, approved=bool(approver))
    if blocked:
        db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, device_id=alert.device_id,
                         tool=alert.tool, action=action.label, actor=actor, detail=blocked, result="blocked"))
        db.commit()
        return False, blocked
    conn = connectors.get(alert.tool)
    ref = alert.client.tool_ref(alert.tool)
    detail = ""
    ok = True
    try:
        if not getattr(conn, "configured", False):
            raise ConnectorError(f"{alert.tool} is not configured")
        if action_id == "s1_kill":
            conn.mitigate([alert.external_id], "kill")
        elif action_id == "s1_quarantine":
            conn.mitigate([alert.external_id], "quarantine")
        elif action_id == "s1_remediate":
            conn.mitigate([alert.external_id], "remediate")
        elif action_id == "s1_resolve_tp":
            conn.set_incident([alert.external_id], "resolved", "true_positive")
            alert.status = "resolved"
        elif action_id == "s1_resolve_fp":
            conn.set_incident([alert.external_id], "resolved", "false_positive")
            alert.status = "resolved"
        elif action_id == "cs_in_progress":
            conn.update_alert(ref, [alert.external_id], "in_progress", comment)
            alert.status = "acknowledged" if alert.status == "open" else alert.status
        elif action_id == "cs_close":
            conn.update_alert(ref, [alert.external_id], "closed", comment)
            alert.status = "resolved"
        elif action_id == "h_approve":
            conn.approve_remediations(alert.external_id)
        elif action_id == "h_reject":
            conn.reject_remediations(alert.external_id, comment)
        elif action_id == "h_resolve":
            conn.resolve_report(alert.external_id)
            alert.status = "resolved"
        elif action_id == "a_dismiss":
            conn.dismiss_alert(alert.external_id)
            alert.status = "resolved"
        elif action_id == "a_run_backup":
            resource = (alert.raw or {}).get("resourceId") or (alert.device.external_id if alert.device else "")
            if not resource:
                raise ConnectorError("Acronis: no workload attached to this alert")
            conn.run_backup_for_resource(str(resource))
        elif action_id == "so_resolve":
            conn.resolve_alert(alert.external_id)
            alert.status = "resolved"
        elif action_id == "so_ticket":
            t = conn.create_ticket(ref, alert.title, f"{alert.detail}\n\nRaised from Vendetta Managed Services.")
            detail = f"ticket {t['display_id'] or t['ticket_id']}"
        else:  # pragma: no cover
            raise ConnectorError(f"unhandled action {action_id}")
    except ConnectorError as e:
        ok, detail = False, str(e)
    if ok:
        # A successful action is a response, so the acknowledge clock stops; a
        # destructive action or a resolution stops the contain clock too.
        sla.mark_acknowledged(alert)
        if action.danger or alert.status == "resolved":
            sla.mark_contained(alert)
    visible = ok and action.shared and alert.published
    db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, device_id=alert.device_id,
                     tool=alert.tool, action=action.label, actor=actor, approver=approver,
                     detail=_portal_text(action, alert, None) if visible else (detail or comment[:500]),
                     result="ok" if ok else "failed", client_visible=visible))
    db.commit()
    return ok, detail or ("done" if ok else "failed")


def run_device_action(db: Session, device: Device, action_id: str, actor: str,
                      alert: Alert | None = None, comment: str = "", confirm: bool = False,
                      can_act: bool = True, approver: str = "") -> tuple[bool, str]:
    action = _ALL.get(action_id)
    if not action or action not in DEVICE_ACTIONS.get(device.tool, []):
        return False, "that action does not apply to this device"
    blocked = _blocked(action, confirm, can_act=can_act, approved=bool(approver))
    if blocked:
        db.add(ActionLog(client_id=device.client_id, alert_id=alert.id if alert else None, device_id=device.id,
                         tool=device.tool, action=action.label, actor=actor, detail=blocked, result="blocked"))
        db.commit()
        return False, blocked
    conn = connectors.get(device.tool)
    ref = device.client.tool_ref(device.tool)
    detail = ""
    ok = True
    try:
        if not getattr(conn, "configured", False):
            raise ConnectorError(f"{device.tool} is not configured")
        if action_id == "s1_disconnect":
            conn.disconnect([device.external_id])
        elif action_id == "s1_reconnect":
            conn.reconnect([device.external_id])
        elif action_id == "cs_contain":
            conn.contain(ref, [device.external_id])
        elif action_id == "cs_lift":
            conn.lift_containment(ref, [device.external_id])
        elif action_id == "h_isolate":
            conn.isolate(device.external_id, comment or "Isolated by Vendetta SOC")
        elif action_id == "h_release":
            conn.release(device.external_id)
        else:  # pragma: no cover
            raise ConnectorError(f"unhandled action {action_id}")
        if action_id in ("s1_disconnect", "cs_contain", "h_isolate"):
            device.status = "isolating"
        elif action_id in ("s1_reconnect", "cs_lift", "h_release"):
            device.status = "online"
    except ConnectorError as e:
        ok, detail = False, str(e)
    if ok and alert is not None:
        sla.mark_acknowledged(alert)
        if action.danger:
            sla.mark_contained(alert)
    visible = ok and action.shared and (alert.published if alert else True)
    db.add(ActionLog(client_id=device.client_id, alert_id=alert.id if alert else None, device_id=device.id,
                     tool=device.tool, action=action.label, actor=actor, approver=approver,
                     detail=_portal_text(action, alert, device) if visible else (detail or comment[:500]),
                     result="ok" if ok else "failed", client_visible=visible))
    db.commit()
    return ok, detail or ("done" if ok else "failed")


def escalate_alert(db: Session, alert: Alert, actor: str) -> tuple[bool, str]:
    try:
        res = hub.escalate(alert, db)
    except Exception as e:  # noqa: BLE001
        db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, tool=alert.tool,
                         action="Escalate to IR case", actor=actor, detail=str(e)[:500], result="failed"))
        db.commit()
        return False, f"escalation failed: {e}"
    if not res.get("escalated"):
        return False, res.get("reason", "hub not configured")
    db.add(ActionLog(client_id=alert.client_id, alert_id=alert.id, tool=alert.tool,
                     action="Escalated to IR case", actor=actor, detail=res["case"], result="ok",
                     client_visible=alert.published))
    db.commit()
    return True, res["case"]
