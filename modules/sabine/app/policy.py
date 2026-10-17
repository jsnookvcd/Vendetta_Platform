"""What SABINE is allowed to do on its own.

Every action SABINE can take is registered here with a risk tier and a default
autonomy level. An admin sets the level per action in the console:

- off: SABINE never raises this action.
- propose: SABINE writes the proposal and waits for a person to approve it.
- auto: SABINE carries it out as soon as the rule fires, and records that it did.

Hard limits that no setting changes: an action with risk "high" can never be set
to auto, and anything that touches a client host (isolate, contain, quarantine) is
not an action SABINE can take at all. For those it raises a proposal whose
execution is a deep link into the module, where a person with the right grant
clicks, with the second-person control that module enforces.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

AUTONOMY = ("off", "propose", "auto")

# action -> dict(label, domain, risk, default, description, executor)
ACTIONS = {
    "escalate_finding": {
        "label": "Escalate a finding into an IR case",
        "domain": "soc", "risk": "medium", "default": "propose",
        "description": "A critical or high finding left unescalated beyond the threshold is escalated to the IR hub through the module's own API, opening or linking a case.",
        "executor": "escalate_finding",
    },
    "link_related_findings": {
        "label": "Note related findings across modules for one client",
        "domain": "soc", "risk": "low", "default": "auto",
        "description": "When one client has active findings in more than one module that share a host, credential or title, a correlation note is raised as a work item so the responder sees the whole story.",
        "executor": "raise_work_item",
    },
    "host_action": {
        "label": "Recommend a response action on a host (isolate, contain, quarantine)",
        "domain": "soc", "risk": "high", "default": "propose",
        "description": "SABINE never touches a host. It recommends the action with its reasoning and links the responder to the module page where the action is taken, under that module's approval rules.",
        "executor": "handoff",
    },
    "roster_sync": {
        "label": "Re-sync a module whose roster pull is failing",
        "domain": "admin", "risk": "low", "default": "auto",
        "description": "When a module reports a failed roster pull, SABINE asks it to pull again; if it still fails the item stays in the queue for an operator.",
        "executor": "roster_sync",
    },
    "readiness_remediation": {
        "label": "Raise a blocking readiness item as work with the fix spelled out",
        "domain": "admin", "risk": "low", "default": "auto",
        "description": "A red item on the go-live screen becomes a work item with the exact parameter or page to fix, assigned to the admin domain.",
        "executor": "raise_work_item",
    },
    "staff_hygiene": {
        "label": "Flag staff access that looks wrong",
        "domain": "admin", "risk": "low", "default": "auto",
        "description": "An active person with no module grants, a module with nobody granted, or more than a handful of admins is raised for review.",
        "executor": "raise_work_item",
    },
    "stale_case_nudge": {
        "label": "Nudge an IR case that has gone quiet",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "An open case with no timeline update past the threshold is raised to its lead with what is outstanding.",
        "executor": "raise_work_item",
    },
    "retest_due": {
        "label": "Queue a pentest retest that is waiting",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "Findings in retest_pending are queued to the engagement owner.",
        "executor": "raise_work_item",
    },
    "remediation_overdue": {
        "label": "Flag a vulnerability past its remediation SLA",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "A finding still remediating past the SLA for its severity is raised, grouped by client, with a draft client note.",
        "executor": "raise_work_item",
    },
    "deliverable_acceptance_nudge": {
        "label": "Nudge a deliverable the client has not accepted",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "A deliverable delivered in the Office of Special Projects and not accepted on the portal within the window is queued to the engagement lead with a note; nothing is sent to the client.",
        "executor": "raise_work_item",
    },
    "engagement_overdue": {
        "label": "Flag a professional-services engagement past its planned end",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "An engagement still open past its planned end date is raised to its lead with what is still outstanding.",
        "executor": "raise_work_item",
    },
    "client_brief": {
        "label": "Write a client brief",
        "domain": "services", "risk": "low", "default": "auto",
        "description": "A short posture brief per client from live data across every module, kept under Briefs for a person to send.",
        "executor": "client_brief",
    },
    "daily_summary": {
        "label": "Write the daily summary",
        "domain": "admin", "risk": "low", "default": "auto",
        "description": "What SABINE saw, proposed and did in the last day, for the morning stand-up.",
        "executor": "daily_summary",
    },
}

RISK_RANK = {"low": 0, "medium": 1, "high": 2}


def seed_policies(db: Session) -> None:
    from .db import Policy

    for action, spec in ACTIONS.items():
        if not db.get(Policy, action):
            db.add(Policy(action=action, autonomy=spec["default"]))
    db.commit()


def autonomy(db: Session, action: str) -> str:
    from .db import Policy

    row = db.get(Policy, action)
    level = row.autonomy if row else ACTIONS[action]["default"]
    # Hard ceiling: high-risk actions are never automatic.
    if ACTIONS[action]["risk"] == "high" and level == "auto":
        return "propose"
    return level


def set_autonomy(db: Session, action: str, level: str, actor: str) -> str:
    from .db import Policy, utcnow

    if action not in ACTIONS or level not in AUTONOMY:
        raise ValueError("bad action or level")
    if ACTIONS[action]["risk"] == "high" and level == "auto":
        raise ValueError("a high-risk action cannot be automatic")
    row = db.get(Policy, action)
    if row is None:
        row = Policy(action=action)
        db.add(row)
    row.autonomy, row.updated_by, row.updated_at = level, actor, utcnow()
    db.commit()
    return level


def table(db: Session) -> list[dict]:
    from .db import Policy

    out = []
    for action, spec in ACTIONS.items():
        row = db.get(Policy, action)
        out.append({"action": action, **spec, "autonomy": row.autonomy if row else spec["default"],
                    "updated_by": row.updated_by if row else "", "can_auto": spec["risk"] != "high"})
    return out
