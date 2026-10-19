"""Reasoning: from the current picture to proposals.

Every rule is deterministic and names the facts it rests on. A proposal carries
those facts, a rationale, a confidence, a risk tier (from policy) and the autonomy
level that applied when it was raised. The language model, when configured,
rewrites the rationale and writes briefs from the same facts; it never adds a
proposal the rules did not make, and its text is marked as narration.

Domains:
- soc: unescalated high-severity findings, cross-module correlation for one
  client, hosts that need a response action.
- admin: red readiness items, failed roster pulls, staff hygiene.
- services: quiet IR cases, retests waiting, remediation past SLA, deliverables
  awaiting client acceptance, engagements past their planned end, client briefs.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import memory, perception, policy, reach, skills
from .config import settings
from .db import Proposal, WorkItem, utcnow

log = logging.getLogger(__name__)


def _age_minutes(iso: str | None) -> float:
    if not iso:
        return 0.0
    try:
        t = dt.datetime.fromisoformat(iso)
    except ValueError:
        return 0.0
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return (utcnow() - t).total_seconds() / 60


def _pending(db: Session, key: str) -> Proposal | None:
    return db.execute(select(Proposal).where(Proposal.key == key, Proposal.status.in_(("pending", "approved", "executed")))
                      .order_by(Proposal.created_at.desc()).limit(1)).scalar_one_or_none()


def _client_id(facts: dict, target: dict) -> str:
    return str((target or {}).get("platform_client_id") or (facts or {}).get("platform_client_id") or "")


def _recently_rejected(db: Session, key: str, hours: float) -> bool:
    since = utcnow() - dt.timedelta(hours=hours)
    return db.execute(select(Proposal.id).where(Proposal.key == key, Proposal.status == "rejected",
                                                Proposal.decided_at >= since).limit(1)).first() is not None


def propose(db: Session, action: str, key: str, title: str, rationale: str, facts: dict, target: dict,
            confidence: float, domain: str | None = None, work_item: WorkItem | None = None,
            window_hours: float = 24, reject_cooldown_hours: float = 0, signature: str | None = None,
            ceiling: str | None = None) -> Proposal | None:
    """Raise a proposal unless an equivalent one is already pending, was executed
    inside the dedupe window (24 hours unless the rule says otherwise), was rejected
    inside the rule's cool-down, or the action is switched off. The action must be a
    skill in the catalog; the proposal takes its domain and risk from there.

    When the proposal targets a client, the client's autonomy override applies, and
    decision memory adjusts the confidence by what people decided before on the same
    (skill, client, signature); the adjustment is written into the facts.

    `ceiling="propose"` caps the level: the investigation agent's recommendations
    use it so they wait for a person unless an admin has raised the ceiling."""
    skill = skills.get(action)
    pid = _client_id(facts, target)
    level = policy.autonomy(db, action, pid or None)
    if level == "off":
        return None
    if ceiling == "propose" and level == "auto":
        level = "propose"  # the caller caps how far this proposal may run on its own
    prior = _pending(db, key)
    if prior is not None:
        if prior.status == "executed" and prior.executed_at and (utcnow() - prior.executed_at) < dt.timedelta(hours=window_hours):
            return None
        if prior.status in ("pending", "approved"):
            return None
    if reject_cooldown_hours and _recently_rejected(db, key, reject_cooldown_hours):
        return None
    facts = dict(facts or {})
    confidence = max(0.0, min(1.0, confidence))
    if pid:
        sig = signature or facts.get("signature") or memory.signature(facts.get("title") or title)
        facts["signature"] = sig
        confidence, record = memory.adjust(db, action, pid, sig, confidence)
        if record:
            facts["memory"] = record
            rationale += (f" Decision memory: people approved {record['approved']} and rejected {record['rejected']} "
                          f"earlier proposals like this for this client, so confidence moved {record['adjustment']:+.2f}.")
    p = Proposal(key=key, action=action, domain=domain or skill.domain, title=title[:400], rationale=rationale,
                 facts=facts, target=target, confidence=confidence, risk=skill.risk,
                 autonomy=level, work_item_id=work_item.id if work_item else None)
    db.add(p)
    db.flush()
    return p


# ---------------------------------------------------------------- SOC
def soc_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    threshold = settings.escalate_after_minutes
    by_client: dict[str, list[dict]] = defaultdict(list)
    covered_by_mdr = perception.mdr_covered_alerts(db)
    for f in perception.findings(db):
        subj = f.get("subject") or {}
        cid = subj.get("platform_client_id") or subj.get("client") or ""
        by_client[cid].append(f)
        sev = f.get("severity")
        if sev not in ("critical", "high"):
            continue
        if subj.get("case_ref"):
            continue  # already in a case
        mod = f["_module"]
        if mod == "managed-services" and str(f["id"]) in covered_by_mdr:
            continue  # MDR investigates this alert and escalates it; a second case would split the story
        wi = db.execute(select(WorkItem).where(WorkItem.key == f"finding:{mod}:{f['id']}")).scalar_one_or_none()
        # The module's triage copilot, when it has spoken and no human has decided yet.
        cp = f.get("copilot") or {}
        cp_verdict, cp_conf = cp.get("verdict") or "", float(cp.get("confidence") or 0.0)
        cp_open = bool(cp_verdict) and not cp.get("decision")
        if cp_open and cp_verdict == "false_positive" and cp_conf >= settings.copilot_fp_confidence:
            # A confident false-positive call is not escalated; a person confirms and
            # closes it in the module, where the two-person rule applies.
            p = propose(
                db, "copilot_false_positive", f"copilot_false_positive:{mod}:{f['id']}",
                f"Copilot says false positive, confirm and close: {f.get('title', '')}"[:400],
                (f"The {mod} triage copilot ({cp.get('model', 'rules')}) proposes false positive at "
                 f"{cp_conf:.0%} confidence for this {sev} finding for {subj.get('client', 'unknown client')}: "
                 f"{cp.get('rationale', '')} SABINE does not escalate it. A responder should confirm the call and "
                 f"close it in {mod}, where closing on the copilot's word needs a second approver."),
                {"module": mod, "finding_id": f["id"], "severity": sev, "title": f.get("title"),
                 "client": subj.get("client"), "platform_client_id": subj.get("platform_client_id"),
                 "copilot": {"verdict": cp_verdict, "confidence": cp_conf, "model": cp.get("model", "")}},
                {"kind": "copilot_fp", "severity": "low", "client": subj.get("client", ""),
                 "platform_client_id": subj.get("platform_client_id") or "",
                 "link": wi.link if wi else ""},
                cp_conf, work_item=wi)
            if p:
                out.append(p)
            continue
        age = _age_minutes(f.get("created_at"))
        limit = policy.threshold(db, subj.get("platform_client_id"), "escalate_after_minutes", threshold)
        if age < limit:
            continue
        confidence = 0.9 if sev == "critical" else 0.75
        why = (f"A {sev} finding (\"{f.get('title', '')}\") has been active in {mod} for "
               f"{int(age)} minutes with no IR case attached. Policy escalates {sev} findings after "
               f"{limit} minutes so a responder owns it on the {f.get('workstream', 'Scoping and Containment')} workstream.")
        facts = {"module": mod, "finding_id": f["id"], "severity": sev, "age_minutes": int(age),
                 "title": f.get("title"), "client": subj.get("client"), "platform_client_id": subj.get("platform_client_id"),
                 "matched": f.get("matched")}
        if f.get("signal_title"):
            facts["signal_title"] = f["signal_title"]  # MDR: what a suppression would match
        if f.get("source_group"):
            facts["source_group"] = f["source_group"]  # MDR: the tool a suppression is scoped to
        if cp_open and cp_verdict == "true_positive" and cp_conf >= settings.copilot_tp_confidence:
            confidence = min(0.99, confidence + 0.1)
            why += (f" The module's triage copilot ({cp.get('model', 'rules')}) agrees it is a true positive at "
                    f"{cp_conf:.0%} confidence.")
            facts["copilot"] = {"verdict": cp_verdict, "confidence": cp_conf, "model": cp.get("model", "")}
        p = propose(
            db, "escalate_finding", f"escalate_finding:{mod}:{f['id']}",
            f"Escalate {sev} {mod.replace('-', ' ')} finding for {subj.get('client', 'unknown client')}",
            why, facts,
            {"module": mod, "id": f["id"], "path": f"/api/findings/{f['id']}/escalate"},
            confidence, work_item=wi)
        if p:
            out.append(p)

    # Correlation: one client, active findings in more than one module sharing a host or term.
    for cid, rows in by_client.items():
        if not cid:
            continue
        mods = {r["_module"] for r in rows}
        if len(mods) < 2:
            continue
        anchors: dict[str, set[str]] = defaultdict(set)
        for r in rows:
            for a in (r.get("matched"), r.get("title")):
                a = (a or "").strip().lower()
                if len(a) >= 4:
                    anchors[a].add(r["_module"])
        shared = {a: m for a, m in anchors.items() if len(m) >= 2}
        if not shared:
            continue
        name = (rows[0].get("subject") or {}).get("client", cid)
        anchor, mset = sorted(shared.items(), key=lambda kv: -len(kv[1]))[0]
        p = propose(
            db, "link_related_findings", f"correlate:{cid}:{anchor[:60]}",
            f"Related findings across {len(mset)} modules for {name}",
            (f"{name} has active findings in {', '.join(sorted(mset))} that share \"{anchor}\". "
             "Seen together they are one exposure, not separate items; the responder should treat them as one story."),
            {"client": name, "platform_client_id": cid, "anchor": anchor, "modules": sorted(mset),
             "finding_ids": [r["id"] for r in rows if (r.get("matched") or "").strip().lower() == anchor or (r.get("title") or "").strip().lower() == anchor]},
            {"kind": "correlation", "client": name, "platform_client_id": cid, "severity": max((r.get("severity", "low") for r in rows), key=lambda s: perception.SEV_RANK.get(s, 0))},
            0.7)
        if p:
            out.append(p)

    # Hosts that need a response action: managed services alerts of a kind that warrants containment.
    for f in perception.findings(db):
        if f["_module"] != "managed-services" or f.get("severity") != "critical":
            continue
        if f.get("type") not in ("threat", "malware", "ransomware", "edr"):
            continue
        host = f.get("matched") or "the affected host"
        subj = f.get("subject") or {}
        p = propose(
            db, "host_action", f"host_action:{f['id']}",
            f"Consider isolating {host} ({subj.get('client', '')})",
            (f"A critical {f.get('type')} alert is active on {host} for {subj.get('client', '')}: \"{f.get('title', '')}\". "
             "SABINE does not touch hosts. A responder with the act grant should decide on isolation in managed services, "
             "where the second-person control applies."),
            {"module": "managed-services", "finding_id": f["id"], "host": host, "client": subj.get("client"), "type": f.get("type"),
             "platform_client_id": subj.get("platform_client_id") or "", "title": f.get("title")},
            {"module": "managed-services", "id": f["id"],
             "link": (reach.public_url("managed-services") + f"/alerts/{f['id']}") if reach.public_url("managed-services") else ""},
            0.6)
        if p:
            out.append(p)
    return out


# ---------------------------------------------------------------- administration
_FIX = {
    "Secret key set": "set <prefix>/<module>/SECRET_KEY in SSM and run infra/redeploy.sh <module>",
    "Sign-in possible": "set <prefix>/<module>/ADMIN_PASSWORD_HASH or verify SSO on the module's Settings > SSO page",
    "Roster from platform": "check PLATFORM_URL and PLATFORM_TOKEN for the module, then Push roster on the platform Connections page",
    "Reachable": "check the module container (docker compose ps) and its base URL on the Connections page",
    "Enabled": "set MODULE_ENABLED=true for the module and redeploy",
    "Platform secret key set": "set <prefix>/platform/SECRET_KEY and redeploy the platform",
}


def admin_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    rep = perception.readiness(db)
    items = []
    for mod in rep.get("modules") or []:
        for chk in mod.get("checks") or []:
            if chk.get("state") == "fail":
                items.append((mod["key"], mod["display_name"], chk))
    for chk in (rep.get("control_plane") or {}).get("checks") or []:
        if chk.get("state") == "fail":
            items.append(("platform", "Control plane", chk))
    for key, name, chk in items:
        label = chk.get("label", "")
        if label == "Roster from platform" and "failed" in (chk.get("detail") or ""):
            p = propose(db, "roster_sync", f"roster_sync:{key}", f"Re-sync {name} roster",
                        f"{name} reports its last roster pull failed: {chk.get('detail')}. SABINE will ask it to pull again.",
                        {"module": key, "detail": chk.get("detail")}, {"module": key, "path": "/api/provision/sync"}, 0.8)
            if p:
                out.append(p)
        p = propose(db, "readiness_remediation", f"readiness:{key}:{label}", f"{name}: {label}",
                    f"The go-live screen shows a blocking item on {name}: {label} ({chk.get('detail') or 'no detail'}). "
                    f"Fix: {_FIX.get(label, 'see the readiness screen')}.",
                    {"module": key, "check": chk}, {"kind": "readiness", "module": key, "label": label, "severity": "high"}, 0.95)
        if p:
            out.append(p)

    # Modules that did not answer at all.
    for source, snap in perception.snapshots(db).items():
        if source.startswith("module:") and not snap.ok:
            key = source.split(":", 1)[1]
            p = propose(db, "readiness_remediation", f"unreachable:{key}", f"{key} is not answering",
                        f"SABINE could not read {key}'s manifest: {snap.detail}. Check the container and the directory entry.",
                        {"module": key, "detail": snap.detail}, {"kind": "readiness", "module": key, "label": "unreachable", "severity": "critical"}, 0.9)
            if p:
                out.append(p)

    # Staff hygiene.
    st = perception.staff(db)
    people = st.get("staff") or []
    if st.get("governs"):
        active = [p for p in people if p.get("active")]
        admins = [p for p in active if p.get("platform_role") == "admin"]
        for person in active:
            if not any(m.get("role") != "none" for m in (person.get("modules") or {}).values()):
                p = propose(db, "staff_hygiene", f"staff:nogrants:{person['email']}", f"{person['email']} has no module access",
                            f"{person.get('name') or person['email']} is active on the roster but granted no module. Either grant a profile or deactivate them.",
                            {"email": person["email"]}, {"kind": "staff", "severity": "low", "link": (reach.public_url("platform") + "/staff") if reach.public_url("platform") else ""}, 0.8)
                if p:
                    out.append(p)
        if len(admins) > 5:
            p = propose(db, "staff_hygiene", "staff:many-admins", f"{len(admins)} platform admins",
                        f"{len(admins)} people hold the platform admin role. Admin should be the exception; review who needs it.",
                        {"admins": [a["email"] for a in admins]}, {"kind": "staff", "severity": "medium"}, 0.7)
            if p:
                out.append(p)
        granted = defaultdict(int)
        for person in active:
            for mk, g in (person.get("modules") or {}).items():
                if g.get("role") != "none":
                    granted[mk] += 1
        for mk in reach.directory():
            if mk in ("platform", "sabine"):
                continue
            if granted.get(mk, 0) == 0:
                p = propose(db, "staff_hygiene", f"staff:nobody:{mk}", f"Nobody is granted {mk}",
                            f"The roster governs sign-in and nobody active is granted {mk}; only the break-glass admin can get in there.",
                            {"module": mk}, {"kind": "staff", "severity": "medium"}, 0.9)
                if p:
                    out.append(p)
    return out


# ---------------------------------------------------------------- professional services
def services_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    for c in perception.cases(db):
        days = _age_minutes(c.get("last_update_at") or c.get("opened_at")) / 1440
        if days < policy.threshold(db, (c.get("client") or {}).get("platform_client_id"), "stale_case_days", settings.stale_case_days):
            continue
        board = c.get("board") or {}
        name = (c.get("client") or {}).get("name", "")
        p = propose(db, "stale_case_nudge", f"stale_case:{c['id']}", f"{c.get('number')} has been quiet for {int(days)} days",
                    (f"Case {c.get('number')} ({name}, {c.get('severity')}) has had no timeline entry for {int(days)} days. "
                     f"Lead: {c.get('lead') or 'unassigned'}. Open cards: {board.get('open', board) if isinstance(board, dict) else board}."),
                    {"case": c.get("number"), "client": name, "days": int(days), "lead": c.get("lead")},
                    {"kind": "nudge", "severity": "medium", "client": name,
                     "platform_client_id": (c.get("client") or {}).get("platform_client_id", ""),
                     "link": (reach.public_url("incident-response") + f"/cases/{c['id']}") if reach.public_url("incident-response") else ""}, 0.8)
        if p:
            out.append(p)

    for w in db.execute(select(WorkItem).where(WorkItem.kind.in_(("retest", "overdue")), WorkItem.state == "open")).scalars().all():
        action = "retest_due" if w.kind == "retest" else "remediation_overdue"
        p = propose(db, action, f"{action}:{w.key}", w.title,
                    (f"{w.client}: {w.title}. " + ("A retest is waiting on the engagement owner." if w.kind == "retest"
                     else f"Past the {w.payload.get('sla_days')}-day SLA for its severity by {w.payload.get('age_days', 0) - w.payload.get('sla_days', 0)} days; the client should hear about it.")),
                    {"work_item": w.key, **w.payload}, {"kind": "nudge", "severity": w.severity, "client": w.client,
                                                         "platform_client_id": w.platform_client_id, "link": w.link}, 0.85, work_item=w)
        if p:
            out.append(p)

    # Office of Special Projects: a deliverable the client has not accepted, and an
    # engagement past its planned end. Both are notes to the engagement lead; nothing
    # goes to the client.
    for w in db.execute(select(WorkItem).where(WorkItem.kind.in_(("acceptance", "engagement_overdue")), WorkItem.state == "open")).scalars().all():
        action = "deliverable_acceptance_nudge" if w.kind == "acceptance" else "engagement_overdue"
        if w.kind == "acceptance":
            why = (f"\"{w.payload.get('deliverable')}\" was delivered {w.payload.get('age_days', 0)} days ago and the client has not "
                   f"accepted it on the portal (window {w.payload.get('nudge_days')} days). The engagement lead "
                   f"({w.payload.get('lead') or 'unassigned'}) should follow up with the sponsor; nothing has been sent to the client.")
        else:
            why = (f"\"{w.payload.get('engagement')}\" ({w.payload.get('kind')}) is {w.payload.get('status')} and "
                   f"{w.payload.get('days_over', 0)} days past its planned end, {w.payload.get('progress', 0)}% of deliverables accepted. "
                   f"The lead ({w.payload.get('lead') or 'unassigned'}) should close it, extend it, or say what is blocking.")
        p = propose(db, action, f"{action}:{w.key}", w.title, f"{w.client}: {why}",
                    {"work_item": w.key, **w.payload}, {"kind": "nudge", "severity": w.severity, "client": w.client,
                                                         "platform_client_id": w.platform_client_id, "link": w.link}, 0.85, work_item=w)
        if p:
            out.append(p)

    # A brief per client that has anything active, at most once a day (dedupe window in propose).
    for cl in perception.clients(db):
        has = any(((f.get("subject") or {}).get("platform_client_id") == cl["id"]) for f in perception.findings(db)) or \
              any(((c.get("client") or {}).get("platform_client_id") == cl["id"]) for c in perception.cases(db))
        if not has:
            continue
        p = propose(db, "client_brief", f"client_brief:{cl['id']}:{utcnow().date().isoformat()}", f"Brief for {cl['name']}",
                    f"{cl['name']} has active findings or cases; a current posture brief is written for the account owner to send.",
                    {"client": cl["name"], "platform_client_id": cl["id"]},
                    {"kind": "brief", "client": cl["name"], "platform_client_id": cl["id"]}, 0.9)
        if p:
            out.append(p)
    p = propose(db, "daily_summary", f"daily_summary:{utcnow().date().isoformat()}", "Daily summary",
                "The day's observations, proposals, decisions and actions for the stand-up.", {}, {"kind": "summary"}, 1.0)
    if p:
        out.append(p)
    return out


def run(db: Session) -> list[Proposal]:
    from . import concierge

    from . import investigator

    out = (soc_rules(db) + investigator.rules(db) + concierge.soc_rules(db) + admin_rules(db) + services_rules(db)
           + concierge.services_rules(db) + concierge.business_rules(db))
    # A finding SABINE already investigated: its conclusion goes on any proposal a
    # rule just raised about it, so the person deciding sees both.
    for p in out:
        if p.action in ("escalate_finding", "host_action", "page_oncall", "copilot_false_positive"):
            investigator.annotate_new(db, p)
    db.commit()
    return out


def expire(db: Session) -> int:
    cutoff = utcnow() - dt.timedelta(hours=settings.proposal_ttl_hours)
    n = 0
    for p in db.execute(select(Proposal).where(Proposal.status == "pending", Proposal.created_at < cutoff)).scalars().all():
        p.status = "expired"
        n += 1
    db.commit()
    return n
