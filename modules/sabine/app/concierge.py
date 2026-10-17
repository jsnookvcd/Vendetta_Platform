"""Concierge and business rules: SABINE running the business.

SOC:
- page_oncall: a critical MDR investigation or managed-services critical with no
  acknowledgement past the client's critical_ack_minutes commitment.
- suggest_suppression: a detection pattern people keep calling noise for one client.

Services (through the platform, never straight to a client):
- journey_suggest and journey_progress: the Security Journey, from evidence.
- posture_review: the monthly review, drafted for a person to approve.
- client_outreach: an email draft when a campaign touches the client, a deliverable
  sits unaccepted, or a response commitment is at risk.

Business (Harvest and HubSpot, when configured):
- engagement_budget_burn, capacity_overload, renewal_upcoming, won_not_onboarded.

Every rule here names the facts it rests on, a rationale and a confidence, and
goes through reasoner.propose, so dedupe, per-client autonomy and decision memory
apply exactly as they do for the original rules.
"""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import business, memory, perception, policy, reach
from .config import settings
from .db import Proposal, WorkItem, utcnow
from .reasoner import _age_minutes, propose

MODULE_LABEL = {"dark-web-monitoring": "dark web monitoring", "managed-services": "managed services",
                "vulnerability-management": "vulnerability management", "penetration-testing": "penetration testing",
                "mdr": "MDR"}
MODULE_AREA = {"dark-web-monitoring": "identity", "managed-services": "endpoint", "vulnerability-management": "vulnerability",
               "penetration-testing": "vulnerability", "mdr": "response"}
_CLASS_AREA = (("phish", "awareness"), ("social", "awareness"), ("email", "email"), ("spf", "email"), ("dmarc", "email"),
               ("cloud", "cloud"), ("aws", "cloud"), ("azure", "cloud"), ("s3", "cloud"), ("network", "network"),
               ("firewall", "network"), ("smb", "network"), ("password", "identity"), ("credential", "identity"),
               ("mfa", "identity"), ("auth", "identity"), ("privilege", "identity"), ("data", "data"), ("backup", "data"))
JOURNEY_WINDOW_H = 30 * 24
MONTH_H = 31 * 24


def _link(mod: str, fid: str) -> str:
    pub = reach.public_url(mod)
    return pub + perception.FINDING_PATH[mod].format(id=fid) if pub and mod in perception.FINDING_PATH else ""


def _client_map(db: Session) -> dict[str, dict]:
    return {c["id"]: c for c in perception.clients(db) if c.get("id")}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:40] or "other"


def _norm_name(s: str) -> str:
    words = re.findall(r"[a-z0-9]+", (s or "").lower())
    return " ".join(w for w in words if w not in ("inc", "llc", "ltd", "the", "co", "corp", "corporation", "company"))


# ---------------------------------------------------------------- SOC
def page_title(title: str) -> str:
    t = title.replace("Page on-call: ", "", 1)
    return t[:1].upper() + t[1:]


def _unacknowledged(f: dict) -> bool:
    if f.get("acknowledged_at"):
        return False
    if f["_module"] == "mdr":
        return (f.get("native_status") or "new") == "new"
    return (f.get("status") or "new") == "new"


def soc_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    cmap = _client_map(db)
    covered_by_mdr = perception.mdr_covered_alerts(db)
    for f in perception.findings(db):
        mod = f["_module"]
        if mod not in ("mdr", "managed-services") or f.get("severity") != "critical" or not _unacknowledged(f):
            continue
        if mod == "managed-services" and str(f["id"]) in covered_by_mdr:
            continue  # the MDR investigation over this alert is the one that pages
        subj = f.get("subject") or {}
        if subj.get("case_ref") or f.get("escalated_case"):
            continue  # a case exists and the hub paged when it opened
        cp = f.get("copilot") or {}
        if cp.get("verdict") == "false_positive" and not cp.get("decision") and float(cp.get("confidence") or 0) >= settings.copilot_fp_confidence:
            continue  # queued to confirm and close instead
        pid = subj.get("platform_client_id") or ""
        client = cmap.get(pid) or {"id": pid, "name": subj.get("client", "")}
        ack, source = policy.critical_ack(db, client)
        since = f.get("opened_at") or f.get("created_at")
        age = _age_minutes(since)
        if age < ack:
            continue
        name = subj.get("client") or client.get("name") or "unknown client"
        what = "MDR investigation" if mod == "mdr" else "managed-services alert"
        ref = f"{mod}:{f['id']}"
        link = _link(mod, f["id"])
        title = f"Page on-call: critical {what} unacknowledged {int(age)}m for {name}"
        body = (f"A critical {what} for {name} has gone {int(age)} minutes without acknowledgement; the commitment is "
                f"{ack} minutes ({source}). \"{f.get('title', '')}\"" + (f" on {f['matched']}" if f.get("matched") else "") + ".")
        p = propose(
            db, "page_oncall", f"page_oncall:{ref}", title,
            (f"{body} SABINE pages the on-call responder through the IR hub so a person acknowledges it now. "
             f"She pages again only if it is still unacknowledged after {settings.page_repeat_minutes} minutes."),
            {"module": mod, "finding_id": f["id"], "severity": "critical", "title": f.get("title"), "client": name,
             "platform_client_id": pid, "age_minutes": int(age), "ack_minutes": ack, "commitment_source": source,
             "matched": f.get("matched"), "rule": f.get("rule"), "signal_title": f.get("signal_title") or ""},
            {"module": "incident-response", "path": "/api/oncall/page", "platform_client_id": pid, "client": name,
             "link": link, "body": {"title": page_title(title), "body": body, "link": link,
                                    "severity": "critical", "platform_client_id": pid, "client": name,
                                    "source_module": mod, "source_ref": f["id"]}},
            0.9 if mod == "mdr" else 0.85, window_hours=settings.page_repeat_minutes / 60)
        if p:
            out.append(p)

    # Decision memory: a pattern people keep calling noise for one client.
    active = perception.suppressions(db)
    now = utcnow()

    def covered(pid: str, phrase: str) -> bool:
        for s in active:
            if (s.get("platform_client_id") or (s.get("client") if isinstance(s.get("client"), str) else "")) != pid:
                continue
            exp = s.get("expires_at")
            try:
                t = dt.datetime.fromisoformat(exp) if exp else None
            except ValueError:
                t = None
            if t is not None and t.tzinfo is None:
                t = t.replace(tzinfo=dt.timezone.utc)
            if t is not None and t <= now:
                continue
            m = s.get("match") or s
            needle = (m.get("title_contains") or "").lower()
            if needle and needle in phrase.lower():
                return True
        return False

    n = settings.suppression_suggest_after
    for (pid, sig), h in memory.noise(db).items():
        total = h["false_positive"] + h["rejected"]
        if total < n or not sig:
            continue
        phrase = memory.common_phrase(h["titles"])
        if not phrase or covered(pid, phrase):
            continue
        name = h["client"] or (cmap.get(pid) or {}).get("name", "")
        p = propose(
            db, "suggest_suppression", f"suggest_suppression:{pid}:{memory.sig_hash(sig)}",
            f"Suppress \"{phrase}\" for {name} for {settings.suppression_days} days"[:400],
            (f"People have called \"{phrase}\" noise for {name} {total} times "
             f"({h['false_positive']} MDR investigations closed as false positive, {h['rejected']} SABINE proposals rejected). "
             f"The threshold is {n}. A {settings.suppression_days}-day MDR suppression for this client only stops the repeat "
             "work; it expires on its own and shows on MDR's monthly review list."),
            {"module": "mdr", "platform_client_id": pid, "client": name, "title": phrase, "signature": sig,
             "false_positive": h["false_positive"], "rejected": h["rejected"], "threshold": n,
             "hosts": sorted(h["hosts"])[:10]},
            {"module": "mdr", "path": "/api/suppressions", "platform_client_id": pid, "client": name,
             "title_contains": phrase, "days": settings.suppression_days,
             "reason": f"SABINE: called noise {total} times for this client ({h['false_positive']} false positive, {h['rejected']} rejected)"},
            min(0.9, 0.6 + 0.05 * (total - n)), reject_cooldown_hours=7 * 24, signature=sig)
        if p:
            out.append(p)
    return out


# ---------------------------------------------------------------- the Security Journey
def _class_area(cls: str) -> str:
    low = (cls or "").lower()
    return next((a for k, a in _CLASS_AREA if k in low), "vulnerability")


def evidence(db: Session) -> dict[str, dict]:
    """Every piece of evidence a journey item can rest on, keyed by its stable
    source_ref: {pid, client, title, detail, area, count, requires, due_on}."""
    out: dict[str, dict] = {}
    cmap = _client_map(db)
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for f in perception.findings(db):
        pid = (f.get("subject") or {}).get("platform_client_id") or ""
        if pid:
            groups[(pid, f["_module"], memory.signature(f.get("title") or ""))].append(f)
    for (pid, mod, sig), rows in groups.items():
        if len(rows) < settings.journey_recurring_min or not sig:
            continue
        title = memory.common_phrase([r.get("title") or "" for r in rows])
        out[f"recurring:{pid}:{mod}:{memory.sig_hash(sig)}"] = {
            "pid": pid, "client": (rows[0].get("subject") or {}).get("client", ""), "count": len(rows),
            "title": f"Fix the root cause behind recurring {MODULE_LABEL.get(mod, mod)} findings: {title}"[:200],
            "detail": (f"{len(rows)} active {MODULE_LABEL.get(mod, mod)} findings share the pattern \"{title}\". "
                       "Fixing the cause once removes the repeat work and the repeat exposure."),
            "area": MODULE_AREA.get(mod, "governance"), "requires": [f"findings:{mod}"], "kind": "recurring pattern"}
    # Remediation past SLA, per client and severity.
    over: dict[tuple[str, str], list[WorkItem]] = defaultdict(list)
    for w in db.execute(select(WorkItem).where(WorkItem.kind == "overdue", WorkItem.state.in_(("open", "claimed")))).scalars().all():
        if w.platform_client_id:
            over[(w.platform_client_id, w.severity)].append(w)
    for (pid, sev), rows in over.items():
        worst = max((r.payload.get("age_days", 0) - r.payload.get("sla_days", 0)) for r in rows)
        sla = rows[0].payload.get("sla_days")
        out[f"overdue:{pid}:{sev}"] = {
            "pid": pid, "client": rows[0].client, "count": len(rows),
            "title": f"Bring {sev} vulnerability remediation inside the {sla}-day SLA",
            "detail": f"{len(rows)} {sev} vulnerabilities are past the {sla}-day remediation SLA, the oldest by {worst} days.",
            "area": "vulnerability", "requires": ["findings:vulnerability-management"], "kind": "overdue remediation",
            "due_on": (utcnow().date() + dt.timedelta(days=30)).isoformat()}
    # Penetration test finding classes.
    classes: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in perception.findings(db):
        if f["_module"] == "penetration-testing":
            pid = (f.get("subject") or {}).get("platform_client_id") or ""
            if pid:
                classes[(pid, f.get("category") or f.get("type") or "finding")].append(f)
    for (pid, cls), rows in classes.items():
        serious = any(perception.SEV_RANK.get(r.get("severity"), 0) >= 2 for r in rows)
        if len(rows) < 2 and not serious:
            continue
        out[f"pentest:{pid}:{_slug(cls)}"] = {
            "pid": pid, "client": (rows[0].get("subject") or {}).get("client", ""), "count": len(rows),
            "title": f"Remediate the {cls} class of penetration test findings"[:200],
            "detail": f"Penetration testing found {len(rows)} open {cls} finding(s); treating the class as one piece of work closes them together.",
            "area": _class_area(cls), "requires": ["findings:penetration-testing"], "kind": "pentest class"}
    # Posture gaps.
    creds: dict[str, list[dict]] = defaultdict(list)
    for f in perception.findings(db):
        if f["_module"] == "dark-web-monitoring" and "@" in (f.get("matched") or ""):
            pid = (f.get("subject") or {}).get("platform_client_id") or ""
            if pid:
                creds[pid].append(f)
    for pid, rows in creds.items():
        out[f"gap:{pid}:credentials"] = {
            "pid": pid, "client": (rows[0].get("subject") or {}).get("client", ""), "count": len(rows),
            "title": "Enforce MFA everywhere and rotate exposed credentials",
            "detail": f"Exposed credentials on the dark web: {len(rows)}. MFA on every account and a rotation of the exposed ones takes them off the table.",
            "area": "identity", "requires": ["findings:dark-web-monitoring"], "kind": "posture gap"}
    for pid, c in cmap.items():
        svc = c.get("services")
        if isinstance(svc, list) and svc and not ({"managed-services", "mdr"} & set(svc)):
            out[f"gap:{pid}:detection"] = {
                "pid": pid, "client": c.get("name", ""), "count": 1,
                "title": "Bring endpoints under 24x7 managed detection and response",
                "detail": "No managed detection service watches your endpoints today, so an intrusion is found when it is already an incident.",
                "area": "endpoint", "requires": ["platform:clients"], "kind": "posture gap"}
    return out


def _requires_for(ref: str) -> list[str]:
    parts = ref.split(":")
    kind = parts[0]
    if kind == "recurring" and len(parts) >= 4:
        return [f"findings:{parts[2]}"]
    if kind == "overdue":
        return ["findings:vulnerability-management"]
    if kind == "pentest":
        return ["findings:penetration-testing"]
    if kind == "gap" and len(parts) >= 3:
        return ["findings:dark-web-monitoring"] if parts[2] == "credentials" else ["platform:clients"]
    return []


def _suggested_count(db: Session, ref: str) -> int | None:
    p = db.execute(select(Proposal).where(Proposal.key == f"journey_suggest:{ref}", Proposal.status == "executed")
                   .order_by(Proposal.created_at.desc()).limit(1)).scalar_one_or_none()
    return int((p.facts or {}).get("count") or 0) if p else None


def journey_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    ev = evidence(db)
    active = {c["id"]: c for c in perception.active_clients(db)}
    for ref, e in ev.items():
        c = active.get(e["pid"])
        if c is None:
            continue
        items = perception.journey(db, e["pid"])
        if items is None or any(i.get("source_ref") == ref for i in items):
            continue  # unread, or already on the journey in any state (declined stays declined)
        p = propose(
            db, "journey_suggest", f"journey_suggest:{ref}", f"Journey for {c['name']}: {e['title']}"[:400],
            (f"{c['name']}: {e['detail']} SABINE proposes it on the client's Security Journey ({e['area']}); "
             "a person accepts or declines it on the platform before the client sees it."),
            {"client": c["name"], "platform_client_id": e["pid"], "source_ref": ref, "evidence": e["kind"],
             "count": e["count"], "area": e["area"], "title": e["title"]},
            {"kind": "journey", "platform_client_id": e["pid"], "client": c["name"], "title": e["title"],
             "detail": e["detail"], "area": e["area"], "source_ref": ref, "due_on": e.get("due_on")},
            0.75 if e["kind"] == "recurring pattern" else 0.8, window_hours=JOURNEY_WINDOW_H)
        if p:
            out.append(p)
    # Progress: evidence gone means done; shrinking evidence moves a planned item along.
    for pid, c in active.items():
        for item in perception.journey(db, pid) or []:
            ref = item.get("source_ref") or ""
            if item.get("status") not in ("planned", "in_progress") or ref.split(":")[0] not in ("recurring", "overdue", "pentest", "gap"):
                continue
            needs = _requires_for(ref)
            if not needs or not all(perception.ok(db, s) for s in needs):
                continue  # never conclude "resolved" from a source that did not answer
            now_ev = ev.get(ref)
            if now_ev is None:
                status, note = "done", "The evidence this item rested on is resolved."
            elif item.get("status") == "planned":
                before = _suggested_count(db, ref)
                if before is None or now_ev["count"] >= before:
                    continue
                status, note = "in_progress", f"Down from {before} to {now_ev['count']}; the work is under way."
            else:
                continue
            p = propose(
                db, "journey_progress", f"journey_progress:{item.get('id')}:{status}",
                f"Journey for {c['name']}: {item.get('title', '')} is {status.replace('_', ' ')}"[:400],
                f"{c['name']}: \"{item.get('title', '')}\" was {item.get('status')}. {note} SABINE records the progress on the platform.",
                {"client": c["name"], "platform_client_id": pid, "item_id": item.get("id"), "source_ref": ref,
                 "from": item.get("status"), "to": status, "count": now_ev["count"] if now_ev else 0,
                 "title": item.get("title")},
                {"kind": "journey_progress", "platform_client_id": pid, "client": c["name"], "item_id": item.get("id"),
                 "status": status, "note": note, "source_ref": ref},
                0.9 if status == "done" else 0.75, window_hours=JOURNEY_WINDOW_H)
            if p:
                out.append(p)
    return out


# ---------------------------------------------------------------- communications
def _has_comm(db: Session, pid: str, ref: str) -> bool | None:
    items = perception.communications(db, pid)
    if items is None:
        return None
    return any(i.get("source_ref") == ref for i in items)


def review_month(now: dt.datetime | None = None) -> str:
    return (now or utcnow()).strftime("%Y-%m")


def communication_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    now = utcnow()
    active = {c["id"]: c for c in perception.active_clients(db)}
    month = review_month(now)
    if now.day >= settings.posture_review_day:
        for pid, c in active.items():
            ref = f"review:{pid}:{month}"
            if _has_comm(db, pid, ref) is not False:
                continue  # already drafted (or the platform could not be read)
            p = propose(
                db, "posture_review", f"posture_review:{pid}:{month}", f"Posture review for {c['name']}, {now:%B %Y}",
                (f"{c['name']} is an active client and has no posture review for {now:%B %Y}. SABINE drafts it from live data "
                 "and what she did on the account, redacted for the client, and posts it as a draft on the platform; "
                 "the account lead approves it before the client sees it."),
                {"client": c["name"], "platform_client_id": pid, "month": month, "source_ref": ref},
                {"kind": "posture_review", "platform_client_id": pid, "client": c["name"], "month": month, "source_ref": ref},
                0.9, window_hours=MONTH_H)
            if p:
                out.append(p)

    def outreach(pid: str, ref: str, reason: str, title: str, why: str, facts: dict, conf: float):
        c = active.get(pid)
        if c is None or _has_comm(db, pid, ref) is not False:
            return
        p = propose(db, "client_outreach", f"client_outreach:{ref}", f"Outreach to {c['name']}: {title}"[:400],
                    f"{c['name']}: {why} SABINE drafts the email on the platform; a person approves it and it sends.",
                    {"client": c["name"], "platform_client_id": pid, "reason": reason, "source_ref": ref, **facts},
                    {"kind": "outreach", "platform_client_id": pid, "client": c["name"], "reason": reason, "source_ref": ref},
                    conf, window_hours=MONTH_H)
        if p:
            out.append(p)

    # A campaign: one high or critical pattern active at several clients.
    camp: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for f in perception.findings(db):
        if perception.SEV_RANK.get(f.get("severity"), 0) < 2:
            continue
        pid = (f.get("subject") or {}).get("platform_client_id") or ""
        sig = memory.signature(f.get("title") or "")
        if pid and sig:
            camp[sig][pid].append(f)
    for sig, by in camp.items():
        if len(by) < settings.campaign_min_clients:
            continue
        for pid, rows in by.items():
            outreach(pid, f"campaign:{memory.sig_hash(sig)}:{pid}", "campaign", "activity seen across several organizations",
                     (f"the pattern \"{rows[0].get('title', '')}\" is active at {len(by)} clients at once, {len(rows)} time(s) here. "
                      "A short note tells them it is a known campaign and that it is being worked."),
                     {"pattern": rows[0].get("title"), "clients_touched": len(by), "count": len(rows),
                      "modules": sorted({r["_module"] for r in rows}), "severity": max((r.get("severity") for r in rows), key=lambda s: perception.SEV_RANK.get(s, 0))},
                     0.75)
    # A deliverable unaccepted well past the internal nudge.
    for w in db.execute(select(WorkItem).where(WorkItem.kind == "acceptance", WorkItem.state.in_(("open", "claimed")))).scalars().all():
        age = int(w.payload.get("age_days") or 0)
        if age < settings.outreach_acceptance_days or not w.platform_client_id:
            continue
        outreach(w.platform_client_id, f"acceptance:{w.payload.get('deliverable_id')}", "acceptance",
                 f"review of {w.payload.get('deliverable')}",
                 (f"\"{w.payload.get('deliverable')}\" ({w.payload.get('engagement')}) was delivered {age} days ago and is not accepted; "
                  f"the window for a client note is {settings.outreach_acceptance_days} days."),
                 {"deliverable": w.payload.get("deliverable"), "engagement": w.payload.get("engagement"),
                  "delivered_at": w.payload.get("delivered_at"), "age_days": age}, 0.8)
    # A response commitment at risk: a critical investigation still not contained.
    for f in perception.findings(db):
        if f["_module"] != "mdr" or f.get("severity") != "critical" or f.get("contained_at"):
            continue
        pid = (f.get("subject") or {}).get("platform_client_id") or ""
        c = active.get(pid)
        if c is None:
            continue
        try:
            contain = int(((c.get("commitments") or {}).get("critical_contain_minutes")) or settings.critical_contain_minutes)
        except (TypeError, ValueError):
            contain = settings.critical_contain_minutes
        age = _age_minutes(f.get("opened_at") or f.get("created_at"))
        if age < contain * settings.commitment_risk_pct / 100:
            continue
        outreach(pid, f"commitment:{f['id']}", "commitment", f"status of {f.get('number') or 'a critical investigation'}",
                 (f"critical investigation {f.get('number') or f['id']} has been open {int(age)} minutes without containment "
                  f"against a {contain}-minute containment commitment. The client should hear it from us first."),
                 {"number": f.get("number"), "title": f.get("title"), "age_minutes": int(age), "contain_minutes": contain,
                  "acknowledged": bool(f.get("acknowledged_at")), "module": "mdr", "finding_id": f["id"]}, 0.85)
    return out


def services_rules(db: Session) -> list[Proposal]:
    return journey_rules(db) + communication_rules(db)


# ---------------------------------------------------------------- business
def _platform_match(db: Session, name: str) -> dict | None:
    n = _norm_name(name)
    if not n:
        return None
    return next((c for c in perception.clients(db) if _norm_name(c.get("name", "")) == n), None)


def _posture(db: Session, pid: str) -> dict:
    sev: dict[str, int] = {}
    for f in perception.findings(db):
        if (f.get("subject") or {}).get("platform_client_id") == pid:
            sev[f.get("severity", "low")] = sev.get(f.get("severity", "low"), 0) + 1
    cases = sum(1 for c in perception.cases(db) if (c.get("client") or {}).get("platform_client_id") == pid)
    return {"active_findings": sev, "open_cases": cases}


def business_rules(db: Session) -> list[Proposal]:
    out: list[Proposal] = []
    st = business.status()
    if st["harvest"] == "configured" and perception.ok(db, "harvest:projects"):
        for pj in perception.harvest_projects(db):
            pct = pj.get("pct")
            if pct is None or pct < settings.budget_burn_pct:
                continue
            band = 100 if pct >= 100 else settings.budget_burn_pct
            p = propose(
                db, "engagement_budget_burn", f"engagement_budget_burn:{pj['id']}:{band}",
                f"{pj['name']} ({pj.get('client') or 'no client'}) has used {pct:.0f}% of its budget"[:400],
                (f"Harvest shows {pj['name']} at {pj['spent']:,.0f} of {pj['budget']:,.0f} {pj.get('budget_by') or ''} spent "
                 f"({pct:.0f}%), past the {settings.budget_burn_pct}% threshold. The engagement lead should confirm the remaining "
                 "scope fits or raise a change order before the work runs over."),
                {"project_id": pj["id"], "project": pj["name"], "harvest_client": pj.get("client"), "budget": pj["budget"],
                 "spent": pj["spent"], "remaining": pj.get("remaining"), "pct": pct, "threshold": settings.budget_burn_pct},
                {"kind": "budget", "severity": "high" if pct >= 100 else "medium", "client": pj.get("client") or ""},
                0.9, window_hours=7 * 24)
            if p:
                out.append(p)
    if st["harvest"] == "configured" and perception.ok(db, "harvest:capacity"):
        for u in perception.harvest_capacity(db):
            pct = u.get("pct")
            if pct is None or pct < settings.capacity_pct:
                continue
            p = propose(
                db, "capacity_overload", f"capacity_overload:{u['id']}:{u.get('week', '')}",
                f"{u['name'] or u['email']} is at {pct:.0f}% of capacity this week",
                (f"Harvest shows {u['hours']} hours logged this week against a {u['capacity_hours']}-hour capacity ({pct:.0f}%), "
                 f"past the {settings.capacity_pct}% threshold. Rebalance the load before it costs quality or the person."),
                {"user_id": u["id"], "name": u["name"], "email": u["email"], "hours": u["hours"],
                 "capacity_hours": u["capacity_hours"], "pct": pct, "week": u.get("week"), "threshold": settings.capacity_pct},
                {"kind": "capacity", "severity": "medium"}, 0.85, window_hours=7 * 24)
            if p:
                out.append(p)
    if st["hubspot"] == "configured" and perception.ok(db, "hubspot:deals"):
        deals = perception.hubspot_deals(db)
        today = utcnow().date()
        for d in deals.get("renewals") or []:
            try:
                close = dt.date.fromisoformat(d.get("close_date") or "")
            except ValueError:
                continue
            days = (close - today).days
            if days < 0 or days > settings.renewal_days:
                continue
            c = _platform_match(db, d.get("company") or "")
            posture = _posture(db, c["id"]) if c else {}
            p = propose(
                db, "renewal_upcoming", f"renewal_upcoming:{d['id']}",
                f"Renewal in {days} days: {d.get('company') or d.get('name')} ({d.get('amount', 0):,.0f})"[:400],
                (f"HubSpot has the renewal \"{d.get('name')}\" for {d.get('company') or 'an unnamed company'} closing {close.isoformat()} "
                 f"({days} days, inside the {settings.renewal_days}-day window), stage {d.get('stage') or 'unknown'}. "
                 + (f"On the platform they have {sum(posture['active_findings'].values())} active findings and {posture['open_cases']} open case(s). "
                    if c else "No matching client on the platform. ")
                 + "The account lead should prepare the renewal conversation now."),
                {"deal_id": d["id"], "deal": d.get("name"), "company": d.get("company"), "close_date": close.isoformat(),
                 "days": days, "amount": d.get("amount"), "stage": d.get("stage"), "platform_client_id": "",
                 "matched_client": c.get("name") if c else None, "posture": posture},
                {"kind": "renewal", "severity": "medium" if days > 14 else "high", "client": d.get("company") or ""},
                0.9, window_hours=30 * 24)
            if p:
                out.append(p)
        active_names = {_norm_name(c.get("name", "")): c for c in perception.active_clients(db)}
        for d in deals.get("won") or []:
            try:
                close = dt.date.fromisoformat(d.get("close_date") or "")
            except ValueError:
                continue
            age = (today - close).days
            if age < settings.won_onboard_days or age > settings.won_lookback_days:
                continue
            c = active_names.get(_norm_name(d.get("company") or ""))
            if c is not None and (c.get("services") is None or c.get("services")):
                continue  # on the platform with services (or services not reported): onboarded
            why = "has no active client on the platform" if c is None else "is on the platform with no service enabled"
            p = propose(
                db, "won_not_onboarded", f"won_not_onboarded:{d['id']}",
                f"Won {age} days ago, not onboarded: {d.get('company') or d.get('name')}"[:400],
                (f"HubSpot shows \"{d.get('name')}\" closed won on {close.isoformat()} ({d.get('amount', 0):,.0f}), and "
                 f"{d.get('company') or 'the company'} {why} after {age} days. Onboarding should start: add the client on the "
                 "platform, set its tier and enable its services."),
                {"deal_id": d["id"], "deal": d.get("name"), "company": d.get("company"), "close_date": close.isoformat(),
                 "age_days": age, "amount": d.get("amount"), "platform_client_id": ""},
                {"kind": "onboarding", "severity": "medium", "client": d.get("company") or "",
                 "link": (reach.public_url("platform") + "/clients") if reach.public_url("platform") else ""},
                0.85, window_hours=7 * 24)
            if p:
                out.append(p)
    return out
