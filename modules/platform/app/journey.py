"""Client tiers, the Security Journey and client communications.

Tier sets the default response commitments a client is promised; an operator can
override either number per client. The Security Journey is the client's agreed
improvement plan: SABINE or staff propose items, a person accepts or declines a
proposal, and automation may then report progress on accepted items. A
communication (posture review or outreach) is drafted by SABINE or staff and has
one human approval point: the client's account lead or a platform admin approves
it, which publishes it to the client portal and emails the client's executives
when mail is configured. Mail never fails an approval; the outcome is recorded.
"""
from __future__ import annotations

import datetime as dt
import html
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import notify
from .config import settings
from .db import Client, Communication, JourneyItem, utcnow

TIERS = ("core", "advanced", "premier")
TIER_NAMES = {"core": "Core", "advanced": "Advanced", "premier": "Premier"}
TIER_DEFAULTS = {
    "core": {"critical_ack_minutes": 15, "critical_contain_minutes": 240},
    "advanced": {"critical_ack_minutes": 10, "critical_contain_minutes": 120},
    "premier": {"critical_ack_minutes": 5, "critical_contain_minutes": 60},
}

AREAS = ("identity", "endpoint", "cloud", "email", "network", "data", "vulnerability", "response",
         "governance", "awareness")
STATUSES = ("proposed", "planned", "in_progress", "done", "declined")
STATUS_NAMES = {"proposed": "Proposed", "planned": "Planned", "in_progress": "In progress", "done": "Done",
                "declined": "Declined"}
# What automation may report on an accepted item.
PROGRESS_STATUSES = ("in_progress", "done")
# What the client sees on the portal: never a proposal nobody accepted, never a decline.
PORTAL_STATUSES = ("planned", "in_progress", "done")

COMM_KINDS = ("posture_review", "outreach")
COMM_KIND_NAMES = {"posture_review": "Posture review", "outreach": "Outreach"}
COMM_STATUSES = ("draft", "approved", "sent", "discarded")
STALE_DRAFT_DAYS = 7


class JourneyError(Exception):
    """A rule was broken. status is the HTTP status the API answers with."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _iso(v) -> str | None:
    return v.isoformat() if v else None


def source_for(actor: str) -> str:
    """A bearer-token caller is SABINE (or another automation); a session is staff."""
    return "sabine" if actor.startswith("api") else "staff"


def parse_due(raw) -> dt.date | None:
    if raw in (None, ""):
        return None
    try:
        return dt.date.fromisoformat(str(raw)[:10])
    except ValueError:
        raise JourneyError(400, "due_on must be YYYY-MM-DD")


# ---------------------------------------------------------------- tiers
def clean_tier(raw: str) -> str:
    t = (raw or "core").strip().lower()
    if t not in TIERS:
        raise JourneyError(400, f"tier must be one of {', '.join(TIERS)}")
    return t


def clean_minutes(raw) -> int | None:
    """A blank override means use the tier default; otherwise a positive whole number."""
    if raw in (None, ""):
        return None
    try:
        n = int(str(raw).strip())
    except ValueError:
        raise JourneyError(400, "response commitments are whole minutes")
    if n <= 0 or n > 100000:
        raise JourneyError(400, "response commitments must be between 1 and 100000 minutes")
    return n


# ---------------------------------------------------------------- journey
def item_dict(i: JourneyItem) -> dict:
    return {"id": i.id, "title": i.title, "detail": i.detail, "area": i.area, "status": i.status,
            "due_on": i.due_on.isoformat() if i.due_on else None, "source": i.source,
            "source_ref": i.source_ref, "note": i.note, "created_at": _iso(i.created_at),
            "updated_at": _iso(i.updated_at), "decided_by": i.decided_by}


def items_for(db: Session, client_id: str, statuses=None) -> list[JourneyItem]:
    q = select(JourneyItem).where(JourneyItem.client_id == client_id)
    if statuses:
        q = q.where(JourneyItem.status.in_(tuple(statuses)))
    rows = db.execute(q.order_by(JourneyItem.created_at)).scalars().all()
    order = {s: n for n, s in enumerate(("in_progress", "planned", "proposed", "done", "declined"))}
    return sorted(rows, key=lambda i: (order.get(i.status, 9), i.due_on or dt.date.max, i.created_at))


def _validate_item(title: str, area: str) -> tuple[str, str]:
    title = (title or "").strip()
    area = (area or "").strip().lower()
    if not title:
        raise JourneyError(400, "title is required")
    if area not in AREAS:
        raise JourneyError(400, f"area must be one of {', '.join(AREAS)}")
    return title[:300], area


def create_item(db: Session, client: Client, *, title: str, detail: str = "", area: str, source_ref: str = "",
                due_on=None, source: str = "staff", status: str = "proposed", actor: str = "") -> tuple[JourneyItem, bool]:
    """Create an item, or return the existing one for the same (client, source_ref)."""
    title, area = _validate_item(title, area)
    due = parse_due(due_on)
    ref = (source_ref or "").strip()[:300]
    if ref:
        existing = db.execute(select(JourneyItem).where(JourneyItem.client_id == client.id,
                                                        JourneyItem.source_ref == ref)).scalar_one_or_none()
        if existing:
            return existing, False
    item = JourneyItem(client_id=client.id, title=title, detail=(detail or "").strip(), area=area, status=status,
                       due_on=due, source=source, source_ref=ref,
                       decided_by=actor if status == "planned" else "")
    db.add(item)
    try:
        db.commit()
    except IntegrityError:
        # A concurrent create with the same source_ref won the race; hand back theirs.
        db.rollback()
        existing = db.execute(select(JourneyItem).where(JourneyItem.client_id == client.id,
                                                        JourneyItem.source_ref == ref)).scalar_one()
        return existing, False
    return item, True


def progress_item(db: Session, item: JourneyItem, status: str, note: str = "") -> JourneyItem:
    """Automation reports progress. Only a person accepts a proposal, so an item that
    is proposed or declined cannot be moved here."""
    if status not in PROGRESS_STATUSES:
        raise JourneyError(400, f"status must be one of {', '.join(PROGRESS_STATUSES)}")
    if item.status in ("proposed", "declined"):
        raise JourneyError(409, f"item is {item.status}; only a person accepts a proposal")
    item.status = status
    if (note or "").strip():
        item.note = note.strip()
    item.updated_at = utcnow()
    db.commit()
    return item


def decide_item(db: Session, item: JourneyItem, accept: bool, actor: str) -> JourneyItem:
    if accept and item.status != "proposed":
        raise JourneyError(409, "only a proposed item can be accepted")
    if not accept and item.status not in ("proposed", "planned"):
        raise JourneyError(409, "only a proposed or planned item can be declined")
    item.status = "planned" if accept else "declined"
    item.decided_by = actor
    item.updated_at = utcnow()
    db.commit()
    return item


def set_status(db: Session, item: JourneyItem, status: str, actor: str) -> JourneyItem:
    """A person moves an accepted item. A proposal goes through accept or decline."""
    if status not in ("planned", "in_progress", "done", "declined"):
        raise JourneyError(400, "pick planned, in progress, done or declined")
    if item.status == "proposed":
        raise JourneyError(409, "accept or decline the proposal first")
    item.status = status
    item.decided_by = actor
    item.updated_at = utcnow()
    db.commit()
    return item


def edit_item(db: Session, item: JourneyItem, *, title: str, detail: str, area: str, due_on, note: str) -> JourneyItem:
    item.title, item.area = _validate_item(title, area)
    item.due_on = parse_due(due_on)
    item.detail = (detail or "").strip()
    item.note = (note or "").strip()
    item.updated_at = utcnow()
    db.commit()
    return item


# ---------------------------------------------------------------- communications
def comm_dict(c: Communication) -> dict:
    return {"id": c.id, "kind": c.kind, "title": c.title, "subject": c.subject, "body_md": c.body_md,
            "status": c.status, "source": c.source, "source_ref": c.source_ref, "created_at": _iso(c.created_at),
            "decided_by": c.decided_by, "decided_at": _iso(c.decided_at), "sent_detail": c.sent_detail,
            "published": bool(c.published)}


def comms_for(db: Session, client_id: str, *, published_only: bool = False) -> list[Communication]:
    q = select(Communication).where(Communication.client_id == client_id)
    if published_only:
        q = q.where(Communication.published.is_(True))
    return db.execute(q.order_by(Communication.created_at.desc())).scalars().all()


def create_comm(db: Session, client: Client, *, kind: str, title: str, subject: str = "", body_md: str = "",
                source_ref: str = "", source: str = "staff") -> tuple[Communication, bool]:
    kind = (kind or "").strip().lower()
    if kind not in COMM_KINDS:
        raise JourneyError(400, f"kind must be one of {', '.join(COMM_KINDS)}")
    title = (title or "").strip()
    if not title:
        raise JourneyError(400, "title is required")
    ref = (source_ref or "").strip()[:300]
    if ref:
        existing = db.execute(select(Communication).where(Communication.client_id == client.id,
                                                          Communication.source_ref == ref)).scalar_one_or_none()
        if existing:
            return existing, False
    c = Communication(client_id=client.id, kind=kind, title=title[:300], subject=(subject or "").strip()[:300] or title[:300],
                      body_md=body_md or "", source=source, source_ref=ref, status="draft")
    db.add(c)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.execute(select(Communication).where(Communication.client_id == client.id,
                                                          Communication.source_ref == ref)).scalar_one()
        return existing, False
    return c, True


def may_approve(ident, client: Client) -> bool:
    """The account lead or a platform admin. A viewer never approves, whatever else
    is true of them."""
    if ident is None or not ident.is_internal or ident.is_viewer:
        return False
    if ident.role == "admin":
        return True
    lead = (client.account_lead or "").strip().lower()
    return bool(lead) and ident.email.strip().lower() == lead


def edit_comm(db: Session, c: Communication, *, title: str | None, subject: str | None, body_md: str | None) -> None:
    if c.status != "draft":
        raise JourneyError(409, f"this communication is {c.status}; only a draft can be edited")
    if title is not None and title.strip():
        c.title = title.strip()[:300]
    if subject is not None and subject.strip():
        c.subject = subject.strip()[:300]
    if body_md is not None:
        c.body_md = body_md
    db.commit()


def portal_link(c: Communication) -> str:
    base = (settings.public_url or "").rstrip("/")
    return f"{base}/portal/communications/{c.id}" if base else ""


def email_body(client: Client, c: Communication) -> str:
    lines = [c.body_md.strip(), ""]
    link = portal_link(c)
    if link:
        lines += [f"This note is also on your Vendetta portal: {link}", ""]
    lines += ["Vendetta Cyber"]
    return "\n".join(lines) + "\n"


def approve_comm(db: Session, client: Client, c: Communication, actor: str) -> Communication:
    """Publish to the portal and email the executives. Mail is attempted only when a
    sender is configured and never fails the approval; each outcome is recorded."""
    if c.status != "draft":
        raise JourneyError(409, f"this communication is {c.status}; only a draft can be approved")
    c.published = True
    c.decided_by = actor
    c.decided_at = utcnow()
    to = sorted(client.executive_set())
    sent_any = False
    if not to:
        detail = "no executive emails on file; published to the portal only"
    elif not notify.can_send():
        detail = "SMTP not configured; published to the portal only"
    else:
        parts = []
        for addr in to:
            ok, d = notify.send(addr, c.subject or c.title, email_body(client, c))
            sent_any = sent_any or ok
            parts.append(f"{addr}: {'sent' if ok else 'not sent'} ({d})")
        detail = "; ".join(parts)
    c.status = "sent" if sent_any else "approved"
    c.sent_detail = detail[:4000]
    db.commit()
    return c


def discard_comm(db: Session, c: Communication, actor: str) -> Communication:
    if c.status != "draft":
        raise JourneyError(409, f"this communication is {c.status}; only a draft can be discarded")
    c.status = "discarded"
    c.decided_by = actor
    c.decided_at = utcnow()
    db.commit()
    return c


def stale_drafts(db: Session, days: int = STALE_DRAFT_DAYS) -> list[Communication]:
    cutoff = utcnow() - dt.timedelta(days=days)
    return db.execute(select(Communication).where(Communication.status == "draft",
                                                  Communication.created_at < cutoff)).scalars().all()


# ---------------------------------------------------------------- safe markdown
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITAL = re.compile(r"(?<![\*\w])\*(?!\s)(.+?)(?<!\s)\*(?![\*\w])")
_CODE = re.compile(r"`([^`]+)`")


def _inline(text: str) -> str:
    out = html.escape(text, quote=True)
    out = _CODE.sub(r"<code>\1</code>", out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    return _ITAL.sub(r"<em>\1</em>", out)


def render_md(md: str) -> str:
    """A small, safe Markdown subset for communications: headings, bullet and
    numbered lists, paragraphs, bold, italic and inline code. Everything is HTML
    escaped first, so a draft can never inject markup into the portal."""
    blocks: list[str] = []
    para: list[str] = []
    lst: list[str] = []
    lst_tag = ""

    def flush_para():
        if para:
            blocks.append("<p>" + "<br>".join(_inline(p) for p in para) + "</p>")
            para.clear()

    def flush_list():
        nonlocal lst_tag
        if lst:
            blocks.append(f"<{lst_tag}>" + "".join(f"<li>{_inline(x)}</li>" for x in lst) + f"</{lst_tag}>")
            lst.clear()
        lst_tag = ""

    for raw in (md or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            flush_para(); flush_list()
            continue
        h = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        bullet = re.match(r"^[-*]\s+(.*)$", stripped)
        num = re.match(r"^\d+[.)]\s+(.*)$", stripped)
        if h:
            flush_para(); flush_list()
            level = min(len(h.group(1)) + 2, 6)
            blocks.append(f"<h{level}>{_inline(h.group(2))}</h{level}>")
        elif bullet or num:
            flush_para()
            tag = "ul" if bullet else "ol"
            if lst_tag and lst_tag != tag:
                flush_list()
            lst_tag = tag
            lst.append((bullet or num).group(1))
        else:
            flush_list()
            para.append(stripped)
    flush_para(); flush_list()
    return "\n".join(blocks)
