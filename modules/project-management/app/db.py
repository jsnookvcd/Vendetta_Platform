"""Project Management data model.

An Engagement is one IR case or Professional Services project a PM runs. It sits as
a card on its practice board (one board per practice, columns are the engagement
lifecycle) and owns a task board of its own (columns are task states). Boards,
columns and cards are one generic model, so the practice board and a task board
behave the same way and a column can be renamed, added, reordered or removed on
either. Every card change is written to card_events, the history the tool reads
back when a PM asks what happened to a task.

Meeting notes belong to an engagement, are stored here, and are mirrored to the
engagement's SharePoint folder. Time is written to Harvest, the billing system of
record; time_logs keeps a local record of every entry this module wrote, changed or
deleted there and who did it.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, Sequence, String, Text,
                        create_engine, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings
from .crypto import EncryptedStr

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------- platform-owned
class Client(Base):
    """Mirrored from the control plane roster (see provision.py)."""
    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(20), default="entra")
    role: Mapped[str] = mapped_column(String(30), default="analyst")
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SsoConfig(Base):
    __tablename__ = "sso_config"
    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="default")
    tenant_id: Mapped[str] = mapped_column(String(100), default="")
    client_id: Mapped[str] = mapped_column(String(100), default="")
    client_secret: Mapped[str] = mapped_column(EncryptedStr(512), default="")
    redirect_url: Mapped[str] = mapped_column(String(400), default="")
    allowed_group: Mapped[str] = mapped_column(String(100), default="")
    allowed_emails: Mapped[str] = mapped_column(String(1000), default="")
    internal_email_domains: Mapped[str] = mapped_column(String(500), default="")
    admin_emails: Mapped[str] = mapped_column(String(1000), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_tested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_detail: Mapped[str] = mapped_column(String(500), default="")
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntegrationConfig(Base):
    """Harvest and SharePoint settings entered in-app. Stored (non-empty) values
    override the environment; secrets are encrypted at rest."""
    __tablename__ = "integration_config"
    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="default")
    harvest_account_id: Mapped[str] = mapped_column(String(40), default="")
    harvest_token: Mapped[str] = mapped_column(EncryptedStr(600), default="")
    graph_tenant_id: Mapped[str] = mapped_column(String(100), default="")
    graph_client_id: Mapped[str] = mapped_column(String(100), default="")
    graph_client_secret: Mapped[str] = mapped_column(EncryptedStr(600), default="")
    sharepoint_site_url: Mapped[str] = mapped_column(String(400), default="")
    sharepoint_folder: Mapped[str] = mapped_column(String(300), default="")
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------- delivery
class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    code: Mapped[str] = mapped_column(String(60), unique=True)  # e.g. VCD-IR-2026-445
    name: Mapped[str] = mapped_column(String(300))
    practice: Mapped[str] = mapped_column(String(16), index=True)  # ir | proserv
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    client_name: Mapped[str] = mapped_column(String(200), default="")  # display; from the roster when linked
    pm_email: Mapped[str] = mapped_column(String(320), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | on_hold | closed
    description: Mapped[str] = mapped_column(Text, default="")
    budget_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    starts_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    ends_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    harvest_project_id: Mapped[str] = mapped_column(String(40), default="")
    harvest_project_name: Mapped[str] = mapped_column(String(300), default="")
    # The engagement's own SharePoint site (an IR case site) and folder. Blank uses
    # the module default site and <default folder>/<code>.
    sharepoint_site_url: Mapped[str] = mapped_column(String(400), default="")
    sharepoint_folder: Mapped[str] = mapped_column(String(300), default="")
    # Reference into the rest of the platform: the IR hub case id or OSP engagement id.
    platform_ref: Mapped[str] = mapped_column(String(120), default="")
    # The engagement type its template set up (bec, ransomware, tabletop, ...), and the
    # technical lead tasks can be routed to by role.
    engagement_type: Mapped[str] = mapped_column(String(40), default="", index=True)
    template_id: Mapped[str] = mapped_column(String(32), default="")
    lead_email: Mapped[str] = mapped_column(String(320), default="")
    # Baseline as sold. Approved change requests move budget_hours and ends_on; the
    # baseline stays, so scope growth is measurable.
    baseline_budget_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_ends_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    # Key dates the portfolio metrics are built on. Set the first time the practice
    # card enters a column that marks them, or by hand.
    contained_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reported_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Closeout checklist: [{"key","text","done","by","at"}]
    closeout: Mapped[list] = mapped_column(JSON, default=list)
    # Client milestone publishing (to the IR hub case or the OSP engagement portal).
    publish_status: Mapped[str] = mapped_column(String(12), default="")  # "" | ok | failed | off
    publish_detail: Mapped[str] = mapped_column(String(400), default="")
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    client: Mapped[Client | None] = relationship()
    notes: Mapped[list[MeetingNote]] = relationship(back_populates="engagement", cascade="all, delete-orphan",
                                                    order_by="MeetingNote.held_at.desc()")


class Board(Base):
    __tablename__ = "boards"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))  # practice | engagement
    practice: Mapped[str] = mapped_column(String(16), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"),
                                                      nullable=True, unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    columns: Mapped[list[BoardColumn]] = relationship(back_populates="board", cascade="all, delete-orphan",
                                                      order_by="BoardColumn.position")


class BoardColumn(Base):
    __tablename__ = "board_columns"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    board_id: Mapped[str] = mapped_column(ForeignKey("boards.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    position: Mapped[int] = mapped_column(Integer, default=0)
    wip_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_done: Mapped[bool] = mapped_column(Boolean, default=False)
    # On a practice board: the engagement date entering this column records
    # (contained | reported). Survives a rename.
    marks: Mapped[str] = mapped_column(String(20), default="")

    board: Mapped[Board] = relationship(back_populates="columns")


card_ref_seq = Sequence("card_ref_seq", start=100)


class Card(Base):
    """A card on a board. On a practice board a card is an engagement; on an
    engagement's task board a card is a task."""
    __tablename__ = "cards"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    ref: Mapped[int] = mapped_column(Integer, card_ref_seq, server_default=card_ref_seq.next_value(),
                                     unique=True)  # short number a PM says out loud: "task 214"
    board_id: Mapped[str] = mapped_column(ForeignKey("boards.id", ondelete="CASCADE"), index=True)
    column_id: Mapped[str] = mapped_column(ForeignKey("board_columns.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"),
                                                      nullable=True, index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(400))
    description: Mapped[str] = mapped_column(Text, default="")
    assignee: Mapped[str] = mapped_column(String(320), default="", index=True)
    due_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    priority: Mapped[str] = mapped_column(String(10), default="normal")
    labels: Mapped[list] = mapped_column(JSON, default=list)
    checklist: Mapped[list] = mapped_column(JSON, default=list)  # [{"text": str, "done": bool}]
    estimate_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    column: Mapped[BoardColumn] = relationship()
    board: Mapped[Board] = relationship()
    engagement: Mapped[Engagement | None] = relationship()


class CardEvent(Base):
    """History of a card: created, moved, edited, assigned, commented, archived,
    deleted. Kept after a card is deleted (no foreign key) so the record survives."""
    __tablename__ = "card_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    card_id: Mapped[str] = mapped_column(String(32), index=True)
    card_ref: Mapped[int | None] = mapped_column(Integer, nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    kind: Mapped[str] = mapped_column(String(20))
    detail: Mapped[str] = mapped_column(Text, default="")


class MeetingNote(Base):
    __tablename__ = "meeting_notes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    held_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    attendees: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")  # markdown
    decisions: Mapped[str] = mapped_column(Text, default="")
    action_items: Mapped[list] = mapped_column(JSON, default=list)  # [{"text","assignee","due_on","card_id"}]
    author: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # SharePoint mirror state: pending | mirrored | failed | off
    sp_status: Mapped[str] = mapped_column(String(12), default="pending", index=True)
    sp_url: Mapped[str] = mapped_column(String(800), default="")
    sp_item_id: Mapped[str] = mapped_column(String(200), default="")
    sp_error: Mapped[str] = mapped_column(String(600), default="")
    sp_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped[Engagement] = relationship(back_populates="notes")


class TimeLog(Base):
    """Every Harvest time entry this module created, changed or deleted, and who
    asked for it. Harvest stays the system of record for the hours themselves."""
    __tablename__ = "time_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    action: Mapped[str] = mapped_column(String(12))  # created | updated | deleted
    actor: Mapped[str] = mapped_column(String(320))
    user_email: Mapped[str] = mapped_column(String(320), default="")
    harvest_entry_id: Mapped[str] = mapped_column(String(40), index=True)
    harvest_project_id: Mapped[str] = mapped_column(String(40), default="")
    harvest_task_id: Mapped[str] = mapped_column(String(40), default="")
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    card_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    spent_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------- delivery method
class Template(Base):
    """A repeatable engagement: the standard tasks (with owner by role and a due
    offset from the start), client milestones, a default budget, target days per
    phase, and closeout items. Applied when an engagement opens, or later."""
    __tablename__ = "templates"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    key: Mapped[str] = mapped_column(String(40), unique=True)  # bec, ransomware, tabletop ...
    name: Mapped[str] = mapped_column(String(200))
    practice: Mapped[str] = mapped_column(String(16), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    budget_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # [{"title","column","labels","owner","offset_days","estimate_hours","checklist","priority"}]
    tasks: Mapped[list] = mapped_column(JSON, default=list)
    # [{"title","workstream","offset_days","client_visible"}]
    milestones: Mapped[list] = mapped_column(JSON, default=list)
    phase_days: Mapped[dict] = mapped_column(JSON, default=dict)  # {"Intake": 1, ...}
    closeout: Mapped[list] = mapped_column(JSON, default=list)  # ["Final report delivered", ...]
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Milestone(Base):
    """A milestone on an engagement. Client-visible ones are published to the
    client's portal: the IR hub case for IR, the Office of Special Projects
    engagement for ProServ."""
    __tablename__ = "milestones"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    workstream: Mapped[str] = mapped_column(String(60), default="")
    status: Mapped[str] = mapped_column(String(16), default="planned")  # planned | in_progress | at_risk | done
    due_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship()


class ChangeRequest(Base):
    """A change to what was sold: hours, end date, scope. Approval moves the
    engagement's budget and end date; the baseline stays."""
    __tablename__ = "change_requests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer)  # CR-1, CR-2 per engagement
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(String(40), default="client_request")
    hours_delta: Mapped[float] = mapped_column(Float, default=0.0)
    days_delta: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(12), default="requested")  # requested | approved | rejected | withdrawn
    client_approval: Mapped[str] = mapped_column(String(300), default="")  # who at the client agreed, and how
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    requested_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_by: Mapped[str] = mapped_column(String(320), default="")
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")

    engagement: Mapped[Engagement] = relationship()


class Capacity(Base):
    """Bookable hours per person per week, for capacity planning."""
    __tablename__ = "capacity"
    email: Mapped[str] = mapped_column(String(320), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    weekly_hours: Mapped[float] = mapped_column(Float, default=32.0)
    practices: Mapped[str] = mapped_column(String(40), default="ir,proserv")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    """Something a PM should act on, computed on a schedule. One row per condition
    (key), so a standing problem is one alert, notified once, until it clears."""
    __tablename__ = "alerts"
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    severity: Mapped[str] = mapped_column(String(8), default="medium")  # high | medium | low
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    card_ref: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner: Mapped[str] = mapped_column(String(320), default="", index=True)
    title: Mapped[str] = mapped_column(String(400))
    detail: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str] = mapped_column(String(300), default="")
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    notified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acked_by: Mapped[str] = mapped_column(String(320), default="")
    acked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Invoice(Base):
    """A Harvest invoice this module drafted at closeout. Drafts only: sending to
    the client stays a person's action in Harvest."""
    __tablename__ = "invoices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    harvest_invoice_id: Mapped[str] = mapped_column(String(40))
    number: Mapped[str] = mapped_column(String(60), default="")
    amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="draft")
    period_from: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    period_to: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    created_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KickoffRun(Base):
    """One engagement kickoff: the request as given, the ordered steps with their
    status, and every external reference a step created (group id, team id, site,
    Harvest project, SuperOps ticket, Slack channel). A retry reads these refs back,
    so no step ever creates the same thing twice."""
    __tablename__ = "kickoff_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), nullable=True, index=True)
    code: Mapped[str] = mapped_column(String(60), default="", index=True)
    practice: Mapped[str] = mapped_column(String(16), default="")
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|waiting|complete|partial|failed
    spec: Mapped[dict] = mapped_column(JSON, default=dict)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    refs: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MailboxJob(Base):
    """Exchange Online settings Graph cannot make (external senders, Send As,
    subscription). The host worker (worker/Invoke-MailboxJobs.ps1) claims pending
    jobs over the API, runs them with Exchange Online app-only auth, and reports."""
    __tablename__ = "mailbox_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("kickoff_runs.id"), index=True)
    group_id: Mapped[str] = mapped_column(String(64))
    address: Mapped[str] = mapped_column(String(320))
    members: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending|claimed|done|failed
    detail: Mapped[str] = mapped_column(String(800), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------- MCP / OAuth
class OAuthClient(Base):
    """A client registered through dynamic client registration (RFC 7591): the
    Claude connector, Claude Code, or another MCP client. Public clients only;
    PKCE is mandatory."""
    __tablename__ = "oauth_clients"
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_name: Mapped[str] = mapped_column(String(200), default="")
    redirect_uris: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OAuthCode(Base):
    __tablename__ = "oauth_codes"
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(320))
    redirect_uri: Mapped[str] = mapped_column(String(800))
    code_challenge: Mapped[str] = mapped_column(String(128))
    scope: Mapped[str] = mapped_column(String(200), default="")
    resource: Mapped[str] = mapped_column(String(400), default="")
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class OAuthToken(Base):
    """Access and refresh tokens issued to MCP clients, and personal access tokens
    a PM mints for Claude Code or a script. Only a SHA-256 of the token is stored."""
    __tablename__ = "oauth_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(10))  # access | refresh | pat
    email: Mapped[str] = mapped_column(String(320), index=True)
    client_id: Mapped[str] = mapped_column(String(64), default="")
    name: Mapped[str] = mapped_column(String(200), default="")
    scope: Mapped[str] = mapped_column(String(200), default="")
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def init_db() -> None:
    with engine.begin() as conn:
        conn.execute(text("CREATE SEQUENCE IF NOT EXISTS card_ref_seq START 100"))
    Base.metadata.create_all(engine)
