"""IR Hub data model. The hub is the system of record for clients and IR cases.

Case numbers are a firm-wide running sequence (client name and incident type are
never part of the number). Every case is opened with the fixed five workstreams.
Findings escalated from other modules land on a case as timeline entries attached
to a workstream, carrying the source module and the finding payload.

Each case also has a Kanban board of task cards, one lane per workstream. Cards
and timeline entries are linked both ways; the rules live in board.py."""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import WORKSTREAMS, settings
from .crypto import EncryptedStr

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    # Read-only client view, enabled per client (same pattern as the dark web module).
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    # Portal users listed here get the executive (summary) view; others technical.
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    # Set when provisioned from the platform control plane; the shared client id.
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    retainer: Mapped[Retainer | None] = relationship(back_populates="client", uselist=False, cascade="all, delete-orphan")
    cases: Mapped[list[Case]] = relationship(back_populates="client")


class Retainer(Base):
    """GetZero retainer: tier, hours, SLA, named responders and readiness items."""

    __tablename__ = "retainers"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), unique=True)
    tier: Mapped[str] = mapped_column(String(50), default="")
    hours_total: Mapped[int] = mapped_column(Integer, default=0)
    hours_used: Mapped[int] = mapped_column(Integer, default=0)
    sla_minutes: Mapped[int] = mapped_column(Integer, default=60)  # response SLA
    named_responders: Mapped[str] = mapped_column(Text, default="")  # comma separated
    readiness: Mapped[list] = mapped_column(JSON, default=list)  # [{item, done}]
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    renews_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)

    client: Mapped[Client] = relationship(back_populates="retainer")

    @property
    def hours_remaining(self) -> int:
        return max(0, (self.hours_total or 0) - (self.hours_used or 0))


class Counter(Base):
    """Single-row counter for the firm-wide case sequence."""

    __tablename__ = "counters"
    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, unique=True)
    number: Mapped[str] = mapped_column(String(40), unique=True)  # e.g. VCD-IR-2026-781
    title: Mapped[str] = mapped_column(String(300))
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"))
    severity: Mapped[str] = mapped_column(String(10), default="high")
    # open | contained | eradicated | recovered | closed
    status: Mapped[str] = mapped_column(String(20), default="open")
    incident_type: Mapped[str] = mapped_column(String(60), default="")
    lead: Mapped[str] = mapped_column(String(200), default="")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)  # counsel-directed
    counsel: Mapped[str] = mapped_column(String(200), default="")
    origin: Mapped[str] = mapped_column(String(40), default="manual")  # manual | declared | escalated
    source_module: Mapped[str] = mapped_column(String(60), default="")
    opened_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    client: Mapped[Client] = relationship(back_populates="cases")
    workstreams: Mapped[list[Workstream]] = relationship(back_populates="case", cascade="all, delete-orphan", order_by="Workstream.position")
    updates: Mapped[list[CaseUpdate]] = relationship(back_populates="case", cascade="all, delete-orphan", order_by=lambda: CaseUpdate.at.desc())
    tasks: Mapped[list[Task]] = relationship(back_populates="case", cascade="all, delete-orphan", order_by=lambda: [Task.position, Task.created_at])


class Workstream(Base):
    __tablename__ = "workstreams"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    name: Mapped[str] = mapped_column(String(80))
    position: Mapped[int] = mapped_column(Integer, default=0)
    # not_started | in_progress | blocked | done
    status: Mapped[str] = mapped_column(String(20), default="not_started")
    owner: Mapped[str] = mapped_column(String(200), default="")
    client_visible_note: Mapped[str] = mapped_column(Text, default="")  # milestone line clients see

    case: Mapped[Case] = relationship(back_populates="workstreams")


class Task(Base):
    """A card on the case board. Lane is the workstream, column is the status."""

    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    workstream: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(300))
    # todo | in_progress | blocked | done
    status: Mapped[str] = mapped_column(String(20), default="todo")
    position: Mapped[int] = mapped_column(Integer, default=0)
    owner: Mapped[str] = mapped_column(String(200), default="")
    due_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    client_visible: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(20), default="manual")  # playbook | manual | escalation | update
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    case: Mapped[Case] = relationship(back_populates="tasks")
    updates: Mapped[list[CaseUpdate]] = relationship(back_populates="task")


class CaseUpdate(Base):
    """Timeline entry. Escalated findings arrive here with their source payload.
    task_id links the entry to a board card when it is about one."""

    __tablename__ = "case_updates"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    workstream: Mapped[str] = mapped_column(String(80), default="")
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320), default="system")
    kind: Mapped[str] = mapped_column(String(20), default="note")  # note | finding | status | system | task
    note: Mapped[str] = mapped_column(Text, default="")
    internal_only: Mapped[bool] = mapped_column(Boolean, default=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("tasks.id", ondelete="SET NULL"), nullable=True, index=True)

    # Chain of custody: filled automatically at flush (see the before_flush hook).
    # These bind the entry into a per-case, signed, tamper-evident chain. task_id is
    # deliberately not among the signed fields because it is a mutable UI link.
    chain_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    signature: Mapped[str | None] = mapped_column(String(160), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    case: Mapped[Case] = relationship(back_populates="updates")
    task: Mapped[Task | None] = relationship(back_populates="updates")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(20), default="entra")
    role: Mapped[str] = mapped_column(String(30), default="analyst")  # admin | analyst | client
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SsoConfig(Base):
    """Microsoft 365 / Entra SSO configuration entered in-app. Single row ('default');
    the secret is encrypted at rest and the rest overlays the environment defaults."""

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


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


def init_db() -> None:
    Base.metadata.create_all(engine)
    # create_all does not add columns to existing tables; keep older databases current.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE clients ADD COLUMN IF NOT EXISTS platform_client_id VARCHAR(32) DEFAULT ''"))
        conn.execute(text("ALTER TABLE clients ADD COLUMN IF NOT EXISTS executive_emails VARCHAR(1000) DEFAULT ''"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_clients_platform_client_id ON clients (platform_client_id)"))
        conn.execute(text(
            "ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS task_id VARCHAR(32) "
            "REFERENCES tasks(id) ON DELETE SET NULL"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_case_updates_task_id ON case_updates (task_id)"))
        # Chain-of-custody columns.
        conn.execute(text("ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS chain_seq INTEGER"))
        conn.execute(text("ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64)"))
        conn.execute(text("ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)"))
        conn.execute(text("ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS signature VARCHAR(160)"))
        conn.execute(text("ALTER TABLE case_updates ADD COLUMN IF NOT EXISTS key_id VARCHAR(32)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_case_updates_content_hash ON case_updates (content_hash)"))


def next_case_number(db: Session) -> tuple[int, str]:
    """Allocate the next firm-wide case number atomically (row lock on the counter)."""
    row = db.execute(select(Counter).where(Counter.name == "case").with_for_update()).scalar_one_or_none()
    if row is None:
        row = Counter(name="case", value=settings.case_seq_start - 1)
        db.add(row)
        db.flush()
    row.value += 1
    seq = row.value
    return seq, f"{settings.case_prefix}-{settings.case_year}-{seq}"


def open_case(
    db: Session,
    client: Client,
    title: str,
    severity: str = "high",
    origin: str = "manual",
    actor: str = "system",
    incident_type: str = "",
    lead: str = "",
    source_module: str = "",
    seed_board: bool = True,
) -> Case:
    """Create a case with the five workstreams, the playbook cards on its board,
    and an opening timeline entry."""
    seq, number = next_case_number(db)
    case = Case(
        seq=seq, number=number, title=title[:300], client_id=client.id, severity=severity,
        origin=origin, incident_type=incident_type, lead=lead, source_module=source_module,
    )
    for i, name in enumerate(WORKSTREAMS):
        case.workstreams.append(Workstream(name=name, position=i))
    case.workstreams[0].status = "in_progress"  # scoping starts immediately
    if seed_board:
        from .board import seed_playbook

        seed_playbook(case)
    case.updates.append(CaseUpdate(actor=actor, kind="system", note=f"Case {number} opened ({origin}).", internal_only=False))
    db.add(case)
    db.commit()
    return case


def update_fields(u: "CaseUpdate") -> dict:
    """The immutable, evidentiary fields of a timeline entry, in the exact shape the
    chain hashes. Write and verify both go through this so the two always agree.
    task_id is excluded on purpose: it is a mutable UI link, not evidence."""
    case_id = u.case_id or (u.case.id if u.case is not None else None)
    at = u.at.isoformat() if u.at is not None else None
    return {
        "id": u.id,
        "case_id": case_id,
        "chain_seq": u.chain_seq,
        "at": at,
        "actor": u.actor,
        "kind": u.kind,
        "note": u.note,
        "workstream": u.workstream,
        "internal_only": bool(u.internal_only),
        "payload": u.payload or {},
    }


def case_chain_records(db: Session, case_id: str) -> list[dict]:
    """The case's timeline as ordered chain records for verification. Only entries
    that were chained are included, in chain order."""
    rows = db.execute(
        select(CaseUpdate).where(CaseUpdate.case_id == case_id, CaseUpdate.content_hash.isnot(None))
        .order_by(CaseUpdate.chain_seq)
    ).scalars().all()
    return [{"fields": update_fields(u), "prev_hash": u.prev_hash,
             "content_hash": u.content_hash, "signature": u.signature,
             "chain_seq": u.chain_seq, "at": u.at, "actor": u.actor, "kind": u.kind,
             "note": u.note} for u in rows]


def build_proof(db: Session, case: "Case", *, client_view: bool = False) -> dict:
    """A self-contained, independently verifiable chain-of-custody document for a
    case. With client_view, internal entries are sealed: their content is withheld
    but their hash, signature and position remain, so the client (or opposing
    counsel) can still verify nothing was added, removed or altered."""
    from . import evidence

    rows = db.execute(
        select(CaseUpdate).where(CaseUpdate.case_id == case.id, CaseUpdate.content_hash.isnot(None))
        .order_by(CaseUpdate.chain_seq)
    ).scalars().all()
    entries, verify_input = [], []
    for u in rows:
        reveal = (not client_view) or (not u.internal_only)
        fields = update_fields(u) if reveal else None
        verify_input.append({"fields": fields, "prev_hash": u.prev_hash,
                             "content_hash": u.content_hash, "signature": u.signature})
        entry = {"chain_seq": u.chain_seq, "prev_hash": u.prev_hash,
                 "content_hash": u.content_hash, "signature": u.signature,
                 "sealed": not reveal}
        if reveal:
            entry["at"] = u.at.isoformat() if u.at else None
            entry["actor"] = u.actor
            entry["kind"] = u.kind
            entry["note"] = u.note
            entry["workstream"] = u.workstream
            entry["internal_only"] = bool(u.internal_only)
            entry["payload"] = u.payload or {}
        entries.append(entry)
    result = evidence.verify_chain(verify_input)
    return {
        "document": "Vendetta Cyber Defense chain-of-custody proof",
        "scheme": evidence.SCHEME,
        "generated_at": utcnow().isoformat(),
        "key_id": evidence.key_id(),
        "public_key": evidence.public_key_hex(),
        "case": {"id": case.id, "number": case.number, "title": case.title,
                 "opened_at": case.opened_at.isoformat() if case.opened_at else None},
        "entry_count": len(entries),
        "verification": result,
        "entries": entries,
        "how_to_verify": (
            "For each entry, Ed25519-verify 'signature' against 'content_hash' using "
            "'public_key'. Confirm each 'prev_hash' equals the previous entry's "
            "'content_hash' (the first is 64 zeros). For entries that are not sealed, "
            "recompute sha256 of the canonical JSON "
            "{\"scheme\",\"prev\":prev_hash,\"fields\":{...}} and confirm it equals "
            "'content_hash'. Any mismatch means the record was altered, added, removed "
            "or reordered."),
    }


def _chain_new_updates(session: Session) -> None:
    """Assign chain position, prev hash, content hash and signature to every new
    timeline entry in this flush, per case, continuing each case's existing chain."""
    from collections import defaultdict

    from . import evidence

    pending = [o for o in session.new if isinstance(o, CaseUpdate) and o.content_hash is None]
    if not pending:
        return

    # Python-side defaults (id, at) and column defaults (actor, kind, ...) are applied
    # at INSERT, after this hook. Any hashed field still None here would be stored as
    # its default and break verification, so materialise every signed field onto the
    # object now, including the parent case id, so what we sign is exactly what is
    # stored. task_id is excluded from the signed set and left to the ORM.
    by_case: dict[str, list[CaseUpdate]] = defaultdict(list)
    for u in pending:
        if u.id is None:
            u.id = new_id()
        if u.case_id is None and u.case is not None:
            if u.case.id is None:
                u.case.id = new_id()
            u.case_id = u.case.id
        if u.at is None:
            u.at = utcnow()
        if u.actor is None:
            u.actor = "system"
        if u.kind is None:
            u.kind = "note"
        if u.note is None:
            u.note = ""
        if u.workstream is None:
            u.workstream = ""
        if u.internal_only is None:
            u.internal_only = True
        if u.payload is None:
            u.payload = {}
        by_case[u.case_id].append(u)

    with session.no_autoflush:
        for cid, ups in by_case.items():
            prev_seq, prev_hash = 0, evidence.GENESIS
            head = session.execute(
                select(CaseUpdate.chain_seq, CaseUpdate.content_hash)
                .where(CaseUpdate.case_id == cid, CaseUpdate.content_hash.isnot(None))
                .order_by(CaseUpdate.chain_seq.desc()).limit(1)
            ).first()
            if head:
                prev_seq, prev_hash = head[0], head[1]
            # Deterministic order within the flush so verify (which reads by chain_seq)
            # always sees the same sequence we signed.
            for u in sorted(ups, key=lambda x: (x.at, x.id)):
                prev_seq += 1
                u.chain_seq = prev_seq
                u.prev_hash = prev_hash
                u.content_hash, u.signature, u.key_id = evidence.compute(update_fields(u), prev_hash)
                prev_hash = u.content_hash


from sqlalchemy import event  # noqa: E402


@event.listens_for(SessionLocal, "before_flush")
def _evidence_before_flush(session, flush_context, instances):  # noqa: ANN001
    _chain_new_updates(session)


def ensure_seq_counter(db: Session) -> None:
    """Keep the counter ahead of any existing cases (e.g. after an import)."""
    mx = db.execute(text("SELECT COALESCE(MAX(seq), 0) FROM cases")).scalar() or 0
    row = db.get(Counter, "case")
    floor = max(mx, settings.case_seq_start - 1)
    if row is None:
        db.add(Counter(name="case", value=floor))
    elif row.value < floor:
        row.value = floor
    db.commit()
