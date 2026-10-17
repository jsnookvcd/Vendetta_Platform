"""Office of Special Projects data model.

An Engagement is one professional-services effort for a client: a vCISO retainer, an
implementation project, a tabletop exercise, an assessment or an advisory. Each
engagement holds Deliverables (documents, reports, playbooks, policies, sessions,
milestones, assessments) that move planned -> in_progress -> in_review -> delivered,
and that the client accepts on the portal. Every material event (deliverable created,
status change, delivered, client-accepted, engagement closed) is bound into a
per-client signed, tamper-evident chain of custody, so a deliverable sign-off is
provable.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text,
                        create_engine, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import (DELIVERABLE_STATUSES, OPEN_DELIVERABLE_STATUSES, OPEN_STATES, settings)
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
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagements: Mapped[list[Engagement]] = relationship(back_populates="client", cascade="all, delete-orphan")


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20), default="advisory")  # vciso|implementation|tabletop|assessment|advisory
    scope: Mapped[str] = mapped_column(Text, default="")
    lead: Mapped[str] = mapped_column(String(200), default="")  # Vendetta engagement lead
    sponsor: Mapped[str] = mapped_column(String(200), default="")  # client sponsor
    cadence: Mapped[str] = mapped_column(String(16), default="one-time")  # one-time|monthly|quarterly|annual
    status: Mapped[str] = mapped_column(String(20), default="scoping")  # scoping|active|on_hold|delivered|closed
    summary: Mapped[str] = mapped_column(Text, default="")  # executive summary, shown to the client
    starts_on: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_on: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # planned end
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published: Mapped[bool] = mapped_column(Boolean, default=False)  # visible to the client portal
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="engagements")
    deliverables: Mapped[list[Deliverable]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", order_by="Deliverable.position")

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATES

    @property
    def is_overdue(self) -> bool:
        """Still open past its planned end date."""
        return bool(self.is_open and self.ends_on and self.ends_on < utcnow())

    def counts(self) -> dict:
        c = {s: 0 for s in DELIVERABLE_STATUSES}
        for d in self.deliverables:
            if d.status in c:
                c[d.status] += 1
        c["total"] = sum(c.values())
        return c

    def progress(self) -> int:
        """Percent of deliverables accepted by the client, 0..100."""
        total = len(self.deliverables)
        if not total:
            return 0
        accepted = sum(1 for d in self.deliverables if d.status == "accepted")
        return round(100 * accepted / total)


class Deliverable(Base):
    __tablename__ = "deliverables"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    title: Mapped[str] = mapped_column(String(400))
    kind: Mapped[str] = mapped_column(String(20), default="document")
    status: Mapped[str] = mapped_column(String(20), default="planned")
    description: Mapped[str] = mapped_column(Text, default="")
    artifact_ref: Mapped[str] = mapped_column(String(600), default="")  # link/path to the delivered artifact
    due_on: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by: Mapped[str] = mapped_column(String(320), default="")
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="deliverables")

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_DELIVERABLE_STATUSES


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


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


class DeliverableEvent(Base):
    """A per-client, signed, tamper-evident record of material delivery events:
    a deliverable created, a status change, delivery, client acceptance, and
    engagement close. This is the deliverable sign-off chain of custody."""

    __tablename__ = "deliverable_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    deliverable_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320), default="system")
    kind: Mapped[str] = mapped_column(String(30), default="note")
    detail: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    chain_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    signature: Mapped[str | None] = mapped_column(String(160), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


def event_fields(e: "DeliverableEvent") -> dict:
    return {"id": e.id, "client_id": e.client_id, "engagement_id": e.engagement_id,
            "deliverable_id": e.deliverable_id, "chain_seq": e.chain_seq,
            "at": e.at.isoformat() if e.at else None, "actor": e.actor, "kind": e.kind,
            "detail": e.detail, "payload": e.payload or {}}


def record_event(db: Session, client_id: str, engagement_id: str | None, deliverable_id: str | None,
                 kind: str, actor: str, detail: str = "", payload: dict | None = None) -> None:
    db.add(DeliverableEvent(client_id=client_id, engagement_id=engagement_id, deliverable_id=deliverable_id,
                            kind=kind, actor=actor, detail=detail[:2000], payload=payload or {}))


def _chain_events(session) -> None:
    from collections import defaultdict

    from sqlalchemy import select as _select

    from . import evidence

    pending = [o for o in session.new if isinstance(o, DeliverableEvent) and o.content_hash is None]
    if not pending:
        return
    by_client: dict[str, list] = defaultdict(list)
    for e in pending:
        if e.id is None:
            e.id = new_id()
        if e.at is None:
            e.at = utcnow()
        for attr, default in (("actor", "system"), ("kind", "note"), ("detail", ""), ("payload", {})):
            if getattr(e, attr) is None:
                setattr(e, attr, default)
        by_client[e.client_id].append(e)
    with session.no_autoflush:
        for cid, evs in by_client.items():
            head = session.execute(
                _select(DeliverableEvent.chain_seq, DeliverableEvent.content_hash)
                .where(DeliverableEvent.client_id == cid, DeliverableEvent.content_hash.isnot(None))
                .order_by(DeliverableEvent.chain_seq.desc()).limit(1)).first()
            prev_seq, prev_hash = (head[0], head[1]) if head else (0, evidence.GENESIS)
            for e in sorted(evs, key=lambda x: (x.at, x.id)):
                prev_seq += 1
                e.chain_seq = prev_seq
                e.prev_hash = prev_hash
                e.content_hash, e.signature, e.key_id = evidence.compute(event_fields(e), prev_hash)
                prev_hash = e.content_hash


def client_event_records(db: Session, client_id: str) -> list[dict]:
    rows = db.execute(
        select(DeliverableEvent).where(DeliverableEvent.client_id == client_id,
                                       DeliverableEvent.content_hash.isnot(None))
        .order_by(DeliverableEvent.chain_seq)
    ).scalars().all()
    return [{"fields": event_fields(e), "prev_hash": e.prev_hash,
             "content_hash": e.content_hash, "signature": e.signature} for e in rows]


def build_event_proof(db: Session, client) -> dict:
    from . import evidence

    rows = db.execute(
        select(DeliverableEvent).where(DeliverableEvent.client_id == client.id,
                                       DeliverableEvent.content_hash.isnot(None))
        .order_by(DeliverableEvent.chain_seq)
    ).scalars().all()
    verify_input, entries = [], []
    for e in rows:
        f = event_fields(e)
        verify_input.append({"fields": f, "prev_hash": e.prev_hash,
                             "content_hash": e.content_hash, "signature": e.signature})
        entries.append({"chain_seq": e.chain_seq, "prev_hash": e.prev_hash,
                        "content_hash": e.content_hash, "signature": e.signature, **f})
    result = evidence.verify_chain(verify_input)
    return {"document": "Vendetta Cyber Defense deliverable sign-off proof",
            "scheme": evidence.SCHEME, "generated_at": utcnow().isoformat(),
            "key_id": evidence.key_id(), "public_key": evidence.public_key_hex(),
            "client": {"id": client.id, "name": client.name}, "entry_count": len(entries),
            "verification": result, "entries": entries}


from sqlalchemy import event as _event  # noqa: E402


@_event.listens_for(SessionLocal, "before_flush")
def _evidence_before_flush(session, flush_context, instances):  # noqa: ANN001
    _chain_events(session)


def init_db() -> None:
    Base.metadata.create_all(engine)
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        have = conn.execute(_text("SELECT 1 FROM information_schema.columns "
                                  "WHERE table_name = 'engagements' AND column_name = 'ends_on'")).first()
        if not have:
            conn.execute(_text("ALTER TABLE engagements ADD COLUMN ends_on TIMESTAMP WITH TIME ZONE"))
