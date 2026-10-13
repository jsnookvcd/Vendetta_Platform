"""Penetration Testing data model.

An Engagement is one test for a client (external, web-app, red-team, ...). Findings
belong to an engagement and carry a severity, asset, evidence, remediation steps the
client checks off, and a retest loop (open -> remediating -> retest_pending ->
retest_passed). At close, the engagement captures its severity counts so the client
portal can trend results across engagements over time, and the report renders from
the findings.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
                        create_engine, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import OPEN_STATUSES, settings
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
    kind: Mapped[str] = mapped_column(String(20), default="external")
    scope: Mapped[str] = mapped_column(Text, default="")
    lead: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="scoping")  # scoping|active|reporting|closed
    summary: Mapped[str] = mapped_column(Text, default="")  # executive summary for the report
    started_on: Mapped[dt.date | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published: Mapped[bool] = mapped_column(Boolean, default=False)  # visible to the client
    # Severity counts captured at close, for the cross-engagement trend.
    n_total: Mapped[int] = mapped_column(Integer, default=0)
    n_critical: Mapped[int] = mapped_column(Integer, default=0)
    n_high: Mapped[int] = mapped_column(Integer, default=0)
    n_medium: Mapped[int] = mapped_column(Integer, default=0)
    n_low: Mapped[int] = mapped_column(Integer, default=0)
    n_info: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="engagements")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", order_by="Finding.cvss.desc()")

    def counts(self) -> dict:
        return {"critical": self.n_critical, "high": self.n_high, "medium": self.n_medium,
                "low": self.n_low, "info": self.n_info, "total": self.n_total}

    def recount(self) -> None:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            if f.severity in c:
                c[f.severity] += 1
        self.n_critical, self.n_high = c["critical"], c["high"]
        self.n_medium, self.n_low, self.n_info = c["medium"], c["low"], c["info"]
        self.n_total = sum(c.values())


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    title: Mapped[str] = mapped_column(String(400))
    asset: Mapped[str] = mapped_column(String(300), default="")
    cve: Mapped[str] = mapped_column(String(40), default="")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    retest_note: Mapped[str] = mapped_column(Text, default="")
    retested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    steps: Mapped[list[RemediationStep]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="RemediationStep.position")

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES


class RemediationStep(Base):
    __tablename__ = "remediation_steps"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    text: Mapped[str] = mapped_column(Text, default="")
    done: Mapped[bool] = mapped_column(Boolean, default=False)
    done_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    done_by: Mapped[str] = mapped_column(String(320), default="")

    finding: Mapped[Finding] = relationship(back_populates="steps")


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


class FindingEvent(Base):
    """A per-client, signed, tamper-evident record of material finding events."""

    __tablename__ = "finding_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
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


def event_fields(e: "FindingEvent") -> dict:
    return {"id": e.id, "client_id": e.client_id, "finding_id": e.finding_id,
            "chain_seq": e.chain_seq, "at": e.at.isoformat() if e.at else None,
            "actor": e.actor, "kind": e.kind, "detail": e.detail, "payload": e.payload or {}}


def record_event(db: Session, client_id: str, finding_id: str | None, kind: str, actor: str,
                 detail: str = "", payload: dict | None = None) -> None:
    db.add(FindingEvent(client_id=client_id, finding_id=finding_id, kind=kind, actor=actor,
                        detail=detail[:2000], payload=payload or {}))


def _chain_events(session) -> None:
    from collections import defaultdict

    from sqlalchemy import select as _select

    from . import evidence

    pending = [o for o in session.new if isinstance(o, FindingEvent) and o.content_hash is None]
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
                _select(FindingEvent.chain_seq, FindingEvent.content_hash)
                .where(FindingEvent.client_id == cid, FindingEvent.content_hash.isnot(None))
                .order_by(FindingEvent.chain_seq.desc()).limit(1)).first()
            prev_seq, prev_hash = (head[0], head[1]) if head else (0, evidence.GENESIS)
            for e in sorted(evs, key=lambda x: (x.at, x.id)):
                prev_seq += 1
                e.chain_seq = prev_seq
                e.prev_hash = prev_hash
                e.content_hash, e.signature, e.key_id = evidence.compute(event_fields(e), prev_hash)
                prev_hash = e.content_hash


def client_event_records(db: Session, client_id: str) -> list[dict]:
    rows = db.execute(
        select(FindingEvent).where(FindingEvent.client_id == client_id, FindingEvent.content_hash.isnot(None))
        .order_by(FindingEvent.chain_seq)
    ).scalars().all()
    return [{"fields": event_fields(e), "prev_hash": e.prev_hash,
             "content_hash": e.content_hash, "signature": e.signature} for e in rows]


def build_event_proof(db: Session, client) -> dict:
    from . import evidence

    rows = db.execute(
        select(FindingEvent).where(FindingEvent.client_id == client.id, FindingEvent.content_hash.isnot(None))
        .order_by(FindingEvent.chain_seq)
    ).scalars().all()
    verify_input, entries = [], []
    for e in rows:
        f = event_fields(e)
        verify_input.append({"fields": f, "prev_hash": e.prev_hash,
                             "content_hash": e.content_hash, "signature": e.signature})
        entries.append({"chain_seq": e.chain_seq, "prev_hash": e.prev_hash,
                        "content_hash": e.content_hash, "signature": e.signature, **f})
    result = evidence.verify_chain(verify_input)
    return {"document": "Vendetta Cyber Defense pentest finding-event proof",
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


def severity_trend(db: Session, client_id: str, limit: int = 12) -> list[dict]:
    """Closed engagements' severity counts, oldest first, for the portal trend."""
    rows = db.execute(
        select(Engagement).where(Engagement.client_id == client_id, Engagement.status == "closed")
        .order_by(Engagement.closed_at.desc()).limit(limit)
    ).scalars().all()
    rows = list(reversed(rows))
    return [{"at": e.closed_at, "label": e.name, **e.counts()} for e in rows]
