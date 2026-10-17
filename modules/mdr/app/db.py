"""MDR data model.

A Signal is one managed-services finding as MDR last pulled it. A Rule is a detection
rule (data, edited by an admin, every edit kept as a RuleVersion). A RuleOverride
disables a rule or changes its severity for one client. A Suppression sets aside a
client's signals that match it until it expires. An Investigation is what the SOC
works: opened when a rule fires, fed by the signals that keep matching it, carried
to a verdict, and recorded step by step in a per-investigation, signed,
hash-chained timeline.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
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


# ---------------------------------------------------------------- rules
class Rule(Base):
    __tablename__ = "rules"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    match: Mapped[dict] = mapped_column(JSON, default=dict)        # tools, types, title_any, min_severity
    correlation: Mapped[dict] = mapped_column(JSON, default=dict)  # group_by, window_minutes, threshold
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    response: Mapped[str] = mapped_column(String(30), default="none")
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(320), default="seed")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def as_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "description": self.description, "enabled": self.enabled,
                "severity": self.severity, "match": dict(self.match or {}),
                "correlation": dict(self.correlation or {}), "mitre": list(self.mitre or []),
                "response": self.response, "version": self.version,
                "updated_by": self.updated_by,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None}


class RuleVersion(Base):
    """Every rule change, kept whole: the snapshot after the change, who made it and
    why. Version 1 is the seed."""
    __tablename__ = "rule_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_key: Mapped[str] = mapped_column(ForeignKey("rules.key", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(20), default="edit")  # seed | edit | override
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    note: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(320), default="")
    changed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuleOverride(Base):
    __tablename__ = "rule_overrides"
    __table_args__ = (UniqueConstraint("rule_key", "client_id", name="uq_override_rule_client"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    rule_key: Mapped[str] = mapped_column(ForeignKey("rules.key", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(10), default="")  # blank keeps the rule's severity
    note: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship()


# ---------------------------------------------------------------- suppressions
class Suppression(Base):
    __tablename__ = "suppressions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    tool: Mapped[str] = mapped_column(String(30), default="")
    title_contains: Mapped[str] = mapped_column(String(400), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    source_investigation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reviewed_by: Mapped[str] = mapped_column(String(320), default="")
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    client: Mapped[Client] = relationship()

    def is_active(self, now: dt.datetime | None = None) -> bool:
        return self.expires_at > (now or utcnow())


# ---------------------------------------------------------------- signals and investigations
class Signal(Base):
    """One managed-services finding, keyed by its managed-services id (the alert id)."""
    __tablename__ = "signals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # managed-services alert id
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    client_name: Mapped[str] = mapped_column(String(200), default="")
    tool: Mapped[str] = mapped_column(String(30), default="")
    type: Mapped[str] = mapped_column(String(30), default="")
    severity: Mapped[str] = mapped_column(String(10), default="low")
    status: Mapped[str] = mapped_column(String(20), default="new")
    title: Mapped[str] = mapped_column(String(600), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    url: Mapped[str] = mapped_column(String(600), default="")
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    copilot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    suppression_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Counter(Base):
    """Per-year sequence behind the MDR-YYYY-NNNN investigation number."""
    __tablename__ = "counters"
    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    n: Mapped[int] = mapped_column(Integer, default=0)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    number: Mapped[str] = mapped_column(String(20), unique=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    title: Mapped[str] = mapped_column(String(400))
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")  # new|investigating|contained|closed
    verdict: Mapped[str] = mapped_column(String(20), default="pending")  # pending|true_positive|false_positive|benign
    rule_key: Mapped[str] = mapped_column(String(80), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    group_key: Mapped[str] = mapped_column(String(255), default="")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    host: Mapped[str] = mapped_column(String(255), default="")
    first_signal_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    last_signal_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    acknowledged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str] = mapped_column(String(320), default="")
    contained_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalated_case: Mapped[str] = mapped_column(String(60), default="")
    response: Mapped[str] = mapped_column(String(30), default="none")  # recommended action
    response_note: Mapped[str] = mapped_column(Text, default="")
    response_prepared_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_prepared_by: Mapped[str] = mapped_column(String(320), default="")
    published: Mapped[bool] = mapped_column(Boolean, default=False)
    client_summary: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    client: Mapped[Client] = relationship()
    links: Mapped[list[InvestigationSignal]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", order_by="InvestigationSignal.attached_at")

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES

    def signals(self) -> list[Signal]:
        return sorted((link.signal for link in self.links), key=lambda s: s.occurred_at)

    def latest_signal(self) -> Signal | None:
        sigs = self.signals()
        return sigs[-1] if sigs else None


class InvestigationSignal(Base):
    __tablename__ = "investigation_signals"
    __table_args__ = (UniqueConstraint("investigation_id", "signal_id", name="uq_inv_signal"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    signal_id: Mapped[str] = mapped_column(ForeignKey("signals.id"), index=True)
    rule_key: Mapped[str] = mapped_column(String(80), index=True)
    attached_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="links")
    signal: Mapped[Signal] = relationship(lazy="joined")


class TimelineEntry(Base):
    """The investigation's signed, tamper-evident record: opened, signals attached,
    acknowledged, notes, verdicts, containment, publication, escalation and close.
    One hash chain per investigation."""
    __tablename__ = "timeline"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(32), index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320), default="system")
    kind: Mapped[str] = mapped_column(String(40), default="note")
    detail: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    client_visible: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    signature: Mapped[str | None] = mapped_column(String(160), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


def entry_fields(e: TimelineEntry) -> dict:
    return {"id": e.id, "investigation_id": e.investigation_id, "client_id": e.client_id,
            "chain_seq": e.chain_seq, "at": e.at.isoformat() if e.at else None, "actor": e.actor,
            "kind": e.kind, "detail": e.detail, "payload": e.payload or {},
            "client_visible": bool(e.client_visible)}


def record(db: Session, inv: Investigation, kind: str, actor: str, detail: str = "",
           payload: dict | None = None, client_visible: bool = False) -> TimelineEntry:
    e = TimelineEntry(investigation_id=inv.id, client_id=inv.client_id, kind=kind, actor=actor,
                      detail=(detail or "")[:4000], payload=payload or {}, client_visible=client_visible)
    db.add(e)
    return e


def _chain_entries(session) -> None:
    from collections import defaultdict

    from . import evidence

    pending = [o for o in session.new if isinstance(o, TimelineEntry) and o.content_hash is None]
    if not pending:
        return
    by_inv: dict[str, list] = defaultdict(list)
    for e in pending:
        if e.id is None:
            e.id = new_id()
        if e.at is None:
            e.at = utcnow()
        for attr, default in (("actor", "system"), ("kind", "note"), ("detail", ""), ("payload", {}),
                              ("client_visible", False)):
            if getattr(e, attr) is None:
                setattr(e, attr, default)
        by_inv[e.investigation_id].append(e)
    with session.no_autoflush:
        for iid, entries in by_inv.items():
            head = session.execute(
                select(TimelineEntry.chain_seq, TimelineEntry.content_hash)
                .where(TimelineEntry.investigation_id == iid, TimelineEntry.content_hash.isnot(None))
                .order_by(TimelineEntry.chain_seq.desc()).limit(1)).first()
            prev_seq, prev_hash = (head[0], head[1]) if head else (0, evidence.GENESIS)
            for e in sorted(entries, key=lambda x: (x.at, x.id)):
                prev_seq += 1
                e.chain_seq = prev_seq
                e.prev_hash = prev_hash
                e.content_hash, e.signature, e.key_id = evidence.compute(entry_fields(e), prev_hash)
                prev_hash = e.content_hash


def timeline_records(db: Session, investigation_id: str) -> list[dict]:
    rows = db.execute(
        select(TimelineEntry).where(TimelineEntry.investigation_id == investigation_id,
                                    TimelineEntry.content_hash.isnot(None))
        .order_by(TimelineEntry.chain_seq)).scalars().all()
    return [{"fields": entry_fields(e), "prev_hash": e.prev_hash,
             "content_hash": e.content_hash, "signature": e.signature} for e in rows]


def timeline(db: Session, investigation_id: str) -> list[TimelineEntry]:
    return db.execute(select(TimelineEntry).where(TimelineEntry.investigation_id == investigation_id)
                      .order_by(TimelineEntry.chain_seq)).scalars().all()


from sqlalchemy import event as _event  # noqa: E402


@_event.listens_for(SessionLocal, "before_flush")
def _evidence_before_flush(session, flush_context, instances):  # noqa: ANN001
    _chain_entries(session)


def seed_rules(db: Session) -> int:
    """Insert any starter rule that is not in the table yet. Never overwrites."""
    from .rules_seed import STARTER_RULES

    have = set(db.execute(select(Rule.key)).scalars().all())
    added = 0
    for spec in STARTER_RULES:
        if spec["key"] in have:
            continue
        r = Rule(key=spec["key"], name=spec["name"], description=spec["description"], enabled=spec["enabled"],
                 severity=spec["severity"], match=spec["match"], correlation=spec["correlation"],
                 mitre=spec["mitre"], response=spec["response"], version=1, updated_by="seed")
        db.add(r)
        db.flush()
        db.add(RuleVersion(rule_key=r.key, version=1, kind="seed", snapshot=r.as_dict(),
                           note="starter rule set", changed_by="seed"))
        added += 1
    db.commit()
    return added


def init_db() -> None:
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        seed_rules(db)
    finally:
        db.close()
