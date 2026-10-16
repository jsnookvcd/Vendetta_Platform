"""MARLOW data model.

Four kinds of record make up what MARLOW knows and does:

- WorkItem: the operator queue. Everything across every module that is waiting on
  a person or on MARLOW, keyed so a repeat observation updates rather than
  duplicates, with severity, a due time and a link to where the work is done.
- Proposal: something MARLOW thinks should happen, with the facts it rests on, a
  written rationale, a confidence, a risk tier and the autonomy level that applied.
  A proposal is decided (approved, rejected, expired) and, if approved, executed.
- Ledger: the signed hash chain. Every observation summary, proposal, decision and
  action is appended, so what MARLOW saw, suggested, who allowed it and what it did
  can be verified independently later.
- Policy: the autonomy level per action kind (off, propose, auto), set by an admin.
- Brief: a document MARLOW wrote (a client brief, a daily summary), kept for review.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
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


class WorkItem(Base):
    __tablename__ = "work_items"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    key: Mapped[str] = mapped_column(String(300), unique=True)  # source:kind:id
    source: Mapped[str] = mapped_column(String(40))              # module key
    kind: Mapped[str] = mapped_column(String(40))                # finding | case | readiness | engagement | admin
    domain: Mapped[str] = mapped_column(String(20), default="soc")  # soc | admin | services
    title: Mapped[str] = mapped_column(String(400))
    client: Mapped[str] = mapped_column(String(200), default="")
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")  # low..critical
    state: Mapped[str] = mapped_column(String(20), default="open")      # open | claimed | done | gone
    owner: Mapped[str] = mapped_column(String(320), default="")
    link: Mapped[str] = mapped_column(String(500), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    done_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Proposal(Base):
    __tablename__ = "proposals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    key: Mapped[str] = mapped_column(String(300), index=True)   # dedupe: action:target
    action: Mapped[str] = mapped_column(String(40))             # policy.ACTIONS key
    domain: Mapped[str] = mapped_column(String(20), default="soc")
    title: Mapped[str] = mapped_column(String(400))
    rationale: Mapped[str] = mapped_column(Text, default="")
    facts: Mapped[dict] = mapped_column(JSON, default=dict)      # what the rule saw
    target: Mapped[dict] = mapped_column(JSON, default=dict)     # module, id, url
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    risk: Mapped[str] = mapped_column(String(20), default="low")      # low | medium | high
    autonomy: Mapped[str] = mapped_column(String(10), default="propose")  # the level that applied
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | approved | rejected | executed | failed | expired
    decided_by: Mapped[str] = mapped_column(String(320), default="")
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    work_item_id: Mapped[str | None] = mapped_column(ForeignKey("work_items.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    work_item: Mapped[WorkItem | None] = relationship()


class Ledger(Base):
    """Signed, hash-chained record of everything MARLOW observed, proposed, was
    told, and did. One chain for the whole brain."""

    __tablename__ = "ledger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    kind: Mapped[str] = mapped_column(String(20))   # observation | proposal | decision | action | cycle
    actor: Mapped[str] = mapped_column(String(320))  # marlow, or the person who decided
    ref: Mapped[str] = mapped_column(String(64), default="")  # proposal id etc.
    summary: Mapped[str] = mapped_column(String(500))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    chain_seq: Mapped[int] = mapped_column(Integer)
    prev_hash: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(16))

    def fields(self) -> dict:
        return {"at": self.at.isoformat(), "kind": self.kind, "actor": self.actor, "ref": self.ref,
                "summary": self.summary, "detail": self.detail}


class Policy(Base):
    __tablename__ = "policies"
    action: Mapped[str] = mapped_column(String(40), primary_key=True)
    autonomy: Mapped[str] = mapped_column(String(10), default="propose")  # off | propose | auto
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Brief(Base):
    __tablename__ = "briefs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(40))   # client-brief | daily-summary
    client: Mapped[str] = mapped_column(String(200), default="")
    platform_client_id: Mapped[str] = mapped_column(String(32), default="")
    title: Mapped[str] = mapped_column(String(300))
    body_md: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20), default="rules")  # rules | llm
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Snapshot(Base):
    """The last observation per source, so the console and the reasoner work from
    one consistent picture and a module being down shows as stale, not absent."""

    __tablename__ = "snapshots"
    source: Mapped[str] = mapped_column(String(80), primary_key=True)  # e.g. findings:dark-web-monitoring
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str] = mapped_column(String(300), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(20), default="entra")
    role: Mapped[str] = mapped_column(String(30), default="analyst")  # admin | analyst
    client_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
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


def init_db() -> None:
    Base.metadata.create_all(engine)
    from .policy import seed_policies

    db = SessionLocal()
    try:
        seed_policies(db)
    finally:
        db.close()
