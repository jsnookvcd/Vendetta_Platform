"""What the Slack responder keeps. Case content never lives here; the IR hub holds
it on its signed chain.

- WarRoom: a Slack channel bound to one IR case. One active binding per channel.
- Posted: an announcement already made (a new case, a SABINE proposal), with the
  channel and message ts so a later change can update the same message rather
  than post a second one.
- SlackUser: Slack user id to work email, cached so every command does not ask
  Slack who someone is.
- AuditLog: every command, button and reaction the responder acted on, and every
  refusal, with the Slack user and the email it resolved to.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class WarRoom(Base):
    __tablename__ = "war_rooms"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    channel_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_name: Mapped[str] = mapped_column(String(100), default="")
    case_id: Mapped[str] = mapped_column(String(32), index=True)       # IR hub case id
    case_number: Mapped[str] = mapped_column(String(40), index=True)   # VCD-IR-2026-781
    client: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    card_ts: Mapped[str] = mapped_column(String(32), default="")       # the pinned case card
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Posted(Base):
    __tablename__ = "posted"
    __table_args__ = (UniqueConstraint("kind", "ref", name="uq_posted_kind_ref"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(20))      # case | proposal
    ref: Mapped[str] = mapped_column(String(64))       # case number | proposal id
    channel: Mapped[str] = mapped_column(String(32), default="")
    ts: Mapped[str] = mapped_column(String(32), default="")  # blank: seen at seed time, never posted
    state: Mapped[str] = mapped_column(String(20), default="open")  # proposals: pending | approved | rejected | ...
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SlackUser(Base):
    __tablename__ = "slack_users"
    slack_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), default="")
    name: Mapped[str] = mapped_column(String(200), default="")
    is_bot: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    slack_user: Mapped[str] = mapped_column(String(32), default="")
    actor: Mapped[str] = mapped_column(String(320), default="")   # resolved email, or "" when refused before that
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=True)


class User(Base):
    """The break-glass admin is the only console login; the table exists so the
    console's identity check has one shape across modules."""
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    role: Mapped[str] = mapped_column(String(30), default="admin")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


def audit(db, action: str, detail: str = "", *, slack_user: str = "", actor: str = "", ok: bool = True) -> None:
    db.add(AuditLog(action=action[:100], detail=detail[:4000], slack_user=slack_user[:32], actor=actor[:320], ok=ok))
    db.commit()
