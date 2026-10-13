"""Managed Services data model.

The module keeps a normalized copy of what each client's deployed tools report:
devices and alerts, in one shape, whatever the source (SuperOps, SentinelOne,
CrowdStrike, Huntress, Acronis). Sync writes here; the console and the client
portal read from here and deep-link back to each vendor console. Actions taken
against a tool are recorded as ActionLog rows, and the client-visible ones feed
the portal's "actions taken" feed. Messaging between a client and the SOC, NOC
or helpdesk lives in Channel and Message."""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import TOOLS, settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Client(Base):
    """A managed client plus its mapping into each tool's tenancy. A tool counts as
    deployed for the client when its mapping field is set."""

    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Tool tenancy mapping
    superops_client_id: Mapped[str] = mapped_column(String(60), default="")      # accountId
    sentinelone_site_ids: Mapped[str] = mapped_column(String(300), default="")   # comma separated
    crowdstrike_cid: Mapped[str] = mapped_column(String(40), default="")         # child CID (member_cid)
    huntress_org_id: Mapped[str] = mapped_column(String(60), default="")
    acronis_tenant_id: Mapped[str] = mapped_column(String(60), default="")       # tenant UUID

    devices: Mapped[list[Device]] = relationship(back_populates="client")
    alerts: Mapped[list[Alert]] = relationship(back_populates="client")
    channels: Mapped[list[Channel]] = relationship(back_populates="client")

    def tool_ref(self, tool: str) -> str:
        return {
            "superops": self.superops_client_id,
            "sentinelone": self.sentinelone_site_ids,
            "crowdstrike": self.crowdstrike_cid,
            "huntress": self.huntress_org_id,
            "acronis": self.acronis_tenant_id,
        }[tool]

    @property
    def tools(self) -> list[str]:
        return [t for t in TOOLS if self.tool_ref(t)]


class Device(Base):
    """Normalized device/agent/workload snapshot from one tool."""

    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    tool: Mapped[str] = mapped_column(String(20))
    external_id: Mapped[str] = mapped_column(String(120))
    hostname: Mapped[str] = mapped_column(String(300), default="")
    platform: Mapped[str] = mapped_column(String(120), default="")
    # online | offline | isolated | isolating | unknown
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    agent_version: Mapped[str] = mapped_column(String(60), default="")
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    link: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    synced_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="devices")

    __table_args__ = (Index("ix_devices_tool_ext", "tool", "external_id", unique=True),)


class Alert(Base):
    """Normalized alert/threat/incident/backup-failure from one tool.

    status is the module's triage state. tool_status is the vendor's own state,
    kept verbatim. published alerts (and their client_note) show on the portal."""

    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    tool: Mapped[str] = mapped_column(String(20))
    external_id: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30), default="alert")  # threat | detection | incident | backup | rmm
    severity: Mapped[str] = mapped_column(String(10), default="medium")  # info..critical
    title: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | acknowledged | resolved
    tool_status: Mapped[str] = mapped_column(String(60), default="")
    occurred_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    synced_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    link: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    published: Mapped[bool] = mapped_column(Boolean, default=False)
    client_note: Mapped[str] = mapped_column(Text, default="")
    escalated_case: Mapped[str] = mapped_column(String(60), default="")  # IR hub case number

    client: Mapped[Client] = relationship(back_populates="alerts")
    device: Mapped[Device | None] = relationship()
    actions: Mapped[list[ActionLog]] = relationship(back_populates="alert", order_by=lambda: ActionLog.at.desc())

    __table_args__ = (Index("ix_alerts_tool_ext", "tool", "external_id", unique=True),)


class ActionLog(Base):
    """An action a tech took against a tool (isolate, contain, quarantine, approve
    remediations, run backup, resolve) or against the module (publish, escalate).
    client_visible rows feed the portal's actions feed."""

    __tablename__ = "action_log"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"), nullable=True, index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    tool: Mapped[str] = mapped_column(String(20), default="")
    action: Mapped[str] = mapped_column(String(60))
    actor: Mapped[str] = mapped_column(String(320), default="system")
    detail: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[str] = mapped_column(String(20), default="ok")  # ok | failed
    client_visible: Mapped[bool] = mapped_column(Boolean, default=False)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alert: Mapped[Alert | None] = relationship(back_populates="actions")
    device: Mapped[Device | None] = relationship()


class Channel(Base):
    """One running conversation between a client and a desk (SOC, NOC or helpdesk).
    A helpdesk channel can be bound to a SuperOps ticket; messages then flow into
    that ticket as conversations."""

    __tablename__ = "channels"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    desk: Mapped[str] = mapped_column(String(12))  # soc | noc | helpdesk
    superops_ticket_id: Mapped[str] = mapped_column(String(60), default="")
    superops_ticket_display: Mapped[str] = mapped_column(String(40), default="")
    tech_unread: Mapped[int] = mapped_column(Integer, default=0)
    client_unread: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="channels")
    messages: Mapped[list[Message]] = relationship(back_populates="channel", cascade="all, delete-orphan",
                                                   order_by=lambda: Message.at)

    __table_args__ = (Index("ix_channels_client_desk", "client_id", "desk", unique=True),)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    channel_id: Mapped[str] = mapped_column(ForeignKey("channels.id"), index=True)
    sender_kind: Mapped[str] = mapped_column(String(10))  # client | tech | system
    sender: Mapped[str] = mapped_column(String(320), default="")
    body: Mapped[str] = mapped_column(Text)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    channel: Mapped[Channel] = relationship(back_populates="messages")


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


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_channel(db, client_id: str, desk: str) -> Channel:
    ch = db.query(Channel).filter_by(client_id=client_id, desk=desk).one_or_none()
    if ch is None:
        ch = Channel(client_id=client_id, desk=desk)
        db.add(ch)
        db.flush()
    return ch
