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
    """A managed client plus its mapping into each tool's tenancy. A tool counts as
    deployed for the client when its mapping field is set."""

    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    # Portal users whose email is listed here get the executive (summary) view;
    # everyone else on the client gets the technical (detail) view.
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    # Set when this client is provisioned from the platform control plane.
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    # Which SLA profile governs this client's alert clocks (see config.SLA_PROFILES).
    sla_profile: Mapped[str] = mapped_column(String(20), default="standard")
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
    # SLA clock anchors. received_at is when the alert first entered our queue (the
    # clock start); acknowledged_at and contained_at are when a responder first
    # triaged it and first contained it, filled on the triage/action that does so.
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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


class Indicator(Base):
    """An indicator of compromise observed on one alert for one client. The same
    (itype, value) seen across more than one client is what the correlation engine
    treats as a campaign. itype is ip | domain | url | sha256 | md5 | signature;
    value is normalized (lowercased) for matching, label keeps the original form."""

    __tablename__ = "indicators"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    tool: Mapped[str] = mapped_column(String(20), default="")
    itype: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(400), index=True)
    label: Mapped[str] = mapped_column(String(400), default="")
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_indicators_match", "itype", "value"),
                      Index("ix_indicators_alert_uniq", "alert_id", "itype", "value", unique=True))


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
    approver: Mapped[str] = mapped_column(String(320), default="")  # who authorized a destructive action
    detail: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[str] = mapped_column(String(20), default="ok")  # ok | failed
    client_visible: Mapped[bool] = mapped_column(Boolean, default=False)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Chain of custody: a signed, tamper-evident chain per client (the tenant), so
    # every response action against a client carries proof of who, what, when and
    # which tenant. Filled automatically at flush (see the before_flush hook).
    chain_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    signature: Mapped[str | None] = mapped_column(String(160), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

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
    # Response-action capabilities. can_act: may run tool actions at all. can_approve:
    # may authorize a destructive action (the second-person control). Admin implies both.
    can_act: Mapped[bool] = mapped_column(Boolean, default=True)
    can_approve: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


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


class ToolCredential(Base):
    """A tool integration's credentials, entered in-app and encrypted at rest. The
    decrypted JSON overlays the environment defaults (see creds.py). `connected`
    reflects the last live test, so the Integrations page shows real status."""

    __tablename__ = "tool_credentials"
    tool: Mapped[str] = mapped_column(String(20), primary_key=True)
    data: Mapped[str] = mapped_column(Text, default="")  # Fernet-encrypted JSON of fields
    connected: Mapped[bool] = mapped_column(Boolean, default=False)
    last_tested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_detail: Mapped[str] = mapped_column(String(500), default="")
    updated_by: Mapped[str] = mapped_column(String(320), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
    from sqlalchemy import text as _text
    with engine.begin() as conn:
        conn.execute(_text("ALTER TABLE clients ADD COLUMN IF NOT EXISTS platform_client_id VARCHAR(32) DEFAULT ''"))
        conn.execute(_text("ALTER TABLE clients ADD COLUMN IF NOT EXISTS executive_emails VARCHAR(1000) DEFAULT ''"))
        conn.execute(_text("CREATE INDEX IF NOT EXISTS ix_clients_platform_client_id ON clients (platform_client_id)"))
        # Chain-of-custody columns on the action log.
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS chain_seq INTEGER"))
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64)"))
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)"))
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS signature VARCHAR(160)"))
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS key_id VARCHAR(32)"))
        conn.execute(_text("CREATE INDEX IF NOT EXISTS ix_action_log_content_hash ON action_log (content_hash)"))
        conn.execute(_text("ALTER TABLE users ADD COLUMN IF NOT EXISTS can_act BOOLEAN DEFAULT true"))
        conn.execute(_text("ALTER TABLE users ADD COLUMN IF NOT EXISTS can_approve BOOLEAN DEFAULT false"))
        conn.execute(_text("ALTER TABLE action_log ADD COLUMN IF NOT EXISTS approver VARCHAR(320) DEFAULT ''"))
        # SLA: per-client profile and per-alert clock anchors.
        conn.execute(_text("ALTER TABLE clients ADD COLUMN IF NOT EXISTS sla_profile VARCHAR(20) DEFAULT 'standard'"))
        conn.execute(_text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ"))
        conn.execute(_text("UPDATE alerts SET received_at = COALESCE(received_at, synced_at, occurred_at, now())"))
        conn.execute(_text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ"))
        conn.execute(_text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS contained_at TIMESTAMPTZ"))
        # Indicators table is created by create_all; nothing to migrate for it yet.


# ---------------------------------------------------------------- chain of custody
_GLOBAL_CHAIN = "_module"  # chain key for actions with no client (module-level)


def action_fields(a: "ActionLog") -> dict:
    """The immutable, evidentiary fields of an action, in the exact shape the chain
    hashes. Write and verify both go through this so the two always agree."""
    return {
        "id": a.id,
        "client_id": a.client_id,
        "alert_id": a.alert_id,
        "device_id": a.device_id,
        "tool": a.tool,
        "action": a.action,
        "actor": a.actor,
        "approver": a.approver,
        "detail": a.detail,
        "result": a.result,
        "client_visible": bool(a.client_visible),
        "at": a.at.isoformat() if a.at is not None else None,
    }


def _chain_new_actions(session) -> None:
    from collections import defaultdict

    from sqlalchemy import select as _select

    from . import evidence

    pending = [o for o in session.new if isinstance(o, ActionLog) and o.content_hash is None]
    if not pending:
        return
    by_client: dict[str, list[ActionLog]] = defaultdict(list)
    for a in pending:
        # Materialise insert-time defaults onto the object so what we sign is exactly
        # what gets stored.
        if a.id is None:
            a.id = new_id()
        if a.at is None:
            a.at = utcnow()
        if a.actor is None:
            a.actor = "system"
        if a.action is None:
            a.action = ""
        if a.approver is None:
            a.approver = ""
        if a.tool is None:
            a.tool = ""
        if a.detail is None:
            a.detail = ""
        if a.result is None:
            a.result = "ok"
        if a.client_visible is None:
            a.client_visible = False
        by_client[a.client_id or _GLOBAL_CHAIN].append(a)

    with session.no_autoflush:
        for key, rows in by_client.items():
            prev_seq, prev_hash = 0, evidence.GENESIS
            q = _select(ActionLog.chain_seq, ActionLog.content_hash).where(ActionLog.content_hash.isnot(None))
            q = q.where(ActionLog.client_id == key) if key != _GLOBAL_CHAIN else q.where(ActionLog.client_id.is_(None))
            head = session.execute(q.order_by(ActionLog.chain_seq.desc()).limit(1)).first()
            if head:
                prev_seq, prev_hash = head[0], head[1]
            for a in sorted(rows, key=lambda x: (x.at, x.id)):
                prev_seq += 1
                a.chain_seq = prev_seq
                a.prev_hash = prev_hash
                a.content_hash, a.signature, a.key_id = evidence.compute(action_fields(a), prev_hash)
                prev_hash = a.content_hash


def client_chain_records(db, client_id: str) -> list[dict]:
    from sqlalchemy import select as _select

    rows = db.execute(
        _select(ActionLog).where(ActionLog.client_id == client_id, ActionLog.content_hash.isnot(None))
        .order_by(ActionLog.chain_seq)
    ).scalars().all()
    return [{"fields": action_fields(a), "prev_hash": a.prev_hash,
             "content_hash": a.content_hash, "signature": a.signature} for a in rows]


def build_action_proof(db, client) -> dict:
    """A self-contained, verifiable proof of every response action taken for a
    client. All fields are included; actions are operator records, not client
    secrets."""
    from sqlalchemy import select as _select

    from . import evidence

    rows = db.execute(
        _select(ActionLog).where(ActionLog.client_id == client.id, ActionLog.content_hash.isnot(None))
        .order_by(ActionLog.chain_seq)
    ).scalars().all()
    verify_input, entries = [], []
    for a in rows:
        f = action_fields(a)
        verify_input.append({"fields": f, "prev_hash": a.prev_hash,
                             "content_hash": a.content_hash, "signature": a.signature})
        entries.append({"chain_seq": a.chain_seq, "prev_hash": a.prev_hash,
                        "content_hash": a.content_hash, "signature": a.signature, **f})
    result = evidence.verify_chain(verify_input)
    return {
        "document": "Vendetta Cyber Defense response action proof",
        "scheme": evidence.SCHEME,
        "generated_at": utcnow().isoformat(),
        "key_id": evidence.key_id(),
        "public_key": evidence.public_key_hex(),
        "client": {"id": client.id, "name": client.name},
        "entry_count": len(entries),
        "verification": result,
        "entries": entries,
    }


from sqlalchemy import event as _event  # noqa: E402


@_event.listens_for(SessionLocal, "before_flush")
def _evidence_before_flush(session, flush_context, instances):  # noqa: ANN001
    _chain_new_actions(session)


def get_channel(db, client_id: str, desk: str) -> Channel:
    ch = db.query(Channel).filter_by(client_id=client_id, desk=desk).one_or_none()
    if ch is None:
        ch = Channel(client_id=client_id, desk=desk)
        db.add(ch)
        db.flush()
    return ch
