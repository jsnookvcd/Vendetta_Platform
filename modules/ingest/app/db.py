"""Telemetry Ingest data model.

A Connector is one client's feed from one tool (the client's CrowdStrike tenant, its
Entra tenant, its AWS organization). An Event is one raw record normalized to OCSF,
stamped with the client's platform id, and hashed twice (raw and normalized). A Batch
seals a run of one tenant's events into a signed Merkle root chained to the tenant's
previous batch. A SigmaRule is a detection rule in Sigma; a Detection is what a rule
(or a vendor's own detection) raised, served to MDR in the shared finding model.

Events are the hot store: they age out after HOT_RETENTION_DAYS. Batch headers and
their leaf hashes are never deleted, so a proof can always be rebuilt for any event
whose raw record is still in the archive or the lake.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String,
                        Text, UniqueConstraint, create_engine, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings
from .crypto import EncryptedStr

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

JSONDoc = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------- shared with every module
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


# ---------------------------------------------------------------- connectors
class Connector(Base):
    __tablename__ = "connectors"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    source: Mapped[str] = mapped_column(String(40))            # mapper key, e.g. crowdstrike_alerts
    name: Mapped[str] = mapped_column(String(200), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Non-secret settings (base URL, tenant domain, region, queue URL).
    config: Mapped[dict] = mapped_column(JSONDoc, default=dict)
    # Secrets as a JSON object string, encrypted at rest. Never rendered or logged.
    credentials: Mapped[str] = mapped_column(EncryptedStr(4000), default="")
    # Per-connector shared secret for push (webhook) delivery, HMAC-SHA256.
    webhook_secret: Mapped[str] = mapped_column(EncryptedStr(200), default="")
    cursor: Mapped[dict] = mapped_column(JSONDoc, default=dict)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=0)   # 0 = module default
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(500), default="")
    last_received: Mapped[int] = mapped_column(Integer, default=0)
    newest_event_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events_total: Mapped[int] = mapped_column(BigInteger, default=0)
    rejected_total: Mapped[int] = mapped_column(BigInteger, default=0)
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client = relationship("Client")


class ConnectorRun(Base):
    __tablename__ = "connector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    connector_id: Mapped[str] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    trigger: Mapped[str] = mapped_column(String(20), default="schedule")  # schedule, manual, push, bucket
    received: Mapped[int] = mapped_column(Integer, default=0)
    stored: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(500), default="")


class Rejected(Base):
    """A record that could not be normalized. Kept so an analyst can see why, and
    hashed so nobody can later claim it said something else."""
    __tablename__ = "rejected"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    connector_id: Mapped[str] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"), index=True)
    tenant: Mapped[str] = mapped_column(String(32), index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reason: Mapped[str] = mapped_column(String(300))
    raw_sha256: Mapped[str] = mapped_column(String(64))
    sample: Mapped[str] = mapped_column(Text, default="")  # first 2 KB, for diagnosis only


# ---------------------------------------------------------------- events and receipts
class Event(Base):
    __tablename__ = "events"
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(32), unique=True, default=new_id)
    tenant: Mapped[str] = mapped_column(String(32))            # platform_client_id
    client_id: Mapped[str] = mapped_column(String(32))
    connector_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(40))
    class_uid: Mapped[int] = mapped_column(Integer)
    time: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity_id: Mapped[int] = mapped_column(Integer, default=0)
    host: Mapped[str] = mapped_column(String(255), default="")
    user: Mapped[str] = mapped_column(String(320), default="")
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(600), default="")
    # Vendor record id or the raw hash, unique per tenant and source: re-polling an
    # overlapping window never stores an event twice.
    dedupe_key: Mapped[str] = mapped_column(String(200))
    raw_sha256: Mapped[str] = mapped_column(String(64))
    event_sha256: Mapped[str] = mapped_column(String(64))
    event: Mapped[dict] = mapped_column(JSONDoc)
    raw: Mapped[str] = mapped_column(Text)                     # canonical JSON as hashed
    batch_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    leaf_index: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant", "source", "dedupe_key", name="uq_event_dedupe"),
        Index("ix_events_tenant_seq", "tenant", "seq"),
        Index("ix_events_unsealed", "tenant", "seq", postgresql_where=text("batch_id IS NULL")),
        Index("ix_events_tenant_time", "tenant", "time"),
    )


class Batch(Base):
    __tablename__ = "batches"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tenant: Mapped[str] = mapped_column(String(32))
    batch_seq: Mapped[int] = mapped_column(Integer)
    size: Mapped[int] = mapped_column(Integer)
    first_seq: Mapped[int] = mapped_column(BigInteger)
    last_seq: Mapped[int] = mapped_column(BigInteger)
    sealed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    header: Mapped[dict] = mapped_column(JSONDoc)
    root: Mapped[str] = mapped_column(String(64))
    prev_batch_hash: Mapped[str] = mapped_column(String(64))
    batch_hash: Mapped[str] = mapped_column(String(64), unique=True)
    signature: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(16))
    public_key: Mapped[str] = mapped_column(String(64))
    # Concatenated 32-byte leaf hashes in leaf order. Kept for life so proofs survive
    # hot-store retention.
    leaves: Mapped[bytes] = mapped_column(LargeBinary)
    anchored_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("tenant", "batch_seq", name="uq_batch_seq"),)

    def record(self) -> dict:
        return {"id": self.id, "header": dict(self.header), "batch_hash": self.batch_hash,
                "signature": self.signature, "public_key": self.public_key}


class Anchor(Base):
    """A daily anchor of every tenant's chain head, written to WORM storage and
    optionally time-stamped. Once anchored, history before it cannot be rewritten
    without the anchor disagreeing."""
    __tablename__ = "anchors"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    digest: Mapped[str] = mapped_column(String(64))           # sha256 of the canonical anchor document
    document: Mapped[dict] = mapped_column(JSONDoc)           # {tenants: {tenant: {batch_seq, batch_hash}}}
    signature: Mapped[str] = mapped_column(String(128))
    stored_at: Mapped[str] = mapped_column(String(500), default="")  # s3:// URI when written to the bucket
    tsa_token: Mapped[str] = mapped_column(Text, default="")         # base64 RFC 3161 token when available


# ---------------------------------------------------------------- detection
class SigmaRule(Base):
    __tablename__ = "sigma_rules"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    level: Mapped[str] = mapped_column(String(20), default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    body: Mapped[str] = mapped_column(Text)                     # the Sigma YAML
    tags: Mapped[list] = mapped_column(JSONDoc, default=list)
    origin: Mapped[str] = mapped_column(String(20), default="custom")  # seed, custom
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(320), default="seed")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits_total: Mapped[int] = mapped_column(BigInteger, default=0)


class SigmaRuleVersion(Base):
    __tablename__ = "sigma_rule_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    version: Mapped[int] = mapped_column(Integer)
    body: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    changed_by: Mapped[str] = mapped_column(String(320))
    changed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    note: Mapped[str] = mapped_column(String(500), default="")


class RuleHit(Base):
    """Matches of threshold rules, kept for the rule's timeframe so a count across
    events can be evaluated as events stream in."""
    __tablename__ = "rule_hits"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(80))
    tenant: Mapped[str] = mapped_column(String(32))
    group_key: Mapped[str] = mapped_column(String(300), default="")
    distinct_value: Mapped[str] = mapped_column(String(300), default="")
    event_id: Mapped[str] = mapped_column(String(32))
    time: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_rule_hits_lookup", "rule_id", "tenant", "group_key", "time"),)


class Detection(Base):
    __tablename__ = "detections"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tenant: Mapped[str] = mapped_column(String(32), index=True)
    client_id: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(10), default="sigma")   # sigma, vendor
    rule_id: Mapped[str] = mapped_column(String(80), default="")
    rule_title: Mapped[str] = mapped_column(String(300), default="")
    source: Mapped[str] = mapped_column(String(40), default="")      # connector source key
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")
    title: Mapped[str] = mapped_column(String(600), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    user: Mapped[str] = mapped_column(String(320), default="")
    group_key: Mapped[str] = mapped_column(String(300), default="")
    event_ids: Mapped[list] = mapped_column(JSONDoc, default=list)
    count: Mapped[int] = mapped_column(Integer, default=1)
    mitre: Mapped[list] = mapped_column(JSONDoc, default=list)
    first_event_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_event_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    escalated_case: Mapped[str] = mapped_column(String(60), default="")
    note: Mapped[str] = mapped_column(Text, default="")


class StreamCursor(Base):
    __tablename__ = "stream_cursors"
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
    from . import sigma_seed

    db = SessionLocal()
    try:
        sigma_seed.seed(db)
    finally:
        db.close()
