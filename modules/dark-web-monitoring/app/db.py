"""SQLAlchemy models. Postgres full text search is used for the research console."""
from __future__ import annotations

import datetime as dt
import hashlib
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
    text,
)
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


class Client(Base):
    """A monitored organization. Managed services clients and active IR matters both live here."""

    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    case_ref: Mapped[str] = mapped_column(String(100), default="")  # IR case number or MSSP contract ref
    kind: Mapped[str] = mapped_column(String(20), default="managed")  # managed | ir
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Client-facing portal: when enabled, users whose email domain is listed in
    # portal_domains can sign in via SSO and see only this client's findings.
    portal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    portal_domains: Mapped[str] = mapped_column(String(500), default="")  # comma-separated email domains
    notes: Mapped[str] = mapped_column(Text, default="")
    # Portal users listed here get the executive (summary) view; others technical.
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    # Set when provisioned from the platform control plane; the shared client id.
    platform_client_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    # Profile used for initial access broker (IAB) matching. Brokers rarely name the
    # victim; they advertise "US credit union, $400M revenue, 300 hosts, VPN access".
    industry: Mapped[str] = mapped_column(String(100), default="")  # e.g. credit union, bank, healthcare, manufacturing
    country: Mapped[str] = mapped_column(String(100), default="")  # e.g. USA
    state: Mapped[str] = mapped_column(String(100), default="")  # e.g. Pennsylvania
    revenue_min_musd: Mapped[int] = mapped_column(Integer, default=0)  # revenue band in $M
    revenue_max_musd: Mapped[int] = mapped_column(Integer, default=0)
    employees_min: Mapped[int] = mapped_column(Integer, default=0)
    employees_max: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    terms: Mapped[list[WatchTerm]] = relationship(back_populates="client", cascade="all, delete-orphan")
    hits: Mapped[list[Hit]] = relationship(back_populates="client", cascade="all, delete-orphan")


class WatchTerm(Base):
    """A keyword, domain, email domain, IP range, brand or executive name tied to a client."""

    __tablename__ = "watch_terms"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"))
    term: Mapped[str] = mapped_column(String(300))
    # domain | email_domain | keyword | regex | ip_cidr | person | brand
    kind: Mapped[str] = mapped_column(String(20), default="keyword")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="terms")


class Source(Base):
    """A place we collect from. Onion leak sites, clearnet feeds, paste dumps, Telegram channels."""

    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    # onion | forum | feed | paste | telegram | hibp | ct
    kind: Mapped[str] = mapped_column(String(20))
    profile: Mapped[str] = mapped_column(String(100), default="")  # parser profile name from app/profiles/*.yaml
    url: Mapped[str] = mapped_column(Text, default="")
    group_name: Mapped[str] = mapped_column(String(100), default="")  # ransomware group label
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_ok: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_sources_kind_url", "kind", "url", unique=True),)


class Item(Base):
    """One collected record: a leak-site victim post, a paste, a breach entry, a CT cert, a message."""

    __tablename__ = "items"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"), nullable=True)
    # victim | post | page | thread | message | paste | breach | stealer | credential | cert
    kind: Mapped[str] = mapped_column(String(20))
    external_id: Mapped[str] = mapped_column(String(300), default="")
    group_name: Mapped[str] = mapped_column(String(100), default="")
    title: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    hits: Mapped[list[Hit]] = relationship(back_populates="item", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_items_kind_ext", "kind", "external_id"),)

    @staticmethod
    def make_hash(*parts: str) -> str:
        h = hashlib.sha256()
        for p in parts:
            h.update((p or "").encode("utf-8", "replace"))
            h.update(b"\x1f")
        return h.hexdigest()


class Hit(Base):
    """A watch term matched an item. This is what analysts triage."""

    __tablename__ = "hits"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"))
    item_id: Mapped[str] = mapped_column(ForeignKey("items.id"))
    term_id: Mapped[str | None] = mapped_column(ForeignKey("watch_terms.id"), nullable=True)
    # term | iab | credential : how the hit was produced
    reason: Mapped[str] = mapped_column(String(20), default="term")
    matched_text: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")  # new | reviewing | confirmed | false_positive | closed
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    alerted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alert_refs: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. {"jira": "IR-812"}
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="hits")
    item: Mapped[Item] = relationship(back_populates="hits")
    term: Mapped[WatchTerm | None] = relationship()

    __table_args__ = (Index("ix_hits_client_item_term", "client_id", "item_id", "term_id", "reason", unique=True),)


class Evidence(Base):
    """A preserved snapshot of a page or record with hashes, for IR and litigation support."""

    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    item_id: Mapped[str | None] = mapped_column(ForeignKey("items.id"), nullable=True)
    url: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    captured_by: Mapped[str] = mapped_column(String(100), default="system")
    http_status: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    storage_uri: Mapped[str] = mapped_column(Text)  # s3://bucket/key or file:///path
    text_excerpt: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(Text, default="")
    headers: Mapped[dict] = mapped_column(JSON, default=dict)


class User(Base):
    """A person who has signed in, by Entra ID SSO or the local admin account.
    Gives per-user attribution now and a place for roles as the platform grows."""

    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(20), default="entra")  # entra | local
    role: Mapped[str] = mapped_column(String(30), default="analyst")  # admin | analyst | client
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)  # set for client-portal users
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
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")


class CollectorRun(Base):
    """One execution of a scheduled or manually requested collector job. Written by
    the worker's job wrapper so the console can show what ran, what it produced and
    why it failed. Rows older than RUN_RETENTION_DAYS are pruned daily."""

    __tablename__ = "collector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(50), index=True)
    trigger: Mapped[str] = mapped_column(String(20), default="schedule")  # schedule | manual | startup
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # None while running
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    hits_new: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class WorkerState(Base):
    """Small key/value store the worker writes and the web container reads:
    the heartbeat, the latest Tor check and similar singletons."""

    __tablename__ = "worker_state"
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkerRequestMixin:
    """A unit of work the web container queues and the worker drains. The web
    container never runs collectors or Tor requests itself; it inserts a row and the
    worker claims it on its next poll. Reused by every worker-polled request table
    (run_requests now; search_requests and similar later): subclass with a
    __tablename__ and hand the model to app.work_requests."""

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # pending | running | done | failed
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    requested_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


class RunRequest(WorkerRequestMixin, Base):
    """"Run now" on the Connectors page. payload: {"connector": key}."""

    __tablename__ = "run_requests"


def init_db() -> None:
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        # Additive migrations for installs created before these columns existed.
        for stmt in (
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS industry VARCHAR(100) DEFAULT ''",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS country VARCHAR(100) DEFAULT ''",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS state VARCHAR(100) DEFAULT ''",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS revenue_min_musd INTEGER DEFAULT 0",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS revenue_max_musd INTEGER DEFAULT 0",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS employees_min INTEGER DEFAULT 0",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS employees_max INTEGER DEFAULT 0",
            "ALTER TABLE sources ADD COLUMN IF NOT EXISTS profile VARCHAR(100) DEFAULT ''",
            "ALTER TABLE hits ADD COLUMN IF NOT EXISTS reason VARCHAR(20) DEFAULT 'term'",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS portal_enabled BOOLEAN DEFAULT FALSE",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS portal_domains VARCHAR(500) DEFAULT ''",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS client_id VARCHAR(32)",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS platform_client_id VARCHAR(32) DEFAULT ''",
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS executive_emails VARCHAR(1000) DEFAULT ''",
            "CREATE INDEX IF NOT EXISTS ix_clients_platform_client_id ON clients (platform_client_id)",
        ):
            conn.execute(text(stmt))
        # Generated tsvector column plus GIN index for the research console search.
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS search_vec tsvector "
            "GENERATED ALWAYS AS (to_tsvector('simple', coalesce(title,'') || ' ' || coalesce(body,''))) STORED"
        ))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_items_search ON items USING GIN (search_vec)"))
