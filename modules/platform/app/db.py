"""Vendetta Platform control-plane data model.

The control plane is the system of record for three things the modules used to
each own separately:

- Client: the canonical client directory. One row per client, platform-wide.
- ClientModule: which modules are turned on for a client (entitlement).
- ClientTool: how a client maps into each tool (the tenancy value managed-services
  needs). Secrets stay in the module; this is the per-client mapping only.

Module rows record how to reach each module (base_url + bearer) so the overview
can read live counts and so modules can be health-checked. Modules pull their
client roster and config from the control plane's provisioning API."""
from __future__ import annotations

import datetime as dt
import re
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


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "client"


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    slug: Mapped[str] = mapped_column(String(120), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    industry: Mapped[str] = mapped_column(String(100), default="")
    # Email domains for the client's staff, pushed to each module's portal.
    portal_domains: Mapped[str] = mapped_column(String(500), default="")
    # Individual emails that get the executive (summary-only) portal view; the rest get technical.
    executive_emails: Mapped[str] = mapped_column(String(1000), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    modules: Mapped[list[ClientModule]] = relationship(back_populates="client", cascade="all, delete-orphan")
    tools: Mapped[list[ClientTool]] = relationship(back_populates="client", cascade="all, delete-orphan")

    def enabled_modules(self) -> set[str]:
        return {m.module_key for m in self.modules if m.enabled}

    def tool_map(self) -> dict[str, str]:
        return {t.tool_key: t.tenancy for t in self.tools if t.enabled and t.tenancy}


class Module(Base):
    """A platform module and how to reach it. status mirrors the registry
    (production | in-progress | planned); base_url and api_token are how the
    control plane talks to a running module."""

    __tablename__ = "modules"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(40), default="")
    status: Mapped[str] = mapped_column(String(20), default="planned")
    base_url: Mapped[str] = mapped_column(String(300), default="")
    # Encrypted at rest; plain in Python. Ciphertext is longer than the token, so the
    # column is widened to 512.
    api_token: Mapped[str] = mapped_column(EncryptedStr(512), default="")
    # Where a person opens the module (https://ir.example.com); base_url is the
    # service-to-service address (http://incident-response:8000 on the shared network).
    public_url: Mapped[str] = mapped_column(String(300), default="")
    has_portal: Mapped[bool] = mapped_column(Boolean, default=False)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def reachable(self) -> bool:
        return bool(self.base_url)


class ClientModule(Base):
    __tablename__ = "client_modules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    module_key: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    activated_by: Mapped[str] = mapped_column(String(320), default="")
    activated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="modules")

    __table_args__ = (Index("ix_client_modules_unique", "client_id", "module_key", unique=True),)


class ToolConnection(Base):
    """Registry of a tool integration at the platform level. The credential itself
    lives in the module that uses it (managed-services); this records that the tool
    exists, who provides it, and its last-known health as the module reports it."""

    __tablename__ = "tool_connections"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(30), default="")
    owner_module: Mapped[str] = mapped_column(String(40), default="managed-services")
    configured: Mapped[bool] = mapped_column(Boolean, default=False)  # module reports creds present
    detail: Mapped[str] = mapped_column(String(300), default="")
    checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ClientTool(Base):
    __tablename__ = "client_tools"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    tool_key: Mapped[str] = mapped_column(String(40))
    tenancy: Mapped[str] = mapped_column(String(300), default="")  # the client's slice in that tool
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="tools")

    __table_args__ = (Index("ix_client_tools_unique", "client_id", "tool_key", unique=True),)


class Staff(Base):
    """A Vendetta employee or contractor and their platform-wide access. The
    control plane is the system of record; modules pull the roster. Deactivating a
    person here (not deleting) locks them out everywhere and keeps the audit trail."""

    __tablename__ = "staff"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(120), default="")
    platform_role: Mapped[str] = mapped_column(String(20), default="analyst")  # admin | analyst
    profile: Mapped[str] = mapped_column(String(40), default="custom")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    invited_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deactivated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    grants: Mapped[list[StaffGrant]] = relationship(back_populates="person", cascade="all, delete-orphan")


class StaffGrant(Base):
    """One person's access level in one module: none, analyst or admin, plus
    module-specific capabilities in config (managed services: can_act, can_approve)."""

    __tablename__ = "staff_grants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    staff_id: Mapped[str] = mapped_column(ForeignKey("staff.id"), index=True)
    module_key: Mapped[str] = mapped_column(String(40))
    role: Mapped[str] = mapped_column(String(20), default="none")  # none | analyst | admin
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    person: Mapped[Staff] = relationship(back_populates="grants")

    __table_args__ = (Index("ix_staff_grants_unique", "staff_id", "module_key", unique=True),)


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
    """Microsoft 365 / Entra SSO configuration entered in-app. Single row ('default').
    The secret is encrypted at rest; the rest overlays the environment defaults so
    SSO can be wired and tested from the UI without a redeploy."""

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
    # Lightweight column migrations for tables created by an earlier schema version.
    # Check first so we only take the ALTER's table lock when the column is truly
    # missing; create_all already adds it on a fresh database.
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        have = conn.execute(_text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'clients' AND column_name = 'executive_emails'"
        )).first()
        if not have:
            conn.execute(_text("ALTER TABLE clients ADD COLUMN executive_emails VARCHAR(1000) DEFAULT ''"))
        # Widen modules.api_token to hold encrypted ciphertext (was VARCHAR(200)).
        # Check first so the ALTER only takes its table lock when the column is still
        # narrow, which avoids an in-suite startup lock.
        width = conn.execute(_text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name = 'modules' AND column_name = 'api_token'"
        )).scalar()
        if width is not None and width < 512:
            conn.execute(_text("ALTER TABLE modules ALTER COLUMN api_token TYPE VARCHAR(512)"))
        have = conn.execute(_text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'modules' AND column_name = 'public_url'"
        )).first()
        if not have:
            conn.execute(_text("ALTER TABLE modules ADD COLUMN public_url VARCHAR(300) DEFAULT ''"))
    from .registry import seed_registry

    from .directory import apply_env_directory

    db = SessionLocal()
    try:
        seed_registry(db)
        apply_env_directory(db)
    finally:
        db.close()


def get_client_module(db, client_id: str, module_key: str) -> ClientModule | None:
    return db.query(ClientModule).filter_by(client_id=client_id, module_key=module_key).one_or_none()
