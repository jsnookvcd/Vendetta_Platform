"""Vendetta Platform control-plane settings.

The control plane is the front door and the system of record for clients, for
which modules are turned on per client, and for how each client maps into the
tools. It holds no vendor secrets: the actual tool credentials live with the
module that uses them (managed-services). The control plane holds the client
roster, the per-client enablement, and the per-client tool tenancy mapping, and
it reaches each module over HTTP using a per-module bearer token stored in the
database."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict

# Tools a client can have activated. The mapping value is the client's tenancy in
# that tool (what managed-services needs to address the client's slice).
TOOLS = ["superops", "sentinelone", "crowdstrike", "huntress", "acronis"]
TOOL_NAMES = {
    "superops": "SuperOps RMM",
    "sentinelone": "SentinelOne",
    "crowdstrike": "CrowdStrike Falcon",
    "huntress": "Huntress MDR",
    "acronis": "Acronis Backup",
}
TOOL_HINTS = {
    "superops": "client accountId",
    "sentinelone": "site IDs, comma separated",
    "crowdstrike": "child CID",
    "huntress": "organization ID",
    "acronis": "customer tenant UUID",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Platform"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://platform:platform@db:5432/platform"
    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Fernet key (urlsafe base64 of 32 bytes) encrypting stored secrets at rest, such
    # as per-module bearer tokens. Blank derives a key from secret_key; set a
    # dedicated key in production so it can be rotated independently.
    encryption_key: str = ""
    cookie_secure: bool = False
    # This console's public base URL (https://<host>), used for links the platform and other modules follow.
    public_url: str = ""
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""

    # Microsoft 365 / Entra ID SSO (blank = admin login only). Staff sign in by
    # roster; client users sign in to the control plane's /portal, mapped to one
    # client by the portal domains on that client.
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""

    # Module directory rendered by the deployment: JSON of
    # {"<module key>": {"base_url": "http://<key>:8000", "token": "...", "public_url": "https://..."}}.
    # Applied at startup to any module row that has no base URL yet, and on demand
    # from the Connections page, so a fresh host wires itself with no hand entry.
    module_directory: str = ""
    # This console's public URL, handed to modules so they can link back here.
    public_url: str = ""

    # Seconds the cross-module overview caches each module probe before re-fetching.
    probe_cache_seconds: int = 45
    # Client 360: seconds each live module read is cached per client, and the
    # per-request timeout. A module slower than the timeout shows as unreachable.
    client360_cache_seconds: int = 30
    client360_timeout_seconds: float = 5.0

    # The onboarding note (app/notify.py). Blank SMTP_HOST logs the note instead of
    # sending it; onboarding never fails on mail. SMTP_FROM is the sender address,
    # shown as "SABINE at Vendetta Cyber <address>".
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    # The voice the note signs off in, the same value SABINE reads: "sabine" or "plain".
    persona: str = "sabine"

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


settings = Settings()
