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
    cookie_secure: bool = False
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""

    # Microsoft 365 / Entra ID SSO (blank = admin login only). Staff only; the
    # control plane has no client portal (clients use each module's own portal).
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""

    # Seconds the cross-module overview caches each module probe before re-fetching.
    probe_cache_seconds: int = 45

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


settings = Settings()
