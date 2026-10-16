"""Managed Services module settings. Everything comes from the environment (SSM in
production). Tool credentials are tenant-level: one SuperOps token, one SentinelOne
API token, one CrowdStrike parent (Flight Control) client, one Huntress key, one
Acronis partner client. Which client each tool record belongs to is mapped per
client in the console, not here."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict

WORKSTREAMS = [
    "Scoping and Containment",
    "Forensics and Analysis",
    "Recovery and Restoration",
    "Notification and Legal",
    "Resilience and Hardening",
]

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Service-level targets in minutes, as (acknowledge, contain) per severity. A profile
# is assigned per client so a premium account can carry tighter commitments and a
# client still in onboarding can run with no SLA clock. None means no target for that
# phase at that severity (an info finding has no contain clock, for example).
SLA_PROFILES: dict[str, dict[str, tuple[int | None, int | None]]] = {
    "standard": {
        "critical": (15, 60),
        "high": (30, 240),
        "medium": (120, 1440),
        "low": (480, None),
        "info": (None, None),
    },
    "priority": {
        "critical": (10, 30),
        "high": (20, 120),
        "medium": (60, 480),
        "low": (240, None),
        "info": (None, None),
    },
    "monitor": {s: (None, None) for s in SEVERITIES},  # onboarding/validation: no clock
}
SLA_PROFILE_NAMES = {
    "standard": "Standard",
    "priority": "Priority",
    "monitor": "Monitoring only",
}
DEFAULT_SLA_PROFILE = "standard"

TOOLS = ["superops", "sentinelone", "crowdstrike", "huntress", "acronis"]
TOOL_NAMES = {
    "superops": "SuperOps RMM",
    "sentinelone": "SentinelOne",
    "crowdstrike": "CrowdStrike Falcon",
    "huntress": "Huntress MDR",
    "acronis": "Acronis Backup",
}
DESKS = ["soc", "noc", "helpdesk"]
DESK_NAMES = {"soc": "SOC", "noc": "NOC", "helpdesk": "Helpdesk"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Managed Services"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://msp:msp@db:5432/msp"
    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Ed25519 private key (32 bytes, hex) that signs the per-client action chain of
    # custody. Blank derives a stable key from secret_key; set a dedicated key in
    # production so it can be backed up and rotated independently.
    evidence_signing_key: str = ""
    # Fernet key (urlsafe base64 of 32 bytes) encrypting tool credentials stored in
    # the database. Blank derives a key from secret_key; set a dedicated key in
    # production so it can be rotated independently.
    encryption_key: str = ""
    cookie_secure: bool = False
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""
    public_url: str = ""

    # Microsoft 365 / Entra ID SSO (blank = admin login only)
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""

    # SuperOps PSA/RMM: API token from My Profile, subdomain from Settings > My MSP
    superops_api_url: str = "https://api.superops.ai/msp"
    superops_api_token: str = ""
    superops_subdomain: str = ""
    superops_base_url: str = ""  # web console, e.g. https://vendetta.superops.ai
    superops_default_techgroup_id: str = ""  # tech group for portal-raised tickets

    # SentinelOne: API token of a service user scoped to the MSP account
    sentinelone_url: str = ""  # e.g. https://usea1-partners.sentinelone.net
    sentinelone_api_token: str = ""

    # CrowdStrike Falcon: MSSP parent (Flight Control) API client
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_console_url: str = "https://falcon.crowdstrike.com"

    # Huntress: user-based API key and secret (account keys are read-only)
    huntress_api_key: str = ""
    huntress_api_secret: str = ""
    huntress_base_url: str = ""  # portal, e.g. https://vendetta.huntress.io

    # Acronis Cyber Protect Cloud: partner-tenant API client on your data center
    acronis_dc_url: str = ""  # e.g. https://us5-cloud.acronis.com
    acronis_client_id: str = ""
    acronis_client_secret: str = ""

    # Safety: when true, every action that writes to a tool (isolate, contain,
    # quarantine, kill, approve remediations, run backup, resolve at source, raise
    # a ticket) is refused. Module-local triage (acknowledge, publish) still works.
    # On by default so a fresh deployment cannot touch a client host until an operator
    # turns actions on deliberately (ACTIONS_READONLY=false). Use it to bring a new client in and watch data flow without touching a
    # single host; turn it off once the integration is validated.
    actions_readonly: bool = True
    # Strict two-person control: when true, a destructive action's approver must be a
    # different internal user (no self-approval). Off by default so a lone on-call
    # responder can still act, with the self-approval recorded in the signed log.
    require_second_approver: bool = False

    # Pre-incident posture thresholds. An endpoint is "dark" once it has gone this
    # many days without reporting; telemetry from a tool is stale once its newest
    # device sync is older than this many hours; a host left isolated longer than
    # this many hours is flagged for review.
    posture_stale_endpoint_days: int = 7
    posture_stale_sync_hours: int = 12
    posture_isolation_review_hours: int = 24

    # Sync and escalation
    sync_interval_seconds: int = 300
    platform_hub_url: str = ""
    platform_hub_token: str = ""

    # Vendetta Platform control plane: where this module pulls its client roster and
    # per-client tool mapping. Blank = clients are managed in this console directly.
    platform_url: str = ""
    # Public URL of the control plane console, for links back to the client's platform page.
    platform_public_url: str = ""
    # Seconds between automatic roster pulls from the control plane (0 disables).
    provision_interval_seconds: int = 300
    platform_token: str = ""

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


settings = Settings()
