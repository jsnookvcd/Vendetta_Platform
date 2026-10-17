"""Managed Detection and Response configuration. Values come from the environment.

MDR is the detection and investigation pipeline over the managed-services signals.
It pulls every alert managed-services has normalized from the client tools
(SentinelOne, CrowdStrike, Huntress, Acronis, SuperOps, Entra, AWS), runs them
through a rule set mapped to MITRE ATT&CK, and opens investigations that analysts
work to a verdict. Clients see investigations with verdicts and what Vendetta did,
never the raw alert stream.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Managed Detection and Response"
    module_enabled: bool = True
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://mdr:mdr@db:5432/mdr"
    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Ed25519 private key (32 bytes hex) that signs every investigation timeline.
    # Blank derives a stable key from secret_key; set a dedicated key in production.
    evidence_signing_key: str = ""
    encryption_key: str = ""
    cookie_secure: bool = False
    # This console's public base URL (https://<host>), used for links the platform and other modules follow.
    public_url: str = ""
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""

    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_client_id and self.entra_tenant_id)

    # IR hub (incident-response) for escalation. Blank runs standalone.
    platform_hub_url: str = ""
    platform_hub_token: str = ""
    # Control plane: client and staff roster pulls, and links back.
    platform_url: str = ""
    platform_token: str = ""
    platform_public_url: str = ""
    provision_interval_seconds: int = 300

    # Managed services: the signal source. MDR reads its findings over the service
    # API and links responders to its alert pages for containment; MDR never acts on
    # a host itself.
    managed_services_url: str = ""
    managed_services_token: str = ""
    managed_services_public_url: str = ""
    # Seconds between scheduled detection runs (0 disables the schedule; POST
    # /api/detect/run still works).
    detect_interval_seconds: int = 120
    # How far back a detection run looks when deciding whether to open an
    # investigation. Older signals are kept but never open anything on their own.
    detect_lookback_minutes: int = 1440
    # Default life of a suppression created from "This was noise".
    noise_suppression_days: int = 30

    # Optional RFC 3161 Time-Stamp Authority for evidence exports.
    tsa_url: str = ""


settings = Settings()

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 0, "medium": 1, "high": 2, "critical": 3}

# Signal sources, as managed-services names them in the finding's `reason` field.
TOOLS = ["sentinelone", "crowdstrike", "huntress", "acronis", "superops", "entra", "aws"]
TOOL_NAMES = {
    "sentinelone": "SentinelOne", "crowdstrike": "CrowdStrike", "huntress": "Huntress",
    "acronis": "Acronis", "superops": "SuperOps", "entra": "Entra ID", "aws": "AWS",
}
# Managed-services alert kinds, carried in the finding's `type` field.
SIGNAL_TYPES = ["threat", "detection", "incident", "backup", "rmm"]

# Investigation lifecycle and analyst verdicts.
STATUSES = ["new", "investigating", "contained", "closed"]
STATUS_NAMES = {"new": "New", "investigating": "Investigating", "contained": "Contained", "closed": "Closed"}
OPEN_STATUSES = ("new", "investigating", "contained")
VERDICTS = ["pending", "true_positive", "false_positive", "benign"]
VERDICT_NAMES = {"pending": "Pending", "true_positive": "True positive",
                 "false_positive": "False positive", "benign": "Benign"}

# Recommended responses. MDR records the recommendation and hands the responder to
# managed-services, where the action runs under that module's approval rules.
RESPONSES = ["none", "isolate_host", "disable_account", "block_indicator"]
RESPONSE_NAMES = {"none": "No action", "isolate_host": "Isolate host",
                  "disable_account": "Disable account", "block_indicator": "Block indicator"}

GROUP_BY = ["host", "client", "title"]

# The hub workstream every MDR escalation lands on.
WORKSTREAM = "Scoping and Containment"
