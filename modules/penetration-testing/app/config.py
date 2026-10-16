"""Penetration Testing configuration. Values come from the environment."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Penetration Testing"
    module_enabled: bool = True
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://pentest:pentest@db:5432/pentest"
    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Ed25519 private key (32 bytes hex) that signs the finding-event chain of
    # custody. Blank derives a stable key from secret_key; set a dedicated key in
    # production so it can be backed up and rotated independently.
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

    platform_hub_url: str = ""
    platform_hub_token: str = ""
    platform_url: str = ""
    # Public URL of the control plane console, for links back to the client's platform page.
    platform_public_url: str = ""
    # Seconds between automatic roster pulls from the control plane (0 disables).
    provision_interval_seconds: int = 300
    platform_token: str = ""


settings = Settings()

ENGAGEMENT_TYPES = ["external", "internal", "web-app", "wireless", "social", "red-team", "physical"]
ENGAGEMENT_STATES = ["scoping", "active", "reporting", "closed"]

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
# A finding's lifecycle, including the retest loop. open/remediating/retest_pending
# are unresolved; the rest close it.
STATUSES = ["open", "remediating", "retest_pending", "retest_passed", "accepted", "false_positive"]
OPEN_STATUSES = {"open", "remediating", "retest_pending"}


def severity_rank(level: str) -> int:
    return SEVERITY_ORDER.get((level or "").lower(), 0)


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"
