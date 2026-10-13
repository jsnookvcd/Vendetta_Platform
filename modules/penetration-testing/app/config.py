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
    encryption_key: str = ""
    cookie_secure: bool = False
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
