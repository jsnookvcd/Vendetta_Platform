"""IR Hub configuration. Values come from the environment (.env locally, SSM in AWS)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Incident Response"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://irhub:irhub@db:5432/irhub"

    secret_key: str = "change-me"
    # Ed25519 private key (32 bytes, hex) that signs the case chain of custody. When
    # blank, a key is derived deterministically from secret_key so a deployment can
    # still verify its own chain; set a dedicated key in production so it can be
    # backed up and rotated independently of the session secret.
    evidence_signing_key: str = ""
    cookie_secure: bool = False
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""

    # Case numbering: firm-wide running sequence, not per client.
    case_year: int = 2026
    case_seq_start: int = 780  # the sequence is in the 700s as of 2026
    case_prefix: str = "VCD-IR"

    # Microsoft 365 / Entra ID SSO (shared pattern with the other modules).
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""

    # Alerting for new incidents.
    sns_topic_arn: str = ""
    teams_webhook_url: str = ""
    aws_region: str = "us-east-1"
    # Console base URL, e.g. https://ir.vendettacd.io. Used for case links in pages.
    public_url: str = ""

    # Platform hub self-reference (this module IS the hub). Kept for symmetry.
    platform_hub_url: str = ""
    platform_hub_token: str = ""

    # Vendetta Platform control plane: where this module pulls its client roster.
    platform_url: str = ""
    platform_token: str = ""

    # Modules the hub pulls findings from, as a JSON list of
    # [{"name": "...", "base_url": "https://...", "token": "..."}]. Empty means the
    # hub shows no cross-module findings (escalation still works regardless).
    findings_sources: str = ""
    findings_cache_seconds: int = 60

    def finding_source_list(self) -> list[dict]:
        import json

        raw = (self.findings_sources or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except ValueError:
            return []
        out = []
        for s in data if isinstance(data, list) else []:
            if s.get("name") and s.get("base_url"):
                out.append({"name": s["name"], "base_url": s["base_url"].rstrip("/"),
                            "token": s.get("token", "")})
        return out

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_client_id and self.entra_tenant_id)


settings = Settings()

WORKSTREAMS = [
    "Scoping and Containment",
    "Forensics and Analysis",
    "Recovery and Restoration",
    "Notification and Legal",
    "Resilience and Hardening",
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
