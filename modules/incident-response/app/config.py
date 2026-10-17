"""IR Hub configuration. Values come from the environment (.env locally, SSM in AWS)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Incident Response"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://irhub:irhub@db:5432/irhub"

    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # A chat bridge (the Slack responder) gets its own token. It reaches the same
    # service API, and it is the only credential under which X-Vendetta-On-Behalf-Of
    # is honored: a module holding API_TOKEN can never put a person's name on the record.
    bridge_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Ed25519 private key (32 bytes, hex) that signs the case chain of custody. When
    # blank, a key is derived deterministically from secret_key so a deployment can
    # still verify its own chain; set a dedicated key in production so it can be
    # backed up and rotated independently of the session secret.
    evidence_signing_key: str = ""
    # Optional RFC 3161 Time-Stamp Authority for court-admissible evidence exports. When
    # set, a sealed case export anchors its manifest hash to this authority; when blank,
    # the export is still sealed and chain-verifiable, just without a third-party time
    # anchor.
    tsa_url: str = ""
    # Fernet key (urlsafe base64 of 32 bytes) encrypting stored secrets such as the
    # SSO client secret. Blank derives a key from secret_key; set a dedicated key in
    # production so it can be rotated independently.
    encryption_key: str = ""
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
    # Public URL of the control plane console, for links back to the client's platform page.
    platform_public_url: str = ""
    # Seconds between automatic roster pulls from the control plane (0 disables).
    provision_interval_seconds: int = 300
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
