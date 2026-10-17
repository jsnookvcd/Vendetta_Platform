"""Runtime configuration. Every value comes from the environment (.env in dev,
SSM Parameter Store rendered to /opt/darkweb/.env in AWS)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core
    app_name: str = "Vendetta Dark Web Monitoring"
    # Platform on/off for this module. When false the console shows a disabled
    # notice, the API reports enabled:false, and the collector idles. The hub
    # flips this to turn the capability on or off.
    module_enabled: bool = True
    # Email domains treated as internal Vendetta staff (full console access).
    internal_email_domains: str = "vendettacd.io"
    # Optional comma-separated emails granted the admin role.
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://darkweb:darkweb@db:5432/darkweb"
    secret_key: str = "change-me"
    # Bearer token other modules and the control plane present to this module's
    # service API. Set by the deployment (Terraform generates one per module); when
    # blank the token is derived from secret_key for backward compatibility.
    api_token: str = ""
    # Refuse to start on placeholder secrets. Only a local developer should set this
    # true; the deployed stack never does.
    allow_insecure_defaults: bool = False
    # Fernet key (urlsafe base64 of 32 bytes) encrypting stored secrets such as the
    # SSO client secret. Blank derives a key from secret_key; set a dedicated key in
    # production so it can be rotated independently.
    encryption_key: str = ""
    cookie_secure: bool = False
    # This console's public base URL (https://<host>), used for links the platform and other modules follow.
    public_url: str = ""  # set true once the console is served over TLS
    login_max_attempts: int = 8  # per IP per window before a temporary lockout
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""  # bcrypt hash; scripts/make_password_hash.py

    # Microsoft 365 / Entra ID single sign-on (OIDC authorization code flow).
    # Off until entra_client_id is set; the local admin login stays as break-glass.
    entra_tenant_id: str = ""      # directory (tenant) ID, restricts who can sign in
    entra_client_id: str = ""      # application (client) ID of the app registration
    entra_client_secret: str = ""  # client secret value
    entra_redirect_url: str = ""   # e.g. https://darkweb.vendettacd.io/auth/callback
    entra_allowed_group: str = ""  # optional group object ID required in the token
    entra_allowed_emails: str = "" # optional comma-separated allowlist of UPNs/emails

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_client_id and self.entra_tenant_id)
    tor_proxy: str = "socks5://tor:9050"
    request_timeout: int = 60
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
    )

    # Collection cadence (minutes)
    leak_feed_interval: int = 30
    onion_crawl_interval: int = 120
    forum_crawl_interval: int = 180
    hibp_interval: int = 360
    ct_interval: int = 360
    paste_interval: int = 60
    telegram_interval: int = 15

    # Evidence
    evidence_bucket: str = ""  # S3 bucket; empty disables S3 and keeps local copies
    evidence_local_dir: str = "/data/evidence"
    aws_region: str = "us-east-1"

    # External APIs (all optional)
    hibp_api_key: str = ""
    ransomware_live_api_key: str = ""  # free PRO key from my.ransomware.live; required for business use
    ransomware_live_api_header: str = "X-API-KEY"
    ransomware_live_base: str = ""  # override; defaults to api-pro with a key, public v2 without
    telegram_api_id: str = ""
    telegram_api_hash: str = ""
    telegram_channels: str = ""  # comma separated public channel usernames

    # Alerting
    alert_min_severity: str = "medium"  # low|medium|high|critical
    sns_topic_arn: str = ""
    teams_webhook_url: str = ""
    jira_base_url: str = ""  # off unless set; https://vendettacyber.atlassian.net when the IR desk is live
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "IR"
    jira_issue_type: str = "Task"
    jira_min_severity: str = "high"  # only open tickets at or above this level

    # Vendetta Platform integration. Off until the hub URL is set, so the module
    # runs standalone today and posts escalations to the engagement hub when live.
    platform_hub_url: str = ""
    platform_hub_token: str = ""

    # Vendetta Platform control plane: where this module pulls its client roster.
    platform_url: str = ""
    # Public URL of the control plane console, for links back to the client's platform page.
    platform_public_url: str = ""
    # Seconds between automatic roster pulls from the control plane (0 disables).
    provision_interval_seconds: int = 300
    platform_token: str = ""

    # ------------------------------------------------------------ Phase 4: optional connectors
    # Telegram session created once by scripts/telegram_login.py; the collector stays
    # off until this file exists.
    telegram_session_path: str = "/data/telegram.session"
    # Paste collection is off by default: psbdmp.ws could not be verified as a
    # working free API (see app/collectors/pastes.py). PASTE_SOURCE picks the
    # implementation in pastes.SOURCES once a working one is available.
    pastes_enabled: bool = False
    paste_source: str = "psbdmp"


settings = Settings()

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_at_least(level: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(level, 0) >= SEVERITY_ORDER.get(floor, 0)
