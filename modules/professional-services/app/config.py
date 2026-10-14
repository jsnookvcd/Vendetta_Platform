"""Office of Special Projects configuration. Values come from the environment.

The Office of Special Projects (OSP) is Vendetta's professional-services delivery
module: vCISO retainers, implementation projects, tabletop exercises, assessments
and advisory, each run as an engagement with deliverables and a signed sign-off
chain of custody.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Office of Special Projects"
    module_enabled: bool = True
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://psvc:psvc@db:5432/psvc"
    secret_key: str = "change-me"
    # Ed25519 private key (32 bytes hex) that signs the deliverable sign-off chain of
    # custody. Blank derives a stable key from secret_key; set a dedicated key in
    # production so it can be backed up and rotated independently.
    evidence_signing_key: str = ""
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

    # Optional RFC 3161 Time-Stamp Authority for court-admissible evidence exports. When
    # set, a defensible export anchors its manifest hash to this authority; when blank,
    # the export is still sealed and chain-verifiable, just without a third-party time
    # anchor.
    tsa_url: str = ""


settings = Settings()

# Engagement types the Office of Special Projects delivers.
ENGAGEMENT_TYPES = ["vciso", "implementation", "tabletop", "assessment", "advisory"]
ENGAGEMENT_TYPE_NAMES = {
    "vciso": "vCISO",
    "implementation": "Implementation",
    "tabletop": "Tabletop Exercise",
    "assessment": "Assessment",
    "advisory": "Advisory",
}
# An engagement's lifecycle. scoping/active/on_hold are open; delivered/closed end it.
ENGAGEMENT_STATES = ["scoping", "active", "on_hold", "delivered", "closed"]
ENGAGEMENT_STATE_NAMES = {
    "scoping": "Scoping", "active": "Active", "on_hold": "On hold",
    "delivered": "Delivered", "closed": "Closed",
}
OPEN_STATES = {"scoping", "active", "on_hold"}

# A deliverable's kind and lifecycle.
DELIVERABLE_KINDS = ["document", "report", "playbook", "policy", "session", "milestone", "assessment"]
DELIVERABLE_KIND_NAMES = {
    "document": "Document", "report": "Report", "playbook": "Playbook", "policy": "Policy",
    "session": "Session", "milestone": "Milestone", "assessment": "Assessment",
}
# planned/in_progress/in_review are open; delivered awaits client acceptance; accepted closes it.
DELIVERABLE_STATUSES = ["planned", "in_progress", "in_review", "delivered", "accepted"]
DELIVERABLE_STATUS_NAMES = {
    "planned": "Planned", "in_progress": "In progress", "in_review": "In review",
    "delivered": "Delivered", "accepted": "Accepted",
}
OPEN_DELIVERABLE_STATUSES = {"planned", "in_progress", "in_review"}

# Billing cadence for a vCISO or ongoing retainer.
CADENCES = ["one-time", "monthly", "quarterly", "annual"]
CADENCE_NAMES = {"one-time": "One-time", "monthly": "Monthly", "quarterly": "Quarterly", "annual": "Annual"}
