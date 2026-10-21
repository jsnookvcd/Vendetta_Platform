"""Project Management configuration. Values come from the environment.

Project Management is the delivery-PM module for the Incident Response and
Professional Services practices: engagements, the practice Kanban boards, each
engagement's task board, meeting notes (stored here and mirrored to SharePoint),
and time entries written to Harvest. PMs drive it from the web board or from
Claude through the module's remote MCP server at /mcp.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Project Management"
    module_enabled: bool = True
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://pmtool:pmtool@db:5432/pmtool"
    secret_key: str = "change-me"
    api_token: str = ""
    allow_insecure_defaults: bool = False
    encryption_key: str = ""
    cookie_secure: bool = False
    # This console's public base URL (https://pm.<domain>). The MCP server and its
    # OAuth metadata advertise URLs built from it, so set it whenever the module is
    # reachable from Claude.
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

    platform_url: str = ""
    platform_public_url: str = ""
    # Where client-visible milestones are published: the IR hub (IR engagements,
    # matched to a case by number) and the Office of Special Projects (ProServ,
    # matched by its engagement id). Both set by the deployment.
    platform_hub_url: str = ""
    platform_hub_token: str = ""
    osp_url: str = ""
    osp_token: str = ""
    provision_interval_seconds: int = 300
    platform_token: str = ""

    # Harvest API v2. The token is an admin personal access token for the Vendetta
    # Harvest account, so a PM's entry is written as that PM (user_id) and an admin
    # can log for someone else. Can also be set in-app on the Integrations page.
    harvest_account_id: str = ""
    harvest_token: str = ""
    harvest_url: str = "https://api.harvestapp.com/v2"

    # SharePoint mirror for meeting notes (Microsoft Graph, app-only). Blank
    # GRAPH_* values fall back to the Entra SSO app registration, which then needs
    # the Sites.Selected (or Sites.ReadWrite.All) application permission.
    graph_tenant_id: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = ""
    # Default site and folder when an engagement has no case site of its own. The
    # note lands at <folder>/<engagement code>/Meeting Notes/<date> <title>.docx.
    sharepoint_site_url: str = ""
    sharepoint_folder: str = "Engagements"
    # Seconds between retries of notes whose SharePoint mirror failed (0 disables).
    sharepoint_retry_seconds: int = 600

    # Remote MCP server (Claude connector). Redirect URIs a dynamically registered
    # OAuth client may use; Claude's hosted callback and loopback for Claude Code.
    mcp_redirect_allowlist: str = (
        "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,"
        "http://localhost,http://127.0.0.1"
    )
    oauth_access_ttl_seconds: int = 3600
    oauth_refresh_ttl_days: int = 30


settings = Settings()

# The two practices this module runs delivery for.
PRACTICES = ["ir", "proserv"]
PRACTICE_NAMES = {"ir": "Incident Response", "proserv": "Professional Services"}

# Full-lifecycle columns per practice board, one per engagement phase. Seeded once;
# PMs rename, add, reorder and remove columns afterward.
PRACTICE_COLUMNS = {
    "ir": ["Intake", "Engaged", "Scoping and Containment", "Forensics and Analysis",
           "Recovery and Restoration", "Notification and Legal", "Reporting",
           "Closeout and Billing", "Closed"],
    "proserv": ["Intake", "Scoping", "SOW Out", "Scheduled", "In Delivery", "In Review",
                "Delivered", "Invoicing", "Closed"],
}
# Practice-board columns whose first entry records an engagement date for the
# portfolio metrics: entering the IR forensics phase means containment is done;
# entering closeout (IR) or Delivered (ProServ) means the report is in the client's hands.
COLUMN_MARKS = {
    "ir": {"Forensics and Analysis": "contained", "Closeout and Billing": "reported"},
    "proserv": {"Delivered": "reported"},
}

# Columns whose cards count as finished.
DONE_COLUMN_NAMES = {"Closed", "Done"}

# Every engagement gets its own task board with these columns.
TASK_COLUMNS = ["Backlog", "To Do", "In Progress", "Blocked", "In Review", "Done"]

# IR engagements carry the platform's five-workstream template as task labels, so a
# PM can filter a case's task board by workstream.
IR_WORKSTREAMS = ["Scoping and Containment", "Forensics and Analysis", "Recovery and Restoration",
                  "Notification and Legal", "Resilience and Hardening"]

ENGAGEMENT_STATES = ["active", "on_hold", "closed"]
ENGAGEMENT_STATE_NAMES = {"active": "Active", "on_hold": "On hold", "closed": "Closed"}
PRIORITIES = ["low", "normal", "high", "urgent"]

MILESTONE_STATUSES = ["planned", "in_progress", "at_risk", "done"]
CHANGE_REASONS = ["client_request", "scope_discovery", "new_systems", "schedule", "other"]

# Closeout items every engagement gets when no template supplies its own.
DEFAULT_CLOSEOUT = {
    "ir": ["Final report delivered", "Client acknowledged the report", "Evidence returned or destruction certified",
           "Vendetta access to client systems removed", "All time entered in Harvest", "Lessons learned recorded",
           "Invoice drafted"],
    "proserv": ["Deliverables accepted by the client", "Final report delivered", "Client satisfaction check done",
                "Vendetta access to client systems removed", "All time entered in Harvest", "Invoice drafted"],
}

# Alert thresholds. Each can be overridden with the matching environment variable.
class AlertSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_prefix="ALERT_")

    interval_seconds: int = 900          # how often alerts are recomputed (0 disables the loop)
    due_soon_hours: int = 48
    blocked_days: int = 3
    burn_warn_pct: float = 80.0
    burn_over_pct: float = 100.0
    end_soon_days: int = 7
    change_pending_days: int = 2
    digest_hour_local: int = 7           # daily digest hour (America/New_York); -1 disables
    teams_webhook_url: str = ""          # new high-severity alerts post here when set
    mail_from: str = ""                  # Graph sendMail sender mailbox for digests (needs Mail.Send)


alert_settings = AlertSettings()


# Project kickoff. One wizard stands an engagement up across every tool; these
# settings shape what it creates. Each can be set with the matching KICKOFF_ variable.
class KickoffSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_prefix="KICKOFF_")

    # Microsoft 365 group per engagement. IR keeps the existing case-site convention,
    # "Incident Response-<client or codename>".
    ir_group_prefix: str = "Incident Response-"
    proserv_group_prefix: str = "Professional Services-"
    group_owners: str = ""                 # emails made owners of every engagement group
    ir_always_members: str = ""            # emails added to every IR engagement team
    proserv_always_members: str = ""       # emails added to every ProServ engagement team
    # Folder tree created in each engagement site's document library ("/" nests).
    folders_ir: str = ("Evidence,Evidence/Client Uploads,Evidence/Collections,Analysis,Reports,"
                       "Correspondence,Meeting Notes")
    folders_proserv: str = "Contracts,Client Uploads,Working,Deliverables,Correspondence,Meeting Notes"
    # Harvest tasks assigned to each new project, by name (must exist in Harvest).
    harvest_tasks_ir: str = ("Incident Response,Forensic Analysis,Project Management,Reporting,"
                             "Internal (Non-billable)")
    harvest_tasks_proserv: str = "Consulting,Project Management,Reporting,Internal (Non-billable)"
    harvest_nonbillable_tasks: str = "Internal (Non-billable)"
    harvest_budget_alert_pct: int = 80
    # Vendetta Time (the Teams time-entry tab). Blank site skips the step.
    vtime_site_url: str = ""
    vtime_projects_list: str = "Projects"
    vtime_tabs_list: str = "TabContexts"
    # Teams app id of the published Vendetta Time Power App, and its tab content URL.
    # Blank skips adding the tab (the Projects and TabContexts rows are still written).
    vtime_teams_app_id: str = ""
    vtime_tab_content_url: str = ""
    # Draft the client kickoff email in the PM's mailbox (needs Graph Mail.ReadWrite).
    draft_client_email: bool = True
    # Steps that wait on Microsoft 365 (a new group's site and team take minutes).
    retry_seconds: int = 60                # 0 disables the background loop
    max_attempts: int = 30


kickoff_settings = KickoffSettings()

BILLING_TYPES = ["hourly", "fixed_fee", "retainer", "carrier_panel"]
BILLING_TYPE_NAMES = {"hourly": "Hourly", "fixed_fee": "Fixed fee", "retainer": "Retainer",
                      "carrier_panel": "Carrier panel"}
