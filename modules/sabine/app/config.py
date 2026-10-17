"""SABINE settings. SABINE (Monitoring, Analysis, Response, Lifecycle and Operations
Workflow) is the agentic brain over the Vendetta Platform: it watches every module
through the same service APIs an operator would use, reasons about what needs
doing across administration, the SOC and professional services, proposes actions
with a written rationale, carries out the ones its policy allows, and records all
of it in a signed chain.

It holds no client data of its own beyond what it observes, and it can do nothing a
module's API does not allow. Its reach is set by MODULE_DIRECTORY (which modules it
can see and the tokens it presents) and by the autonomy policy per action kind."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SABINE"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://sabine:sabine@db:5432/sabine"
    secret_key: str = "change-me"
    api_token: str = ""
    allow_insecure_defaults: bool = False
    # Ed25519 seed (32 bytes hex) signing SABINE's own chain of observations,
    # proposals, decisions and actions. Blank derives from secret_key with a warning.
    evidence_signing_key: str = ""
    encryption_key: str = ""
    cookie_secure: bool = False
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""
    public_url: str = ""

    # Microsoft 365 / Entra ID SSO for SABINE's own console (staff only).
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""

    # The control plane: staff roster for console access, the client directory,
    # the module directory and the readiness report.
    platform_url: str = ""
    platform_token: str = ""
    platform_public_url: str = ""
    provision_interval_seconds: int = 300

    # Every module SABINE may reach, as JSON {"<key>": {"base_url", "token", "public_url"}}.
    # Rendered by the deployment; includes the platform and the IR hub. SABINE
    # presents each module's own token and names itself in X-Vendetta-Actor, so a
    # module's audit log shows "api:sabine" for anything it did.
    module_directory: str = ""
    actor_name: str = "sabine"

    # How often SABINE runs a full cycle (perceive, reason, act). 0 disables the
    # scheduler (the cycle can still be run from the console or /api/run).
    cycle_interval_seconds: int = 120
    # A proposal SABINE made that nobody decided within this window is re-raised,
    # never silently executed.
    proposal_ttl_hours: int = 72

    # Optional language-model backend for narrative (rationales, client briefs,
    # answers to questions). Never decides anything: it writes about facts the rules
    # produced. Blank means templated text only.
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-5"
    # How SABINE sounds to Vendetta's own people (the Ask page, the daily summary,
    # the console). "sabine": she is warm, confident, quick, with a dry wit, and she
    # talks to the team like a trusted colleague who has already read everything.
    # "plain": neutral and flat. Client-facing briefs are always professional,
    # whatever the voice.
    persona: str = "sabine"

    # The board: a read-only, full-screen view for a wall display in the SOC. A kiosk
    # token in the URL once (/board?k=...) sets a long-lived cookie so the screen
    # never asks for a password. Blank disables the board.
    kiosk_token: str = ""
    board_refresh_seconds: int = 30

    # Spoken voice. "browser" uses the viewer's own speech synthesis (no key, no
    # audio leaves the server); "elevenlabs" and "azure" render audio server-side in a
    # chosen voice and cache it. Listening (push to talk) always runs in the browser.
    tts_provider: str = "browser"
    elevenlabs_api_key: str = ""
    elevenlabs_voice_id: str = ""
    elevenlabs_model: str = "eleven_multilingual_v2"
    azure_speech_key: str = ""
    azure_speech_region: str = ""
    # Jane (Dragon HD): rich, warm, friendly, the one you want in the room at 2 a.m.
    # Alternate if the region lacks HD voices: en-US-Ava:DragonHDLatestNeural or
    # en-US-AvaMultilingualNeural.
    azure_speech_voice: str = "en-US-Jane:DragonHDLatestNeural"

    # Thresholds the rules use.
    escalate_after_minutes: int = 30       # a critical/high finding left unescalated this long
    stale_case_days: int = 5               # an open IR case with no update this long
    stale_engagement_days: int = 30        # a pentest engagement open this long with no findings
    remediation_sla_days: dict = {"critical": 7, "high": 30, "medium": 90, "low": 180}
    acceptance_nudge_days: int = 7         # an OSP deliverable delivered and not yet accepted this long
    # The client brief's "What SABINE did on your account" section lists actions
    # carried out for that client inside this many days.
    client_brief_window_days: int = 7
    # A module's triage copilot verdict (the finding's "copilot" sub-object) at or above
    # these confidences: a false positive is queued for confirmation instead of being
    # escalated; a true positive raises the escalation proposal's confidence.
    copilot_fp_confidence: float = 0.9
    copilot_tp_confidence: float = 0.85

    # Concierge: response commitments, the Security Journey and client communications.
    # A critical MDR investigation or managed-services critical left unacknowledged past
    # the client's commitments.critical_ack_minutes pages the IR on-call path; this is the
    # fallback when the platform gives the client no commitments.
    critical_ack_minutes: int = 15
    critical_contain_minutes: int = 240
    page_repeat_minutes: int = 60          # never page twice for one detection inside this
    # An outreach draft is raised when an open critical investigation has used this share
    # of the containment commitment.
    commitment_risk_pct: int = 75
    # The posture review is drafted once a month per active client, from this day on.
    posture_review_day: int = 1
    # A finding pattern seen this many times at once for one client becomes a journey item.
    journey_recurring_min: int = 3
    # The same high or critical finding pattern active at this many clients is a campaign.
    campaign_min_clients: int = 2
    # An OSP deliverable unaccepted this long gets a client outreach draft (the internal
    # nudge to the lead comes first, at acceptance_nudge_days).
    outreach_acceptance_days: int = 14
    # Decision memory: people rejecting or closing as false positive the same MDR pattern
    # for one client this many times makes SABINE propose a suppression for that many days.
    suppression_suggest_after: int = 3
    suppression_days: int = 30
    memory_reject_step: float = 0.1
    memory_approve_step: float = 0.05

    # Running the business: Harvest (time, budgets, capacity) and HubSpot (deals). Each
    # is optional; without credentials the source is skipped and readiness says so.
    harvest_account_id: str = ""
    harvest_token: str = ""
    harvest_url: str = "https://api.harvestapp.com/v2"
    hubspot_token: str = ""
    hubspot_url: str = "https://api.hubapi.com"
    hubspot_renewal_pipeline: str = ""     # a pipeline id holding renewals; dealtype=renewal always counts
    budget_burn_pct: int = 80
    capacity_pct: int = 110
    renewal_days: int = 60
    won_lookback_days: int = 30
    won_onboard_days: int = 3              # a closed-won deal not on the platform after this many days

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


settings = Settings()
