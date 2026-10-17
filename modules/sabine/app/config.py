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

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


settings = Settings()
