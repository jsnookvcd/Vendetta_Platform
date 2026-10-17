"""Slack responder settings.

The Slack responder puts the tactical half of incident response where responders
already are. It holds no case data of its own: every case, note, status change and
card lives in the IR hub, on the hub's signed chain, and every proposal lives with
SABINE. This module keeps only the mapping from Slack channels to cases, the
markers that stop it announcing the same thing twice, and its own audit log.

Who may do what comes from the platform staff roster: a Slack user's email must
hold an incident-response grant to touch a case (analyst or admin to change one,
viewer to read), and a SABINE grant to ask her anything or decide a proposal.
Nobody outside the roster can use the bot, whatever Slack workspace they are in."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Slack Responder"
    module_enabled: bool = True
    database_url: str = "postgresql+psycopg://slack:slack@db:5432/slack"
    secret_key: str = "change-me"
    api_token: str = ""
    allow_insecure_defaults: bool = False
    # Rendered for every module by the deployment. The responder stores no secrets of
    # its own today; the key is reported so the go-live screen grades it like the rest.
    encryption_key: str = ""
    cookie_secure: bool = False
    admin_user: str = "admin"
    admin_password_hash: str = ""
    public_url: str = ""
    login_max_attempts: int = 8
    login_window_seconds: int = 300

    # ------------------------------------------------------------ Slack app
    # Bot token (xoxb-) for the Web API. Always required.
    slack_bot_token: str = ""
    # Socket Mode: an app-level token (xapp-) with connections:write. When set, the
    # module opens an outbound websocket to Slack and needs no public endpoint; this
    # is the default and the recommended mode.
    slack_app_token: str = ""
    # HTTP mode: Slack posts to /slack/commands, /slack/interactions and
    # /slack/events on PUBLIC_URL, verified with the signing secret. Needed only
    # when Socket Mode is not used; the signing secret is checked in both modes
    # whenever a request arrives over HTTP.
    slack_signing_secret: str = ""
    # Refuse requests from any workspace but this one (T0123...). Blank accepts the
    # workspace the bot token belongs to, learned at startup from auth.test.
    slack_team_id: str = ""
    # The slash command the app registers. Change it here and in the app manifest
    # together if /ir collides with something in the workspace.
    slack_command: str = "/ir"

    # Where announcements go, by channel id (C0123...). Blank turns that feed off.
    slack_ir_channel: str = ""       # new cases, from anywhere: escalations, portal, console, Slack
    slack_sabine_channel: str = ""   # SABINE proposals waiting on a person

    # War rooms: one channel per case, named <prefix>-<case number>.
    warroom_prefix: str = "ir"
    warroom_private: bool = True
    # Always invited to a new war room: Slack user ids or work emails, comma separated
    # (the IR leadership, the on-call alias).
    warroom_invite: str = ""
    # The reaction that logs a message to the case timeline.
    memo_reaction: str = "memo"

    # How often the announcement feeds look for new cases and proposals. 0 turns off.
    poll_interval_seconds: int = 30

    # ------------------------------------------------------------ platform reach
    # The control plane: the staff roster that decides who in Slack may act.
    platform_url: str = ""
    platform_token: str = ""
    platform_public_url: str = ""
    # Every module the responder calls, as JSON {"<key>": {"base_url", "token",
    # "public_url"}}: incident-response and sabine (and platform, optional). It
    # presents each module's own token, names itself in X-Vendetta-Actor and names
    # the person it acts for in X-Vendetta-On-Behalf-Of.
    module_directory: str = ""
    actor_name: str = "slack"
    # Work emails from Slack must sit in one of these domains, on top of the roster.
    internal_email_domains: str = "vendettacd.io"


settings = Settings()
