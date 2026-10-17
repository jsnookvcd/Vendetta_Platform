"""What the responder reports to the control plane's go-live screen: the shared
core every module reports, plus whether Slack is reachable, which transport is
live, whether the IR hub, SABINE and the staff roster are wired, and the feeds."""
from __future__ import annotations

from . import boot, feed, identity, reach, slack, socketmode
from .config import settings

MODULE = "slack"


def core() -> dict:
    d = reach.directory()
    return {
        "module": MODULE,
        "enabled": bool(settings.module_enabled),
        "keys": {"signing_applicable": False, "signing_dedicated": False,
                 "encryption_dedicated": bool((settings.encryption_key or "").strip())},
        # Responders sign in to Slack, not here; the console is the break-glass admin only.
        "sso": {"configured": False, "enabled": False, "verified": False, "source": "not applicable"},
        "hub_configured": "incident-response" in d,
        "hub_token_set": bool(d.get("incident-response", {}).get("token")),
        "platform": _platform(d),
        "posture": {
            "secret_placeholder": bool(boot.problems()),
            "cookie_secure": bool(settings.cookie_secure),
            "admin_login_possible": bool((settings.admin_password_hash or "").strip()),
            "api_token_dedicated": bool((settings.api_token or "").strip()),
            "public_url": settings.public_url or "",
            "actions_readonly": None,
        },
    }


def _platform(d: dict) -> dict:
    """The roster pull in the shape the go-live screen reads. The responder has no
    client roster; its "pull" is the staff roster it checks every Slack user against."""
    st = identity.roster_state().get("incident-response") or {}
    return {
        "configured": "platform" in d,
        "token_set": bool(d.get("platform", {}).get("token")),
        "last_ok": st.get("ok"),
        "last_at": st.get("at") or "",
        "last_detail": st.get("detail") or "",
        "staff": {"governs": st.get("governs"), "count": st.get("count", 0),
                  "last_ok": st.get("ok"), "last_detail": st.get("detail") or ""},
    }


def integrations() -> dict:
    return {
        "kind": "bridge",
        "slack": {
            "bot_token_set": slack.configured(),
            "workspace": slack.IDENTITY.get("team_id", ""),
            "auth_detail": slack.IDENTITY.get("detail", ""),
            "transport": "socket" if socketmode.enabled() else ("http" if settings.slack_signing_secret else "none"),
            "socket": {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in socketmode.STATE.items()},
            "signing_secret_set": bool((settings.slack_signing_secret or "").strip()),
        },
        "reach": sorted(reach.directory().keys()),
        "sabine_configured": "sabine" in reach.directory(),
        "feeds": {
            "ir_channel": bool(settings.slack_ir_channel),
            "sabine_channel": bool(settings.slack_sabine_channel),
            "last_ok": feed.LAST["ok"],
            "last_at": feed.LAST["at"].isoformat() if feed.LAST["at"] else None,
            "last_detail": feed.LAST["detail"],
        },
    }


def problems() -> list[str]:
    """Plain-language blockers for the console banner."""
    out = []
    if not slack.configured():
        out.append("SLACK_BOT_TOKEN is not set, so nothing reaches Slack.")
    elif slack.IDENTITY.get("detail") not in ("ok", "not checked"):
        out.append(f"Slack rejected the bot token: {slack.IDENTITY.get('detail')}.")
    if not socketmode.enabled() and not settings.slack_signing_secret:
        out.append("Neither SLACK_APP_TOKEN (Socket Mode) nor SLACK_SIGNING_SECRET (HTTP mode) is set, so Slack cannot reach the responder.")
    d = reach.directory()
    if "incident-response" not in d:
        out.append("The IR hub is not in MODULE_DIRECTORY.")
    if "platform" not in d:
        out.append("The control plane is not wired, so nobody can be matched to the staff roster and every command is refused.")
    return out


def block() -> dict:
    return {**core(), "integrations": integrations()}
