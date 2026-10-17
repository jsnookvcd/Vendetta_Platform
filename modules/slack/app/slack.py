"""The Slack side: request signature verification and a small Web API client.

No Slack SDK. The responder calls a dozen Web API methods and verifies one HMAC;
httpx covers both, and tests inject a MockTransport the same way the rest of the
platform does.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time

import httpx

from .config import settings

log = logging.getLogger(__name__)
API = "https://slack.com/api/"
_TRANSPORT: httpx.BaseTransport | None = None  # tests inject a MockTransport here

# Read methods take form or query parameters; Slack only accepts JSON bodies on
# write methods.
_FORM_METHODS = {"auth.test", "users.info", "users.lookupByEmail", "conversations.history",
                 "conversations.replies", "conversations.info", "chat.getPermalink", "apps.connections.open"}


class SlackError(Exception):
    def __init__(self, method: str, error: str):
        super().__init__(f"{method}: {error}")
        self.method, self.error = method, error


def set_transport(t: httpx.BaseTransport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = t


def configured() -> bool:
    return bool((settings.slack_bot_token or "").strip())


def verify(headers, body: bytes, *, now: float | None = None) -> bool:
    """Slack's v0 request signature: HMAC-SHA256 over "v0:<timestamp>:<body>" with
    the signing secret, and a timestamp within five minutes so a captured request
    cannot be replayed later. Without a signing secret nothing over HTTP verifies."""
    secret = (settings.slack_signing_secret or "").strip()
    ts = headers.get("x-slack-request-timestamp", "")
    sig = headers.get("x-slack-signature", "")
    if not secret or not ts or not sig:
        return False
    try:
        if abs((now or time.time()) - int(ts)) > 300:
            return False
    except ValueError:
        return False
    base = b"v0:" + ts.encode() + b":" + body
    want = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


def call(method: str, *, token: str | None = None, **params) -> dict:
    """Call a Web API method and return the body. Raises SlackError when Slack
    answers ok=false or cannot be reached."""
    token = token if token is not None else settings.slack_bot_token
    headers = {"Authorization": f"Bearer {token}"}
    params = {k: v for k, v in params.items() if v is not None}
    try:
        with httpx.Client(timeout=10.0, transport=_TRANSPORT) as http:
            if method in _FORM_METHODS:
                r = http.post(API + method, headers=headers, data=params)
            else:
                r = http.post(API + method, headers={**headers, "Content-Type": "application/json; charset=utf-8"},
                              json=params)
    except httpx.HTTPError as e:
        raise SlackError(method, f"unreachable: {type(e).__name__}") from e
    if r.status_code == 429:
        raise SlackError(method, "ratelimited")
    try:
        data = r.json()
    except ValueError as e:
        raise SlackError(method, f"http {r.status_code}") from e
    if not data.get("ok"):
        raise SlackError(method, str(data.get("error") or "unknown_error"))
    return data


def try_call(method: str, **params) -> dict | None:
    """call() that logs and returns None instead of raising, for the steps where a
    failure should not stop the rest (a pin, a topic, an invite)."""
    try:
        return call(method, **params)
    except SlackError as e:
        log.warning("slack %s", e)
        return None


def respond(response_url: str, payload: dict) -> bool:
    """Reply through a response_url (slash commands and buttons). These URLs are
    Slack's own; anything else is refused so a forged payload cannot make the
    responder post somewhere else."""
    if not response_url.startswith("https://hooks.slack.com/"):
        log.warning("refusing a response_url outside hooks.slack.com")
        return False
    try:
        with httpx.Client(timeout=10.0, transport=_TRANSPORT) as http:
            r = http.post(response_url, json=payload)
        return r.status_code < 400
    except httpx.HTTPError as e:
        log.warning("response_url post failed: %s", type(e).__name__)
        return False


IDENTITY: dict = {"team_id": "", "bot_user_id": "", "checked": False, "detail": "not checked"}


def whoami() -> dict:
    """auth.test once: which workspace the bot token belongs to and the bot's own
    user id (so its own messages and reactions are ignored)."""
    if not configured():
        IDENTITY.update(checked=True, detail="SLACK_BOT_TOKEN not set")
        return IDENTITY
    try:
        d = call("auth.test")
        IDENTITY.update(team_id=d.get("team_id", ""), bot_user_id=d.get("user_id", ""), checked=True, detail="ok")
    except SlackError as e:
        IDENTITY.update(checked=True, detail=str(e))
    return IDENTITY


def allowed_team(team_id: str) -> bool:
    want = (settings.slack_team_id or IDENTITY.get("team_id") or "").strip()
    return not want or team_id == want
