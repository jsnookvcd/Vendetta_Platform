"""Slack (Web API, bot token).

Two uses at kickoff, both optional:

- announce: a short kickoff notice in the internal delivery channel
  (SLACK_ANNOUNCE_CHANNEL), with links to everything the kickoff created.
- engagement channel: a private channel per engagement for clients and partners who
  work in Slack. Vendetta staff are invited by email; client contacts get a Slack
  Connect invitation, which they accept from their own workspace. Teams stays the
  internal system of record; this channel is for working with the client.

Bot scopes: chat:write, channels:manage, groups:write, users:read, users:read.email,
conversations.connect:write.
"""
from __future__ import annotations

import re

import httpx

from .config import settings

TRANSPORT: httpx.BaseTransport | None = None


class SlackError(Exception):
    pass


def configured() -> bool:
    return bool(settings.slack_bot_token)


def _call(method: str, payload: dict) -> dict:
    if not settings.slack_bot_token:
        raise SlackError("Slack is not connected (SLACK_BOT_TOKEN)")
    with httpx.Client(timeout=20.0, transport=TRANSPORT) as http:
        r = http.post(f"{settings.slack_api_url.rstrip('/')}/{method}", json=payload,
                      headers={"Authorization": f"Bearer {settings.slack_bot_token}"})
    if r.status_code != 200:
        raise SlackError(f"Slack {method} HTTP {r.status_code}")
    body = r.json()
    if not body.get("ok"):
        raise SlackError(f"Slack {method}: {body.get('error', 'failed')}")
    return body


def channel_name(code: str, client: str) -> str:
    base = f"eng-{code}-{client}".lower()
    return re.sub(r"[^a-z0-9_-]+", "-", base).strip("-")[:80]


def ensure_channel(refs: dict, *, code: str, client: str, purpose: str, staff: list[str],
                   client_contacts: list[str]) -> dict:
    if not refs.get("slack_channel_id"):
        name = channel_name(code, client)
        try:
            ch = _call("conversations.create", {"name": name, "is_private": True})["channel"]
        except SlackError as e:
            if "name_taken" not in str(e):
                raise
            ch = _find_own_channel(name)
            if ch is None:
                raise SlackError(f"A Slack channel named #{name} already exists and the bot is not in it; "
                                 "archive or rename it and retry")
        refs.update(slack_channel_id=ch["id"], slack_channel=f"#{name}")
        _call("conversations.setPurpose", {"channel": ch["id"], "purpose": purpose[:250]})
    invited = refs.setdefault("slack_invited", [])
    ids = []
    for email in staff:
        email = email.strip().lower()
        if not email or email in invited:
            continue
        try:
            ids.append(_call("users.lookupByEmail", {"email": email})["user"]["id"])
            invited.append(email)
        except SlackError:
            refs.setdefault("slack_not_found", []).append(email)
    if ids:
        _call("conversations.invite", {"channel": refs["slack_channel_id"], "users": ",".join(ids)})
    shared = refs.setdefault("slack_connect_invited", [])
    todo = [e.strip().lower() for e in client_contacts if e.strip() and e.strip().lower() not in shared]
    if todo:
        _call("conversations.inviteShared", {"channel": refs["slack_channel_id"], "emails": todo,
                                             "external_limited": True})
        shared.extend(todo)
    return refs


def _find_own_channel(name: str) -> dict | None:
    """A private channel the bot is in, by name (a retried kickoff created it already)."""
    cursor = ""
    for _ in range(20):
        body = _call("users.conversations", {"types": "private_channel", "limit": 200,
                                             **({"cursor": cursor} if cursor else {})})
        for ch in body.get("channels") or []:
            if ch.get("name") == name:
                return ch
        cursor = (body.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            return None
    return None


def announce(text: str, blocks: list[dict] | None = None) -> str:
    if not settings.slack_announce_channel:
        raise SlackError("SLACK_ANNOUNCE_CHANNEL is not set")
    body = _call("chat.postMessage", {"channel": settings.slack_announce_channel, "text": text,
                                      **({"blocks": blocks} if blocks else {}), "unfurl_links": False})
    return body.get("ts", "")
