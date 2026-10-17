"""Socket Mode: an outbound websocket to Slack, so the responder needs no public
endpoint and nothing new opens on the ALB. Slack delivers slash commands,
interactions and events as envelopes; each is acknowledged within three seconds
with the handler's immediate body.

Reconnects with backoff on any drop. Slack also asks clients to reconnect from
time to time with a "disconnect" envelope; that is a normal event.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time

from . import responder, slack
from .config import settings

log = logging.getLogger(__name__)
STATE: dict = {"enabled": False, "connected": False, "since": None, "detail": "not started", "envelopes": 0}


def enabled() -> bool:
    return bool((settings.slack_app_token or "").strip()) and slack.configured()


def dispatch(envelope: dict) -> dict | None:
    """One envelope in, the ack out (or None when the envelope needs none)."""
    kind = envelope.get("type")
    eid = envelope.get("envelope_id")
    payload = envelope.get("payload") or {}
    body = None
    try:
        if kind == "slash_commands":
            body = responder.handle_command(payload)
        elif kind == "interactive":
            body = responder.handle_interaction(payload)
        elif kind == "events_api":
            if not envelope.get("retry_attempt"):
                responder.handle_event(payload)
    except Exception:  # noqa: BLE001
        log.exception("socket mode %s handler failed", kind)
    if not eid:
        return None
    ack = {"envelope_id": eid}
    if body:
        ack["payload"] = body
    return ack


def _run_once() -> None:
    from websockets.sync.client import connect

    url = slack.call("apps.connections.open", token=settings.slack_app_token)["url"]
    with connect(url, open_timeout=15, close_timeout=5, max_size=8 * 1024 * 1024) as ws:
        STATE.update(connected=True, since=dt.datetime.now(dt.timezone.utc), detail="connected")
        for raw in ws:
            try:
                env = json.loads(raw)
            except ValueError:
                continue
            if env.get("type") == "hello":
                continue
            if env.get("type") == "disconnect":
                STATE.update(detail=f"Slack asked for a reconnect ({env.get('reason', '')})")
                return
            STATE["envelopes"] += 1
            ack = dispatch(env)
            if ack:
                ws.send(json.dumps(ack))


def start() -> None:
    if not enabled():
        STATE.update(enabled=False, detail="SLACK_APP_TOKEN not set; HTTP mode only")
        return
    STATE.update(enabled=True, detail="starting")

    def _loop():
        backoff = 1
        while True:
            try:
                _run_once()
                backoff = 1
            except Exception as e:  # noqa: BLE001
                STATE.update(detail=f"{type(e).__name__}: {e}"[:300])
                log.warning("socket mode dropped: %s", e)
                backoff = min(backoff * 2, 60)
            STATE["connected"] = False
            time.sleep(backoff)

    threading.Thread(target=_loop, name="slack-socket", daemon=True).start()
