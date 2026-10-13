"""Client-to-desk messaging: one running channel per client per desk (SOC, NOC,
helpdesk). A client's first helpdesk message opens a SuperOps ticket when SuperOps
is configured and the client is mapped, and every later message in that channel,
from either side, is mirrored into the ticket as a conversation. Mirroring is best
effort: a SuperOps failure never blocks the message itself."""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from . import connectors
from .connectors import ConnectorError
from .db import Channel, Client, Message, get_channel, utcnow

log = logging.getLogger(__name__)


def post(db: Session, client: Client, desk: str, sender_kind: str, sender: str, body: str) -> Message:
    """Append a message to the client's desk channel and handle unread counts and
    the SuperOps ticket binding. Caller validates desk and non-empty body."""
    ch = get_channel(db, client.id, desk)
    msg = Message(channel_id=ch.id, sender_kind=sender_kind, sender=sender, body=body.strip()[:8000])
    db.add(msg)
    ch.updated_at = utcnow()
    if sender_kind == "client":
        ch.tech_unread += 1
    elif sender_kind == "tech":
        ch.client_unread += 1
    db.commit()
    _mirror_to_superops(db, client, ch, msg)
    return msg


def _mirror_to_superops(db: Session, client: Client, ch: Channel, msg: Message) -> None:
    if ch.desk != "helpdesk" or not client.superops_client_id or msg.sender_kind == "system":
        return
    conn = connectors.get("superops")
    if not getattr(conn, "configured", False):
        return
    try:
        if not ch.superops_ticket_id:
            if msg.sender_kind != "client":
                return  # a ticket opens on the client's ask, not on a tech's outbound note
            t = conn.create_ticket(client.superops_client_id,
                                   subject=msg.body.splitlines()[0][:120],
                                   description=msg.body)
            ch.superops_ticket_id = t["ticket_id"]
            ch.superops_ticket_display = t["display_id"]
            db.add(Message(channel_id=ch.id, sender_kind="system", sender="helpdesk",
                           body=f"Opened helpdesk ticket {t['display_id'] or t['ticket_id']}."))
            db.commit()
        else:
            prefix = "Client" if msg.sender_kind == "client" else "Vendetta"
            conn.add_ticket_reply(ch.superops_ticket_id, f"[{prefix}: {msg.sender}] {msg.body}")
    except ConnectorError as e:
        log.warning("superops mirror failed for channel %s: %s", ch.id, e)
        db.rollback()


def mark_read(db: Session, ch: Channel, side: str) -> None:
    if side == "tech":
        ch.tech_unread = 0
    else:
        ch.client_unread = 0
    db.commit()
