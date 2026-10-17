"""Paging the on-call channel. SNS (email/SMS) and a Teams webhook, each optional.

page(title, body, link) is the one delivery path. A declared or escalated case
pages through page_new_case; SABINE pages through POST /api/oncall/page when a
critical detection goes unacknowledged past the client's commitment."""
from __future__ import annotations

import logging

import httpx

from .config import settings
from .db import Case

log = logging.getLogger(__name__)


def configured() -> dict:
    return {"sns": bool(settings.sns_topic_arn), "teams": bool(settings.teams_webhook_url)}


def page(title: str, body: str, link: str = "", link_label: str = "Open") -> dict:
    """Deliver one page to every configured channel. Returns {channel: detail}
    for each channel that accepted it; empty when nothing is configured or every
    channel failed. Never raises."""
    title = (title or "").strip()[:240] or "Vendetta page"
    body = body or ""
    if link and link not in body:
        body = body.rstrip("\n") + f"\nOpen: {link}\n"
    sent: dict = {}
    if settings.sns_topic_arn:
        try:
            import boto3

            r = boto3.client("sns", region_name=settings.aws_region).publish(
                TopicArn=settings.sns_topic_arn, Subject=title[:99], Message=body)
            sent["sns"] = r.get("MessageId", "")
        except Exception as e:  # noqa: BLE001
            log.error("sns page failed: %s", e)
    if settings.teams_webhook_url:
        try:
            card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title, "wrap": True},
                         {"type": "TextBlock", "text": body, "wrap": True}]}}]}
            if link:
                card["attachments"][0]["content"]["actions"] = [{"type": "Action.OpenUrl", "title": link_label, "url": link}]
            httpx.post(settings.teams_webhook_url, json=card, timeout=20).raise_for_status()
            sent["teams"] = "sent"
        except Exception as e:  # noqa: BLE001
            log.error("teams page failed: %s", e)
    return sent


def page_new_case(case: Case) -> dict:
    title = f"[{case.severity.upper()}] {case.number} opened for {case.client.name}: {case.title}"[:240]
    body = (
        f"Case: {case.number}\nClient: {case.client.name}\nSeverity: {case.severity}\n"
        f"Origin: {case.origin}{(' from ' + case.source_module) if case.source_module else ''}\n"
        f"Lead: {case.lead or 'unassigned'}\nTitle: {case.title}\n"
    )
    link = f"{settings.public_url.rstrip('/')}/cases/{case.id}" if settings.public_url else ""
    return page(title, body, link, link_label="Open case")
