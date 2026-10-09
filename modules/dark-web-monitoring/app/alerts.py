"""Alert routing. A hit fans out to SNS (email/SMS), a Teams incoming webhook, and
Jira Service Management (the IR desk). Each path is independent and optional."""
from __future__ import annotations

import base64
import logging

import httpx
from sqlalchemy.orm import Session

from .config import settings, severity_at_least
from .db import Hit, utcnow

log = logging.getLogger(__name__)


def _summary(hit: Hit) -> tuple[str, str]:
    item = hit.item
    client = hit.client
    term = hit.term.term if hit.term else ""
    label = {"iab": "INITIAL ACCESS BROKER candidate", "credential": "CREDENTIAL exposure"}.get(hit.reason, "hit")
    title = f"[{hit.severity.upper()}] Dark web {label} for {client.name}: {item.kind} ({item.group_name or 'n/a'})"
    body = (
        f"Client: {client.name}  Case/Contract: {client.case_ref or 'n/a'}\n"
        f"Severity: {hit.severity}  Reason: {hit.reason}\n"
        f"Watch term: {term}  Matched: {hit.matched_text}\n"
        f"Item kind: {item.kind}  Group/source: {item.group_name or 'n/a'}\n"
        f"Title: {item.title[:200]}\n"
        f"Published: {item.published_at}  Collected: {item.collected_at}\n"
        f"URL: {item.url}\n\n"
        f"Excerpt:\n{item.body[:1200]}\n"
    )
    return title, body


def _sns(title: str, body: str) -> str:
    import boto3

    r = boto3.client("sns", region_name=settings.aws_region).publish(
        TopicArn=settings.sns_topic_arn, Subject=title[:99], Message=body
    )
    return r.get("MessageId", "")


def _teams(title: str, body: str) -> str:
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title, "wrap": True},
                    {"type": "TextBlock", "text": body, "wrap": True, "fontType": "Monospace"},
                ],
            },
        }],
    }
    r = httpx.post(settings.teams_webhook_url, json=card, timeout=20)
    r.raise_for_status()
    return "sent"


def _jira(title: str, body: str, hit: Hit) -> str:
    auth = base64.b64encode(f"{settings.jira_email}:{settings.jira_api_token}".encode()).decode()
    payload = {
        "fields": {
            "project": {"key": settings.jira_project_key},
            "summary": title[:250],
            "issuetype": {"name": settings.jira_issue_type},
            "labels": ["darkweb", f"sev-{hit.severity}", hit.item.kind],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "codeBlock", "content": [{"type": "text", "text": body}]}],
            },
        }
    }
    r = httpx.post(
        f"{settings.jira_base_url.rstrip('/')}/rest/api/3/issue",
        json=payload,
        headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("key", "")


def dispatch(db: Session, hits: list[Hit]) -> None:
    for hit in hits:
        if not severity_at_least(hit.severity, settings.alert_min_severity):
            continue
        title, body = _summary(hit)
        refs: dict = {}
        if settings.sns_topic_arn:
            try:
                refs["sns"] = _sns(title, body)
            except Exception as e:  # noqa: BLE001
                log.error("sns failed: %s", e)
        if settings.teams_webhook_url:
            try:
                refs["teams"] = _teams(title, body)
            except Exception as e:  # noqa: BLE001
                log.error("teams failed: %s", e)
        if settings.jira_base_url and settings.jira_api_token and severity_at_least(hit.severity, settings.jira_min_severity):
            try:
                refs["jira"] = _jira(title, body, hit)
            except Exception as e:  # noqa: BLE001
                log.error("jira failed: %s", e)
        hit.alert_refs = refs
        hit.alerted_at = utcnow()
        db.add(hit)
    db.commit()
