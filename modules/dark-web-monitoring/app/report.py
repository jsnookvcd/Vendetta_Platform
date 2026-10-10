"""Per-client dark web exposure report.

Aggregates a client's findings over a period into a structured context for the
branded report template. This is the client-facing deliverable: an executive
summary, findings grouped by type, an evidence appendix with hashes, and
recommended actions. Credential material is already redacted at ingest, so the
report names the exposed accounts and sources without reproducing secrets.
"""
from __future__ import annotations

import base64
import datetime as dt
import re
from functools import lru_cache
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from .db import Client, Evidence, Hit

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATIC = Path(__file__).resolve().parent / "static"


@lru_cache(maxsize=1)
def logo_data_uri() -> str:
    for name in ("logo@512.png", "logo.png"):
        p = _STATIC / name
        if p.exists():
            return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode()
    return ""


def _domain_of(text: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", text or "")
    return m.group(1).lower() if m else ""


def build_report(db: Session, client: Client, days: int = 30) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(days=days)
    hits = db.execute(
        select(Hit).options(selectinload(Hit.item), selectinload(Hit.term))
        .where(Hit.client_id == client.id, Hit.created_at >= since, Hit.status != "false_positive")
        .order_by(desc(Hit.created_at))
    ).scalars().all()

    by_sev = {k: 0 for k in SEV_ORDER}
    for h in hits:
        by_sev[h.severity] = by_sev.get(h.severity, 0) + 1

    leak = [h for h in hits if h.item.kind in ("victim", "post", "page")]
    credential = [h for h in hits if h.reason == "credential"]
    iab = [h for h in hits if h.reason == "iab"]
    certs = [h for h in hits if h.item.kind == "cert"]
    mentions = [h for h in hits if h.reason == "term" and h.item.kind in ("message", "thread", "paste")]

    cred_domains = sorted({_domain_of(h.matched_text) or (h.term.term if h.term else "") for h in credential})
    cred_domains = [d for d in cred_domains if d]

    # Dedupe credential rows: one per distinct match, accounts (with @) shown before
    # bare-domain matches, so the report does not list the same exposure twice.
    seen_match: set[str] = set()
    cred_rows = []
    for h in sorted(credential, key=lambda x: (0 if "@" in x.matched_text else 1, x.matched_text)):
        key = h.matched_text.lower()
        if key in seen_match:
            continue
        seen_match.add(key)
        cred_rows.append(h)

    evidence = db.execute(
        select(Evidence).where(Evidence.client_id == client.id, Evidence.captured_at >= since)
        .order_by(desc(Evidence.captured_at))
    ).scalars().all()

    # Recommended actions are driven by what was actually found.
    actions: list[tuple[str, str]] = []
    if credential:
        actions.append((
            "Force password resets and revoke sessions for exposed accounts",
            "Infostealer and breach data indicate valid credentials for the accounts and domains listed. "
            "Reset those passwords, revoke active sessions and tokens, and confirm multi-factor authentication is enforced.",
        ))
    if any(h.severity in ("critical", "high") for h in iab):
        actions.append((
            "Treat the network as a likely access-for-sale target",
            "A broker posting matches this organization's profile. Hunt for unauthorized remote access (VPN, RDP, "
            "management tooling), review external exposure, and raise monitoring sensitivity.",
        ))
    if leak:
        actions.append((
            "Validate leak-site claims and preserve evidence",
            "Confirm whether the named data set is genuine, scope the affected systems, and preserve the posting "
            "before the group's mirror rotates. Vendetta has captured the pages noted in the evidence appendix.",
        ))
    if certs:
        actions.append((
            "Review certificate and lookalike-domain activity",
            "New certificates and lookalike domains can signal phishing infrastructure. Validate the legitimate "
            "certificates and consider takedown or blocking for the lookalikes.",
        ))
    if not actions:
        actions.append((
            "Maintain monitoring",
            "No actionable exposure surfaced in this period. Monitoring continues across leak sites, forums, "
            "credential sources and certificate transparency.",
        ))

    return {
        "client": client,
        "generated_at": now,
        "period_days": days,
        "period_start": since,
        "logo": logo_data_uri(),
        "total": len(hits),
        "by_sev": by_sev,
        "leak": leak,
        "credential": cred_rows,
        "credential_count": len(credential),
        "credential_domains": cred_domains,
        "iab": iab,
        "certs": certs,
        "mentions": mentions,
        "evidence": evidence,
        "actions": actions,
        "prepared_by": "Jordan Snook, Founder and CEO",
        "issuing_line": "Office of Special Projects",
    }
