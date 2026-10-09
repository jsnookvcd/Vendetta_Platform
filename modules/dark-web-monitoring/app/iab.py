"""Initial access broker (IAB) detection.

Brokers selling access to a compromised network almost never name the victim.
They post an anonymized profile: sector, country, revenue, host count and the
kind of access ("US credit union, revenue $420M, 1200 hosts, VPN + domain admin,
start $25k"). So this does not match on the client's name. It matches the client's
business profile against forum posts and flags likely candidates for an analyst to
confirm. It is deliberately recall-oriented and every hit is a lead, not a finding.

Scoring: industry match is required to raise a hit at all. Country, state, revenue
band and employee/host band each add confidence. An access-for-sale signal in the
post is required so ordinary chatter about a sector does not fire."""
from __future__ import annotations

import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Client, Hit, Item

log = logging.getLogger(__name__)

# Industry synonyms so "credit union" also catches "FCU", "CU", "financial institution".
INDUSTRY_SYNONYMS = {
    "credit union": ["credit union", "fcu", "ccu", r"\bcu\b", "financial institution", "financial services"],
    "bank": ["bank", "banking", "financial institution", "financial services"],
    "healthcare": ["healthcare", "health care", "hospital", "clinic", "medical", "health system"],
    "manufacturing": ["manufacturing", "manufacturer", "industrial", "factory"],
    "legal": ["law firm", "legal", "attorney", "counsel"],
    "education": ["school", "university", "college", "education", "academic", "k-12"],
    "government": ["government", "municipal", "city of", "county", "gov", "public sector"],
    "insurance": ["insurance", "insurer", "underwriter"],
    "retail": ["retail", "retailer", "ecommerce", "e-commerce"],
    "technology": ["technology", "software", "saas", "msp", "it services"],
}

ACCESS_SIGNALS = [
    "access", "rdp", "vpn", "domain admin", "da access", "citrix", "vcenter", "esxi",
    "webshell", "shell", "foothold", "privileged", "for sale", "selling", "auction",
    "start price", "blitz", "step", "corp network", "corporate network", "fortinet", "fortigate",
]

MONEY = re.compile(r"\$?\s?(\d{1,4})\s?(k|m|mil|million|b|bn|billion)\b", re.I)
HOSTS = re.compile(r"(\d{2,6})\s*(hosts?|machines?|endpoints?|pcs?|employees?|users?|staff|workstations?)", re.I)


def _industry_terms(industry: str) -> list[str]:
    key = (industry or "").strip().lower()
    return INDUSTRY_SYNONYMS.get(key, [re.escape(key)] if key else [])


def _revenue_musd(text: str) -> list[float]:
    out = []
    for num, unit in MONEY.findall(text):
        n = float(num)
        u = unit.lower()
        if u.startswith("b"):
            out.append(n * 1000)
        elif u.startswith("m"):
            out.append(n)
        # 'k' amounts are almost always the asking price, not revenue; ignore for revenue.
    return out


def match_iab(db: Session, item: Item) -> list[Hit]:
    """Only forum-style items carry broker ads."""
    if item.kind not in ("message", "thread", "post", "page"):
        return []
    text = f"{item.title}\n{item.body}".lower()
    if not any(sig in text for sig in ACCESS_SIGNALS):
        return []
    clients = db.execute(select(Client).where(Client.active.is_(True), Client.industry != "")).scalars().all()
    created: list[Hit] = []
    for c in clients:
        ind_terms = _industry_terms(c.industry)
        if not ind_terms or not any(re.search(t, text) for t in ind_terms):
            continue
        score = 1
        reasons = [f"industry~{c.industry}"]
        if c.country and c.country.lower() in text:
            score += 1
            reasons.append(f"country~{c.country}")
        if c.state and c.state.lower() in text:
            score += 1
            reasons.append(f"state~{c.state}")
        if c.revenue_min_musd or c.revenue_max_musd:
            for rev in _revenue_musd(text):
                lo = c.revenue_min_musd or 0
                hi = c.revenue_max_musd or 10**9
                if lo <= rev <= hi:
                    score += 1
                    reasons.append(f"revenue~${int(rev)}M")
                    break
        if c.employees_min or c.employees_max:
            for num, _unit in HOSTS.findall(text):
                n = int(num)
                lo = c.employees_min or 0
                hi = c.employees_max or 10**9
                if lo <= n <= hi:
                    score += 1
                    reasons.append(f"size~{n}")
                    break
        # Industry alone is weak. Require at least one corroborating attribute.
        if score < 2:
            continue
        sev = "critical" if score >= 4 else "high" if score >= 3 else "medium"
        exists = db.execute(
            select(Hit.id).where(Hit.client_id == c.id, Hit.item_id == item.id, Hit.reason == "iab")
        ).first()
        if exists:
            continue
        hit = Hit(
            client_id=c.id, item_id=item.id, term_id=None, reason="iab",
            matched_text=f"IAB candidate (score {score}): " + ", ".join(reasons), severity=sev,
        )
        db.add(hit)
        created.append(hit)
    if created:
        db.commit()
        log.info("IAB: %d candidate(s) on item %s", len(created), item.title[:60])
    return created
