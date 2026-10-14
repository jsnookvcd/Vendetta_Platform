"""Cross-client correlation.

Each alert carries indicators of compromise: addresses, domains, URLs and file
hashes pulled from the vendor payload and the alert text, plus a signature derived
from the detection name. The same indicator seen on more than one client is how a
single actor working through a sector shows up, so correlating indicators across the
book turns five separate alerts into one campaign the SOC can get ahead of.

extract() reads an alert; record()/sync_for_alert() persist its indicators; and
correlate() groups them across clients into campaigns.
"""
from __future__ import annotations

import datetime as dt
import re

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import SEVERITY_ORDER
from .db import Alert, Client, Indicator, utcnow

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)

# Addresses that are never useful as shared indicators.
_PRIVATE_IP = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")
_IGNORE_DOMAINS = {"microsoft.com", "windows.com", "sentinelone.net", "crowdstrike.com",
                   "huntress.io", "acronis.com", "google.com", "example.com", "example.net"}


def _norm_signature(title: str) -> str:
    """A stable signature key from a detection name: lowercased, trailing host/ids
    and punctuation stripped, so 'Mimikatz on WS01' and 'Mimikatz on WS42' match."""
    s = title.lower().strip()
    s = re.split(r"\bon\b|[:\-–(]", s)[0]  # cut off " on HOST", colons, parens
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _add(found: set, itype: str, value: str, label: str | None = None) -> None:
    v = (value or "").strip()
    if v:
        found.add((itype, v.lower()[:400], (label or v)[:400]))


def extract(alert) -> set[tuple[str, str, str]]:
    """Return {(itype, value, label)} for an alert (ORM row or a plain dict).

    Structured indicators in raw win; free-text in title/detail is scanned too; and a
    signature indicator is always derived from the title so same-name detections
    across clients correlate even when no IOC is parsed."""
    get = (lambda k, d=None: alert.get(k, d)) if isinstance(alert, dict) else (lambda k, d=None: getattr(alert, k, d))
    raw = get("raw") or {}
    found: set[tuple[str, str, str]] = set()

    # Structured list form: raw["indicators"] = [{"type","value"}, ...]
    for ind in (raw.get("indicators") if isinstance(raw, dict) else None) or []:
        if isinstance(ind, dict) and ind.get("value"):
            _add(found, str(ind.get("type") or "ioc").lower(), str(ind["value"]), str(ind["value"]))

    # Known single-value keys.
    if isinstance(raw, dict):
        for key, itype in (("ip", "ip"), ("src_ip", "ip"), ("dst_ip", "ip"), ("remote_ip", "ip"),
                           ("domain", "domain"), ("url", "url"), ("sha256", "sha256"), ("md5", "md5"),
                           ("hash", "sha256")):
            if raw.get(key):
                _add(found, itype, str(raw[key]))
        for v in raw.get("ips", []) or []:
            _add(found, "ip", str(v))

    text = f"{get('title') or ''}\n{get('detail') or ''}"
    for m in _URL.findall(text):
        _add(found, "url", m)
    for m in _SHA256.findall(text):
        _add(found, "sha256", m)
    for m in _MD5.findall(text):
        # avoid double-counting the first 32 chars of a sha256
        if not any(m.lower() in v for t, v, _ in found if t == "sha256"):
            _add(found, "md5", m)
    for m in _IPV4.findall(text):
        if not _PRIVATE_IP.match(m):
            _add(found, "ip", m)
    for m in _DOMAIN.findall(text):
        ml = m.lower()
        if ml not in _IGNORE_DOMAINS and not any(ml.endswith("." + d) for d in _IGNORE_DOMAINS) \
                and not _IPV4.fullmatch(m):
            _add(found, "domain", m)

    sig = _norm_signature(get("title") or "")
    if sig:
        _add(found, "signature", sig, (get("title") or "")[:120])
    return found


def sync_for_alert(db: Session, alert: Alert) -> None:
    """Replace the stored indicators for one alert with its freshly extracted set."""
    if alert.id is None:
        db.flush()
    db.execute(delete(Indicator).where(Indicator.alert_id == alert.id))
    for itype, value, label in extract(alert):
        db.add(Indicator(client_id=alert.client_id, alert_id=alert.id, tool=alert.tool or "",
                         itype=itype, value=value, label=label, first_seen=alert.received_at or utcnow()))


def backfill(db: Session) -> int:
    """(Re)compute indicators for every alert. Returns the number of alerts processed."""
    alerts = db.execute(select(Alert)).scalars().all()
    for a in alerts:
        sync_for_alert(db, a)
    db.commit()
    return len(alerts)


# --- itype display, worst first for ordering within a campaign ---
ITYPE_NAMES = {"ip": "IP address", "domain": "Domain", "url": "URL", "sha256": "SHA-256",
               "md5": "MD5", "signature": "Detection", "ioc": "Indicator"}
_ITYPE_RANK = {"sha256": 0, "md5": 1, "ip": 2, "domain": 3, "url": 4, "signature": 5, "ioc": 6}


def correlate(db: Session, window_days: int = 30, now: dt.datetime | None = None) -> list[dict]:
    """Group indicators seen on two or more distinct clients into campaigns, within
    the window, worst first (most clients, then highest severity)."""
    now = now or utcnow()
    since = now - dt.timedelta(days=window_days)
    rows = db.execute(
        select(Indicator, Alert, Client)
        .join(Alert, Indicator.alert_id == Alert.id)
        .join(Client, Indicator.client_id == Client.id)
        .where(Indicator.first_seen >= since)
    ).all()

    groups: dict[tuple[str, str], dict] = {}
    for ind, alert, client in rows:
        key = (ind.itype, ind.value)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"itype": ind.itype, "value": ind.value, "label": ind.label,
                               "itype_name": ITYPE_NAMES.get(ind.itype, ind.itype),
                               "clients": {}, "alerts": [], "tools": set(),
                               "first_seen": ind.first_seen, "last_seen": ind.first_seen,
                               "severity": "info"}
        g["clients"][client.id] = client.name
        g["alerts"].append({"id": alert.id, "client": client.name, "client_id": client.id,
                            "title": alert.title, "severity": alert.severity, "tool": alert.tool,
                            "status": alert.status})
        g["tools"].add(alert.tool)
        g["first_seen"] = min(g["first_seen"], ind.first_seen)
        g["last_seen"] = max(g["last_seen"], ind.first_seen)
        if SEVERITY_ORDER.get(alert.severity, 0) > SEVERITY_ORDER.get(g["severity"], 0):
            g["severity"] = alert.severity

    campaigns = []
    for g in groups.values():
        if len(g["clients"]) < 2:
            continue
        g["client_list"] = sorted(g["clients"].items(), key=lambda kv: kv[1])
        g["n_clients"] = len(g["clients"])
        g["tools"] = sorted(t for t in g["tools"] if t)
        g["open_alerts"] = sum(1 for a in g["alerts"] if a["status"] != "resolved")
        campaigns.append(g)

    campaigns.sort(key=lambda g: (-g["n_clients"], -SEVERITY_ORDER.get(g["severity"], 0),
                                  _ITYPE_RANK.get(g["itype"], 9)))
    return campaigns
