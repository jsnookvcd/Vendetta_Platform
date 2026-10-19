"""Effective Harvest and SharePoint settings: stored in-app (non-empty) over the
environment. Graph credentials fall back to the Entra SSO app registration, so one
app registration can serve sign-in and the SharePoint mirror."""
from __future__ import annotations

from . import sso
from .config import settings

FIELDS = ("harvest_account_id", "harvest_token", "graph_tenant_id", "graph_client_id",
          "graph_client_secret", "sharepoint_site_url", "sharepoint_folder")
SECRETS = {"harvest_token", "graph_client_secret"}


def _row():
    from .db import IntegrationConfig, SessionLocal

    try:
        db = SessionLocal()
        try:
            return db.get(IntegrationConfig, "default")
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        return None


def resolve() -> dict:
    row = _row()
    out = {}
    for f in FIELDS:
        val = (getattr(row, f, "") if row else "") or getattr(settings, f, "") or ""
        out[f] = val.strip() if isinstance(val, str) else val
    if not (out["graph_tenant_id"] and out["graph_client_id"] and out["graph_client_secret"]):
        s = sso.resolve()
        out["graph_tenant_id"] = out["graph_tenant_id"] or s["tenant_id"]
        out["graph_client_id"] = out["graph_client_id"] or s["client_id"]
        out["graph_client_secret"] = out["graph_client_secret"] or s["client_secret"]
    out["harvest_url"] = settings.harvest_url
    out["sharepoint_folder"] = out["sharepoint_folder"] or "Engagements"
    return out


def status() -> dict:
    cfg = resolve()
    return {
        "harvest": bool(cfg["harvest_account_id"] and cfg["harvest_token"]),
        "graph": bool(cfg["graph_tenant_id"] and cfg["graph_client_id"] and cfg["graph_client_secret"]),
        "sharepoint_site": bool(cfg["sharepoint_site_url"]),
        "values": {f: cfg[f] for f in FIELDS if f not in SECRETS},
        "has": {f: bool(cfg[f]) for f in SECRETS},
    }


def save(values: dict, actor: str) -> None:
    from .db import IntegrationConfig, SessionLocal, utcnow

    db = SessionLocal()
    try:
        row = db.get(IntegrationConfig, "default")
        if row is None:
            row = IntegrationConfig(id="default")
            db.add(row)
        for f in FIELDS:
            if f not in values:
                continue
            new = (values.get(f) or "").strip()
            if f in SECRETS and not new:
                continue  # blank secret keeps the stored one
            setattr(row, f, new)
        row.updated_by = actor
        row.updated_at = utcnow()
        db.commit()
    finally:
        db.close()
