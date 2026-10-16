"""Tool credential resolution. Credentials can be entered in-app (stored encrypted
in tool_credentials) or supplied by the environment. A stored, non-empty value wins;
otherwise the environment default from settings is used. This is what lets an
operator wire a tool in through the Integrations page in one step, with no SSM edit
or redeploy: save, reset the connector, test.

FIELDS is the single source of truth for which fields each tool takes, which are
secret, which are required, and the settings attribute each falls back to. The
Integrations page renders forms from it and the connectors resolve values from it.
"""
from __future__ import annotations

import json
import logging

from . import crypto
from .config import TOOLS, settings

log = logging.getLogger(__name__)


def _f(key, attr, label, *, secret=False, required=False, placeholder="", help=""):
    return {"key": key, "attr": attr, "label": label, "secret": secret,
            "required": required, "placeholder": placeholder, "help": help}


FIELDS: dict[str, list[dict]] = {
    "superops": [
        _f("api_token", "superops_api_token", "API token", secret=True, required=True,
           help="SuperOps > My Profile > API Token"),
        _f("subdomain", "superops_subdomain", "Subdomain", required=True, placeholder="vendetta"),
        _f("base_url", "superops_base_url", "Console URL", placeholder="https://vendetta.superops.ai"),
        _f("default_techgroup_id", "superops_default_techgroup_id", "Default tech group ID"),
        _f("api_url", "superops_api_url", "API URL", placeholder="https://api.superops.ai/msp"),
    ],
    "sentinelone": [
        _f("url", "sentinelone_url", "Management URL", required=True,
           placeholder="https://usea1-partners.sentinelone.net"),
        _f("api_token", "sentinelone_api_token", "API token", secret=True, required=True),
    ],
    "crowdstrike": [
        _f("client_id", "crowdstrike_client_id", "API client ID", required=True),
        _f("client_secret", "crowdstrike_client_secret", "API client secret", secret=True, required=True),
        _f("base_url", "crowdstrike_base_url", "API base URL", placeholder="https://api.crowdstrike.com"),
        _f("console_url", "crowdstrike_console_url", "Console URL", placeholder="https://falcon.crowdstrike.com"),
    ],
    "huntress": [
        _f("api_key", "huntress_api_key", "API key", secret=True, required=True),
        _f("api_secret", "huntress_api_secret", "API secret", secret=True, required=True),
        _f("base_url", "huntress_base_url", "Portal URL", placeholder="https://vendetta.huntress.io"),
    ],
    "acronis": [
        _f("dc_url", "acronis_dc_url", "Data center URL", required=True,
           placeholder="https://us5-cloud.acronis.com"),
        _f("client_id", "acronis_client_id", "API client ID", required=True),
        _f("client_secret", "acronis_client_secret", "API client secret", secret=True, required=True),
    ],
    "entra": [
        _f("client_id", "graph_client_id", "Entra app (client) ID", required=True,
           help="A multi-tenant Entra app with Graph IdentityRiskEvent.Read.All and SecurityEvents.Read.All, app-only"),
        _f("client_secret", "graph_client_secret", "Client secret", secret=True, required=True),
        _f("base_url", "graph_base_url", "Graph base URL", placeholder="https://graph.microsoft.com"),
        _f("login_url", "graph_login_url", "Login base URL", placeholder="https://login.microsoftonline.com"),
    ],
    "aws": [
        _f("access_key_id", "aws_access_key_id", "Access key ID", required=True,
           help="MSP base credentials that assume each client's cross-account role"),
        _f("secret_access_key", "aws_secret_access_key", "Secret access key", secret=True, required=True),
        _f("region", "aws_region", "Default region", placeholder="us-east-1"),
        _f("external_id", "aws_external_id", "Role external ID"),
    ],
}


def required_keys(tool: str) -> list[str]:
    return [f["key"] for f in FIELDS.get(tool, []) if f["required"]]


def _stored(tool: str) -> dict:
    """Decrypted stored fields for a tool, or {} if none / unreadable."""
    from .db import SessionLocal, ToolCredential  # local import to avoid a cycle

    try:
        db = SessionLocal()
        try:
            row = db.get(ToolCredential, tool)
        finally:
            db.close()
    except Exception:  # noqa: BLE001  (no DB in some contexts: fall back to env)
        return {}
    if not row or not row.data:
        return {}
    try:
        return json.loads(crypto.decrypt(row.data)) or {}
    except (ValueError, TypeError):
        return {}


def stored(tool: str) -> dict:
    """The decrypted stored fields only, with no environment fallback."""
    return _stored(tool)


def env_value(tool: str, key: str) -> str:
    for f in FIELDS.get(tool, []):
        if f["key"] == key:
            return getattr(settings, f["attr"], "") or ""
    return ""


def resolve(tool: str) -> dict:
    """Effective values for a tool: stored (non-empty) over environment defaults."""
    if tool not in FIELDS:
        return {}
    stored = _stored(tool)
    out = {}
    for f in FIELDS[tool]:
        val = stored.get(f["key"])
        if val is None or val == "":
            val = getattr(settings, f["attr"], "") or ""
        out[f["key"]] = val
    return out


def configured(tool: str) -> bool:
    vals = resolve(tool)
    return all(vals.get(k) for k in required_keys(tool))


def source(tool: str) -> str:
    """Where the effective credentials come from: stored, env, or none."""
    if any(_stored(tool).get(k) for k in required_keys(tool)):
        return "stored"
    if all(getattr(settings, f["attr"], "") for f in FIELDS.get(tool, []) if f["required"]):
        return "env"
    return "none"


def save(tool: str, values: dict, actor: str) -> None:
    """Persist credential fields for a tool, encrypted. Empty optional fields are
    kept out so they fall back to the environment."""
    from .db import SessionLocal, ToolCredential, utcnow

    if tool not in FIELDS:
        raise ValueError(f"unknown tool {tool!r}")
    clean = {f["key"]: (values.get(f["key"]) or "").strip()
             for f in FIELDS[tool] if (values.get(f["key"]) or "").strip()}
    db = SessionLocal()
    try:
        row = db.get(ToolCredential, tool)
        if row is None:
            row = ToolCredential(tool=tool)
            db.add(row)
        row.data = crypto.encrypt(json.dumps(clean))
        row.updated_by = actor
        row.updated_at = utcnow()
        db.commit()
    finally:
        db.close()


def set_status(tool: str, connected: bool, detail: str) -> None:
    from .db import SessionLocal, ToolCredential, utcnow

    db = SessionLocal()
    try:
        row = db.get(ToolCredential, tool)
        if row is None:
            row = ToolCredential(tool=tool)
            db.add(row)
        row.connected = connected
        row.last_detail = detail[:500]
        row.last_tested_at = utcnow()
        db.commit()
    finally:
        db.close()


def clear(tool: str, actor: str) -> None:
    """Remove stored credentials so the tool falls back to the environment (or off)."""
    from .db import SessionLocal, ToolCredential

    db = SessionLocal()
    try:
        row = db.get(ToolCredential, tool)
        if row is not None:
            db.delete(row)
            db.commit()
    finally:
        db.close()


def all_status() -> dict[str, dict]:
    """Per-tool view for the Integrations page: source, configured, and last test."""
    from .db import SessionLocal, ToolCredential

    rows = {}
    try:
        db = SessionLocal()
        try:
            for r in db.query(ToolCredential).all():
                rows[r.tool] = r
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        rows = {}
    out = {}
    for tool in TOOLS:
        r = rows.get(tool)
        out[tool] = {
            "source": source(tool),
            "configured": configured(tool),
            "connected": bool(r.connected) if r else False,
            "last_tested_at": r.last_tested_at if r else None,
            "last_detail": r.last_detail if r else "",
            "values": {f["key"]: resolve(tool).get(f["key"], "") for f in FIELDS[tool]},
        }
    return out
