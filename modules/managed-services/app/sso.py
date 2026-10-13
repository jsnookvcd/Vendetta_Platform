"""Microsoft 365 / Entra SSO configuration, resolved stored-over-environment.

SSO can be wired in-app: an admin enters the tenant, client id and secret and tests
it, and it takes effect without a redeploy. Stored values (the secret encrypted at
rest) override the environment defaults; when nothing is stored the environment is
used, so a deployment can still be configured through SSM.

test() verifies a configuration without a browser: it fetches the tenant's OIDC
discovery document (proving the tenant id is valid and reachable) and performs a
client-credentials token request (proving the client id and secret are correct).
"""
from __future__ import annotations

import logging

import httpx
from authlib.integrations.starlette_client import OAuth

from .config import settings

log = logging.getLogger(__name__)

_FIELDS = ("tenant_id", "client_id", "client_secret", "redirect_url", "allowed_group",
           "allowed_emails", "internal_email_domains", "admin_emails")
_ENV = {
    "tenant_id": "entra_tenant_id",
    "client_id": "entra_client_id",
    "client_secret": "entra_client_secret",
    "redirect_url": "entra_redirect_url",
    "allowed_group": "entra_allowed_group",
    "allowed_emails": "entra_allowed_emails",
    "internal_email_domains": "internal_email_domains",
    "admin_emails": "admin_emails",
}


def _row():
    from .db import SessionLocal, SsoConfig

    try:
        db = SessionLocal()
        try:
            return db.get(SsoConfig, "default")
        finally:
            db.close()
    except Exception:  # noqa: BLE001  (no DB in some contexts)
        return None


def resolve() -> dict:
    """Effective SSO settings: stored (non-empty) over environment defaults. Includes
    'enabled', which an admin can switch off even when credentials are present."""
    row = _row()
    out = {}
    for f in _FIELDS:
        val = getattr(row, f, "") if row else ""
        if not val:
            val = getattr(settings, _ENV[f], "") or ""
        out[f] = val
    out["enabled"] = (row.enabled if row else True)
    out["configured"] = bool(out["tenant_id"] and out["client_id"] and out["client_secret"])
    out["source"] = "stored" if (row and (row.tenant_id and row.client_id)) else (
        "env" if (settings.entra_tenant_id and settings.entra_client_id) else "none")
    return out


def enabled() -> bool:
    cfg = resolve()
    return bool(cfg["enabled"] and cfg["tenant_id"] and cfg["client_id"])


def _metadata_url(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"


def client():
    """Build an Authlib OAuth client from the current resolved config. Rebuilt per use
    so a config change takes effect immediately; Authlib keeps flow state in the
    session, not on the client."""
    cfg = resolve()
    oauth = OAuth()
    oauth.register(
        name="entra",
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"],
        server_metadata_url=_metadata_url(cfg["tenant_id"]),
        client_kwargs={"scope": "openid profile email"},
    )
    return oauth.entra


def test(cfg: dict | None = None, transport: httpx.BaseTransport | None = None) -> tuple[bool, str]:
    """Verify a config: tenant discovery, then a client-credentials token request.
    Returns (ok, detail). Never raises."""
    cfg = cfg or resolve()
    tenant, cid, secret = cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret")
    if not (tenant and cid and secret):
        return False, "tenant ID, client ID and client secret are all required"
    try:
        with httpx.Client(timeout=8.0, transport=transport) as h:
            disc = h.get(_metadata_url(tenant))
            if disc.status_code != 200:
                return False, f"tenant discovery failed (http {disc.status_code}); check the tenant ID"
            token_ep = (disc.json().get("token_endpoint")
                        or f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
            r = h.post(token_ep, data={
                "client_id": cid, "client_secret": secret, "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default"})
            if r.status_code == 200 and (r.json() or {}).get("access_token"):
                return True, "tenant reachable and client credentials valid"
            body = {}
            try:
                body = r.json()
            except ValueError:
                pass
            reason = body.get("error_description") or body.get("error") or f"http {r.status_code}"
            return False, f"client credentials rejected: {str(reason).splitlines()[0]}"[:400]
    except httpx.HTTPError as e:  # noqa: BLE001
        return False, f"unreachable: {type(e).__name__}"


def save(values: dict, actor: str) -> None:
    from .db import SessionLocal, SsoConfig, utcnow

    db = SessionLocal()
    try:
        row = db.get(SsoConfig, "default")
        if row is None:
            row = SsoConfig(id="default")
            db.add(row)
        for f in _FIELDS:
            if f == "client_secret":
                # blank secret keeps the stored one
                new = (values.get(f) or "").strip()
                if new:
                    row.client_secret = new
            else:
                setattr(row, f, (values.get(f) or "").strip())
        if "enabled" in values:
            row.enabled = bool(values["enabled"])
        row.updated_by = actor
        row.updated_at = utcnow()
        db.commit()
    finally:
        db.close()


def set_status(ok: bool, detail: str) -> None:
    from .db import SessionLocal, SsoConfig, utcnow

    db = SessionLocal()
    try:
        row = db.get(SsoConfig, "default")
        if row is None:
            row = SsoConfig(id="default")
            db.add(row)
        row.last_tested_at = utcnow()
        # The pass/fail result rides in the stored detail (no schema change): a
        # leading "ok:" marks a verified test, which readiness reads back.
        row.last_detail = (("ok: " if ok else "fail: ") + detail)[:500]
        db.commit()
    finally:
        db.close()


def _last_result(detail: str) -> tuple[bool | None, str]:
    """(passed, clean_detail) from a stored last_detail. passed is None if never tested."""
    if not detail:
        return None, ""
    if detail.startswith("ok: "):
        return True, detail[4:]
    if detail.startswith("fail: "):
        return False, detail[6:]
    return None, detail  # pre-marker rows: tested, result unknown


def verified() -> bool:
    """SSO is enabled, fully configured, and the last test passed."""
    cfg = resolve()
    if not (cfg["enabled"] and cfg["configured"]):
        return False
    row = _row()
    passed, _ = _last_result(row.last_detail if row else "")
    return passed is True


def status() -> dict:
    row = _row()
    cfg = resolve()
    passed, clean = _last_result(row.last_detail if row else "")
    return {
        "configured": cfg["configured"],
        "enabled": cfg["enabled"],
        "source": cfg["source"],
        "verified": verified(),
        "last_tested_at": row.last_tested_at if row else None,
        "last_ok": passed,
        "last_detail": clean,
        "values": {f: cfg[f] for f in _FIELDS if f != "client_secret"},
        "has_secret": bool(cfg["client_secret"]),
    }
