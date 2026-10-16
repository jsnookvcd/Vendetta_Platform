"""Microsoft 365 / Entra ID single sign-on (OIDC authorization code flow).

When configured, the team signs in with their 365 accounts and each session is
tied to the real user. Access is restricted to the configured tenant, and
optionally to a security group or an email allowlist. The local admin login
remains as a break-glass path. Off entirely until ENTRA_CLIENT_ID and
ENTRA_TENANT_ID are set.

Entra app registration (one time):
  - Redirect URI (Web): https://<host>/auth/callback
  - Implicit grant: none; this is the confidential code flow with a client secret
  - API permissions: Microsoft Graph openid, profile, email (delegated)
  - To use entra_allowed_group, add a groups claim to the token configuration so
    the group object IDs appear in the id_token.
"""
from __future__ import annotations

import datetime as dt
import logging

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from . import auth, provision, sso
from .config import settings
from .db import AuditLog, SessionLocal, User, utcnow

log = logging.getLogger(__name__)
router = APIRouter()


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def _map_identity(claims: dict) -> tuple[str, str, str | None] | None:
    """Return (email, role, client_id) for an allowed sign-in, or None to deny.

    Internal Vendetta staff get the role the platform roster grants them for
    MARLOW. Everyone else is denied; MARLOW is staff-only."""
    email = (claims.get("email") or claims.get("preferred_username") or "").lower()
    if not email:
        return None
    domain = _email_domain(email)

    cfg = sso.resolve()
    internal_domains = {d.strip().lower() for d in cfg["internal_email_domains"].split(",") if d.strip()}
    allow_emails = {e.strip().lower() for e in cfg["allowed_emails"].split(",") if e.strip()}
    groups = claims.get("groups") or []
    is_internal = (
        domain in internal_domains
        or email in allow_emails
        or (cfg["allowed_group"] and cfg["allowed_group"] in groups)
    )
    if is_internal:
        db = SessionLocal()
        try:
            verdict, role, _cfg = provision.staff_decision(email, db)
        finally:
            db.close()
        if verdict == "admit":
            return email, role, None
        if verdict == "deny":
            log.warning("oidc: %s is internal but not granted MARLOW on the platform roster; denied", email)
            return None
        admins = {e.strip().lower() for e in cfg["admin_emails"].split(",") if e.strip()}
        return email, ("admin" if email in admins else "analyst"), None
    # The control plane is staff-only; clients use each module's own portal.
    log.warning("oidc: %s is not internal; MARLOW is staff-only", email)
    return None


def _upsert_user(email: str, name: str, role: str, client_id: str | None) -> None:
    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        now = utcnow()
        if u:
            u.last_seen = now
            u.name = name or u.name
            u.role = role
            u.client_id = client_id
        else:
            db.add(User(email=email, name=name, source="entra", role=role, client_id=client_id))
        db.add(AuditLog(at=now, actor=email, action="login.sso", detail=f"entra role={role}"))
        db.commit()
    finally:
        db.close()


@router.get("/auth/login")
async def auth_login(request: Request):
    if not sso.enabled():
        raise HTTPException(404)
    redirect_uri = sso.resolve()["redirect_url"] or str(request.url_for("auth_callback"))
    return await sso.client().authorize_redirect(request, redirect_uri)


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request):
    if not sso.enabled():
        raise HTTPException(404)
    entra = sso.client()
    try:
        token = await entra.authorize_access_token(request)
    except OAuthError as e:
        log.warning("oidc callback error: %s", e)
        return RedirectResponse("/login?sso=failed", status_code=302)
    claims = token.get("userinfo") or {}
    if not claims:
        claims = await entra.userinfo(token=token)
    name = claims.get("name") or ""
    mapped = _map_identity(claims)
    if not mapped:
        return RedirectResponse("/login?sso=denied", status_code=302)
    email, role, client_id = mapped
    _upsert_user(email, name, role, client_id)
    dest = "/portal" if role == "client" else "/"
    resp = RedirectResponse(dest, status_code=302)
    resp.set_cookie(auth.COOKIE, auth.make_session(email), httponly=True, samesite="lax",
                    secure=settings.cookie_secure, max_age=12 * 3600)
    return resp
