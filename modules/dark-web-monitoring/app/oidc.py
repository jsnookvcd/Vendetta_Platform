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

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from . import auth
from .config import settings
from .db import AuditLog, SessionLocal, User, utcnow

log = logging.getLogger(__name__)
router = APIRouter()
oauth = OAuth()

if settings.oidc_enabled:
    oauth.register(
        name="entra",
        client_id=settings.entra_client_id,
        client_secret=settings.entra_client_secret,
        server_metadata_url=(
            f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid profile email"},
    )


def _authorized(claims: dict) -> bool:
    email = (claims.get("email") or claims.get("preferred_username") or "").lower()
    allow = [e.strip().lower() for e in settings.entra_allowed_emails.split(",") if e.strip()]
    if allow and email not in allow:
        log.warning("oidc: %s not in allowed emails", email)
        return False
    if settings.entra_allowed_group:
        groups = claims.get("groups") or []
        if settings.entra_allowed_group not in groups:
            log.warning("oidc: %s missing required group", email)
            return False
    return True


def _upsert_user(email: str, name: str) -> None:
    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        now = utcnow()
        if u:
            u.last_seen = now
            u.name = name or u.name
        else:
            db.add(User(email=email, name=name, source="entra", role="analyst"))
        db.add(AuditLog(at=now, actor=email, action="login.sso", detail="entra"))
        db.commit()
    finally:
        db.close()


@router.get("/auth/login")
async def auth_login(request: Request):
    if not settings.oidc_enabled:
        raise HTTPException(404)
    redirect_uri = settings.entra_redirect_url or str(request.url_for("auth_callback"))
    return await oauth.entra.authorize_redirect(request, redirect_uri)


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request):
    if not settings.oidc_enabled:
        raise HTTPException(404)
    try:
        token = await oauth.entra.authorize_access_token(request)
    except OAuthError as e:
        log.warning("oidc callback error: %s", e)
        return RedirectResponse("/login?sso=failed", status_code=302)
    claims = token.get("userinfo") or {}
    if not claims:
        claims = await oauth.entra.userinfo(token=token)
    email = (claims.get("email") or claims.get("preferred_username") or "").lower()
    name = claims.get("name") or ""
    if not email or not _authorized(claims):
        return RedirectResponse("/login?sso=denied", status_code=302)
    _upsert_user(email, name)
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(auth.COOKIE, auth.make_session(email), httponly=True, samesite="lax",
                    secure=settings.cookie_secure, max_age=12 * 3600)
    return resp
