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

from . import auth, sso, staff
from .config import settings
from .db import AuditLog, Client, SessionLocal, User, utcnow

log = logging.getLogger(__name__)
router = APIRouter()


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def _map_identity(claims: dict) -> tuple[str, str, str | None] | None:
    """Return (email, role, client_id) for an allowed sign-in, or None to deny.

    Internal Vendetta staff get their roster role (or admin or analyst before a
    roster exists). Anyone else is admitted only to the client portal, and only if
    their email domain matches exactly one active client with the portal on; a
    domain matching two clients is refused, never guessed."""
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
    admins = {e.strip().lower() for e in cfg["admin_emails"].split(",") if e.strip()}
    # Once anyone is on the staff roster, the roster decides. A configured admin
    # email stays admitted as the bootstrap path, so the first admin can onboard
    # themselves and nobody can be locked out by an empty or broken roster.
    db = SessionLocal()
    try:
        if staff.governs(db):
            person = staff.lookup(db, email)
            if person and person.active:
                return email, person.platform_role, None
            if email in admins:
                return email, "admin", None
            if is_internal or person is not None:
                log.warning("oidc: %s is not on the staff roster (or is deactivated); denied", email)
                return None
    finally:
        db.close()
    if is_internal:
        return email, ("admin" if email in admins else "analyst"), None
    return _map_client(email, domain)


def _map_client(email: str, domain: str) -> tuple[str, str, str | None] | None:
    """The client portal: the one active, portal-enabled client whose portal domains
    include this email's domain."""
    if not domain:
        return None
    db = SessionLocal()
    try:
        rows = db.execute(select(Client).where(Client.portal_enabled.is_(True),
                                               Client.active.is_(True))).scalars().all()
        matches = [c for c in rows
                   if domain in {d.strip().lower() for d in (c.portal_domains or "").split(",") if d.strip()}]
    finally:
        db.close()
    if len(matches) == 1:
        return email, "client", matches[0].id
    if len(matches) > 1:
        log.warning("oidc: %s domain %s maps to %d clients; refusing sign-in (ambiguous tenant)",
                    email, domain, len(matches))
        return None
    log.warning("oidc: %s is not internal and no client has the portal on for %s; denied", email, domain)
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
