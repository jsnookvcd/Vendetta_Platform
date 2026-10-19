"""Microsoft 365 / Entra ID single sign-on (OIDC authorization code flow).

Project Management is staff-only: an Entra sign-in is admitted when the platform
staff roster grants this module (or, with no roster, when the email is on an
internal domain or the allowlist). There is no client portal.

The sign-in remembers where the PM was going (?next=), so a PM who is sent here
from Claude's connector consent screen lands back on it after signing in.
"""
from __future__ import annotations

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


def safe_next(nxt: str | None) -> str:
    """Only a local path: never an absolute URL or a scheme-relative one, so the
    sign-in can never be turned into an open redirect."""
    nxt = (nxt or "/").strip()
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        return "/"
    return nxt


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def _map_identity(claims: dict) -> tuple[str, str] | None:
    """Return (email, role) for an allowed staff sign-in, or None to deny."""
    email = (claims.get("email") or claims.get("preferred_username") or "").lower()
    if not email:
        return None
    cfg = sso.resolve()
    internal_domains = {d.strip().lower() for d in cfg["internal_email_domains"].split(",") if d.strip()}
    allow_emails = {e.strip().lower() for e in cfg["allowed_emails"].split(",") if e.strip()}
    groups = claims.get("groups") or []
    is_internal = (
        _email_domain(email) in internal_domains
        or email in allow_emails
        or (cfg["allowed_group"] and cfg["allowed_group"] in groups)
    )
    if not is_internal:
        log.warning("oidc: %s is not Vendetta staff; denied", email)
        return None
    db = SessionLocal()
    try:
        verdict, role, _cfg = provision.staff_decision(email, db)
    finally:
        db.close()
    if verdict == "admit":
        return email, role
    if verdict == "deny":
        log.warning("oidc: %s is not on the platform staff roster for this module; denied", email)
        return None
    admins = {e.strip().lower() for e in cfg["admin_emails"].split(",") if e.strip()}
    return email, ("admin" if email in admins else "analyst")


def _upsert_user(email: str, name: str, role: str) -> None:
    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        now = utcnow()
        if u:
            u.last_seen = now
            u.name = name or u.name
            u.role = role
            u.client_id = None
            u.active = True
        else:
            db.add(User(email=email, name=name, source="entra", role=role))
        db.add(AuditLog(at=now, actor=email, action="login.sso", detail=f"entra role={role}"))
        db.commit()
    finally:
        db.close()


@router.get("/auth/login")
async def auth_login(request: Request, next: str = "/"):
    if not sso.enabled():
        raise HTTPException(404)
    request.session["sso_next"] = safe_next(next)
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
    mapped = _map_identity(claims)
    if not mapped:
        return RedirectResponse("/login?sso=denied", status_code=302)
    email, role = mapped
    _upsert_user(email, claims.get("name") or "", role)
    resp = RedirectResponse(safe_next(request.session.pop("sso_next", "/")), status_code=302)
    resp.set_cookie(auth.COOKIE, auth.make_session(email), httponly=True, samesite="lax",
                    secure=settings.cookie_secure, max_age=12 * 3600)
    return resp
