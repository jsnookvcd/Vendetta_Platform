"""OAuth 2.1 authorization server for the MCP endpoint, so a PM adds this module to
Claude as a custom connector and signs in with their own Vendetta account.

What Claude's connector expects, and what this implements:
  - Protected resource metadata (RFC 9728) at /.well-known/oauth-protected-resource,
    and a 401 from /mcp whose WWW-Authenticate header points at it.
  - Authorization server metadata (RFC 8414) at /.well-known/oauth-authorization-server.
  - Dynamic client registration (RFC 7591) at /oauth/register. Public clients only,
    and only for redirect URIs on the allowlist (Claude's hosted callback, and
    loopback for Claude Code), so a stranger cannot register a client that sends
    codes somewhere else.
  - The authorization code grant with mandatory PKCE (S256) at /oauth/authorize and
    /oauth/token, and refresh tokens that rotate on every use.

The authorize step is the module's own staff sign-in (Microsoft 365 SSO or the
break-glass admin) followed by a consent screen, so a token is always tied to a real
staff member. Every call made with the token resolves that person's current role
from the staff roster mirror, so a viewer stays read-only in Claude and removing
someone from the platform cuts their connector off at once.

Personal access tokens, minted on the Connect Claude page, use the same table and
the same identity resolution, for Claude Code or a script.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import logging
import secrets
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select, update

from . import auth
from .config import settings
from .db import OAuthClient, OAuthCode, OAuthToken, SessionLocal, utcnow

log = logging.getLogger(__name__)
router = APIRouter()
SCOPE = "pm"
CODE_TTL = 600


def _h(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def base_url(request: Request) -> str:
    return (settings.public_url or str(request.base_url)).rstrip("/")


def resource_url(request: Request) -> str:
    return f"{base_url(request)}/mcp"


def resource_metadata_url(request: Request) -> str:
    return f"{base_url(request)}/.well-known/oauth-protected-resource"


# ---------------------------------------------------------------- tokens
def _issue(db, kind: str, email: str, client_id: str = "", name: str = "", ttl: dt.timedelta | None = None) -> str:
    prefix = {"access": "vpm_at_", "refresh": "vpm_rt_", "pat": "vpm_pat_"}[kind]
    raw = prefix + secrets.token_urlsafe(32)
    db.add(OAuthToken(token_hash=_h(raw), kind=kind, email=email, client_id=client_id, name=name, scope=SCOPE,
                      expires_at=(utcnow() + ttl) if ttl else None))
    return raw


def issue_pair(db, email: str, client_id: str) -> dict:
    access = _issue(db, "access", email, client_id, ttl=dt.timedelta(seconds=settings.oauth_access_ttl_seconds))
    refresh = _issue(db, "refresh", email, client_id, ttl=dt.timedelta(days=settings.oauth_refresh_ttl_days))
    return {"access_token": access, "token_type": "Bearer", "expires_in": settings.oauth_access_ttl_seconds,
            "refresh_token": refresh, "scope": SCOPE}


def create_pat(email: str, name: str, days: int | None) -> str:
    db = SessionLocal()
    try:
        raw = _issue(db, "pat", email, name=name[:200] or "Personal access token",
                     ttl=dt.timedelta(days=days) if days else None)
        db.commit()
        return raw
    finally:
        db.close()


def identity_from_token(raw: str) -> auth.Identity | None:
    """The staff identity behind an access token or personal access token, or None."""
    if not raw or not raw.startswith(("vpm_at_", "vpm_pat_")):
        return None
    db = SessionLocal()
    try:
        tok = db.execute(select(OAuthToken).where(OAuthToken.token_hash == _h(raw))).scalar_one_or_none()
        if tok is None or tok.revoked or tok.kind not in ("access", "pat"):
            return None
        now = utcnow()
        if tok.expires_at and tok.expires_at < now:
            return None
        if not tok.last_used_at or (now - tok.last_used_at).total_seconds() > 300:
            tok.last_used_at = now
            db.commit()
        email = tok.email
    finally:
        db.close()
    return auth.identity_for_email(email)


def revoke_for(email: str, token_id: str | None = None) -> int:
    db = SessionLocal()
    try:
        q = update(OAuthToken).where(OAuthToken.email == email, OAuthToken.revoked.is_(False))
        if token_id:
            q = q.where(OAuthToken.id == token_id)
        n = db.execute(q.values(revoked=True)).rowcount
        db.commit()
        return n
    finally:
        db.close()


def tokens_for(email: str) -> list[OAuthToken]:
    db = SessionLocal()
    try:
        return list(db.execute(select(OAuthToken).where(
            OAuthToken.email == email, OAuthToken.revoked.is_(False), OAuthToken.kind.in_(("pat", "refresh")))
            .order_by(OAuthToken.created_at.desc())).scalars())
    finally:
        db.close()


# ---------------------------------------------------------------- redirect allowlist
def _redirect_allowed(uri: str) -> bool:
    try:
        u = urlparse(uri)
    except ValueError:
        return False
    if u.fragment or not u.scheme or not u.hostname:
        return False
    for entry in (e.strip() for e in settings.mcp_redirect_allowlist.split(",") if e.strip()):
        a = urlparse(entry)
        if a.hostname in ("localhost", "127.0.0.1"):
            # Loopback (RFC 8252): any port and path on the loopback host over http.
            if u.scheme == "http" and u.hostname == a.hostname:
                return True
        elif uri == entry:
            return True
    return False


# ---------------------------------------------------------------- metadata
@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource(request: Request):
    return {"resource": resource_url(request), "authorization_servers": [base_url(request)],
            "scopes_supported": [SCOPE], "bearer_methods_supported": ["header"],
            "resource_name": "Vendetta Project Management"}


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
def authorization_server(request: Request):
    b = base_url(request)
    return {"issuer": b, "authorization_endpoint": f"{b}/oauth/authorize", "token_endpoint": f"{b}/oauth/token",
            "registration_endpoint": f"{b}/oauth/register", "revocation_endpoint": f"{b}/oauth/revoke",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE]}


# ---------------------------------------------------------------- registration
@router.post("/oauth/register")
async def register(request: Request):
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "invalid_client_metadata", "error_description": "body must be JSON"}, 400)
    uris = body.get("redirect_uris") or []
    if not isinstance(uris, list) or not uris:
        return JSONResponse({"error": "invalid_redirect_uri", "error_description": "redirect_uris required"}, 400)
    bad = [u for u in uris if not isinstance(u, str) or not _redirect_allowed(u)]
    if bad:
        log.warning("oauth register refused redirect uris %s", bad)
        return JSONResponse({"error": "invalid_redirect_uri",
                             "error_description": "redirect URI not permitted for this server"}, 400)
    client_id = "vpm_client_" + secrets.token_urlsafe(16)
    db = SessionLocal()
    try:
        db.add(OAuthClient(client_id=client_id, client_name=str(body.get("client_name") or "MCP client")[:200],
                           redirect_uris=uris))
        db.commit()
    finally:
        db.close()
    return JSONResponse({"client_id": client_id, "client_id_issued_at": int(utcnow().timestamp()),
                         "client_name": body.get("client_name") or "MCP client", "redirect_uris": uris,
                         "token_endpoint_auth_method": "none",
                         "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]},
                        status_code=201)


# ---------------------------------------------------------------- authorize
def _client(client_id: str) -> OAuthClient | None:
    db = SessionLocal()
    try:
        return db.get(OAuthClient, client_id or "")
    finally:
        db.close()


def _deny_page(msg: str, status: int = 400) -> HTMLResponse:
    return HTMLResponse("<!doctype html><meta charset=utf-8><title>Cannot connect</title>"
                        "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
                        "place-items:center;height:100vh;margin:0'><div style='max-width:46ch'>"
                        f"<h1 style='color:#e0122f'>Cannot connect</h1><p>{msg}</p></div></body>", status_code=status)


def _redirect(uri: str, **params) -> RedirectResponse:
    sep = "&" if "?" in uri else "?"
    return RedirectResponse(uri + sep + urlencode({k: v for k, v in params.items() if v}), status_code=302)


@router.get("/oauth/authorize")
def authorize(request: Request, response_type: str = "", client_id: str = "", redirect_uri: str = "",
              code_challenge: str = "", code_challenge_method: str = "", state: str = "", scope: str = "",
              resource: str = ""):
    from .main import render  # the consent page uses the console templates

    client = _client(client_id)
    if client is None:
        return _deny_page("This connector is not registered with Vendetta Project Management. Remove it in "
                          "Claude and add it again.")
    if redirect_uri not in (client.redirect_uris or []):
        return _deny_page("The connector asked to return to an address it did not register.")
    if response_type != "code":
        return _redirect(redirect_uri, error="unsupported_response_type", state=state)
    if code_challenge_method != "S256" or not code_challenge:
        return _redirect(redirect_uri, error="invalid_request", error_description="PKCE S256 is required",
                         state=state)
    ident = auth.resolve_identity(request)
    if ident is None:
        nxt = request.url.path + "?" + request.url.query
        return RedirectResponse("/login?" + urlencode({"next": nxt}), status_code=302)
    if not ident.is_internal:
        return _deny_page("Only Vendetta staff can connect Claude to Project Management.", 403)
    csrf = secrets.token_urlsafe(24)
    request.session["oauth_csrf"] = csrf
    return render(request, "oauth_consent.html", user=ident.email, role=ident.role, client=client,
                  csrf=csrf, params={"client_id": client_id, "redirect_uri": redirect_uri, "state": state,
                                     "code_challenge": code_challenge, "scope": scope, "resource": resource})


@router.post("/oauth/authorize")
def authorize_decide(request: Request, decision: str = Form(...), csrf: str = Form(...), client_id: str = Form(...),
                     redirect_uri: str = Form(...), code_challenge: str = Form(...), state: str = Form(""),
                     scope: str = Form(""), resource: str = Form("")):
    ident = auth.resolve_identity(request)
    if ident is None or not ident.is_internal:
        raise HTTPException(401, "login required")
    expected = request.session.pop("oauth_csrf", "")
    if not expected or not hmac.compare_digest(expected, csrf):
        return _deny_page("This approval form expired. Start the connection again from Claude.")
    client = _client(client_id)
    if client is None or redirect_uri not in (client.redirect_uris or []):
        return _deny_page("The connector registration does not match.")
    iss = base_url(request)
    if decision != "approve":
        return _redirect(redirect_uri, error="access_denied", state=state, iss=iss)
    code = secrets.token_urlsafe(32)
    db = SessionLocal()
    try:
        db.add(OAuthCode(code_hash=_h(code), client_id=client_id, email=ident.email, redirect_uri=redirect_uri,
                         code_challenge=code_challenge, scope=scope or SCOPE, resource=resource,
                         expires_at=utcnow() + dt.timedelta(seconds=CODE_TTL)))
        from .db import AuditLog
        db.add(AuditLog(actor=ident.email, action="oauth.approve", detail=f"{client.client_name} {client_id}"))
        db.commit()
    finally:
        db.close()
    return _redirect(redirect_uri, code=code, state=state, iss=iss)


# ---------------------------------------------------------------- token
def _err(error: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc}, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _pkce_ok(verifier: str, challenge: str) -> bool:
    if not verifier or not 43 <= len(verifier) <= 128:
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return hmac.compare_digest(digest, challenge)


@router.post("/oauth/token")
async def token(request: Request):
    form = await request.form()
    grant = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    db = SessionLocal()
    try:
        if grant == "authorization_code":
            row = db.get(OAuthCode, _h(form.get("code", "")))
            if row is None or row.used or row.expires_at < utcnow():
                return _err("invalid_grant", "code is invalid, used or expired")
            row.used = True
            db.commit()
            if row.client_id != client_id or row.redirect_uri != form.get("redirect_uri", ""):
                return _err("invalid_grant", "client or redirect URI does not match the code")
            if not _pkce_ok(form.get("code_verifier", ""), row.code_challenge):
                return _err("invalid_grant", "PKCE verification failed")
            if auth.identity_for_email(row.email) is None:
                return _err("invalid_grant", "that account no longer has access")
            body = issue_pair(db, row.email, client_id)
            db.commit()
            return JSONResponse(body, headers={"Cache-Control": "no-store"})
        if grant == "refresh_token":
            raw = form.get("refresh_token", "")
            tok = db.execute(select(OAuthToken).where(OAuthToken.token_hash == _h(raw),
                                                      OAuthToken.kind == "refresh")).scalar_one_or_none()
            if tok is None or tok.revoked or (tok.expires_at and tok.expires_at < utcnow()):
                return _err("invalid_grant", "refresh token is invalid or expired")
            if client_id and tok.client_id != client_id:
                return _err("invalid_grant", "refresh token was issued to another client")
            if auth.identity_for_email(tok.email) is None:
                tok.revoked = True
                db.commit()
                return _err("invalid_grant", "that account no longer has access")
            tok.revoked = True  # rotate
            body = issue_pair(db, tok.email, tok.client_id)
            db.commit()
            return JSONResponse(body, headers={"Cache-Control": "no-store"})
        return _err("unsupported_grant_type", f"grant_type '{grant}' is not supported")
    finally:
        db.close()


@router.post("/oauth/revoke")
async def revoke(request: Request):
    form = await request.form()
    raw = form.get("token", "")
    db = SessionLocal()
    try:
        tok = db.execute(select(OAuthToken).where(OAuthToken.token_hash == _h(raw))).scalar_one_or_none()
        if tok:
            tok.revoked = True
            db.commit()
    finally:
        db.close()
    return JSONResponse({}, status_code=200)
