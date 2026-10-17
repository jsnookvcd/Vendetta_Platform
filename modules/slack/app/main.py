"""Slack responder: lean, tactical incident response from Slack, on top of the IR
hub and SABINE.

Slack reaches the responder through Socket Mode (default, outbound only) or over
HTTP at /slack/commands, /slack/interactions and /slack/events, signed with the
app's signing secret. The console is an operator status page for the
break-glass admin. The service API (/api/module) reports readiness to the
control plane, and /api/provision/sync lets the control plane drop the cached
staff roster the moment someone is onboarded or deactivated."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from . import auth, boot, feed, identity, readiness, reach, responder, slack, socketmode
from .config import settings
from .db import AuditLog, SessionLocal, WarRoom, init_db

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals["app_name"] = settings.app_name
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    slack.whoami()
    socketmode.start()
    feed.start()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


# ---------------------------------------------------------------- Slack over HTTP
def _disabled() -> Response | None:
    if not settings.module_enabled:
        return JSONResponse({"response_type": "ephemeral", "text": "The Slack responder is turned off."})
    return None


async def _verified(request: Request) -> bytes | None:
    body = await request.body()
    return body if slack.verify(request.headers, body) else None


@app.post("/slack/commands")
async def slack_commands(request: Request):
    body = await _verified(request)
    if body is None:
        return Response(status_code=401)
    off = _disabled()
    if off:
        return off
    form = {k: v[0] for k, v in parse_qs(body.decode(), keep_blank_values=True).items()}
    ack = responder.handle_command(form)
    return JSONResponse(ack) if ack else Response(status_code=200)


@app.post("/slack/interactions")
async def slack_interactions(request: Request):
    body = await _verified(request)
    if body is None:
        return Response(status_code=401)
    if not settings.module_enabled:
        return Response(status_code=200)
    raw = parse_qs(body.decode()).get("payload", ["{}"])[0]
    try:
        payload = json.loads(raw)
    except ValueError:
        return Response(status_code=400)
    ack = responder.handle_interaction(payload)
    return JSONResponse(ack) if ack else Response(status_code=200)


@app.post("/slack/events")
async def slack_events(request: Request):
    body = await _verified(request)
    if body is None:
        return Response(status_code=401)
    try:
        payload = json.loads(body)
    except ValueError:
        return Response(status_code=400)
    if payload.get("type") == "url_verification":
        return JSONResponse({"challenge": payload.get("challenge", "")})
    # Slack retries when it did not hear back in time; the first delivery was handled.
    if request.headers.get("x-slack-retry-num") or not settings.module_enabled:
        return Response(status_code=200)
    if payload.get("type") == "event_callback":
        responder.handle_event(payload)
    return Response(status_code=200)


# ---------------------------------------------------------------- console
def render(request: Request, name: str, **ctx):
    return templates.TemplateResponse(request, name, ctx)


@app.exception_handler(401)
async def _login_redirect(request: Request, exc):
    if request.url.path.startswith(("/api/", "/slack/")):
        return JSONResponse({"detail": "login required"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", user=None, error="")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ""
    if not auth.check_password(username, password, ip):
        return render(request, "login.html", user=None, error="Wrong username or password.")
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                    secure=settings.cookie_secure, max_age=60 * 60 * 12)
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rooms = db.execute(select(WarRoom).where(WarRoom.active.is_(True)).order_by(desc(WarRoom.created_at)).limit(50)).scalars().all()
    logs = db.execute(select(AuditLog).order_by(desc(AuditLog.id)).limit(60)).scalars().all()
    return render(request, "dashboard.html", user=user, rooms=rooms, logs=logs, block=readiness.block(),
                  problems=readiness.problems(), command=settings.slack_command)


@app.post("/feed/run")
def feed_run(user: str = auth.RequireUser):
    feed.cycle()
    return RedirectResponse("/", status_code=302)


# ---------------------------------------------------------------- service API
@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    return {
        "module": "slack", "display_name": "Slack Responder", "platform": "Vendetta Platform",
        "enabled": settings.module_enabled, "role": "bridge",
        "acts_through": sorted(k for k in reach.directory() if k != "platform"),
        "readiness": readiness.block(),
        "endpoints": ["/slack/commands", "/slack/interactions", "/slack/events", "/api/war-rooms", "/api/provision/sync", "/api/module"],
    }


@app.get("/api/war-rooms")
def api_war_rooms(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Open war rooms, for the control plane's overview count."""
    rows = db.execute(select(WarRoom).where(WarRoom.active.is_(True)).order_by(desc(WarRoom.created_at))).scalars().all()
    return [{"case_number": r.case_number, "client": r.client, "channel": r.channel_name or r.channel_id,
             "created_by": r.created_by, "created_at": r.created_at.isoformat()} for r in rows]


@app.post("/api/provision/sync")
def api_provision_sync(user: str = Depends(auth.api_user)):
    """The control plane calls this whenever a client or a member of staff changes.
    The responder keeps no client roster; it drops its cached staff roster so a
    deactivation takes effect on the very next Slack command."""
    identity.reset_cache()
    return {"ok": True, "staff_cache": "cleared"}


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
