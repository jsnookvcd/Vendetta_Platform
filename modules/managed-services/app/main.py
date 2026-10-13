"""Vendetta Managed Services: the NOC/SOC console over every tool a client has
deployed (SuperOps, SentinelOne, CrowdStrike, Huntress, Acronis).

Tech side: one page per client with the tools, devices, alerts and actions in one
place, deep links into each vendor console, and the message desks. Client side: a
portal showing published alerts and the actions taken, with messaging to the SOC,
NOC and helpdesk. Helpdesk messages become SuperOps tickets."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session, selectinload

from . import actions as act
from . import auth, connectors, messaging, oidc, preflight, provision, sync
from .config import DESK_NAMES, DESKS, SEVERITIES, SEVERITY_ORDER, TOOL_NAMES, TOOLS, settings
from .db import (ActionLog, Alert, AuditLog, Channel, Client, Device, Message, SessionLocal,
                 get_channel, init_db, utcnow)

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(app_name=settings.app_name, TOOLS=TOOLS, TOOL_NAMES=TOOL_NAMES,
                             DESKS=DESKS, DESK_NAMES=DESK_NAMES, SEVERITIES=SEVERITIES,
                             ALERT_ACTIONS=act.ALERT_ACTIONS, DEVICE_ACTIONS=act.DEVICE_ACTIONS)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax",
                   https_only=settings.cookie_secure)
app.include_router(oidc.router)

ALERT_STATUSES = ["open", "acknowledged", "resolved"]


@app.on_event("startup")
def _startup():
    init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------- middleware
_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0'>"
    "<div style='text-align:center;max-width:40ch'><h1 style='color:#e0122f'>Managed Services is turned off</h1>"
    "<p style='color:#93a0b4'>This module is currently disabled on the Vendetta Platform.</p></div></body>"
)


@app.middleware("http")
async def _access_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path == "/healthz":
        return await call_next(request)
    if not settings.module_enabled:
        if path == "/api/module":
            return await call_next(request)
        return HTMLResponse(_DISABLED_HTML, status_code=503)
    ident = auth.resolve_identity(request)
    if ident and ident.is_client and not path.startswith(("/portal", "/auth", "/logout")):
        return RedirectResponse("/portal", status_code=302)
    return await call_next(request)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    return resp


@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def _audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail[:4000]))
    db.commit()


def _shell(db: Session) -> dict:
    return {
        "open_alerts": db.scalar(select(func.count(Alert.id)).where(Alert.status != "resolved")) or 0,
        "critical": db.scalar(select(func.count(Alert.id)).where(Alert.status != "resolved",
                                                                 Alert.severity == "critical")) or 0,
        "unread": db.scalar(select(func.coalesce(func.sum(Channel.tech_unread), 0))) or 0,
        "readonly": settings.actions_readonly,
    }


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user") and not ctx.get("portal"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    return templates.TemplateResponse(request, name, ctx)


def _sev_rank(a: Alert) -> tuple:
    return (-SEVERITY_ORDER.get(a.severity, 0), -(a.occurred_at or a.synced_at).timestamp())


def _back(url: str, ok: bool, message: str) -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}{'msg' if ok else 'err'}={quote(message[:300])}", status_code=302)


# ---------------------------------------------------------------- login
_login_hits: dict[str, list[float]] = {}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso: str = ""):
    m = {"failed": "Microsoft sign-in did not complete. Try again.",
         "denied": "That account is not permitted to access this console."}.get(sso, "")
    return render(request, "login.html", next=next, error=m, oidc_enabled=settings.oidc_enabled)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
          db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < settings.login_window_seconds]
    _login_hits[ip] = hits
    if len(hits) >= settings.login_max_attempts:
        return render(request, "login.html", next=next, error="Too many attempts. Wait a few minutes.",
                      oidc_enabled=settings.oidc_enabled)
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(next or "/", status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_hits.setdefault(ip, []).append(now)
    _audit(db, username, "login.failed", ip)
    return render(request, "login.html", next=next, error="Invalid credentials", oidc_enabled=settings.oidc_enabled)


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    open_alerts = db.execute(
        select(Alert).options(selectinload(Alert.client), selectinload(Alert.device))
        .where(Alert.status != "resolved")).scalars().all()
    open_alerts.sort(key=_sev_rank)
    by_sev = {s: 0 for s in SEVERITIES}
    for a in open_alerts:
        by_sev[a.severity] += 1
    n_devices = db.scalar(select(func.count(Device.id))) or 0
    n_online = db.scalar(select(func.count(Device.id)).where(Device.status == "online")) or 0
    n_isolated = db.scalar(select(func.count(Device.id)).where(Device.status.in_(["isolated", "isolating"]))) or 0
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    recent_actions = db.execute(select(ActionLog).order_by(desc(ActionLog.at)).limit(10)).scalars().all()
    channels = db.execute(select(Channel).options(selectinload(Channel.client))
                          .where(Channel.tech_unread > 0).order_by(desc(Channel.updated_at)).limit(8)).scalars().all()
    tools_up = {t: getattr(connectors.get(t), "configured", False) for t in TOOLS}
    return render(request, "dashboard.html", user=user, alerts=open_alerts[:25], by_sev=by_sev,
                  n_devices=n_devices, n_online=n_online, n_isolated=n_isolated, clients=clients,
                  recent_actions=recent_actions, channels=channels, tools_up=tools_up)


# ---------------------------------------------------------------- clients
@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).order_by(Client.name)).scalars().all()
    counts = {c.id: {"devices": 0, "alerts": 0} for c in rows}
    for cid, n in db.execute(select(Device.client_id, func.count(Device.id)).group_by(Device.client_id)):
        counts.setdefault(cid, {"devices": 0, "alerts": 0})["devices"] = n
    for cid, n in db.execute(select(Alert.client_id, func.count(Alert.id))
                             .where(Alert.status != "resolved").group_by(Alert.client_id)):
        counts.setdefault(cid, {"devices": 0, "alerts": 0})["alerts"] = n
    return render(request, "clients.html", user=user, clients=rows, counts=counts,
                  platform_on=provision.configured())


@app.post("/clients")
def add_client(name: str = Form(...), industry: str = Form(""), user: str = auth.RequireUser,
               db: Session = Depends(get_db)):
    c = Client(name=name.strip(), industry=industry.strip())
    db.add(c)
    db.commit()
    _audit(db, user, "client.add", name)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


@app.post("/clients/pull")
def pull_from_platform(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Pull the client roster and tool mappings from the platform control plane."""
    if not provision.configured():
        return _back("/clients", False, "No platform control plane is configured (set PLATFORM_URL).")
    try:
        summ = provision.pull(db)
    except provision.ProvisionError as e:
        _audit(db, user, "platform.pull.failed", str(e))
        return _back("/clients", False, f"Platform pull failed: {e}")
    _audit(db, user, "platform.pull", str(summ))
    return _back("/clients", True,
                 f"Pulled {summ['roster']} clients ({summ['added']} new, {summ['updated']} updated"
                 + (f", {summ['deactivated']} deactivated" if summ['deactivated'] else "") + ").")


def _get_client(db: Session, cid: str) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    return c


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_page(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    devices = db.execute(select(Device).where(Device.client_id == cid)
                         .order_by(Device.tool, Device.hostname)).scalars().all()
    alerts = db.execute(select(Alert).options(selectinload(Alert.device))
                        .where(Alert.client_id == cid, Alert.status != "resolved")).scalars().all()
    alerts.sort(key=_sev_rank)
    tool_cards = []
    for tool in TOOLS:
        ref = c.tool_ref(tool)
        devs = [d for d in devices if d.tool == tool]
        tool_cards.append({
            "tool": tool, "ref": ref, "configured": getattr(connectors.get(tool), "configured", False),
            "devices": len(devs), "online": sum(1 for d in devs if d.status == "online"),
            "isolated": sum(1 for d in devs if d.status in ("isolated", "isolating")),
            "alerts": sum(1 for a in alerts if a.tool == tool),
            "last": sync.last_sync(cid, tool),
            "link": _tool_link(tool, devs),
        })
    channels = {d: db.query(Channel).filter_by(client_id=cid, desk=d).one_or_none() for d in DESKS}
    recent_actions = db.execute(select(ActionLog).where(ActionLog.client_id == cid)
                                .order_by(desc(ActionLog.at)).limit(12)).scalars().all()
    return render(request, "client.html", user=user, client=c, devices=devices, alerts=alerts,
                  tool_cards=tool_cards, channels=channels, recent_actions=recent_actions)


def _tool_link(tool: str, devices: list[Device]) -> str:
    fixed = {
        "superops": settings.superops_base_url,
        "sentinelone": settings.sentinelone_url,
        "crowdstrike": settings.crowdstrike_console_url if settings.crowdstrike_client_id else "",
        "huntress": settings.huntress_base_url,
        "acronis": settings.acronis_dc_url,
    }[tool]
    if fixed:
        return fixed
    return next((d.link for d in devices if d.link), "")


@app.post("/clients/{cid}/map")
def map_tools(cid: str, superops_client_id: str = Form(""), sentinelone_site_ids: str = Form(""),
              crowdstrike_cid: str = Form(""), huntress_org_id: str = Form(""),
              acronis_tenant_id: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    c.superops_client_id = superops_client_id.strip()
    c.sentinelone_site_ids = ",".join(x.strip() for x in sentinelone_site_ids.split(",") if x.strip())
    c.crowdstrike_cid = crowdstrike_cid.strip().lower()
    c.huntress_org_id = huntress_org_id.strip()
    c.acronis_tenant_id = acronis_tenant_id.strip()
    db.commit()
    _audit(db, user, "client.map", f"{c.name}: {', '.join(c.tools) or 'no tools'}")
    return _back(f"/clients/{cid}", True, "Tool mapping saved.")


@app.post("/clients/{cid}/portal")
def save_portal(cid: str, portal_enabled: bool = Form(False), portal_domains: str = Form(""),
                user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    c.portal_enabled, c.portal_domains = portal_enabled, portal_domains.strip()
    db.commit()
    _audit(db, user, "client.portal", f"{c.name} enabled={portal_enabled}")
    return _back(f"/clients/{cid}", True, "Portal settings saved.")


@app.post("/clients/{cid}/sync")
def sync_now(cid: str, tool: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    if tool:
        res = {tool: sync.sync_client_tool(db, c, tool)}
    else:
        res = sync.sync_client(db, c)
    failed = {t: r["detail"] for t, r in res.items() if not r["ok"]}
    _audit(db, user, "client.sync", f"{c.name}: {res}")
    if failed:
        return _back(f"/clients/{cid}", False, "; ".join(f"{TOOL_NAMES[t]}: {d}" for t, d in failed.items()))
    pulled = sum(r["alerts"] for r in res.values())
    return _back(f"/clients/{cid}", True, f"Synced {len(res)} tool{'s' if len(res) != 1 else ''}, {pulled} alerts.")


# ---------------------------------------------------------------- alerts
@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, status: str = "active", severity: str = "", tool: str = "",
                client_id: str = "", user: str = auth.RequireUser, db: Session = Depends(get_db)):
    q = select(Alert).options(selectinload(Alert.client), selectinload(Alert.device))
    if status == "active":
        q = q.where(Alert.status != "resolved")
    elif status in ALERT_STATUSES:
        q = q.where(Alert.status == status)
    if severity in SEVERITY_ORDER:
        q = q.where(Alert.severity == severity)
    if tool in TOOLS:
        q = q.where(Alert.tool == tool)
    if client_id:
        q = q.where(Alert.client_id == client_id)
    rows = db.execute(q.order_by(desc(Alert.updated_at)).limit(500)).scalars().all()
    rows.sort(key=_sev_rank)
    clients = db.execute(select(Client).order_by(Client.name)).scalars().all()
    return render(request, "alerts.html", user=user, alerts=rows, clients=clients, status=status,
                  severity=severity, tool=tool, client_id=client_id)


def _get_alert(db: Session, aid: str) -> Alert:
    a = db.execute(select(Alert).options(
        selectinload(Alert.client), selectinload(Alert.device), selectinload(Alert.actions)
    ).where(Alert.id == aid)).scalar_one_or_none()
    if not a:
        raise HTTPException(404)
    return a


@app.get("/alerts/{aid}", response_class=HTMLResponse)
def alert_page(aid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    a = _get_alert(db, aid)
    return render(request, "alert.html", user=user, a=a, hub_ready=bool(settings.platform_hub_url))


@app.post("/alerts/{aid}/triage")
def triage(aid: str, op: str = Form(...), client_note: str = Form(""),
           user: str = auth.RequireUser, db: Session = Depends(get_db)):
    a = _get_alert(db, aid)
    label = ""
    if op == "acknowledge" and a.status == "open":
        a.status, label = "acknowledged", "Acknowledged"
    elif op == "resolve":
        a.status, label = "resolved", "Resolved in console"
    elif op == "reopen":
        a.status, label = "open", "Reopened"
    elif op == "publish":
        a.published, a.client_note = True, client_note.strip()[:2000]
        label = "Published to client portal"
    elif op == "unpublish":
        a.published, label = False, "Removed from client portal"
    else:
        raise HTTPException(400)
    a.updated_at = utcnow()
    db.add(ActionLog(client_id=a.client_id, alert_id=a.id, tool=a.tool, action=label, actor=user))
    db.commit()
    return _back(f"/alerts/{aid}", True, f"{label}.")


@app.post("/alerts/{aid}/action")
def alert_action(aid: str, action_id: str = Form(...), comment: str = Form(""), confirm: bool = Form(False),
                 user: str = auth.RequireUser, db: Session = Depends(get_db)):
    a = _get_alert(db, aid)
    spec = act.spec(action_id)
    if spec and a.device and spec in act.DEVICE_ACTIONS.get(a.device.tool, []):
        ok, detail = act.run_device_action(db, a.device, action_id, user, alert=a, comment=comment, confirm=confirm)
    else:
        ok, detail = act.run_alert_action(db, a, action_id, user, comment=comment, confirm=confirm)
    _audit(db, user, "alert.action", f"{a.id} {action_id}: {detail}")
    return _back(f"/alerts/{aid}", ok, f"{(spec.label if spec else action_id)}: {detail}")


@app.post("/alerts/{aid}/escalate")
def escalate(aid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    a = _get_alert(db, aid)
    ok, detail = act.escalate_alert(db, a, user)
    _audit(db, user, "alert.escalate", f"{a.id}: {detail}")
    return _back(f"/alerts/{aid}", ok, f"IR case {detail}" if ok else detail)


@app.post("/devices/{did}/action")
def device_action(did: str, action_id: str = Form(...), comment: str = Form(""), confirm: bool = Form(False),
                  user: str = auth.RequireUser, db: Session = Depends(get_db)):
    d = db.execute(select(Device).options(selectinload(Device.client))
                   .where(Device.id == did)).scalar_one_or_none()
    if not d:
        raise HTTPException(404)
    ok, detail = act.run_device_action(db, d, action_id, user, comment=comment, confirm=confirm)
    _audit(db, user, "device.action", f"{d.hostname} {action_id}: {detail}")
    return _back(f"/clients/{d.client_id}", ok, f"{d.hostname}: {detail}")


# ---------------------------------------------------------------- messages
@app.get("/messages", response_class=HTMLResponse)
def messages_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    channels = db.execute(select(Channel).options(selectinload(Channel.client), selectinload(Channel.messages))
                          .order_by(desc(Channel.updated_at))).scalars().all()
    return render(request, "messages.html", user=user, channels=channels)


@app.get("/messages/{chid}", response_class=HTMLResponse)
def channel_page(chid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ch = db.execute(select(Channel).options(selectinload(Channel.client), selectinload(Channel.messages))
                    .where(Channel.id == chid)).scalar_one_or_none()
    if not ch:
        raise HTTPException(404)
    messaging.mark_read(db, ch, "tech")
    return render(request, "channel.html", user=user, ch=ch)


@app.post("/messages/{chid}")
def channel_reply(chid: str, body: str = Form(...), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ch = db.execute(select(Channel).options(selectinload(Channel.client)).where(Channel.id == chid)).scalar_one_or_none()
    if not ch or not body.strip():
        raise HTTPException(404 if not ch else 400)
    messaging.post(db, ch.client, ch.desk, "tech", user, body)
    return RedirectResponse(f"/messages/{chid}", status_code=302)


# ---------------------------------------------------------------- settings
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser):
    tools_cfg = {t: getattr(connectors.get(t), "configured", False) for t in TOOLS}
    cfg = {
        "module_enabled": settings.module_enabled,
        "sso": f"Entra ID tenant {settings.entra_tenant_id}" if settings.oidc_enabled else "off (local admin login)",
        "hub": settings.platform_hub_url or "not connected",
        "sync_interval": settings.sync_interval_seconds,
        "actions": "read-only (tool writes disabled)" if settings.actions_readonly else "live",
    }
    return render(request, "settings.html", user=user, cfg=cfg, tools_cfg=tools_cfg,
                  api_token=auth.api_token(), preflight=None)


@app.post("/settings/preflight", response_class=HTMLResponse)
def run_preflight(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    results = preflight.run()
    _audit(db, user, "preflight", ", ".join(f"{r.tool}:{'ok' if r.ok else ('-' if not r.configured else 'fail')}" for r in results))
    tools_cfg = {t: getattr(connectors.get(t), "configured", False) for t in TOOLS}
    cfg = {
        "module_enabled": settings.module_enabled,
        "sso": f"Entra ID tenant {settings.entra_tenant_id}" if settings.oidc_enabled else "off (local admin login)",
        "hub": settings.platform_hub_url or "not connected",
        "sync_interval": settings.sync_interval_seconds,
        "actions": "read-only (tool writes disabled)" if settings.actions_readonly else "live",
    }
    return render(request, "settings.html", user=user, cfg=cfg, tools_cfg=tools_cfg,
                  api_token=auth.api_token(), preflight=results)


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    c = db.get(Client, ident.client_id or "")
    if not c:
        raise HTTPException(404)
    return c


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    alerts = db.execute(select(Alert).options(selectinload(Alert.device))
                        .where(Alert.client_id == c.id, Alert.published.is_(True))
                        .order_by(desc(Alert.updated_at)).limit(100)).scalars().all()
    open_alerts = sorted([a for a in alerts if a.status != "resolved"], key=_sev_rank)
    resolved = [a for a in alerts if a.status == "resolved"][:10]
    feed = db.execute(select(ActionLog).where(ActionLog.client_id == c.id, ActionLog.client_visible.is_(True))
                      .order_by(desc(ActionLog.at)).limit(30)).scalars().all()
    devices = db.execute(select(Device).where(Device.client_id == c.id)).scalars().all()
    channels = {d: db.query(Channel).filter_by(client_id=c.id, desk=d).one_or_none() for d in DESKS}
    by_sev = {s_: sum(1 for a in open_alerts if a.severity == s_) for s_ in SEVERITIES}
    return render(request, "portal.html", user=ident.email, portal=True, client=c,
                  open_alerts=open_alerts, resolved=resolved, feed=feed, channels=channels,
                  n_devices=len(devices), n_online=sum(1 for d in devices if d.status == "online"),
                  exec_view=ident.is_executive, by_sev=by_sev)


@app.get("/portal/alerts/{aid}", response_class=HTMLResponse)
def portal_alert(aid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                 db: Session = Depends(get_db)):
    a = _get_alert(db, aid)
    auth.require_owned(ident, a, extra=a.published)
    if ident.is_executive:
        return RedirectResponse("/portal", status_code=302)
    feed = db.execute(select(ActionLog).where(ActionLog.alert_id == a.id, ActionLog.client_visible.is_(True))
                      .order_by(desc(ActionLog.at))).scalars().all()
    return render(request, "portal_alert.html", user=ident.email, portal=True, client=a.client, a=a, feed=feed)


@app.get("/portal/messages/{desk}", response_class=HTMLResponse)
def portal_channel(desk: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                   db: Session = Depends(get_db)):
    if desk not in DESKS:
        raise HTTPException(404)
    c = _portal_client(db, ident)
    ch = get_channel(db, c.id, desk)
    db.commit()
    messaging.mark_read(db, ch, "client")
    msgs = db.execute(select(Message).where(Message.channel_id == ch.id).order_by(Message.at)).scalars().all()
    return render(request, "portal_channel.html", user=ident.email, portal=True, client=c, desk=desk,
                  ch=ch, messages=msgs)


@app.post("/portal/messages/{desk}")
def portal_post(desk: str, body: str = Form(...), ident: auth.Identity = Depends(auth.require_client),
                db: Session = Depends(get_db)):
    if desk not in DESKS or not body.strip():
        raise HTTPException(400)
    c = _portal_client(db, ident)
    messaging.post(db, c, desk, "client", ident.email, body)
    return RedirectResponse(f"/portal/messages/{desk}", status_code=302)


# ---------------------------------------------------------------- platform API
@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    return {
        "module": "managed-services", "display_name": "Managed Services",
        "platform": "Vendetta Platform", "enabled": settings.module_enabled,
        "tools": {t: getattr(connectors.get(t), "configured", False) for t in TOOLS},
        "endpoints": ["/api/findings", "/api/module"],
    }


@app.get("/api/findings")
def api_findings(status: str = Query("active"), user: str = Depends(auth.api_user),
                 db: Session = Depends(get_db)):
    from . import hub as hub_mod
    q = select(Alert).options(selectinload(Alert.client), selectinload(Alert.device))
    if status == "active":
        q = q.where(Alert.status != "resolved")
    rows = db.execute(q.order_by(desc(Alert.updated_at)).limit(1000)).scalars().all()
    return [hub_mod.finding_dict(a) for a in rows]


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
