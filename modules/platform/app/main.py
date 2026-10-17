"""Vendetta Platform control plane: the front door.

The main screen is a launcher and a cross-module overview. Behind it the control
plane is the system of record for the client directory, which modules are turned
on per client, and how each client maps into the tools. Modules read their roster
and config from the provisioning API; the overview reads their live counts back."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from . import boot
from . import aggregate, auth, client360, directory, journey, notify, oidc, readiness as readiness_mod, sso, staff as staff_mod
from .config import TOOL_HINTS, TOOL_NAMES, TOOLS, settings
from .db import (AuditLog, Client, ClientModule, ClientTool, Communication, JourneyItem, Module, SessionLocal, Staff,
                 ToolConnection, User, get_client_module, init_db, slugify, utcnow)

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(app_name=settings.app_name, TOOLS=TOOLS, TOOL_NAMES=TOOL_NAMES,
                             TOOL_HINTS=TOOL_HINTS, TIERS=journey.TIERS, TIER_NAMES=journey.TIER_NAMES,
                             TIER_DEFAULTS=journey.TIER_DEFAULTS, AREAS=journey.AREAS,
                             STATUS_NAMES=journey.STATUS_NAMES, COMM_KIND_NAMES=journey.COMM_KIND_NAMES,
                             render_md=lambda s: Markup(journey.render_md(s)))
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax",
                   https_only=settings.cookie_secure)
app.include_router(oidc.router)

_STATUS_RANK = {"production": 0, "in-progress": 1, "planned": 2}


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0'>"
    "<div style='text-align:center'><h1 style='color:#e0122f'>Platform is turned off</h1></div></body>"
)


@app.middleware("http")
async def _gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path == "/healthz":
        return await call_next(request)
    if not settings.module_enabled and path != "/api/module":
        return HTMLResponse(_DISABLED_HTML, status_code=503)
    # Tenant boundary, gate half: a client-portal session reaches only the portal,
    # sign-in and sign-out. Every staff route and the service API also refuse a
    # client at the route itself (auth.current_user, auth.api_user).
    if request.cookies.get(auth.COOKIE) and not _portal_open(path):
        ident = auth.resolve_identity(request)
        if ident and ident.is_client:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "client portal only"}, status_code=403)
            return RedirectResponse("/portal", status_code=302)
    return await call_next(request)


def _portal_open(path: str) -> bool:
    return path == "/portal" or path.startswith(("/portal/", "/auth/", "/logout"))


@app.middleware("http")
async def _headers(request: Request, call_next):
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


def render(request: Request, name: str, **ctx):
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    return templates.TemplateResponse(request, name, ctx)


def _back(url: str, ok: bool, message: str) -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}{'msg' if ok else 'err'}={quote(message[:300])}", status_code=302)


def _modules(db: Session) -> list[Module]:
    return sorted(db.execute(select(Module)).scalars().all(),
                  key=lambda m: (m.position, m.display_name))


# ---------------------------------------------------------------- login
_login_hits: dict[str, list[float]] = {}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso_status: str = Query("", alias="sso")):
    m = {"failed": "Microsoft sign-in did not complete.", "denied": "That account is not permitted."}.get(sso_status, "")
    return render(request, "login.html", next=next, error=m, oidc_enabled=sso.enabled())


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
          db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < settings.login_window_seconds]
    _login_hits[ip] = hits
    if len(hits) >= settings.login_max_attempts:
        return render(request, "login.html", next=next, error="Too many attempts.", oidc_enabled=sso.enabled())
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(next or "/", status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_hits.setdefault(ip, []).append(now)
    _audit(db, username, "login.failed", ip)
    return render(request, "login.html", next=next, error="Invalid credentials", oidc_enabled=sso.enabled())


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------------------------------------------------------------- main screen
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    clients = db.execute(select(Client).options(selectinload(Client.modules), selectinload(Client.tools))
                         .where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    tools = db.execute(select(ToolConnection)).scalars().all()
    # roll-ups
    live = [m for m in modules if ov.get(m.key, {}).get("reachable")]
    total_open = sum((ov[m.key]["open"] or 0) for m in live if ov[m.key].get("open") is not None)
    total_crit = sum(ov[m.key]["critical"] for m in live if ov[m.key].get("open") is not None)
    tools_ok = sum(1 for t in tools if t.configured)
    enabled_counts = {m.key: 0 for m in modules}
    for c in clients:
        for k in c.enabled_modules():
            enabled_counts[k] = enabled_counts.get(k, 0) + 1
    return render(request, "dashboard.html", user=user, modules=modules, ov=ov, clients=clients,
                  tools=tools, total_open=total_open, total_crit=total_crit, tools_ok=tools_ok,
                  n_clients=len(clients), live=len(live), enabled_counts=enabled_counts)


@app.post("/refresh")
def refresh(user: str = auth.RequireUser):
    aggregate.clear_cache()
    return _back("/", True, "Overview refreshed.")


# ---------------------------------------------------------------- go-live readiness
@app.get("/readiness", response_class=HTMLResponse)
def readiness_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    report = readiness_mod.assess(modules, ov)
    return render(request, "readiness.html", user=user, report=report)


@app.get("/api/platform/readiness")
def api_readiness(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    return readiness_mod.assess(modules, ov)


# ---------------------------------------------------------------- clients
@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).options(selectinload(Client.modules), selectinload(Client.tools))
                      .order_by(Client.name)).scalars().all()
    return render(request, "clients.html", user=user, clients=rows, modules=_modules(db))


@app.post("/clients")
def add_client(name: str = Form(...), industry: str = Form(""), user: str = auth.RequireUser,
               db: Session = Depends(get_db)):
    name = name.strip()
    if db.query(Client).filter(func.lower(Client.name) == name.lower()).count():
        return _back("/clients", False, "A client with that name already exists.")
    slug = slugify(name)
    n = 2
    while db.query(Client).filter_by(slug=slug).count():
        slug = f"{slugify(name)}-{n}"
        n += 1
    c = Client(name=name, slug=slug, industry=industry.strip())
    db.add(c)
    db.commit()
    _audit(db, user, "client.add", name)
    directory.push_sync(db)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


def _get_client(db: Session, cid: str) -> Client:
    c = db.execute(select(Client).options(selectinload(Client.modules), selectinload(Client.tools))
                   .where(Client.id == cid)).scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    return c


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_page(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    enabled = c.enabled_modules()
    tool_map = {t.tool_key: t for t in c.tools}
    ms_on = "managed-services" in enabled
    c360 = client360.build(db, c, modules)
    ident = auth.require_identity(request)
    return render(request, "client.html", user=user, client=c, modules=modules, ov=ov,
                  enabled=enabled, tool_map=tool_map, ms_on=ms_on, c360=c360,
                  journey_items=journey.items_for(db, c.id), comms=journey.comms_for(db, c.id),
                  can_approve=journey.may_approve(ident, c), staff_emails=_staff_emails(db))


def _staff_emails(db: Session) -> list[str]:
    return [p.email for p in db.execute(select(Staff).where(Staff.active.is_(True)).order_by(Staff.email)).scalars()]


@app.post("/clients/{cid}/edit")
def edit_client(cid: str, request: Request, industry: str = Form(""), portal_domains: str = Form(""),
                executive_emails: str = Form(""), active: bool = Form(False),
                tier: str | None = Form(None), account_lead: str | None = Form(None),
                critical_ack_minutes: str | None = Form(None), critical_contain_minutes: str | None = Form(None),
                portal_enabled: str | None = Form(None),
                user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Saves the fields the form sent. Tier, lead, commitments and the portal switch
    are on the client page form; a caller that omits them leaves them unchanged."""
    c = _get_client(db, cid)
    wanted = {d.strip().lower() for d in portal_domains.split(",") if d.strip()}
    # A portal domain must belong to one client only; two clients sharing a domain
    # would make portal sign-in ambiguous, so refuse it here at the source.
    clash = _domain_clash(db, cid, wanted)
    if clash:
        return _back(f"/clients/{cid}", False,
                     f"Portal domain {clash[0]} is already used by {clash[1]}. A domain belongs to one client.")
    try:
        new_tier = journey.clean_tier(tier) if tier is not None else c.tier
        ack = journey.clean_minutes(critical_ack_minutes) if critical_ack_minutes is not None else c.critical_ack_minutes
        contain = (journey.clean_minutes(critical_contain_minutes) if critical_contain_minutes is not None
                   else c.critical_contain_minutes)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    lead = c.account_lead
    if account_lead is not None:
        wanted_lead = staff_mod.normalize_email(account_lead)
        if wanted_lead != (c.account_lead or ""):
            # The account lead approves client communications, so only a platform
            # admin may change who it is. An analyst may still edit the other fields.
            if auth.require_identity(request).role != "admin":
                return _back(f"/clients/{cid}", False,
                             "Only a platform admin can change the account lead. Nothing was saved.")
            if wanted_lead and "@" not in wanted_lead:
                return _back(f"/clients/{cid}", False, "The account lead is the Vendetta person's work email.")
            if wanted_lead:
                person = staff_mod.lookup(db, wanted_lead)
                if person is None or not person.active:
                    return _back(f"/clients/{cid}", False,
                                 f"{wanted_lead} is not an active person on the staff roster. "
                                 "The account lead must be on the roster.")
        lead = wanted_lead
    # Normalise executive emails to a clean, lower-cased, comma-separated list.
    execs = ",".join(sorted({e.strip().lower() for e in executive_emails.split(",") if e.strip()}))
    c.industry, c.portal_domains, c.active = industry.strip(), portal_domains.strip(), active
    c.executive_emails = execs
    c.tier, c.account_lead = new_tier, lead
    c.critical_ack_minutes, c.critical_contain_minutes = ack, contain
    if portal_enabled is not None:
        c.portal_enabled = portal_enabled == "true"
    db.commit()
    _audit(db, user, "client.edit", f"{c.name} tier={c.tier} lead={c.account_lead or 'none'} "
           f"portal={'on' if c.portal_enabled else 'off'}")
    directory.push_sync(db, keys=c.enabled_modules())
    return _back(f"/clients/{cid}", True, "Client saved. Modules are being told to sync.")


def _domain_clash(db: Session, cid: str, wanted: set[str]) -> tuple[str, str] | None:
    """Return (domain, other client name) if any wanted portal domain is already
    used by a different active client, else None."""
    if not wanted:
        return None
    for other in db.execute(select(Client).where(Client.id != cid, Client.active.is_(True))).scalars().all():
        theirs = {d.strip().lower() for d in (other.portal_domains or "").split(",") if d.strip()}
        overlap = wanted & theirs
        if overlap:
            return sorted(overlap)[0], other.name
    return None


@app.post("/clients/{cid}/modules/{key}")
def toggle_module(cid: str, key: str, enabled: bool = Form(False), user: str = auth.RequireUser,
                  db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    if not db.get(Module, key):
        raise HTTPException(404)
    cm = get_client_module(db, cid, key)
    if cm is None:
        cm = ClientModule(client_id=cid, module_key=key)
        db.add(cm)
    cm.enabled = enabled
    cm.activated_by = user
    cm.activated_at = utcnow()
    db.commit()
    _audit(db, user, "client.module", f"{c.name} {key} {'on' if enabled else 'off'}")
    directory.push_sync(db, keys={key, "incident-response"})
    return _back(f"/clients/{cid}", True, f"{key} {'activated' if enabled else 'deactivated'} for {c.name}.")


@app.post("/clients/{cid}/tool/{tool}")
def map_tool(cid: str, tool: str, tenancy: str = Form(""), enabled: bool = Form(False),
             user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    if tool not in TOOLS:
        raise HTTPException(404)
    row = db.query(ClientTool).filter_by(client_id=cid, tool_key=tool).one_or_none()
    if row is None:
        row = ClientTool(client_id=cid, tool_key=tool)
        db.add(row)
    row.tenancy = tenancy.strip()
    row.enabled = enabled and bool(tenancy.strip())
    row.updated_at = utcnow()
    db.commit()
    _audit(db, user, "client.tool", f"{c.name} {tool} {'mapped' if row.enabled else 'cleared'}")
    directory.push_sync(db, keys={"managed-services"})
    return _back(f"/clients/{cid}", True, f"{TOOL_NAMES[tool]} mapping saved for {c.name}.")


@app.post("/clients/{cid}/refresh-360")
def refresh_360(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    _get_client(db, cid)
    client360.clear_cache()
    return _back(f"/clients/{cid}", True, "Client 360 refreshed.")


# ---------------------------------------------------------------- Security Journey (staff)
def _journey_item(db: Session, cid: str, iid: str) -> tuple[Client, JourneyItem]:
    c = _get_client(db, cid)
    item = db.get(JourneyItem, iid)
    if not item or item.client_id != c.id:
        raise HTTPException(404)
    return c, item


@app.post("/clients/{cid}/journey")
def journey_add(cid: str, title: str = Form(""), detail: str = Form(""), area: str = Form(""),
                due_on: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """A person adding an item has already agreed to it, so it starts planned."""
    c = _get_client(db, cid)
    try:
        item, _ = journey.create_item(db, c, title=title, detail=detail, area=area, due_on=due_on,
                                      source="staff", status="planned", actor=user)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}#journey", False, e.detail)
    _audit(db, user, "journey.add", f"{c.name}: {item.title} [{item.area}]")
    return _back(f"/clients/{cid}", True, "Journey item added.")


@app.post("/clients/{cid}/journey/{iid}/accept")
def journey_accept(cid: str, iid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c, item = _journey_item(db, cid, iid)
    try:
        journey.decide_item(db, item, True, user)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    _audit(db, user, "journey.accept", f"{c.name}: {item.title}")
    return _back(f"/clients/{cid}", True, f"Accepted: {item.title}.")


@app.post("/clients/{cid}/journey/{iid}/decline")
def journey_decline(cid: str, iid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c, item = _journey_item(db, cid, iid)
    try:
        journey.decide_item(db, item, False, user)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    _audit(db, user, "journey.decline", f"{c.name}: {item.title}")
    return _back(f"/clients/{cid}", True, f"Declined: {item.title}.")


@app.post("/clients/{cid}/journey/{iid}/status")
def journey_status(cid: str, iid: str, status: str = Form(""), user: str = auth.RequireUser,
                   db: Session = Depends(get_db)):
    c, item = _journey_item(db, cid, iid)
    try:
        journey.set_status(db, item, status, user)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    _audit(db, user, "journey.status", f"{c.name}: {item.title} -> {status}")
    return _back(f"/clients/{cid}", True, f"{item.title}: {journey.STATUS_NAMES[status].lower()}.")


@app.post("/clients/{cid}/journey/{iid}/edit")
def journey_edit(cid: str, iid: str, title: str = Form(""), detail: str = Form(""), area: str = Form(""),
                 due_on: str = Form(""), note: str = Form(""), user: str = auth.RequireUser,
                 db: Session = Depends(get_db)):
    c, item = _journey_item(db, cid, iid)
    try:
        journey.edit_item(db, item, title=title, detail=detail, area=area, due_on=due_on, note=note)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    _audit(db, user, "journey.edit", f"{c.name}: {item.title}")
    return _back(f"/clients/{cid}", True, "Journey item saved.")


# ---------------------------------------------------------------- communications (staff)
def _comm(db: Session, cid: str, mid: str) -> tuple[Client, Communication]:
    c = _get_client(db, cid)
    m = db.get(Communication, mid)
    if not m or m.client_id != c.id:
        raise HTTPException(404)
    return c, m


def _approver(request: Request, client: Client) -> str:
    """The one approval point: the client's account lead or a platform admin."""
    ident = auth.require_internal(request)
    auth.require_write(request, ident)
    if not journey.may_approve(ident, client):
        raise HTTPException(403, "only this client's account lead or a platform admin can approve, edit or "
                                 "discard a communication")
    return ident.email


@app.get("/communications", response_class=HTMLResponse)
def comms_inbox(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Drafts waiting for a person across every client, oldest first."""
    rows = db.execute(select(Communication, Client).join(Client, Client.id == Communication.client_id)
                      .where(Communication.status == "draft")
                      .order_by(Communication.created_at)).all()
    ident = auth.require_identity(request)
    now = utcnow()
    drafts = [{"m": m, "client": c, "age_days": (now - m.created_at).days,
               "mine": journey.may_approve(ident, c)} for m, c in rows]
    recent = db.execute(select(Communication, Client).join(Client, Client.id == Communication.client_id)
                        .where(Communication.status != "draft")
                        .order_by(Communication.decided_at.desc().nullslast()).limit(20)).all()
    return render(request, "communications.html", user=user, drafts=drafts, recent=recent,
                  stale_days=journey.STALE_DRAFT_DAYS)


@app.get("/clients/{cid}/communications/{mid}", response_class=HTMLResponse)
def comm_page(cid: str, mid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c, m = _comm(db, cid, mid)
    ident = auth.require_identity(request)
    return render(request, "communication.html", user=user, client=c, m=m,
                  can_approve=journey.may_approve(ident, c), recipients=sorted(c.executive_set()),
                  mail_ready=notify.can_send())


@app.post("/clients/{cid}/communications/{mid}/edit")
def comm_edit(cid: str, mid: str, request: Request, title: str = Form(""), subject: str = Form(""),
              body_md: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c, m = _comm(db, cid, mid)
    actor = _approver(request, c)
    try:
        journey.edit_comm(db, m, title=title, subject=subject, body_md=body_md)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}/communications/{mid}", False, e.detail)
    _audit(db, actor, "comm.edit", f"{c.name}: {m.title}")
    return _back(f"/clients/{cid}/communications/{mid}", True, "Draft saved.")


@app.post("/clients/{cid}/communications/{mid}/approve")
def comm_approve(cid: str, mid: str, request: Request, title: str | None = Form(None),
                 subject: str | None = Form(None), body_md: str | None = Form(None),
                 user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Approve (with any last edits from the same form): published to the client
    portal and emailed to the executives when mail is configured."""
    c, m = _comm(db, cid, mid)
    actor = _approver(request, c)
    try:
        if title is not None or subject is not None or body_md is not None:
            journey.edit_comm(db, m, title=title, subject=subject, body_md=body_md)
        journey.approve_comm(db, c, m, actor)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}/communications/{mid}", False, e.detail)
    _audit(db, actor, "comm.approve", f"{c.name}: {m.title} status={m.status}; {m.sent_detail}")
    return _back(f"/clients/{cid}/communications/{mid}", True,
                 "Approved and published to the portal. " + ("Emailed to the executives." if m.status == "sent"
                                                             else m.sent_detail.capitalize() + "."))


@app.post("/clients/{cid}/communications/{mid}/discard")
def comm_discard(cid: str, mid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c, m = _comm(db, cid, mid)
    actor = _approver(request, c)
    try:
        journey.discard_comm(db, m, actor)
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}/communications/{mid}", False, e.detail)
    _audit(db, actor, "comm.discard", f"{c.name}: {m.title}")
    return _back(f"/clients/{cid}", True, f"Discarded: {m.title}.")


@app.post("/clients/{cid}/communications")
def comm_add(cid: str, kind: str = Form("outreach"), title: str = Form(""), subject: str = Form(""),
             body_md: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    try:
        m, _ = journey.create_comm(db, c, kind=kind, title=title, subject=subject, body_md=body_md, source="staff")
    except journey.JourneyError as e:
        return _back(f"/clients/{cid}", False, e.detail)
    _audit(db, user, "comm.draft", f"{c.name}: {m.kind} {m.title}")
    return RedirectResponse(f"/clients/{cid}/communications/{m.id}", status_code=302)


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    """The signed-in client's own record, only while it is active with the portal on."""
    c = db.execute(select(Client).options(selectinload(Client.modules))
                   .where(Client.id == ident.client_id)).scalar_one_or_none()
    if not c or not c.active or not c.portal_enabled:
        raise HTTPException(404, "not found")
    return c


def _service_tiles(db: Session, c: Client) -> list[dict]:
    enabled = c.enabled_modules()
    tiles = []
    for m in _modules(db):
        if m.key in enabled and m.has_portal and m.public_url and m.status != "planned":
            tiles.append({"key": m.key, "name": m.display_name, "url": f"{m.public_url.rstrip('/')}/portal"})
    return tiles


@app.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    items = journey.items_for(db, c.id, statuses=journey.PORTAL_STATUSES)
    comms = journey.comms_for(db, c.id, published_only=True)
    return render(request, "portal.html", portal_user=ident.email, client=c, exec_view=ident.is_executive,
                  commitments=c.commitments(), tiles=_service_tiles(db, c), items=items, comms=comms)


@app.get("/portal/communications/{mid}", response_class=HTMLResponse)
def portal_comm(mid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    m = db.get(Communication, mid)
    auth.require_owned(ident, m, extra=bool(m and m.published))
    return render(request, "portal_communication.html", portal_user=ident.email, client=c, m=m,
                  exec_view=ident.is_executive)


# ---------------------------------------------------------------- connections
@app.get("/connections", response_class=HTMLResponse)
def connections(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    tools = db.execute(select(ToolConnection).order_by(ToolConnection.display_name)).scalars().all()
    return render(request, "connections.html", user=user, modules=modules, ov=ov, tools=tools,
                  env_dir=directory.env_directory(), last_push=directory.LAST_PUSH)


@app.post("/connections/module/{key}")
def save_module(key: str, base_url: str = Form(""), api_token: str = Form(""), status: str = Form(""),
                public_url: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    m = db.get(Module, key)
    if not m:
        raise HTTPException(404)
    m.base_url = base_url.strip().rstrip("/")
    m.public_url = public_url.strip().rstrip("/")
    if api_token.strip():
        m.api_token = api_token.strip()
    if status in _STATUS_RANK:
        m.status = status
    db.commit()
    aggregate.clear_cache()
    _audit(db, user, "module.save", f"{key} -> {m.base_url or 'no url'}")
    return _back("/connections", True, f"{m.display_name} connection saved.")


@app.post("/connections/apply-directory")
def apply_directory(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Overwrite module endpoints and tokens with the deployment's MODULE_DIRECTORY."""
    if not directory.env_directory():
        return _back("/connections", False, "MODULE_DIRECTORY is not set in this deployment.")
    n = directory.apply_env_directory(db, force=True)
    aggregate.clear_cache()
    _audit(db, user, "module.directory", f"applied to {n} module(s)")
    return _back("/connections", True, f"Deployment directory applied to {n} module(s).")


@app.post("/connections/push")
def push_roster(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Tell every connected module to pull the roster now and show the result."""
    res = directory.push_sync(db, wait=True)
    if not res:
        return _back("/connections", False, "No module has a base URL yet.")
    bad = [k for k, r in res.items() if not r["ok"]]
    _audit(db, user, "roster.push", f"{len(res)} pushed, {len(bad)} failed")
    if bad:
        return _back("/connections", False, f"Pushed to {len(res)} module(s); failed: {', '.join(bad)}.")
    return _back("/connections", True, f"Roster pushed to {len(res)} module(s).")


@app.post("/connections/refresh")
def refresh_tools(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Refresh each tool's configured state from what managed-services reports."""
    aggregate.clear_cache()
    ms = db.get(Module, "managed-services")
    updated = 0
    if ms and ms.base_url:
        tools_state = aggregate.probe_module(ms, force=True).get("tools") or {}
        for key, ok in tools_state.items():
            tc = db.get(ToolConnection, key)
            if tc:
                tc.configured = bool(ok)
                tc.detail = "reported by managed-services"
                tc.checked_at = utcnow()
                updated += 1
        db.commit()
    return _back("/connections", True, f"Tool health refreshed ({updated} reported)." if updated
                 else "managed-services is not connected yet; set its endpoint first.")


# ---------------------------------------------------------------- settings
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n_users = db.scalar(select(func.count(User.id))) or 0
    scfg = sso.resolve()
    cfg = {
        "module_enabled": settings.module_enabled,
        "sso": (f"Entra ID tenant {scfg['tenant_id']} ({scfg['source']})" if sso.enabled()
                else "off (local admin login)"),
        "probe_cache": settings.probe_cache_seconds,
    }
    return render(request, "settings.html", user=user, cfg=cfg, api_token=auth.api_token(), n_users=n_users)


# ---------------------------------------------------------------- SSO configuration
@app.get("/settings/sso", response_class=HTMLResponse)
def sso_page(request: Request, user: str = auth.RequireUser):
    q = request.query_params
    msg = err = ""
    st = sso.status()
    if q.get("ok"):
        msg = f"Microsoft 365 SSO verified. {st['last_detail']}".strip()
    elif q.get("testfail"):
        err = f"SSO saved but the test failed: {st['last_detail']}".strip()
    elif q.get("saved"):
        msg = "SSO settings saved."
    return render(request, "sso.html", user=user, st=st, msg=msg, err=err)


@app.post("/settings/sso")
async def sso_save(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    form = await request.form()
    values = {k: (form.get(k) or "") for k in
              ("tenant_id", "client_id", "client_secret", "redirect_url", "allowed_group",
               "allowed_emails", "internal_email_domains", "admin_emails")}
    values["enabled"] = form.get("enabled") == "true"
    sso.save(values, user)
    _audit(db, user, "sso.save", f"tenant={values['tenant_id']} enabled={values['enabled']}")
    # Test immediately so saving and verifying are one action.
    ok, detail = sso.test()
    sso.set_status(ok, detail)
    _audit(db, user, "sso.test", f"{'ok' if ok else 'fail'}: {detail}")
    return RedirectResponse(f"/settings/sso?{'ok' if ok else 'testfail'}=1", status_code=302)


@app.post("/settings/sso/test")
def sso_test(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ok, detail = sso.test()
    sso.set_status(ok, detail)
    _audit(db, user, "sso.test", f"{'ok' if ok else 'fail'}: {detail}")
    return RedirectResponse(f"/settings/sso?{'ok' if ok else 'testfail'}=1", status_code=302)


# ---------------------------------------------------------------- staff
def _require_admin(request: Request) -> str:
    """Staff management is admin-only: the break-glass admin, a platform admin by
    SSO, or (once the roster governs) a person whose platform role is admin."""
    ident = auth.require_internal(request)
    if ident.role != "admin":
        raise HTTPException(403, "only a platform admin can manage staff")
    return ident.email


RequireAdmin = Depends(_require_admin)


def _get_staff(db: Session, sid: str) -> Staff:
    p = db.execute(select(Staff).options(selectinload(Staff.grants)).where(Staff.id == sid)).scalar_one_or_none()
    if not p:
        raise HTTPException(404)
    return p


def _welcome(db: Session, person: Staff, actor: str, *, reactivated: bool = False) -> None:
    """Send the onboarding note with a console link for every module the person
    was granted, and record the attempt in the audit log. Never raises."""
    consoles: list[tuple[str, str, str]] = []
    if settings.public_url:
        consoles.append(("Vendetta Platform", person.platform_role, settings.public_url.rstrip("/")))
    grants = staff_mod.grant_map(person)
    for m in _modules(db):
        g = grants.get(m.key)
        if g and g.role != "none" and m.public_url:
            consoles.append((m.display_name, g.role, m.public_url.rstrip("/")))
    subject, body = notify.welcome_message(person, consoles, reactivated=reactivated)
    ok, detail = notify.send(person.email, subject, body)
    _audit(db, actor, "staff.invite", f"{person.email} {'sent' if ok else 'not sent'} ({detail}); "
           f"consoles={','.join(c[0] for c in consoles) or 'none'}")


def _staff_pushed(db: Session, person: Staff) -> None:
    """A staff change reaches the modules the same way a client change does."""
    directory.push_sync(db, keys=staff_mod.modules_affected(person) or None)
    # The platform's own login table mirrors the staff row so a deactivation ends
    # an existing session here too.
    u = db.execute(select(User).where(User.email == person.email)).scalar_one_or_none()
    if u:
        u.active = person.active
        u.role = person.platform_role
        db.commit()


@app.get("/staff", response_class=HTMLResponse)
def staff_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    people = db.execute(select(Staff).options(selectinload(Staff.grants))
                        .order_by(Staff.active.desc(), Staff.name, Staff.email)).scalars().all()
    ident = auth.require_identity(request)
    return render(request, "staff.html", user=user, people=people, profiles=staff_mod.PROFILES,
                  modules=[m for m in _modules(db) if m.key in staff_mod.GRANTABLE],
                  is_admin=ident.role == "admin", governs=staff_mod.governs(db),
                  internal_domains=sso.resolve()["internal_email_domains"])


@app.post("/staff")
def staff_add(email: str = Form(...), name: str = Form(""), title: str = Form(""), profile: str = Form("soc-analyst"),
              user: str = RequireAdmin, db: Session = Depends(get_db)):
    email = staff_mod.normalize_email(email)
    if "@" not in email:
        return _back("/staff", False, "Enter the person's work email.")
    if profile not in staff_mod.PROFILES:
        return _back("/staff", False, "Pick an access profile.")
    if staff_mod.lookup(db, email):
        return _back("/staff", False, f"{email} is already on the roster.")
    p = Staff(email=email, name=name.strip(), title=title.strip(), invited_by=user)
    db.add(p)
    db.flush()
    staff_mod.apply_profile(db, p, profile)
    db.commit()
    _audit(db, user, "staff.add", f"{email} profile={profile}")
    _staff_pushed(db, p)
    _welcome(db, p, user)
    return RedirectResponse(f"/staff/{p.id}?msg={quote('Onboarded. Modules are being told and a welcome note is on its way.')}",
                            status_code=302)


@app.get("/staff/{sid}", response_class=HTMLResponse)
def staff_detail(sid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    p = _get_staff(db, sid)
    ident = auth.require_identity(request)
    mods = [m for m in _modules(db) if m.key in staff_mod.GRANTABLE]
    return render(request, "staff_detail.html", user=user, person=p, grants=staff_mod.grant_map(p),
                  profiles=staff_mod.PROFILES, modules=mods, roles=staff_mod.MODULE_ROLES,
                  is_admin=ident.role == "admin", last_push=directory.LAST_PUSH)


@app.post("/staff/{sid}/edit")
def staff_edit(sid: str, name: str = Form(""), title: str = Form(""), platform_role: str = Form("analyst"),
               notes: str = Form(""), user: str = RequireAdmin, db: Session = Depends(get_db)):
    p = _get_staff(db, sid)
    if platform_role not in staff_mod.PLATFORM_ROLES:
        raise HTTPException(400)
    p.name, p.title, p.platform_role, p.notes = name.strip(), title.strip(), platform_role, notes.strip()
    p.updated_at = utcnow()
    db.commit()
    _audit(db, user, "staff.edit", f"{p.email} platform_role={platform_role}")
    _staff_pushed(db, p)
    return _back(f"/staff/{sid}", True, "Saved.")


@app.post("/staff/{sid}/profile")
def staff_profile(sid: str, profile: str = Form(...), user: str = RequireAdmin, db: Session = Depends(get_db)):
    p = _get_staff(db, sid)
    if profile not in staff_mod.PROFILES:
        raise HTTPException(400)
    staff_mod.apply_profile(db, p, profile)
    db.commit()
    _audit(db, user, "staff.profile", f"{p.email} -> {profile}")
    _staff_pushed(db, p)
    return _back(f"/staff/{sid}", True, f"{staff_mod.PROFILES[profile][0]} profile applied.")


@app.post("/staff/{sid}/grant/{key}")
def staff_grant(sid: str, key: str, role: str = Form("none"), can_act: bool = Form(False),
                can_approve: bool = Form(False), user: str = RequireAdmin, db: Session = Depends(get_db)):
    p = _get_staff(db, sid)
    cfg = {"can_act": bool(can_act), "can_approve": bool(can_approve)} if key == "managed-services" else {}
    try:
        staff_mod.set_grant(db, p, key, role, cfg)
    except ValueError:
        raise HTTPException(400)
    db.commit()
    _audit(db, user, "staff.grant", f"{p.email} {key}={role} {cfg or ''}".strip())
    directory.push_sync(db, keys={key})
    return _back(f"/staff/{sid}", True, f"{key}: {role}.")


@app.post("/staff/{sid}/active")
def staff_active(sid: str, active: bool = Form(False), user: str = RequireAdmin, db: Session = Depends(get_db)):
    p = _get_staff(db, sid)
    if p.email == user and not active:
        return _back(f"/staff/{sid}", False, "You cannot deactivate yourself.")
    p.active = bool(active)
    p.deactivated_at = None if active else utcnow()
    p.updated_at = utcnow()
    db.commit()
    _audit(db, user, "staff.active", f"{p.email} {'reactivated' if active else 'deactivated'}")
    _staff_pushed(db, p)
    if active:
        _welcome(db, p, user, reactivated=True)
    return _back(f"/staff/{sid}", True, "Reactivated. Modules are being told." if active
                 else "Deactivated. Every module is being told; sessions end on their next request.")


@app.get("/api/platform/staff")
def api_staff(module: str = "", user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """What a module pulls to learn who may sign in and at what level. With
    ?module=<key>, the active people granted that module, each with role and the
    module-specific config (managed services: can_act, can_approve). `governs` tells
    the module whether a roster exists at all: once it does, the module admits
    internal sign-ins only from this list."""
    if module:
        return {"module": module, "governs": staff_mod.governs(db), "staff": staff_mod.roster_for_module(db, module)}
    return {"module": "all", "governs": staff_mod.governs(db), "staff": staff_mod.roster_all(db)}


# ---------------------------------------------------------------- provisioning API
@app.get("/api/platform/clients")
def provision_clients(module: str = "", user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """What a module pulls to learn its roster and per-client config. With
    ?module=<key>, returns only clients that have that module enabled. For
    managed-services, each client carries its tool tenancy mapping."""
    q = select(Client).options(selectinload(Client.modules), selectinload(Client.tools)).where(Client.active.is_(True))
    rows = db.execute(q.order_by(Client.name)).scalars().all()
    out = []
    for c in rows:
        enabled = c.enabled_modules()
        if module and module not in enabled:
            continue
        entry = {"id": c.id, "name": c.name, "slug": c.slug, "industry": c.industry,
                 "portal_domains": c.portal_domains, "executive_emails": c.executive_emails,
                 "modules": sorted(enabled), "services": sorted(enabled),
                 "tier": c.tier or "core", "account_lead": c.account_lead or "",
                 "commitments": c.commitments()}
        if not module or module == "managed-services":
            entry["tools"] = c.tool_map()
        out.append(entry)
    return {"module": module or "all", "clients": out}


# ---------------------------------------------------------------- journey and communications API
def _api_client(db: Session, pid: str) -> Client:
    c = db.get(Client, pid)
    if not c:
        raise HTTPException(404, "unknown client")
    return c


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    return body


def _rule(e: journey.JourneyError):
    raise HTTPException(e.status, e.detail)


@app.get("/api/platform/clients/{pid}/journey")
def api_journey(pid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    c = _api_client(db, pid)
    return {"client": {"id": c.id, "name": c.name},
            "items": [journey.item_dict(i) for i in journey.items_for(db, c.id)]}


@app.post("/api/platform/clients/{pid}/journey")
async def api_journey_add(pid: str, request: Request, user: str = Depends(auth.api_user),
                          db: Session = Depends(get_db)):
    """A proposal. Idempotent on (client, source_ref) when source_ref is set, so
    SABINE can raise the same evidence every cycle without duplicating it."""
    c = _api_client(db, pid)
    body = await _json_body(request)
    try:
        item, created = journey.create_item(
            db, c, title=str(body.get("title") or ""), detail=str(body.get("detail") or ""),
            area=str(body.get("area") or ""), source_ref=str(body.get("source_ref") or ""),
            due_on=body.get("due_on"), source=journey.source_for(user), status="proposed")
    except journey.JourneyError as e:
        _rule(e)
    if created:
        _audit(db, user, "journey.propose", f"{c.name}: {item.title} [{item.area}] ref={item.source_ref or '-'}")
    return {"id": item.id, "created": created}


@app.post("/api/platform/clients/{pid}/journey/{item_id}/progress")
async def api_journey_progress(pid: str, item_id: str, request: Request, user: str = Depends(auth.api_user),
                               db: Session = Depends(get_db)):
    c = _api_client(db, pid)
    item = db.get(JourneyItem, item_id)
    if not item or item.client_id != c.id:
        raise HTTPException(404, "unknown journey item")
    body = await _json_body(request)
    try:
        journey.progress_item(db, item, str(body.get("status") or ""), str(body.get("note") or ""))
    except journey.JourneyError as e:
        _rule(e)
    _audit(db, user, "journey.progress", f"{c.name}: {item.title} -> {item.status}"
           f" ref={body.get('source_ref') or '-'}")
    return {"id": item.id, "status": item.status}


@app.get("/api/platform/clients/{pid}/communications")
def api_comms(pid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    c = _api_client(db, pid)
    return {"items": [journey.comm_dict(m) for m in journey.comms_for(db, c.id)]}


@app.post("/api/platform/clients/{pid}/communications")
async def api_comm_add(pid: str, request: Request, user: str = Depends(auth.api_user),
                       db: Session = Depends(get_db)):
    """A draft for a person to approve. Idempotent on (client, source_ref)."""
    c = _api_client(db, pid)
    body = await _json_body(request)
    try:
        m, created = journey.create_comm(
            db, c, kind=str(body.get("kind") or ""), title=str(body.get("title") or ""),
            subject=str(body.get("subject") or ""), body_md=str(body.get("body_md") or ""),
            source_ref=str(body.get("source_ref") or ""), source=journey.source_for(user))
    except journey.JourneyError as e:
        _rule(e)
    if created:
        _audit(db, user, "comm.draft", f"{c.name}: {m.kind} {m.title} ref={m.source_ref or '-'}")
    return {"id": m.id, "created": created}


@app.get("/api/platform/clients/{pid}/360")
def api_client_360(pid: str, refresh: bool = False, user: str = Depends(auth.api_user),
                   db: Session = Depends(get_db)):
    c = _get_client(db, pid)
    return client360.build(db, c, _modules(db), force=refresh)


@app.get("/api/platform/modules")
def platform_modules(module: str = "", user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """The module directory, scoped to the caller. The caller names itself in
    `module` and receives only the modules it is allowed to reach, with base URL
    and bearer token: the incident-response hub gets the finding-serving modules
    it pulls from (registry.DIRECTORY_CONSUMERS), so finding sources are configured
    once here (on the Connections page) rather than duplicated in the hub's own
    config. Any other caller is refused; SABINE has its own MODULE_DIRECTORY."""
    from .registry import DIRECTORY_CONSUMERS

    if not module:
        raise HTTPException(400, "name the consuming module: ?module=incident-response")
    allowed = DIRECTORY_CONSUMERS.get(module)
    if allowed is None:
        raise HTTPException(403, f"the module directory is not served to {module}")
    rows = db.execute(select(Module).where(Module.key.in_(allowed))).scalars().all()
    out = []
    for m in rows:
        if not m.base_url or m.status == "planned":
            continue
        out.append({"name": m.key, "display_name": m.display_name,
                    "base_url": m.base_url, "token": m.api_token, "public_url": m.public_url,
                    "findings_path": "/api/findings"})
    return {"modules": out}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    mods = db.execute(select(Module)).scalars().all()
    return {
        "module": "platform", "display_name": "Vendetta Platform", "role": "control-plane",
        "enabled": settings.module_enabled,
        "modules": {m.key: m.status for m in mods},
        "public_url": settings.public_url,
        "endpoints": ["/api/platform/clients", "/api/platform/staff", "/api/platform/modules",
                      "/api/platform/readiness", "/api/platform/clients/{pid}/journey",
                      "/api/platform/clients/{pid}/communications", "/api/platform/clients/{pid}/360",
                      "/api/module"],
    }


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
