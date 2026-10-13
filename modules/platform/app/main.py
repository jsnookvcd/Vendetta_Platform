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
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from . import aggregate, auth, oidc, sso
from .config import TOOL_HINTS, TOOL_NAMES, TOOLS, settings
from .db import (AuditLog, Client, ClientModule, ClientTool, Module, SessionLocal, ToolConnection,
                 User, get_client_module, init_db, slugify, utcnow)

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(app_name=settings.app_name, TOOLS=TOOLS, TOOL_NAMES=TOOL_NAMES,
                             TOOL_HINTS=TOOL_HINTS)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax",
                   https_only=settings.cookie_secure)
app.include_router(oidc.router)

_STATUS_RANK = {"production": 0, "in-progress": 1, "planned": 2}


@app.on_event("startup")
def _startup():
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
    return await call_next(request)


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
    return render(request, "client.html", user=user, client=c, modules=modules, ov=ov,
                  enabled=enabled, tool_map=tool_map, ms_on=ms_on)


@app.post("/clients/{cid}/edit")
def edit_client(cid: str, industry: str = Form(""), portal_domains: str = Form(""),
                executive_emails: str = Form(""), active: bool = Form(False),
                user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    wanted = {d.strip().lower() for d in portal_domains.split(",") if d.strip()}
    # A portal domain must belong to one client only; two clients sharing a domain
    # would make portal sign-in ambiguous, so refuse it here at the source.
    clash = _domain_clash(db, cid, wanted)
    if clash:
        return _back(f"/clients/{cid}", False,
                     f"Portal domain {clash[0]} is already used by {clash[1]}. A domain belongs to one client.")
    # Normalise executive emails to a clean, lower-cased, comma-separated list.
    execs = ",".join(sorted({e.strip().lower() for e in executive_emails.split(",") if e.strip()}))
    c.industry, c.portal_domains, c.active = industry.strip(), portal_domains.strip(), active
    c.executive_emails = execs
    db.commit()
    _audit(db, user, "client.edit", c.name)
    return _back(f"/clients/{cid}", True, "Client saved.")


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
    return _back(f"/clients/{cid}", True, f"{TOOL_NAMES[tool]} mapping saved for {c.name}.")


# ---------------------------------------------------------------- connections
@app.get("/connections", response_class=HTMLResponse)
def connections(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    modules = _modules(db)
    ov = aggregate.overview([m for m in modules if m.base_url])
    tools = db.execute(select(ToolConnection).order_by(ToolConnection.display_name)).scalars().all()
    return render(request, "connections.html", user=user, modules=modules, ov=ov, tools=tools)


@app.post("/connections/module/{key}")
def save_module(key: str, base_url: str = Form(""), api_token: str = Form(""), status: str = Form(""),
                user: str = auth.RequireUser, db: Session = Depends(get_db)):
    m = db.get(Module, key)
    if not m:
        raise HTTPException(404)
    m.base_url = base_url.strip().rstrip("/")
    if api_token.strip():
        m.api_token = api_token.strip()
    if status in _STATUS_RANK:
        m.status = status
    db.commit()
    aggregate.clear_cache()
    _audit(db, user, "module.save", f"{key} -> {m.base_url or 'no url'}")
    return _back("/connections", True, f"{m.display_name} connection saved.")


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
                 "modules": sorted(enabled)}
        if not module or module == "managed-services":
            entry["tools"] = c.tool_map()
        out.append(entry)
    return {"module": module or "all", "clients": out}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    mods = db.execute(select(Module)).scalars().all()
    return {
        "module": "platform", "display_name": "Vendetta Platform", "role": "control-plane",
        "enabled": settings.module_enabled,
        "modules": {m.key: m.status for m in mods},
        "endpoints": ["/api/platform/clients", "/api/module"],
    }


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
