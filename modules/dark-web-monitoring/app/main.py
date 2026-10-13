"""Analyst console and JSON API."""
from __future__ import annotations

import datetime as dt
import io
import logging

from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session, selectinload

from . import auth, evidence, iab, oidc, platform, profiles, report as report_mod
from .config import settings
from .db import AuditLog, Client, Evidence, Hit, Item, SessionLocal, Source, WatchTerm, init_db
from .fetch import fetch, html_to_text, tor_check
from .matcher import match_item
from . import alerts

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals["app_name"] = settings.app_name
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
# Session middleware backs the OIDC state/nonce during the sign-in round trip.
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)


@app.on_event("startup")
def _startup():
    init_db()


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>Dark Web Monitoring is turned off</h1>"
    "<p style='color:#93a0b4'>This module is currently disabled on the Vendetta Platform. "
    "Contact your administrator to enable it.</p></div></body>"
)


@app.middleware("http")
async def _access_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path == "/healthz":
        return await call_next(request)
    if not settings.module_enabled:
        if path == "/api/module":  # let the hub read status while disabled
            return await call_next(request)
        return HTMLResponse(_DISABLED_HTML, status_code=503)
    # Client-portal users are confined to the portal and auth paths.
    ident = auth.resolve_identity(request)
    if ident and ident.is_client:
        if not path.startswith(("/portal", "/auth", "/logout")):
            return RedirectResponse("/portal", status_code=302)
    return await call_next(request)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    )
    return resp


# Simple in-memory login throttle. The console sits behind SSM/VPN, so this is a
# second layer against credential stuffing, not the only one. Resets on restart.
_login_hits: dict[str, list[float]] = {}


def _login_allowed(ip: str) -> bool:
    import time

    now = time.time()
    window = settings.login_window_seconds
    hits = [t for t in _login_hits.get(ip, []) if now - t < window]
    _login_hits[ip] = hits
    return len(hits) < settings.login_max_attempts


def _login_record(ip: str) -> None:
    import time

    _login_hits.setdefault(ip, []).append(time.time())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def _audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail[:4000]))
    db.commit()


def _shell(db: Session) -> dict:
    """Lightweight operational status for the topbar. Cheap counts only, no network."""
    try:
        return {
            "sources_ok": db.scalar(select(func.count(Source.id)).where(Source.enabled.is_(True), Source.fail_count == 0)) or 0,
            "sources_total": db.scalar(select(func.count(Source.id)).where(Source.enabled.is_(True))) or 0,
            "open_hits": db.scalar(select(func.count(Hit.id)).where(Hit.status.in_(("new", "reviewing")))) or 0,
        }
    except Exception:  # noqa: BLE001
        return {"sources_ok": 0, "sources_total": 0, "open_hits": 0}


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    return templates.TemplateResponse(request, name, ctx)


# ---------------------------------------------------------------- auth
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso: str = ""):
    msg = {"failed": "Microsoft sign-in did not complete. Try again.",
           "denied": "That account is not permitted to access this console."}.get(sso, "")
    return render(request, "login.html", next=next, error=msg, oidc_enabled=settings.oidc_enabled)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if not _login_allowed(ip):
        _audit(db, username, "login.throttled", ip)
        return render(request, "login.html", next=next, error="Too many attempts. Wait a few minutes and try again.", oidc_enabled=settings.oidc_enabled)
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(next or "/", status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_record(ip)
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
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    stats = {
        "clients": db.scalar(select(func.count(Client.id)).where(Client.active.is_(True))),
        "terms": db.scalar(select(func.count(WatchTerm.id)).where(WatchTerm.enabled.is_(True))),
        "items_24h": db.scalar(select(func.count(Item.id)).where(Item.collected_at >= since)),
        "victims_24h": db.scalar(select(func.count(Item.id)).where(Item.collected_at >= since, Item.kind == "victim")),
        "open_hits": db.scalar(select(func.count(Hit.id)).where(Hit.status.in_(("new", "reviewing")))),
        "sources_ok": db.scalar(select(func.count(Source.id)).where(Source.enabled.is_(True), Source.fail_count == 0)),
        "sources_total": db.scalar(select(func.count(Source.id)).where(Source.enabled.is_(True))),
    }
    hits = db.execute(
        select(Hit).options(selectinload(Hit.client), selectinload(Hit.item), selectinload(Hit.term))
        .where(Hit.status.in_(("new", "reviewing"))).order_by(desc(Hit.created_at)).limit(15)
    ).scalars().all()
    victims = db.execute(select(Item).where(Item.kind == "victim").order_by(desc(Item.collected_at)).limit(25)).scalars().all()
    return render(request, "dashboard.html", user=user, stats=stats, hits=hits, victims=victims)


# ---------------------------------------------------------------- clients and terms
@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).options(selectinload(Client.terms)).order_by(Client.name)).scalars().all()
    return render(request, "clients.html", user=user, clients=rows)


@app.post("/clients")
def add_client(name: str = Form(...), case_ref: str = Form(""), kind: str = Form("managed"), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = Client(name=name.strip(), case_ref=case_ref.strip(), kind=kind)
    db.add(c)
    db.commit()
    _audit(db, user, "client.add", name)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


@app.post("/clients/{cid}/profile")
def update_profile(cid: str, industry: str = Form(""), country: str = Form(""), state: str = Form(""),
                   revenue_min_musd: int = Form(0), revenue_max_musd: int = Form(0),
                   employees_min: int = Form(0), employees_max: int = Form(0),
                   user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    c.industry, c.country, c.state = industry.strip(), country.strip(), state.strip()
    c.revenue_min_musd, c.revenue_max_musd = revenue_min_musd, revenue_max_musd
    c.employees_min, c.employees_max = employees_min, employees_max
    db.commit()
    _audit(db, user, "client.profile", f"{c.name}: {industry} {country}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.post("/clients/{cid}/case-ref")
def update_case_ref(cid: str, case_ref: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Point this client's escalations at an open IR case in the engagement hub."""
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    c.case_ref = case_ref.strip()[:100]
    db.commit()
    _audit(db, user, "client.case_ref", f"{c.name}: {c.case_ref or '(cleared)'}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_detail(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    hits = db.execute(
        select(Hit).options(selectinload(Hit.item), selectinload(Hit.term)).where(Hit.client_id == cid).order_by(desc(Hit.created_at)).limit(100)
    ).scalars().all()
    ev = db.execute(select(Evidence).where(Evidence.client_id == cid).order_by(desc(Evidence.captured_at)).limit(50)).scalars().all()
    trend = _hit_trend(db, cid, days=21)
    return render(request, "client.html", user=user, client=c, hits=hits, evidence=ev, trend=trend)


def _hit_trend(db: Session, cid: str, days: int = 21) -> list[int]:
    """Hits per day for the last N days, oldest first, for a sparkline."""
    today = dt.datetime.now(dt.timezone.utc).date()
    start = today - dt.timedelta(days=days - 1)
    rows = db.execute(
        select(Hit.created_at).where(Hit.client_id == cid, Hit.created_at >= dt.datetime(start.year, start.month, start.day, tzinfo=dt.timezone.utc))
    ).scalars().all()
    counts = {start + dt.timedelta(days=i): 0 for i in range(days)}
    for ts in rows:
        d = ts.date()
        if d in counts:
            counts[d] += 1
    return [counts[start + dt.timedelta(days=i)] for i in range(days)]


@app.post("/clients/{cid}/portal")
def update_portal(cid: str, portal_enabled: bool = Form(False), portal_domains: str = Form(""),
                  user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    c.portal_enabled = portal_enabled
    c.portal_domains = portal_domains.strip()
    db.commit()
    _audit(db, user, "client.portal", f"{c.name} enabled={portal_enabled} domains={portal_domains}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.post("/clients/{cid}/terms")
def add_term(cid: str, term: str = Form(...), kind: str = Form("keyword"), severity: str = Form("medium"), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    for t in [x.strip() for x in term.splitlines() if x.strip()]:
        db.add(WatchTerm(client_id=cid, term=t, kind=kind, severity=severity))
    db.commit()
    _audit(db, user, "term.add", f"{cid}: {kind} {term[:200]}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.post("/clients/{cid}/terms/{tid}/delete")
def del_term(cid: str, tid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    t = db.get(WatchTerm, tid)
    if t:
        db.delete(t)
        db.commit()
        _audit(db, user, "term.delete", f"{cid}: {t.term}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.post("/clients/{cid}/toggle")
def toggle_client(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if c:
        c.active = not c.active
        db.commit()
        _audit(db, user, "client.toggle", f"{c.name} active={c.active}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.get("/clients/{cid}/report", response_class=HTMLResponse)
def client_report(cid: str, request: Request, days: int = 30, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    ctx = report_mod.build_report(db, c, days)
    return templates.TemplateResponse(request, "report.html", ctx)


@app.get("/clients/{cid}/report.pdf")
def client_report_pdf(cid: str, request: Request, days: int = 30, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    ctx = report_mod.build_report(db, c, days)
    html = templates.env.get_template("report.html").render(request=request, **ctx)
    try:
        from weasyprint import HTML
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=501, detail="PDF engine not installed; open the report and print to PDF, or install weasyprint")
    pdf = HTML(string=html, base_url=str(_APP_DIR)).write_pdf()
    _audit(db, user, "report.pdf", f"{c.name} {days}d")
    safe = "".join(ch for ch in c.name if ch.isalnum() or ch in " -_").strip().replace(" ", "_")
    fname = f"Vendetta_Dark_Web_Exposure_{safe}_{dt.date.today():%Y%m%d}.pdf"
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/clients/{cid}/backfill")
def backfill(cid: str, days: int = Form(90), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Re-run matching for this client's terms against items already collected.
    Use when onboarding an IR client: did their name show up on a leak site last month?"""
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    items = db.execute(select(Item).where(Item.collected_at >= since)).scalars().all()
    n = 0
    for it in items:
        new = [h for h in match_item(db, it) if h.client_id == cid]
        new += [h for h in iab.match_iab(db, it) if h.client_id == cid]
        n += len(new)
    _audit(db, user, "client.backfill", f"{cid}: {n} hits over {days}d")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


# ---------------------------------------------------------------- hits
@app.get("/hits", response_class=HTMLResponse)
def hits(request: Request, status: str = "open", client_id: str = "", severity: str = "", reason: str = "", user: str = auth.RequireUser, db: Session = Depends(get_db)):
    q = select(Hit).options(selectinload(Hit.client), selectinload(Hit.item), selectinload(Hit.term))
    if status == "open":
        q = q.where(Hit.status.in_(("new", "reviewing")))
    elif status != "all":
        q = q.where(Hit.status == status)
    if client_id:
        q = q.where(Hit.client_id == client_id)
    if severity:
        q = q.where(Hit.severity == severity)
    if reason:
        q = q.where(Hit.reason == reason)
    rows = db.execute(q.order_by(desc(Hit.created_at)).limit(300)).scalars().all()
    clients_ = db.execute(select(Client).order_by(Client.name)).scalars().all()
    return render(request, "hits.html", user=user, hits=rows, clients=clients_, status=status, client_id=client_id, severity=severity, reason=reason)


_VALID_STATUS = {"new", "reviewing", "confirmed", "false_positive", "closed"}


@app.post("/hits/bulk")
def hits_bulk(request: Request, status: str = Form(...), hit_ids: list[str] = Form(default=[]),
              user: str = auth.RequireUser, db: Session = Depends(get_db)):
    if status not in _VALID_STATUS or not hit_ids:
        return RedirectResponse(request.headers.get("referer", "/hits"), status_code=302)
    n = 0
    for h in db.execute(select(Hit).where(Hit.id.in_(hit_ids))).scalars().all():
        h.status = status
        n += 1
    db.commit()
    _audit(db, user, "hit.bulk", f"{n} -> {status}")
    return RedirectResponse(request.headers.get("referer", "/hits"), status_code=302)


@app.post("/hits/{hid}/status/{value}")
def hit_quick_status(hid: str, value: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Used by keyboard triage on the hits queue; returns JSON."""
    if value not in _VALID_STATUS:
        raise HTTPException(400, "invalid status")
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    h.status = value
    db.commit()
    _audit(db, user, "hit.quick", f"{hid} -> {value}")
    return {"ok": True, "id": hid, "status": value}


@app.get("/hits/{hid}", response_class=HTMLResponse)
def hit_detail(hid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    ev = db.execute(select(Evidence).where(Evidence.item_id == h.item_id).order_by(desc(Evidence.captured_at))).scalars().all()
    return render(request, "hit.html", user=user, hit=h, evidence=ev)


@app.post("/hits/{hid}")
def hit_update(hid: str, status: str = Form(...), analyst_notes: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    h.status = status
    h.analyst_notes = analyst_notes
    db.commit()
    _audit(db, user, "hit.update", f"{hid} -> {status}")
    return RedirectResponse(f"/hits/{hid}", status_code=302)


@app.post("/hits/{hid}/preserve")
def hit_preserve(hid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h or not h.item.url:
        raise HTTPException(404)
    evidence.preserve(db, h.item.url, client_id=h.client_id, item_id=h.item_id, captured_by=user, note=f"manual: hit {hid}")
    _audit(db, user, "evidence.preserve", h.item.url)
    return RedirectResponse(f"/hits/{hid}", status_code=302)


@app.post("/hits/{hid}/realert")
def hit_realert(hid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    alerts.dispatch(db, [h])
    _audit(db, user, "hit.realert", hid)
    return RedirectResponse(f"/hits/{hid}", status_code=302)


# ---------------------------------------------------------------- research console
@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = "", kind: str = "", days: int = 365, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = []
    if q.strip():
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        stmt = select(Item).where(Item.collected_at >= since)
        if kind:
            stmt = stmt.where(Item.kind == kind)
        if any(ch in q for ch in "*%"):
            stmt = stmt.where((Item.title.ilike(q.replace("*", "%"))) | (Item.body.ilike(q.replace("*", "%"))))
        else:
            stmt = stmt.where(text("search_vec @@ websearch_to_tsquery('simple', :q)")).params(q=q)
        rows = db.execute(stmt.order_by(desc(Item.collected_at)).limit(200)).scalars().all()
    return render(request, "search.html", user=user, q=q, kind=kind, days=days, items=rows)


@app.get("/items/{iid}", response_class=HTMLResponse)
def item_detail(iid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    it = db.get(Item, iid)
    if not it:
        raise HTTPException(404)
    return render(request, "item.html", user=user, item=it)


@app.get("/research", response_class=HTMLResponse)
def research(request: Request, user: str = auth.RequireUser):
    return render(request, "research.html", user=user, result=None, url="", tor=None)


@app.post("/research", response_class=HTMLResponse)
def research_fetch(request: Request, url: str = Form(...), force_tor: bool = Form(False), preserve: bool = Form(False), client_id: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    res = fetch(url.strip(), force_tor=force_tor)
    txt = html_to_text(res.text) if res.text else f"[{len(res.content)} bytes, content-type {res.headers.get('content-type')}]"
    ev = None
    if preserve and (res.ok or res.content):
        ev = evidence.preserve(db, url.strip(), client_id=client_id or None, captured_by=user, note="research console", result=res)
    _audit(db, user, "research.fetch", f"{url} tor={force_tor} preserve={preserve}")
    clients_ = db.execute(select(Client).order_by(Client.name)).scalars().all()
    return render(request, "research.html", user=user, result=res, text=txt[:60_000], url=url, evidence=ev, clients=clients_, tor=None)


@app.get("/research/torcheck")
def research_torcheck(user: str = auth.RequireUser):
    return tor_check()


# ---------------------------------------------------------------- evidence
@app.get("/evidence", response_class=HTMLResponse)
def evidence_list(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Evidence).order_by(desc(Evidence.captured_at)).limit(300)).scalars().all()
    return render(request, "evidence.html", user=user, evidence=rows)


@app.get("/evidence/{eid}/download")
def evidence_download(eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ev = db.get(Evidence, eid)
    if not ev:
        raise HTTPException(404)
    data = evidence.read_evidence_bytes(ev)
    _audit(db, user, "evidence.download", eid)
    return StreamingResponse(io.BytesIO(data), media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{ev.sha256[:16]}.bin"'})


@app.get("/evidence/{eid}/verify")
def evidence_verify(eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ev = db.get(Evidence, eid)
    if not ev:
        raise HTTPException(404)
    return {"id": eid, "sha256": ev.sha256, "intact": evidence.verify(ev), "storage": ev.storage_uri}


# ---------------------------------------------------------------- sources
@app.get("/sources", response_class=HTMLResponse)
def sources(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Source).order_by(Source.kind, Source.fail_count.desc(), Source.name)).scalars().all()
    return render(request, "sources.html", user=user, sources=rows)


@app.post("/sources")
def add_source(name: str = Form(...), url: str = Form(...), kind: str = Form("onion"), group_name: str = Form(""),
               profile: str = Form(""), cookie: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    meta = {"seeded_from": "manual"}
    if cookie.strip():
        meta["cookie"] = cookie.strip()
    db.add(Source(name=name.strip(), kind=kind if kind in ("onion", "forum") else "onion", url=url.strip(),
                  group_name=group_name.strip(), profile=profile.strip(), meta=meta))
    db.commit()
    _audit(db, user, "source.add", f"{kind} {url} profile={profile} cookie={'yes' if cookie else 'no'}")
    return RedirectResponse("/sources", status_code=302)


@app.post("/sources/{sid}/cookie")
def set_cookie(sid: str, cookie: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    s = db.get(Source, sid)
    if s:
        meta = dict(s.meta or {})
        if cookie.strip():
            meta["cookie"] = cookie.strip()
        else:
            meta.pop("cookie", None)
        s.meta = meta
        s.fail_count = 0
        db.commit()
        _audit(db, user, "source.cookie", f"{s.name} {'set' if cookie else 'cleared'}")
    return RedirectResponse("/sources", status_code=302)


@app.post("/sources/{sid}/toggle")
def toggle_source(sid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    s = db.get(Source, sid)
    if s:
        s.enabled = not s.enabled
        s.fail_count = 0
        db.commit()
    return RedirectResponse("/sources", status_code=302)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser):
    cfg = {
        "alert_min_severity": settings.alert_min_severity,
        "sns": bool(settings.sns_topic_arn),
        "teams": bool(settings.teams_webhook_url),
        "jira": bool(settings.jira_base_url and settings.jira_api_token),
        "jira_project": settings.jira_project_key,
        "hibp": bool(settings.hibp_api_key),
        "telegram": bool(settings.telegram_api_id),
        "evidence_bucket": settings.evidence_bucket or "(local disk)",
        "platform_hub": settings.platform_hub_url or "(standalone, not wired to hub)",
        "sso": f"Entra ID tenant {settings.entra_tenant_id}" if settings.oidc_enabled else "off (local admin login)",
        "module_enabled": settings.module_enabled,
    }
    return render(request, "settings.html", user=user, cfg=cfg, api_token=auth.api_token())


# ---------------------------------------------------------------- JSON API
@app.get("/api/hits")
def api_hits(status: str = Query("open"), client: str = Query(""), user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    q = select(Hit).options(selectinload(Hit.client), selectinload(Hit.item), selectinload(Hit.term))
    if status == "open":
        q = q.where(Hit.status.in_(("new", "reviewing")))
    elif status != "all":
        q = q.where(Hit.status == status)
    if client:
        q = q.join(Client).where(Client.name.ilike(f"%{client}%"))
    rows = db.execute(q.order_by(desc(Hit.created_at)).limit(500)).scalars().all()
    return [{
        "id": h.id, "client": h.client.name, "case_ref": h.client.case_ref, "severity": h.severity, "status": h.status,
        "term": h.term.term if h.term else None, "matched": h.matched_text, "item_kind": h.item.kind, "group": h.item.group_name,
        "title": h.item.title, "url": h.item.url, "published_at": h.item.published_at, "created_at": h.created_at, "alert_refs": h.alert_refs,
    } for h in rows]


@app.get("/api/victims")
def api_victims(days: int = 7, group: str = "", user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    q = select(Item).where(Item.kind == "victim", Item.collected_at >= since)
    if group:
        q = q.where(Item.group_name.ilike(group))
    rows = db.execute(q.order_by(desc(Item.collected_at)).limit(1000)).scalars().all()
    return [{"group": i.group_name, "title": i.title, "url": i.url, "published_at": i.published_at, "collected_at": i.collected_at} for i in rows]


@app.post("/api/clients/{cid}/terms")
def api_add_terms(cid: str, payload: dict, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    if not db.get(Client, cid):
        raise HTTPException(404)
    for t in payload.get("terms", []):
        db.add(WatchTerm(client_id=cid, term=t["term"], kind=t.get("kind", "keyword"), severity=t.get("severity", "medium")))
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- Vendetta Platform module
@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    """Module manifest the platform reads to register this capability."""
    return {
        "module": "dark-web-monitoring",
        "display_name": "Dark Web Monitoring",
        "platform": "Vendetta Platform",
        "enabled": settings.module_enabled,
        "roles": ["admin", "analyst", "client"],
        "finding_reasons": ["term", "credential", "iab"],
        "severities": ["low", "medium", "high", "critical"],
        "statuses": ["new", "reviewing", "confirmed", "false_positive", "closed"],
        "hub_configured": bool(settings.platform_hub_url),
        "endpoints": ["/api/findings", "/api/findings/{id}", "/api/findings/{id}/escalate", "/api/hits", "/api/victims"],
    }


@app.get("/api/findings")
def api_findings(status: str = Query("open"), client: str = Query(""), reason: str = Query(""),
                 user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    q = select(Hit).options(selectinload(Hit.client), selectinload(Hit.item), selectinload(Hit.term))
    if status == "open":
        q = q.where(Hit.status.in_(("new", "reviewing")))
    elif status != "all":
        q = q.where(Hit.status == status)
    if reason:
        q = q.where(Hit.reason == reason)
    if client:
        q = q.join(Client).where(Client.name.ilike(f"%{client}%"))
    rows = db.execute(q.order_by(desc(Hit.created_at)).limit(500)).scalars().all()
    return [platform.finding_dict(h, db) for h in rows]


@app.get("/api/findings/{hid}")
def api_finding(hid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    return platform.finding_dict(h, db)


@app.post("/api/findings/{hid}/escalate")
def api_escalate(hid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    result = platform.escalate(h, db)
    _audit(db, user, "finding.escalate", f"{hid}: {result}")
    return result


@app.post("/hits/{hid}/escalate")
def hit_escalate(hid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    h = db.get(Hit, hid)
    if not h:
        raise HTTPException(404)
    platform.escalate(h, db)
    _audit(db, user, "finding.escalate", hid)
    return RedirectResponse(f"/hits/{hid}", status_code=302)


# ---------------------------------------------------------------- client portal (read-only)
@app.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = db.get(Client, ident.client_id)
    if not c:
        raise HTTPException(404)
    # Only confirmed findings are shown to clients, so triage noise stays internal.
    hits = db.execute(
        select(Hit).options(selectinload(Hit.item), selectinload(Hit.term))
        .where(Hit.client_id == c.id, Hit.status == "confirmed").order_by(desc(Hit.created_at)).limit(200)
    ).scalars().all()
    by_sev = {k: 0 for k in ("critical", "high", "medium", "low")}
    for h in hits:
        by_sev[h.severity] = by_sev.get(h.severity, 0) + 1
    trend = _hit_trend(db, c.id, days=21)
    return render(request, "portal.html", user=ident.email, portal=True, client=c, hits=hits, by_sev=by_sev, trend=trend)


@app.get("/portal/report.pdf")
def portal_report_pdf(request: Request, days: int = 30, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = db.get(Client, ident.client_id)
    if not c:
        raise HTTPException(404)
    ctx = report_mod.build_report(db, c, days)
    html = templates.env.get_template("report.html").render(request=request, **ctx)
    try:
        from weasyprint import HTML
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=501, detail="PDF engine not installed")
    pdf = HTML(string=html, base_url=str(_APP_DIR)).write_pdf()
    _audit(db, ident.email, "portal.report", c.name)
    safe = "".join(ch for ch in c.name if ch.isalnum() or ch in " -_").strip().replace(" ", "_")
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="Dark_Web_Exposure_{safe}.pdf"'})


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
