"""Office of Special Projects console, client portal and JSON API."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from . import auth, oidc, platform as platform_mod, provision, readiness, sso
from .config import (CADENCES, DELIVERABLE_KINDS, DELIVERABLE_KIND_NAMES, DELIVERABLE_STATUS_NAMES,
                     DELIVERABLE_STATUSES, ENGAGEMENT_STATE_NAMES, ENGAGEMENT_STATES, ENGAGEMENT_TYPE_NAMES,
                     ENGAGEMENT_TYPES, OPEN_DELIVERABLE_STATUSES, OPEN_STATES, settings)
from .db import (AuditLog, Client, Deliverable, Engagement, SessionLocal, User,
                 build_event_proof, client_event_records, init_db, record_event, utcnow)

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals["app_name"] = settings.app_name
templates.env.globals["TYPE_NAMES"] = ENGAGEMENT_TYPE_NAMES
templates.env.globals["STATE_NAMES"] = ENGAGEMENT_STATE_NAMES
templates.env.globals["DKIND_NAMES"] = DELIVERABLE_KIND_NAMES
templates.env.globals["DSTATUS_NAMES"] = DELIVERABLE_STATUS_NAMES
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)


@app.on_event("startup")
def _startup():
    init_db()


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>The Office of Special Projects is turned off</h1>"
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
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    )
    return resp


_login_hits: dict[str, list[float]] = {}


def _login_allowed(ip: str) -> bool:
    import time
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < settings.login_window_seconds]
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
    try:
        return {"open_deliv": db.scalar(select(func.count(Deliverable.id)).where(
                    Deliverable.status.in_(OPEN_DELIVERABLE_STATUSES))) or 0,
                "active": db.scalar(select(func.count(Engagement.id)).where(
                    Engagement.status.in_(tuple(OPEN_STATES)))) or 0}
    except Exception:  # noqa: BLE001
        return {"open_deliv": 0, "active": 0}


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    return templates.TemplateResponse(request, name, ctx)


# ---------------------------------------------------------------- auth
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso_status: str = Query("", alias="sso")):
    msg = {"failed": "Microsoft sign-in did not complete. Try again.",
           "denied": "That account is not permitted to access this console."}.get(sso_status, "")
    return render(request, "login.html", next=next, error=msg, oidc_enabled=sso.enabled())


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
          db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if not _login_allowed(ip):
        _audit(db, username, "login.throttled", ip)
        return render(request, "login.html", next=next, error="Too many attempts. Wait a few minutes.", oidc_enabled=sso.enabled())
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(next or "/", status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_record(ip)
    _audit(db, username, "login.failed", ip)
    return render(request, "login.html", next=next, error="Invalid credentials", oidc_enabled=sso.enabled())


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------------------------------------------------------------- SSO config
@app.get("/settings/sso", response_class=HTMLResponse)
def sso_page(request: Request, user: str = auth.RequireUser):
    q = request.query_params
    msg = err = ""
    st = sso.status()
    if q.get("ok"):
        msg = f"Microsoft 365 SSO verified. {st['last_detail']}".strip()
    elif q.get("testfail"):
        err = f"SSO saved but the test failed: {st['last_detail']}".strip()
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


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser):
    return render(request, "settings.html", user=user, api_token=auth.api_token(),
                  sso_enabled=sso.enabled(), platform_url=settings.platform_url or "not set",
                  hub=settings.platform_hub_url or "not connected")


# ---------------------------------------------------------------- helpers
def _get_client(db: Session, cid: str) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    return c


def _get_engagement(db: Session, eid: str) -> Engagement:
    e = db.execute(select(Engagement).options(selectinload(Engagement.client), selectinload(Engagement.deliverables))
                   .where(Engagement.id == eid)).scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    return e


def _get_deliverable(db: Session, did: str) -> Deliverable:
    d = db.execute(select(Deliverable).options(
        selectinload(Deliverable.engagement).selectinload(Engagement.client))
        .where(Deliverable.id == did)).scalar_one_or_none()
    if not d:
        raise HTTPException(404)
    return d


# ---------------------------------------------------------------- staff console
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    by_status = {s: db.scalar(select(func.count(Deliverable.id)).where(Deliverable.status == s)) or 0
                 for s in DELIVERABLE_STATUSES}
    by_type = {t: db.scalar(select(func.count(Engagement.id)).where(
        Engagement.kind == t, Engagement.status.in_(tuple(OPEN_STATES)))) or 0 for t in ENGAGEMENT_TYPES}
    engagements = db.execute(select(Engagement).options(selectinload(Engagement.client),
                             selectinload(Engagement.deliverables))
                             .order_by(Engagement.created_at.desc()).limit(14)).scalars().all()
    # Deliverables delivered and awaiting client acceptance, oldest first.
    awaiting = db.execute(select(Deliverable).options(selectinload(Deliverable.engagement).selectinload(Engagement.client))
                          .where(Deliverable.status == "delivered").order_by(Deliverable.delivered_at)).scalars().all()
    return render(request, "dashboard.html", user=user, by_status=by_status, by_type=by_type,
                  engagements=engagements, awaiting=awaiting[:10])


@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    counts = {c.id: db.scalar(select(func.count(Engagement.id)).where(
        Engagement.client_id == c.id, Engagement.status.in_(tuple(OPEN_STATES)))) or 0 for c in rows}
    return render(request, "clients.html", user=user, clients=rows, counts=counts,
                  platform_configured=provision.configured())


@app.post("/clients")
def add_client(name: str = Form(...), industry: str = Form(""), user: str = auth.RequireUser,
               db: Session = Depends(get_db)):
    name = name.strip()
    if not name:
        return RedirectResponse("/clients?err=name+required", status_code=302)
    if db.query(Client).filter(Client.name.ilike(name)).count():
        return RedirectResponse("/clients?err=client+exists", status_code=302)
    c = Client(name=name, industry=industry.strip())
    db.add(c); db.commit()
    _audit(db, user, "client.add", name)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


@app.post("/clients/pull")
def clients_pull(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    if not provision.configured():
        return RedirectResponse("/clients?err=platform+not+configured", status_code=302)
    try:
        summ = provision.pull(db)
    except provision.ProvisionError as e:
        _audit(db, user, "platform.pull.failed", str(e))
        return RedirectResponse(f"/clients?err={str(e).replace(' ', '+')}", status_code=302)
    _audit(db, user, "platform.pull", str(summ))
    return RedirectResponse(f"/clients?msg=pulled+{summ['added']}+new", status_code=302)


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_page(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    engagements = db.execute(select(Engagement).options(selectinload(Engagement.deliverables))
                             .where(Engagement.client_id == cid)
                             .order_by(Engagement.created_at.desc())).scalars().all()
    return render(request, "client.html", user=user, client=c, engagements=engagements,
                  kinds=ENGAGEMENT_TYPES, cadences=CADENCES)


@app.post("/clients/{cid}/engagements")
def add_engagement(cid: str, name: str = Form(...), kind: str = Form("advisory"), cadence: str = Form("one-time"),
                   scope: str = Form(""), lead: str = Form(""), sponsor: str = Form(""),
                   user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    name = name.strip()
    if not name:
        return RedirectResponse(f"/clients/{cid}?err=name+required", status_code=302)
    e = Engagement(client_id=c.id, name=name[:200], kind=kind if kind in ENGAGEMENT_TYPES else "advisory",
                   cadence=cadence if cadence in CADENCES else "one-time", scope=scope.strip(),
                   lead=lead.strip(), sponsor=sponsor.strip(), status="scoping")
    db.add(e); db.flush()
    record_event(db, c.id, e.id, None, "engagement_opened", user, f"{ENGAGEMENT_TYPE_NAMES.get(e.kind, e.kind)}: {e.name}")
    db.commit()
    _audit(db, user, "engagement.add", f"{c.name}: {name}")
    return RedirectResponse(f"/engagements/{e.id}", status_code=302)


@app.get("/clients/{cid}/evidence/verify")
def client_evidence_verify(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    from . import evidence
    c = _get_client(db, cid)
    result = evidence.verify_chain(client_event_records(db, c.id))
    _audit(db, user, "evidence.verify", f"{c.name} ok={result['ok']}")
    return JSONResponse(result)


@app.get("/clients/{cid}/evidence/proof.json")
def client_evidence_proof(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    _audit(db, user, "evidence.proof", c.name)
    return JSONResponse(build_event_proof(db, c), headers={
        "Content-Disposition": f'attachment; filename="deliverable_signoff_{c.id}.json"'})


@app.get("/api/clients/{cid}/evidence/verify")
def api_client_evidence_verify(cid: str, _: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    from . import evidence
    if not db.get(Client, cid):
        raise HTTPException(404)
    return JSONResponse(evidence.verify_chain(client_event_records(db, cid)))


# ---------------------------------------------------------------- engagements
@app.get("/engagements/{eid}", response_class=HTMLResponse)
def engagement_page(eid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    return render(request, "engagement.html", user=user, e=e, states=ENGAGEMENT_STATES, kinds=ENGAGEMENT_TYPES,
                  cadences=CADENCES, dkinds=DELIVERABLE_KINDS, dstatuses=DELIVERABLE_STATUSES,
                  counts=e.counts(), progress=e.progress())


@app.post("/engagements/{eid}/edit")
def engagement_edit(eid: str, status: str = Form(...), kind: str = Form(""), cadence: str = Form(""),
                    published: bool = Form(False), scope: str = Form(""), lead: str = Form(""),
                    sponsor: str = Form(""), summary: str = Form(""), user: str = auth.RequireUser,
                    db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    was_published, prev_status = e.published, e.status
    if status in ENGAGEMENT_STATES:
        if status == "closed" and e.status != "closed":
            e.closed_at = utcnow()
        e.status = status
    if kind in ENGAGEMENT_TYPES:
        e.kind = kind
    if cadence in CADENCES:
        e.cadence = cadence
    e.published = bool(published)
    e.scope, e.lead, e.sponsor, e.summary = scope.strip(), lead.strip(), sponsor.strip(), summary.strip()
    if status in ENGAGEMENT_STATES and status != prev_status:
        record_event(db, e.client_id, e.id, None, "engagement_status", user, f"{prev_status} -> {status}",
                     {"from": prev_status, "to": status})
    if e.published and not was_published:
        record_event(db, e.client_id, e.id, None, "engagement_published", user, f"shared with client: {e.name}")
    db.commit()
    _audit(db, user, "engagement.edit", f"{e.name} -> {e.status}")
    return RedirectResponse(f"/engagements/{eid}?msg=saved", status_code=302)


@app.post("/engagements/{eid}/escalate")
def engagement_escalate(eid: str, note: str = Form(""), severity: str = Form("high"),
                        user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    result = platform_mod.escalate(e, note=note.strip(), severity=severity)
    record_event(db, e.client_id, e.id, None, "escalated", user, note.strip()[:200] or "escalated to IR hub")
    db.commit()
    _audit(db, user, "engagement.escalate", f"{e.name}: {result}")
    flag = "msg=escalated+to+hub" if result.get("escalated") else f"err={str(result.get('reason', 'failed')).replace(' ', '+')}"
    return RedirectResponse(f"/engagements/{eid}?{flag}", status_code=302)


# ---------------------------------------------------------------- deliverables
@app.post("/engagements/{eid}/deliverables")
def add_deliverable(eid: str, title: str = Form(...), kind: str = Form("document"), description: str = Form(""),
                    artifact_ref: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    title = title.strip()
    if not title:
        return RedirectResponse(f"/engagements/{eid}?err=title+required", status_code=302)
    pos = max((d.position for d in e.deliverables), default=-1) + 1
    d = Deliverable(client_id=e.client_id, title=title[:400], kind=kind if kind in DELIVERABLE_KINDS else "document",
                    description=description.strip(), artifact_ref=artifact_ref.strip()[:600], position=pos)
    e.deliverables.append(d)
    db.flush()
    record_event(db, e.client_id, e.id, d.id, "deliverable_created", user,
                 f"{DELIVERABLE_KIND_NAMES.get(d.kind, d.kind)}: {title}", {"kind": d.kind})
    db.commit()
    _audit(db, user, "deliverable.add", f"{e.name}: {title}")
    return RedirectResponse(f"/engagements/{eid}?msg=saved", status_code=302)


@app.post("/deliverables/{did}/edit")
def deliverable_edit(did: str, status: str = Form(...), kind: str = Form(""), title: str = Form(""),
                     description: str = Form(""), artifact_ref: str = Form(""), user: str = auth.RequireUser,
                     db: Session = Depends(get_db)):
    d = _get_deliverable(db, did)
    prev = d.status
    if title.strip():
        d.title = title.strip()[:400]
    if kind in DELIVERABLE_KINDS:
        d.kind = kind
    d.description = description.strip()
    d.artifact_ref = artifact_ref.strip()[:600]
    if status in DELIVERABLE_STATUSES and status != prev:
        d.status = status
        if status == "delivered" and d.delivered_at is None:
            d.delivered_at = utcnow()
        if status != "accepted":  # staff cannot accept on the client's behalf
            record_event(db, d.client_id, d.engagement_id, d.id, "deliverable_status", user,
                         f"{prev} -> {status}: {d.title}", {"from": prev, "to": status})
        else:
            # Guard: acceptance is a client action; staff edit cannot set it.
            d.status = prev
    db.commit()
    _audit(db, user, "deliverable.edit", f"{d.title} -> {d.status}")
    return RedirectResponse(f"/engagements/{d.engagement_id}?msg=saved", status_code=302)


@app.post("/deliverables/{did}/delete")
def deliverable_delete(did: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    d = _get_deliverable(db, did)
    eid = d.engagement_id
    # Deleting a deliverable the client already accepted would break the sign-off
    # record; refuse it once accepted.
    if d.status == "accepted":
        return RedirectResponse(f"/engagements/{eid}?err=cannot+delete+an+accepted+deliverable", status_code=302)
    db.delete(d); db.commit()
    _audit(db, user, "deliverable.delete", did)
    return RedirectResponse(f"/engagements/{eid}?msg=saved", status_code=302)


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    c = db.get(Client, ident.client_id)
    if not c:
        raise HTTPException(404)
    return c


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    engagements = db.execute(select(Engagement).options(selectinload(Engagement.deliverables))
                             .where(Engagement.client_id == c.id, Engagement.published.is_(True))
                             .order_by(Engagement.created_at.desc())).scalars().all()
    awaiting = [d for e in engagements for d in e.deliverables if d.status == "delivered"]
    from . import evidence
    chain = evidence.verify_chain(client_event_records(db, c.id))
    return render(request, "portal.html", user=ident.email, portal=True, client=c, engagements=engagements,
                  awaiting=awaiting, exec_view=ident.is_executive, chain=chain)


@app.get("/portal/evidence/proof.json")
def portal_evidence_proof(ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    _audit(db, ident.email, "portal.evidence.proof", c.name)
    return JSONResponse(build_event_proof(db, c), headers={
        "Content-Disposition": f'attachment; filename="deliverable_signoff_{c.id}.json"'})


@app.get("/portal/engagements/{eid}", response_class=HTMLResponse)
def portal_engagement(eid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                      db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    auth.require_owned(ident, e, extra=e.published)
    return render(request, "portal_engagement.html", user=ident.email, portal=True, client=e.client, e=e,
                  counts=e.counts(), progress=e.progress(), exec_view=ident.is_executive)


@app.post("/portal/deliverables/{did}/accept")
def portal_accept(did: str, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    d = _get_deliverable(db, did)
    auth.require_owned(ident, d, extra=d.engagement.published)
    # The client accepts a delivered item. This is the client-owned sign-off, recorded
    # in the signed chain with who accepted it and when.
    if d.status == "delivered":
        d.status = "accepted"
        d.accepted_at = utcnow()
        d.accepted_by = ident.email
        record_event(db, d.client_id, d.engagement_id, d.id, "deliverable_accepted", ident.email,
                     f"accepted: {d.title}")
        db.commit()
    return RedirectResponse(f"/portal/engagements/{d.engagement_id}", status_code=302)


# ---------------------------------------------------------------- JSON API
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    return {"module": "professional-services", "display_name": "Office of Special Projects",
            "platform": "Vendetta Platform", "enabled": settings.module_enabled,
            "roles": ["admin", "analyst", "client"], "engagement_types": ENGAGEMENT_TYPES,
            "deliverable_statuses": DELIVERABLE_STATUSES, "readiness": readiness.block(),
            "endpoints": ["/api/module", "/api/clients/{id}/evidence/verify"]}
