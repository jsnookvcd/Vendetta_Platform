"""Penetration Testing console, client portal and JSON API."""
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

from . import boot
from . import auth, oidc, platform as platform_mod, provision, readiness, sso
from .config import (ENGAGEMENT_STATES, ENGAGEMENT_TYPES, OPEN_STATUSES, SEVERITIES, STATUSES,
                     cvss_to_severity, settings, severity_rank)
from .db import (AuditLog, Client, Engagement, Finding, RemediationStep, SessionLocal, User,
                 build_event_proof, client_event_records, init_db, record_event, severity_trend,
                 utcnow)

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals["app_name"] = settings.app_name
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    provision.start_scheduler(SessionLocal)


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>Penetration Testing is turned off</h1>"
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
        return {"open": db.scalar(select(func.count(Finding.id)).where(Finding.status.in_(OPEN_STATUSES))) or 0,
                "active": db.scalar(select(func.count(Engagement.id)).where(Engagement.status.in_(("scoping", "active", "reporting")))) or 0}
    except Exception:  # noqa: BLE001
        return {"open": 0, "active": 0}


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ctx.setdefault("sev", severity_rank)
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


# ---------------------------------------------------------------- staff console
def _get_client(db: Session, cid: str) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    return c


def _get_engagement(db: Session, eid: str) -> Engagement:
    e = db.execute(select(Engagement).options(selectinload(Engagement.client), selectinload(Engagement.findings))
                   .where(Engagement.id == eid)).scalar_one_or_none()
    if not e:
        raise HTTPException(404)
    return e


def _get_finding(db: Session, fid: str) -> Finding:
    f = db.execute(select(Finding).options(
        selectinload(Finding.engagement).selectinload(Engagement.client), selectinload(Finding.steps))
        .where(Finding.id == fid)).scalar_one_or_none()
    if not f:
        raise HTTPException(404)
    return f


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    by_sev = {s: db.scalar(select(func.count(Finding.id)).where(
        Finding.status.in_(OPEN_STATUSES), Finding.severity == s)) or 0 for s in SEVERITIES}
    engagements = db.execute(select(Engagement).options(selectinload(Engagement.client))
                             .order_by(Engagement.created_at.desc()).limit(12)).scalars().all()
    return render(request, "dashboard.html", user=user, by_sev=by_sev, engagements=engagements)


@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    counts = {c.id: db.scalar(select(func.count(Engagement.id)).where(Engagement.client_id == c.id)) or 0 for c in rows}
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
    engagements = db.execute(select(Engagement).where(Engagement.client_id == cid)
                             .order_by(Engagement.created_at.desc())).scalars().all()
    trend = severity_trend(db, cid)
    return render(request, "client.html", user=user, client=c, engagements=engagements, trend=trend,
                  kinds=ENGAGEMENT_TYPES)


@app.post("/clients/{cid}/engagements")
def add_engagement(cid: str, name: str = Form(...), kind: str = Form("external"), scope: str = Form(""),
                   lead: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    name = name.strip()
    if not name:
        return RedirectResponse(f"/clients/{cid}?err=name+required", status_code=302)
    e = Engagement(client_id=c.id, name=name[:200], kind=kind if kind in ENGAGEMENT_TYPES else "external",
                   scope=scope.strip(), lead=lead.strip(), status="scoping")
    db.add(e); db.commit()
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
        "Content-Disposition": f'attachment; filename="finding_events_{c.id}.json"'})


@app.get("/api/clients/{cid}/evidence/verify")
def api_client_evidence_verify(cid: str, _: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    from . import evidence
    if not db.get(Client, cid):
        raise HTTPException(404)
    return JSONResponse(evidence.verify_chain(client_event_records(db, cid)))


@app.get("/engagements/{eid}", response_class=HTMLResponse)
def engagement_page(eid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    return render(request, "engagement.html", user=user, e=e, states=ENGAGEMENT_STATES,
                  severities=SEVERITIES, kinds=ENGAGEMENT_TYPES)


@app.post("/engagements/{eid}/edit")
def engagement_edit(eid: str, status: str = Form(...), published: bool = Form(False), scope: str = Form(""),
                    lead: str = Form(""), summary: str = Form(""), user: str = auth.RequireUser,
                    db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    was_published = e.published
    if status in ENGAGEMENT_STATES:
        if status == "closed" and e.status != "closed":
            e.closed_at = utcnow()
            e.recount()  # freeze the severity counts for the trend
        e.status = status
    e.published = bool(published)
    e.scope, e.lead, e.summary = scope.strip(), lead.strip(), summary.strip()
    if e.published and not was_published:
        record_event(db, e.client_id, None, "published", user, f"engagement shared: {e.name}")
    db.commit()
    _audit(db, user, "engagement.edit", f"{e.name} -> {e.status}")
    return RedirectResponse(f"/engagements/{eid}?msg=saved", status_code=302)


@app.post("/engagements/{eid}/findings")
def add_finding(eid: str, title: str = Form(...), asset: str = Form(""), cve: str = Form(""),
                cvss: float = Form(0.0), severity: str = Form(""), description: str = Form(""),
                impact: str = Form(""), remediation: str = Form(""), user: str = auth.RequireUser,
                db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    title = title.strip()
    if not title:
        return RedirectResponse(f"/engagements/{eid}?err=title+required", status_code=302)
    sev = (severity or "").strip().lower() or cvss_to_severity(float(cvss or 0))
    if sev not in SEVERITIES:
        sev = cvss_to_severity(float(cvss or 0))
    pos = max((f.position for f in e.findings), default=-1) + 1
    f = Finding(client_id=e.client_id, title=title[:400], asset=asset.strip()[:300],
                cve=cve.strip()[:40], cvss=float(cvss or 0), severity=sev, description=description.strip(),
                impact=impact.strip(), remediation=remediation.strip(), position=pos)
    e.findings.append(f)  # via the relationship so recount sees it
    db.flush()
    e.recount()
    record_event(db, e.client_id, f.id, "created", user, f"{sev} {title}",
                 {"severity": sev, "asset": f.asset, "engagement": e.name})
    db.commit()
    _audit(db, user, "finding.add", f"{e.name}: {title}")
    return RedirectResponse(f"/findings/{f.id}", status_code=302)


@app.get("/findings/{fid}", response_class=HTMLResponse)
def finding_page(fid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    return render(request, "finding.html", user=user, f=f, statuses=STATUSES, severities=SEVERITIES)


@app.post("/findings/{fid}/edit")
def finding_edit(fid: str, status: str = Form(...), severity: str = Form(...), cvss: float = Form(0.0),
                 description: str = Form(""), impact: str = Form(""), remediation: str = Form(""),
                 retest_note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    prev_status = f.status
    if status in STATUSES:
        was_open = f.status in OPEN_STATUSES
        f.status = status
        if status == "retest_passed":
            f.retested_at = utcnow()
        if status not in OPEN_STATUSES and was_open:
            f.resolved_at = utcnow()
        elif status in OPEN_STATUSES:
            f.resolved_at = None
    if severity in SEVERITIES:
        f.severity = severity
    f.cvss = float(cvss or 0)
    f.description, f.impact, f.remediation, f.retest_note = (description.strip(), impact.strip(),
                                                             remediation.strip(), retest_note.strip())
    f.engagement.recount()
    if status in STATUSES and status != prev_status:
        record_event(db, f.client_id, f.id, "status", user, f"{prev_status} -> {status}",
                     {"from": prev_status, "to": status})
    db.commit()
    _audit(db, user, "finding.edit", f"{f.title} -> {f.status}")
    return RedirectResponse(f"/findings/{fid}?msg=saved", status_code=302)


@app.post("/findings/{fid}/steps")
def finding_add_step(fid: str, text: str = Form(...), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    text = text.strip()
    if text:
        pos = max((s.position for s in f.steps), default=-1) + 1
        db.add(RemediationStep(finding_id=f.id, position=pos, text=text[:2000]))
        record_event(db, f.client_id, f.id, "step_added", user, text[:200])
        db.commit()
    return RedirectResponse(f"/findings/{fid}", status_code=302)


@app.post("/findings/{fid}/steps/{sid}/delete")
def finding_del_step(fid: str, sid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    s = db.get(RemediationStep, sid)
    if s and s.finding_id == fid:
        db.delete(s); db.commit()
    return RedirectResponse(f"/findings/{fid}", status_code=302)


@app.post("/findings/{fid}/escalate")
def finding_escalate(fid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    result = platform_mod.escalate(f, db)
    _audit(db, user, "finding.escalate", f"{f.title}: {result}")
    flag = "msg=escalated+to+hub" if result.get("escalated") else f"err={str(result.get('reason', 'failed')).replace(' ', '+')}"
    return RedirectResponse(f"/findings/{fid}?{flag}", status_code=302)


def _report_counts(e) -> dict:
    if e.status == "closed":
        return e.counts()
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in e.findings:
        if f.severity in c:
            c[f.severity] += 1
    c["total"] = sum(c.values())
    return c


@app.get("/engagements/{eid}/report", response_class=HTMLResponse)
def engagement_report(eid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    return render(request, "report.html", user=user, e=e, portal=False, counts=_report_counts(e))


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    c = db.get(Client, ident.client_id)
    if not c:
        raise HTTPException(404)
    return c


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    engagements = db.execute(select(Engagement).options(selectinload(Engagement.findings))
                             .where(Engagement.client_id == c.id, Engagement.published.is_(True))
                             .order_by(Engagement.created_at.desc())).scalars().all()
    open_findings = [f for e in engagements for f in e.findings if f.is_open]
    by_sev = {s: sum(1 for f in open_findings if f.severity == s) for s in SEVERITIES}
    trend = severity_trend(db, c.id)
    from . import evidence
    chain = evidence.verify_chain(client_event_records(db, c.id))
    return render(request, "portal.html", user=ident.email, portal=True, client=c, engagements=engagements,
                  open_findings=open_findings, by_sev=by_sev, trend=trend, exec_view=ident.is_executive,
                  chain=chain)


@app.get("/portal/evidence/proof.json")
def portal_evidence_proof(ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    _audit(db, ident.email, "portal.evidence.proof", c.name)
    return JSONResponse(build_event_proof(db, c), headers={
        "Content-Disposition": f'attachment; filename="finding_events_{c.id}.json"'})


@app.get("/portal/findings/{fid}", response_class=HTMLResponse)
def portal_finding(fid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                   db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    auth.require_owned(ident, f, extra=f.engagement.published)
    if ident.is_executive:
        return RedirectResponse("/portal", status_code=302)
    return render(request, "portal_finding.html", user=ident.email, portal=True, client=f.engagement.client, f=f)


@app.get("/portal/engagements/{eid}/report", response_class=HTMLResponse)
def portal_report(eid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                  db: Session = Depends(get_db)):
    e = _get_engagement(db, eid)
    auth.require_owned(ident, e, extra=e.published)
    return render(request, "report.html", user=ident.email, e=e, portal=True, counts=_report_counts(e))


@app.post("/portal/findings/{fid}/steps/{sid}")
def portal_toggle_step(fid: str, sid: str, ident: auth.Identity = Depends(auth.require_client),
                       db: Session = Depends(get_db)):
    f = _get_finding(db, fid)
    auth.require_owned(ident, f, extra=f.engagement.published)
    s = db.get(RemediationStep, sid)
    if not s or s.finding_id != f.id:
        raise HTTPException(404)
    s.done = not s.done
    s.done_at = utcnow() if s.done else None
    s.done_by = ident.email if s.done else ""
    record_event(db, f.client_id, f.id, "step_done" if s.done else "step_reopened", ident.email, s.text[:200])
    db.commit()
    return RedirectResponse(f"/portal/findings/{fid}", status_code=302)


# ---------------------------------------------------------------- JSON API
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    return {"module": "penetration-testing", "enabled": settings.module_enabled,
            "roles": ["admin", "analyst", "client"], "finding_types": ["pentest-finding"],
            "engagement_types": ENGAGEMENT_TYPES, "readiness": readiness.block()}


@app.get("/api/findings")
def api_findings(status: str = Query("active"), platform_client_id: str = Query(""), client: str = Query(""),
                 user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Shared finding model. status: active (default; "open" is a synonym), all, or a
    literal finding status. Filter by the shared platform_client_id or a client-name substring."""
    q = select(Finding).options(selectinload(Finding.engagement).selectinload(Engagement.client))
    if status in ("active", "open"):
        q = q.where(Finding.status.in_(OPEN_STATUSES))
    elif status != "all":
        q = q.where(Finding.status == status)
    if platform_client_id:
        q = q.join(Client, Finding.client_id == Client.id).where(Client.platform_client_id == platform_client_id)
    elif client:
        q = q.join(Client, Finding.client_id == Client.id).where(Client.name.ilike(f"%{client}%"))
    rows = db.execute(q.order_by(Finding.cvss.desc()).limit(1000)).scalars().all()
    return [platform_mod.finding_dict(f) for f in rows]


@app.post("/api/findings/{fid}/escalate")
def api_finding_escalate(fid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Escalate one finding into the IR hub over the service API (the control plane
    or another module can drive this). Same result shape as every module:
    {escalated, case, linked} or {escalated: false, reason}."""
    f = _get_finding(db, fid)
    result = platform_mod.escalate(f, db)
    _audit(db, user, "finding.escalate", f"{f.title}: {result}")
    return JSONResponse(result, status_code=200 if result.get("escalated") else 502)


# ---------------------------------------------------------------- platform link
@app.post("/api/provision/sync")
def api_provision_sync(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """The control plane calls this right after a client changes there, so a roster
    edit lands here within seconds instead of at the next scheduled pull."""
    if not provision.configured():
        return JSONResponse({"ok": False, "detail": "PLATFORM_URL not set"}, status_code=409)
    try:
        return {"ok": True, **provision.pull(db)}
    except provision.ProvisionError as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=502)


@app.get("/clients/platform/{pid}")
def client_by_platform_id(pid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Deep link from the control plane: open this module's page for the client that
    carries the given platform client id."""
    c = db.query(Client).filter_by(platform_client_id=pid).first()
    if not c:
        raise HTTPException(404, "that client has not been provisioned into this module yet")
    return RedirectResponse(f"/clients/{c.id}", status_code=302)
