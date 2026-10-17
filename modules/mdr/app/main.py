"""Managed Detection and Response: staff console, client portal and service API."""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from . import actions, attack, auth, boot, coverage, detect, hub, metrics, oidc, provision, readiness, sso
from .config import (GROUP_BY, OPEN_STATUSES, RESPONSE_NAMES, RESPONSES, SEV_RANK, SEVERITIES, SIGNAL_TYPES,
                     STATUS_NAMES, STATUSES, TOOL_NAMES, TOOLS, VERDICT_NAMES, VERDICTS, WORKSTREAM, settings)
from .db import (AuditLog, Client, Investigation, InvestigationSignal, Rule, RuleOverride, RuleVersion,
                 SessionLocal, Signal, Suppression, init_db, timeline, timeline_records, utcnow)

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(
    app_name=settings.app_name, STATUS_NAMES=STATUS_NAMES, VERDICT_NAMES=VERDICT_NAMES,
    RESPONSE_NAMES=RESPONSE_NAMES, TOOL_NAMES=TOOL_NAMES, SEVERITIES=SEVERITIES, fmt=metrics.fmt,
    technique_name=attack.technique_name, TACTIC_NAMES=attack.TACTIC_NAMES)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    provision.start_scheduler(SessionLocal)
    detect.start_scheduler(SessionLocal)


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>Managed Detection and Response is turned off</h1>"
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
        open_n = db.scalar(select(func.count(Investigation.id)).where(Investigation.status.in_(OPEN_STATUSES))) or 0
        unack = db.scalar(select(func.count(Investigation.id)).where(
            Investigation.status.in_(OPEN_STATUSES), Investigation.severity == "critical",
            Investigation.acknowledged_at.is_(None))) or 0
        return {"open": open_n, "unack_crit": unack, "detect": detect.state()}
    except Exception:  # noqa: BLE001
        return {"open": 0, "unack_crit": 0, "detect": detect.state()}


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user") and not ctx.get("portal"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ident = auth.resolve_identity(request)
    ctx.setdefault("ident", ident)
    return templates.TemplateResponse(request, name, ctx)


def _back(path: str, ok: bool, message: str) -> RedirectResponse:
    sep = "&" if "?" in path else "?"
    return RedirectResponse(f"{path}{sep}{'msg' if ok else 'err'}={quote_plus(message)}", status_code=302)


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
        return render(request, "login.html", next=next, error="Too many attempts. Wait a few minutes.",
                      oidc_enabled=sso.enabled())
    if username == settings.admin_user and auth.check_password(password):
        dest = next if (next or "").startswith("/") and not next.startswith("//") else "/"
        resp = RedirectResponse(dest, status_code=302)
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


# ---------------------------------------------------------------- settings and SSO
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
async def sso_save(request: Request, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
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
    return render(request, "settings.html", user=user, api_token=auth.api_token(), sso_enabled=sso.enabled(),
                  platform_url=settings.platform_url or "not set", hub=settings.platform_hub_url or "not connected",
                  ms_url=settings.managed_services_url or "not set",
                  ms_public=settings.managed_services_public_url or "not set",
                  detect_state=detect.state(), interval=settings.detect_interval_seconds,
                  noise_days=settings.noise_suppression_days)


# ---------------------------------------------------------------- helpers
def _inv_query():
    return select(Investigation).options(selectinload(Investigation.client),
                                         selectinload(Investigation.links).selectinload(InvestigationSignal.signal))


def _get_inv(db: Session, iid: str) -> Investigation:
    inv = db.execute(_inv_query().where(Investigation.id == iid)).scalar_one_or_none()
    if not inv:
        raise HTTPException(404)
    return inv


def _get_client(db: Session, cid: str) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    return c


def _sev_sort(inv: Investigation):
    return (-SEV_RANK.get(inv.severity, 0), inv.opened_at)


def _open_by_severity(db: Session, client_id: str | None = None) -> dict:
    q = select(Investigation.severity, func.count(Investigation.id)).where(
        Investigation.status.in_(OPEN_STATUSES))
    if client_id:
        q = q.where(Investigation.client_id == client_id)
    counts = dict(db.execute(q.group_by(Investigation.severity)).all())
    return {s: int(counts.get(s, 0)) for s in SEVERITIES}


# ---------------------------------------------------------------- overview
@app.get("/", response_class=HTMLResponse)
def overview(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    by_sev = _open_by_severity(db)
    unack = db.execute(_inv_query().where(Investigation.status.in_(OPEN_STATUSES),
                                          Investigation.severity == "critical",
                                          Investigation.acknowledged_at.is_(None))
                       .order_by(Investigation.opened_at)).scalars().all()
    recent = db.execute(_inv_query().where(Investigation.status.in_(OPEN_STATUSES))).scalars().all()
    recent = sorted(recent, key=_sev_sort)[:15]
    m = metrics.for_window(db, 30)
    week = utcnow() - dt.timedelta(days=7)
    stats = {
        "opened_7d": db.scalar(select(func.count(Investigation.id)).where(Investigation.opened_at >= week)) or 0,
        "closed_7d": db.scalar(select(func.count(Investigation.id)).where(Investigation.closed_at >= week)) or 0,
        "fp_7d": db.scalar(select(func.count(Investigation.id)).where(
            Investigation.closed_at >= week, Investigation.verdict == "false_positive")) or 0,
        "signals_7d": db.scalar(select(func.count(Signal.id)).where(Signal.occurred_at >= week)) or 0,
        "suppressed_7d": db.scalar(select(func.count(Signal.id)).where(
            Signal.occurred_at >= week, Signal.suppression_id.isnot(None))) or 0,
        "active_suppressions": db.scalar(select(func.count(Suppression.id)).where(
            Suppression.expires_at > utcnow())) or 0,
    }
    return render(request, "overview.html", user=user, by_sev=by_sev, unack=unack, recent=recent, m=m,
                  stats=stats, detect_state=detect.state())


@app.post("/detect/run")
def detect_run(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    if not detect.configured():
        return _back("/", False, "MANAGED_SERVICES_URL is not set, so there is nothing to pull.")
    try:
        summ = detect.run(db)
    except Exception as e:  # noqa: BLE001
        _audit(db, user, "detect.run.failed", str(e))
        return _back("/", False, f"Detection run failed: {e}")
    _audit(db, user, "detect.run", str(summ))
    return _back("/", True, f"Detection run: {summ['opened']} opened, {summ['attached']} attached, "
                            f"{summ['suppressed']} suppressed.")


# ---------------------------------------------------------------- investigations
@app.get("/investigations", response_class=HTMLResponse)
def investigations(request: Request, status: str = "open", severity: str = "", client_id: str = "",
                   user: str = auth.RequireUser, db: Session = Depends(get_db)):
    q = _inv_query()
    if status == "open":
        q = q.where(Investigation.status.in_(OPEN_STATUSES))
    elif status in STATUSES:
        q = q.where(Investigation.status == status)
    if severity in SEVERITIES:
        q = q.where(Investigation.severity == severity)
    if client_id:
        q = q.where(Investigation.client_id == client_id)
    rows = db.execute(q.order_by(Investigation.opened_at.desc()).limit(500)).scalars().all()
    if status == "open":
        rows = sorted(rows, key=_sev_sort)
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    return render(request, "investigations.html", user=user, rows=rows, status=status, severity=severity,
                  client_id=client_id, clients=clients, statuses=STATUSES)


@app.get("/investigations/{iid}", response_class=HTMLResponse)
def investigation_page(iid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    from . import evidence
    inv = _get_inv(db, iid)
    rule = db.get(Rule, inv.rule_key)
    entries = timeline(db, inv.id)
    chain = evidence.verify_chain(timeline_records(db, inv.id))
    latest = inv.latest_signal()
    others = db.execute(_inv_query().where(Investigation.client_id == inv.client_id, Investigation.id != inv.id,
                                           Investigation.status.in_(OPEN_STATUSES))).scalars().all()
    return render(request, "investigation.html", user=user, inv=inv, rule=rule, entries=entries, chain=chain,
                  latest=latest, alert_link=hub.alert_link(inv), alert_ref=hub.alert_ref(inv), others=others,
                  verdicts=VERDICTS, responses=[r for r in RESPONSES if r != "none"],
                  noise_days=settings.noise_suppression_days, hub_configured=bool(settings.platform_hub_url),
                  workstream=WORKSTREAM)


def _act(db: Session, iid: str, user: str, action: str, fn, ok_msg: str):
    inv = _get_inv(db, iid)
    try:
        result = fn(inv)
    except actions.ActionError as e:
        return _back(f"/investigations/{iid}", False, str(e))
    _audit(db, user, f"investigation.{action}", f"{inv.number}")
    return _back(f"/investigations/{iid}", True, ok_msg if not callable(ok_msg) else ok_msg(result))


@app.post("/investigations/{iid}/ack")
def inv_ack(iid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _act(db, iid, user, "ack", lambda inv: actions.acknowledge(db, inv, user), "Acknowledged.")


@app.post("/investigations/{iid}/verdict")
def inv_verdict(iid: str, verdict: str = Form(...), note: str = Form(""), user: str = auth.RequireUser,
                db: Session = Depends(get_db)):
    return _act(db, iid, user, "verdict", lambda inv: actions.set_verdict(db, inv, verdict, user, note.strip()),
                f"Verdict set to {VERDICT_NAMES.get(verdict, verdict)}.")


@app.post("/investigations/{iid}/note")
def inv_note(iid: str, text: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _act(db, iid, user, "note", lambda inv: actions.add_note(db, inv, text, user), "Note added.")


@app.post("/investigations/{iid}/publish")
def inv_publish(iid: str, client_summary: str = Form(""), published: bool = Form(False),
                user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _act(db, iid, user, "publish",
                lambda inv: actions.publish(db, inv, client_summary, published, user),
                "Shared with the client." if published else "Client summary saved.")


@app.post("/investigations/{iid}/contain")
def inv_contain(iid: str, note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _act(db, iid, user, "contain", lambda inv: actions.mark_contained(db, inv, user, note.strip()),
                "Marked contained.")


@app.post("/investigations/{iid}/close")
def inv_close(iid: str, verdict: str = Form(""), note: str = Form(""), user: str = auth.RequireUser,
              db: Session = Depends(get_db)):
    return _act(db, iid, user, "close", lambda inv: actions.close(db, inv, user, verdict, note.strip()), "Closed.")


@app.post("/investigations/{iid}/reopen")
def inv_reopen(iid: str, note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _act(db, iid, user, "reopen", lambda inv: actions.reopen(db, inv, user, note.strip()), "Reopened.")


@app.post("/investigations/{iid}/noise")
def inv_noise(iid: str, reason: str = Form(""), days: int = Form(30), tool: str = Form(""),
              title_contains: str = Form(""), host: str = Form(""), user: str = auth.RequireUser,
              db: Session = Depends(get_db)):
    return _act(db, iid, user, "noise",
                lambda inv: actions.noise(db, inv, user, reason, days, tool, title_contains, host),
                lambda sup: f"Closed as false positive and suppressed until {sup.expires_at.date().isoformat()}.")


@app.post("/investigations/{iid}/prepare-containment")
def inv_prepare(iid: str, action: str = Form(...), note: str = Form(""), user: str = auth.RequireUser,
                db: Session = Depends(get_db)):
    def _msg(res):
        if res["link"]:
            return f"{RESPONSE_NAMES[res['action']]} prepared. Open the managed-services alert to carry it out."
        return (f"{RESPONSE_NAMES[res['action']]} prepared. Set MANAGED_SERVICES_PUBLIC_URL to link the "
                f"managed-services alert ({res['alert_ref'] or 'no alert'}).")
    return _act(db, iid, user, "prepare_containment",
                lambda inv: actions.prepare_containment(db, inv, action, user, note), _msg)


@app.post("/investigations/{iid}/escalate")
def inv_escalate(iid: str, note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    inv = _get_inv(db, iid)
    result = hub.escalate(inv, db, user, note.strip())
    _audit(db, user, "investigation.escalate", f"{inv.number}: {result}")
    if result.get("escalated"):
        return _back(f"/investigations/{iid}", True,
                     f"{'Linked to' if result.get('linked') else 'Opened'} IR case {result['case']}.")
    return _back(f"/investigations/{iid}", False, f"Escalation failed: {result.get('reason')}")


def _export(db: Session, inv: Investigation, client_copy: bool) -> Response:
    from . import evidence
    from .evidence_export import build_package
    records = timeline_records(db, inv.id)
    if client_copy:
        # Internal entries are sealed in the client's copy: content withheld, the chain
        # still verifies because linkage and signatures are checked over the hashes.
        records = [r if r["fields"]["client_visible"] else {**r, "fields": None} for r in records]
    data = build_package(records=records, subject={"id": inv.id, "name": inv.number, "client": inv.client.name},
                         product="Vendetta Managed Detection and Response", document="investigation timeline",
                         signer=evidence.sign_bytes, public_key_hex=evidence.public_key_hex(),
                         key_id=evidence.key_id(), scheme=evidence.SCHEME, tsa_url=settings.tsa_url)
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="vendetta_{inv.number}.zip"'})


@app.get("/investigations/{iid}/evidence/verify")
def inv_verify(iid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    from . import evidence
    inv = _get_inv(db, iid)
    return JSONResponse(evidence.verify_chain(timeline_records(db, inv.id)))


@app.get("/investigations/{iid}/evidence/export.zip")
def inv_export(iid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    inv = _get_inv(db, iid)
    _audit(db, user, "evidence.export", inv.number)
    return _export(db, inv, client_copy=False)


# ---------------------------------------------------------------- rules
def _split(value: str) -> list[str]:
    out = []
    for part in (value or "").replace("\r", "").replace("\n", ",").split(","):
        p = part.strip()
        if p and p not in out:
            out.append(p)
    return out


@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rules = db.execute(select(Rule).order_by(Rule.key)).scalars().all()
    fired = dict(db.execute(select(Investigation.rule_key, func.count(Investigation.id))
                            .where(Investigation.opened_at >= utcnow() - dt.timedelta(days=30))
                            .group_by(Investigation.rule_key)).all())
    overrides = dict(db.execute(select(RuleOverride.rule_key, func.count(RuleOverride.id))
                                .group_by(RuleOverride.rule_key)).all())
    return render(request, "rules.html", user=user, rules=rules, fired=fired, overrides=overrides)


@app.get("/rules/{key}", response_class=HTMLResponse)
def rule_page(key: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    r = db.get(Rule, key)
    if not r:
        raise HTTPException(404)
    versions = db.execute(select(RuleVersion).where(RuleVersion.rule_key == key)
                          .order_by(RuleVersion.id.desc())).scalars().all()
    overrides = db.execute(select(RuleOverride).options(selectinload(RuleOverride.client))
                           .where(RuleOverride.rule_key == key)).scalars().all()
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    ident = auth.resolve_identity(request)
    return render(request, "rule.html", user=user, r=r, versions=versions, overrides=overrides, clients=clients,
                  tools=TOOLS, types=SIGNAL_TYPES, group_by=GROUP_BY, responses=RESPONSES,
                  can_edit=bool(ident and ident.is_admin))


@app.post("/rules/{key}")
async def rule_save(key: str, request: Request, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    r = db.get(Rule, key)
    if not r:
        raise HTTPException(404)
    form = await request.form()
    errs = []
    name = (form.get("name") or "").strip() or r.name
    severity = form.get("severity") or r.severity
    min_sev = form.get("min_severity") or "low"
    if severity not in SEVERITIES or min_sev not in SEVERITIES:
        errs.append("unknown severity")
    group_by = form.get("group_by") or "host"
    if group_by not in GROUP_BY:
        errs.append("group by must be host, client or title")
    response = form.get("response") or "none"
    if response not in RESPONSES:
        errs.append("unknown response")
    try:
        window = int(form.get("window_minutes") or 60)
        threshold = int(form.get("threshold") or 1)
    except ValueError:
        window, threshold = 0, 0
    if not (1 <= window <= 10080) or not (1 <= threshold <= 1000):
        errs.append("window must be 1 to 10080 minutes and threshold 1 to 1000")
    tools = [t.lower() for t in _split(form.get("tools", ""))]
    if any(t not in TOOLS for t in tools):
        errs.append(f"tools must be from: {', '.join(TOOLS)}")
    types = [t.lower() for t in _split(form.get("types", ""))]
    mitre = [t.upper() for t in _split(form.get("mitre", ""))]
    if any(not attack.valid_technique(t) for t in mitre):
        errs.append("ATT&CK ids look like T1059 or T1059.001")
    title_any = [s for s in (form.get("title_any") or "").replace("\r", "").split("\n") if s.strip()]
    title_any = [s.strip() for s in title_any]
    if not (tools or types or title_any) and threshold < 2:
        errs.append("a rule with no tool, type or title filter must correlate (threshold 2 or more)")
    if errs:
        return _back(f"/rules/{key}", False, "; ".join(errs))
    note = (form.get("note") or "").strip()
    r.name, r.description = name[:200], (form.get("description") or "").strip()
    r.enabled = form.get("enabled") == "true"
    r.severity, r.response, r.mitre = severity, response, mitre
    r.match = {"tools": tools, "types": types, "title_any": title_any, "min_severity": min_sev}
    r.correlation = {"group_by": group_by, "window_minutes": window, "threshold": threshold}
    r.version = (r.version or 1) + 1
    r.updated_by, r.updated_at = user, utcnow()
    db.flush()
    db.add(RuleVersion(rule_key=r.key, version=r.version, kind="edit", snapshot=r.as_dict(), note=note,
                       changed_by=user))
    db.commit()
    _audit(db, user, "rule.edit", f"{r.key} v{r.version}: {note}")
    return _back(f"/rules/{key}", True, f"Saved as version {r.version}.")


@app.post("/rules/{key}/overrides")
def rule_override(key: str, client_id: str = Form(...), disabled: bool = Form(False), severity: str = Form(""),
                  note: str = Form(""), user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    r = db.get(Rule, key)
    if not r:
        raise HTTPException(404)
    c = _get_client(db, client_id)
    if severity and severity not in SEVERITIES:
        return _back(f"/rules/{key}", False, "unknown severity")
    if not disabled and not severity:
        return _back(f"/rules/{key}", False, "an override either disables the rule or changes its severity")
    o = db.execute(select(RuleOverride).where(RuleOverride.rule_key == key, RuleOverride.client_id == c.id)
                   ).scalar_one_or_none()
    if o is None:
        o = RuleOverride(rule_key=key, client_id=c.id)
        db.add(o)
    o.disabled, o.severity, o.note = bool(disabled), severity, note.strip()
    o.updated_by, o.updated_at = user, utcnow()
    db.flush()
    snap = {**r.as_dict(), "override": {"client": c.name, "platform_client_id": c.platform_client_id,
                                        "disabled": o.disabled, "severity": o.severity}}
    db.add(RuleVersion(rule_key=key, version=r.version, kind="override", snapshot=snap,
                       note=f"{c.name}: {'disabled' if o.disabled else 'severity ' + o.severity}. {o.note}".strip(),
                       changed_by=user))
    db.commit()
    _audit(db, user, "rule.override", f"{key} {c.name} disabled={o.disabled} severity={o.severity}")
    return _back(f"/rules/{key}", True, f"Override saved for {c.name}.")


@app.post("/rules/{key}/overrides/{oid}/delete")
def rule_override_delete(key: str, oid: str, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    o = db.get(RuleOverride, oid)
    r = db.get(Rule, key)
    if not o or o.rule_key != key or not r:
        raise HTTPException(404)
    c = o.client
    db.add(RuleVersion(rule_key=key, version=r.version, kind="override", snapshot=r.as_dict(),
                       note=f"{c.name}: override removed", changed_by=user))
    db.delete(o)
    db.commit()
    _audit(db, user, "rule.override.delete", f"{key} {c.name}")
    return _back(f"/rules/{key}", True, f"Override removed for {c.name}.")


# ---------------------------------------------------------------- suppressions
def suppression_dict(s: Suppression, now: dt.datetime | None = None) -> dict:
    return {"id": s.id, "platform_client_id": s.platform_client_id, "client": s.client.name if s.client else "",
            "match": {"tool": s.tool, "title_contains": s.title_contains, "host": s.host},
            "tool": s.tool, "title_contains": s.title_contains, "host": s.host,
            "reason": s.reason, "expires_at": s.expires_at.isoformat(), "created_by": s.created_by,
            "created_at": s.created_at.isoformat() if s.created_at else None, "hits": s.hits,
            "active": s.is_active(now), "source_investigation_id": s.source_investigation_id}


@app.get("/suppressions", response_class=HTMLResponse)
def suppressions_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    now = utcnow()
    rows = db.execute(select(Suppression).options(selectinload(Suppression.client))
                      .order_by(Suppression.expires_at)).scalars().all()
    soon = now + dt.timedelta(days=7)
    active = [s for s in rows if s.expires_at > soon]
    expiring = [s for s in rows if now < s.expires_at <= soon]
    expired = sorted([s for s in rows if s.expires_at <= now and s.expires_at > now - dt.timedelta(days=90)],
                     key=lambda s: s.expires_at, reverse=True)
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    return render(request, "suppressions.html", user=user, active=active, expiring=expiring, expired=expired,
                  clients=clients, tools=TOOLS, now=now, noise_days=settings.noise_suppression_days)


@app.post("/suppressions")
def suppression_add(client_id: str = Form(...), tool: str = Form(""), title_contains: str = Form(""),
                    host: str = Form(""), reason: str = Form(""), days: int = Form(30),
                    user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, client_id)
    try:
        sup = actions.create_suppression(db, c, tool=tool, title_contains=title_contains, host=host,
                                         reason=reason, days=days, created_by=user)
    except actions.ActionError as e:
        return _back("/suppressions", False, str(e))
    db.commit()
    _audit(db, user, "suppression.add", f"{c.name} {sup.id}: {sup.reason}")
    return _back("/suppressions", True, f"Suppression added for {c.name}.")


@app.post("/suppressions/{sid}/expire")
def suppression_expire(sid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    s = db.get(Suppression, sid)
    if not s:
        raise HTTPException(404)
    if s.is_active():
        s.expires_at = utcnow()
        db.commit()
    _audit(db, user, "suppression.expire", sid)
    return _back("/suppressions", True, "Suppression ended.")


@app.post("/suppressions/{sid}/review")
def suppression_review(sid: str, renew_days: int = Form(0), user: str = auth.RequireUser,
                       db: Session = Depends(get_db)):
    s = db.get(Suppression, sid)
    if not s:
        raise HTTPException(404)
    s.reviewed_by, s.reviewed_at = user, utcnow()
    msg = "Marked reviewed."
    if renew_days:
        if not 1 <= renew_days <= 90:
            return _back("/suppressions", False, "renewal is 1 to 90 days")
        s.expires_at = utcnow() + dt.timedelta(days=renew_days)
        msg = f"Renewed for {renew_days} days."
    db.commit()
    _audit(db, user, "suppression.review", f"{sid} renew={renew_days}")
    return _back("/suppressions", True, msg)


# ---------------------------------------------------------------- coverage
def _coverage(db: Session) -> dict:
    return coverage.compute([r.as_dict() for r in db.execute(select(Rule).order_by(Rule.key)).scalars().all()])


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return render(request, "coverage.html", user=user, cov=_coverage(db))


# ---------------------------------------------------------------- clients
@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    counts = dict(db.execute(select(Investigation.client_id, func.count(Investigation.id))
                             .where(Investigation.status.in_(OPEN_STATUSES))
                             .group_by(Investigation.client_id)).all())
    m = metrics.for_window(db, 30)
    by_pid = {b["platform_client_id"]: b for b in m["by_client"]}
    return render(request, "clients.html", user=user, clients=rows, counts=counts, by_pid=by_pid,
                  platform_configured=provision.configured())


@app.post("/clients")
def add_client(name: str = Form(...), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    name = name.strip()
    if not name:
        return _back("/clients", False, "name required")
    if db.query(Client).filter(Client.name.ilike(name)).count():
        return _back("/clients", False, "client exists")
    c = Client(name=name[:200])
    db.add(c)
    db.commit()
    _audit(db, user, "client.add", name)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


@app.post("/clients/pull")
def clients_pull(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    if not provision.configured():
        return _back("/clients", False, "platform not configured")
    try:
        summ = provision.pull(db)
    except provision.ProvisionError as e:
        _audit(db, user, "platform.pull.failed", str(e))
        return _back("/clients", False, str(e))
    _audit(db, user, "platform.pull", str(summ))
    return _back("/clients", True, f"pulled {summ['added']} new")


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_page(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    invs = db.execute(_inv_query().where(Investigation.client_id == cid)
                      .order_by(Investigation.opened_at.desc()).limit(100)).scalars().all()
    sups = db.execute(select(Suppression).options(selectinload(Suppression.client))
                      .where(Suppression.client_id == cid, Suppression.expires_at > utcnow())).scalars().all()
    overrides = db.execute(select(RuleOverride).where(RuleOverride.client_id == cid)).scalars().all()
    m = metrics.for_window(db, 30, client_id=cid)
    return render(request, "client.html", user=user, client=c, invs=invs, sups=sups, overrides=overrides, m=m,
                  by_sev=_open_by_severity(db, cid), platform_public_url=settings.platform_public_url)


@app.post("/clients/{cid}/portal")
def client_portal_toggle(cid: str, portal_enabled: bool = Form(False), user: str = auth.RequireUser,
                         db: Session = Depends(get_db)):
    c = _get_client(db, cid)
    c.portal_enabled = bool(portal_enabled)
    db.commit()
    _audit(db, user, "client.portal", f"{c.name} portal={c.portal_enabled}")
    return _back(f"/clients/{cid}", True, "Portal " + ("enabled." if c.portal_enabled else "turned off."))


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    """The signed-in client's tenant, checked on every portal request. A session
    outlives sign-in, so a client that has been deactivated or had its portal
    switched off gets 404 here even with a valid cookie."""
    c = db.get(Client, ident.client_id)
    if not c or not c.active or not c.portal_enabled:
        raise HTTPException(404)
    return c


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    rows = db.execute(_inv_query().where(Investigation.client_id == c.id, Investigation.published.is_(True))
                      .order_by(Investigation.opened_at.desc()).limit(200)).scalars().all()
    open_rows = [i for i in rows if i.is_open]
    recent = [i for i in rows if not i.is_open and i.closed_at and i.closed_at >= utcnow() - dt.timedelta(days=90)]
    m = metrics.for_window(db, 90, client_id=c.id)
    counts = {
        "open": len(open_rows),
        "closed_90d": len(recent),
        "true_positive_90d": sum(1 for i in recent if i.verdict == "true_positive"),
        "contained_90d": sum(1 for i in rows if i.contained_at and i.contained_at >= utcnow() - dt.timedelta(days=90)),
        "by_sev": {s: sum(1 for i in open_rows if i.severity == s) for s in SEVERITIES},
    }
    return render(request, "portal.html", user=ident.email, portal=True, client=c, open_rows=open_rows,
                  recent=recent, m=m, counts=counts, exec_view=ident.is_executive)


@app.get("/portal/investigations/{iid}", response_class=HTMLResponse)
def portal_investigation(iid: str, request: Request, ident: auth.Identity = Depends(auth.require_client),
                         db: Session = Depends(get_db)):
    _portal_client(db, ident)
    inv = db.execute(_inv_query().where(Investigation.id == iid)).scalar_one_or_none()
    auth.require_owned(ident, inv, extra=bool(inv and inv.published))
    if ident.is_executive:
        return RedirectResponse("/portal", status_code=302)
    entries = [e for e in timeline(db, inv.id) if e.client_visible]
    return render(request, "portal_investigation.html", user=ident.email, portal=True, client=inv.client,
                  inv=inv, entries=entries, exec_view=False)


@app.get("/portal/investigations/{iid}/evidence/export.zip")
def portal_investigation_export(iid: str, ident: auth.Identity = Depends(auth.require_client),
                                db: Session = Depends(get_db)):
    _portal_client(db, ident)
    inv = db.execute(_inv_query().where(Investigation.id == iid)).scalar_one_or_none()
    auth.require_owned(ident, inv, extra=bool(inv and inv.published))
    if ident.is_executive:
        raise HTTPException(404, "not found")
    _audit(db, ident.email, "portal.evidence.export", inv.number)
    return _export(db, inv, client_copy=True)


# ---------------------------------------------------------------- service API
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    counts = {"open": 0, "by_severity": {s: 0 for s in SEVERITIES}, "unacknowledged_critical": 0}
    try:
        counts["by_severity"] = _open_by_severity(db)
        counts["open"] = sum(counts["by_severity"].values())
        counts["unacknowledged_critical"] = db.scalar(select(func.count(Investigation.id)).where(
            Investigation.status.in_(OPEN_STATUSES), Investigation.severity == "critical",
            Investigation.acknowledged_at.is_(None))) or 0
    except Exception:  # noqa: BLE001
        pass
    return {"module": "mdr", "display_name": "Managed Detection and Response", "platform": "Vendetta Platform",
            "enabled": settings.module_enabled, "roles": ["admin", "analyst", "viewer", "client"],
            "finding_types": ["investigation"], "statuses": STATUSES, "verdicts": VERDICTS,
            "workstream": WORKSTREAM, "counts": counts, "readiness": readiness.block(),
            "endpoints": ["/api/module", "/api/findings", "/api/findings/{id}/escalate", "/api/suppressions",
                          "/api/metrics", "/api/coverage", "/api/rules", "/api/detect/run", "/api/provision/sync"]}


@app.get("/api/findings")
def api_findings(status: str = Query("active"), platform_client_id: str = Query(""), client: str = Query(""),
                 user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Investigations in the shared finding model. status is active (default) or open
    for anything not closed, all, or a literal investigation status."""
    q = _inv_query()
    if status in ("active", "open"):
        q = q.where(Investigation.status.in_(OPEN_STATUSES))
    elif status in STATUSES:
        q = q.where(Investigation.status == status)
    elif status != "all":
        raise HTTPException(400, "unknown status")
    if platform_client_id:
        q = q.join(Investigation.client).where(Client.platform_client_id == platform_client_id)
    elif client:
        q = q.join(Investigation.client).where(Client.name.ilike(f"%{client}%"))
    rows = db.execute(q.order_by(Investigation.opened_at.desc()).limit(1000)).scalars().all()
    return [hub.finding_dict(i) for i in rows]


@app.post("/api/findings/{iid}/escalate")
def api_escalate(iid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    inv = _get_inv(db, iid)
    result = hub.escalate(inv, db, user)
    _audit(db, user, "investigation.escalate", f"{inv.number}: {result}")
    if result.get("escalated"):
        return result
    return JSONResponse(result, status_code=502)


@app.post("/api/suppressions")
async def api_suppression_add(request: Request, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "JSON body required")
    if not isinstance(body, dict):
        raise HTTPException(400, "JSON object required")
    pid = (body.get("platform_client_id") or "").strip()
    c = db.execute(select(Client).where(Client.platform_client_id == pid)).scalar_one_or_none() if pid else None
    if c is None:
        raise HTTPException(404, "unknown client")
    try:
        sup = actions.create_suppression(db, c, tool=body.get("tool") or "",
                                         title_contains=body.get("title_contains") or "",
                                         host=body.get("host") or "", reason=body.get("reason") or "",
                                         days=body.get("days", settings.noise_suppression_days),
                                         created_by=(body.get("created_by") or user))
    except actions.ActionError as e:
        raise HTTPException(400, str(e))
    db.commit()
    _audit(db, user, "suppression.add", f"{c.name} {sup.id} by {sup.created_by}: {sup.reason}")
    return {"id": sup.id, "expires_at": sup.expires_at.isoformat()}


@app.get("/api/suppressions")
def api_suppressions(platform_client_id: str = Query(""), user: str = Depends(auth.api_user),
                     db: Session = Depends(get_db)):
    q = select(Suppression).options(selectinload(Suppression.client)).order_by(Suppression.created_at.desc())
    if platform_client_id:
        q = q.where(Suppression.platform_client_id == platform_client_id)
    now = utcnow()
    return [suppression_dict(s, now) for s in db.execute(q.limit(1000)).scalars().all()]


@app.get("/api/metrics")
def api_metrics(days: int = Query(30, ge=1, le=365), platform_client_id: str = Query(""),
                user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return metrics.for_window(db, days, platform_client_id=platform_client_id)


@app.get("/api/coverage")
def api_coverage(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return _coverage(db)


@app.get("/api/rules")
def api_rules(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return [r.as_dict() for r in db.execute(select(Rule).order_by(Rule.key)).scalars().all()]


@app.post("/api/detect/run")
def api_detect_run(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    if not detect.configured():
        return JSONResponse({"ok": False, "detail": "MANAGED_SERVICES_URL not set"}, status_code=409)
    try:
        summ = detect.run(db)
    except detect.DetectError as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=502)
    _audit(db, user, "detect.run", str(summ))
    return {"ok": True, **summ}


@app.get("/api/investigations/{iid}/evidence/verify")
def api_inv_verify(iid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    from . import evidence
    if not db.get(Investigation, iid):
        raise HTTPException(404)
    return JSONResponse(evidence.verify_chain(timeline_records(db, iid)))


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
