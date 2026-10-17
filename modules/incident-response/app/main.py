"""IR Hub: incident response and case management, the engagement hub spine.

Internal console for running cases on the five-workstream template and managing
retainers; a read-only client portal with one-button incident declaration for
retainer clients; and the hub API other modules call to escalate findings."""
from __future__ import annotations

import datetime as dt
import logging
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware

from . import boot
from . import auth, board, findings as findings_mod, hub, notify, oidc, provision, sso
from . import readiness as readiness_mod
from .config import WORKSTREAMS, settings
from .db import (AuditLog, Case, CaseUpdate, Client, Retainer, SessionLocal, Task, Workstream,
                 ensure_seq_counter, init_db, open_case, utcnow)

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals["app_name"] = settings.app_name
templates.env.globals["WORKSTREAMS"] = WORKSTREAMS
templates.env.globals["TASK_STATUSES"] = board.TASK_STATUSES
templates.env.globals["TASK_LABELS"] = board.TASK_LABELS
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)

CASE_STATUSES = ["open", "contained", "eradicated", "recovered", "closed"]
WS_STATUSES = ["not_started", "in_progress", "blocked", "done"]
DEFAULT_READINESS = [
    "Emergency contacts confirmed",
    "Network diagram on file",
    "Privileged access path for responders agreed",
    "Log retention verified (90 days minimum)",
    "Cyber insurance carrier and counsel on file",
    "Tabletop exercise completed this year",
]


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    provision.start_scheduler(SessionLocal)
    db = SessionLocal()
    try:
        ensure_seq_counter(db)
    finally:
        db.close()


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
    "<div style='text-align:center;max-width:40ch'><h1 style='color:#e0122f'>Incident Response is turned off</h1>"
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
        "open_cases": db.scalar(select(func.count(Case.id)).where(Case.status != "closed")) or 0,
        "critical": db.scalar(select(func.count(Case.id)).where(Case.status != "closed", Case.severity == "critical")) or 0,
    }


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user") and not ctx.get("portal"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    return templates.TemplateResponse(request, name, ctx)


# ---------------------------------------------------------------- login
_login_hits: dict[str, list[float]] = {}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso_status: str = Query("", alias="sso")):
    msg = {"failed": "Microsoft sign-in did not complete. Try again.",
           "denied": "That account is not permitted to access this console."}.get(sso_status, "")
    return render(request, "login.html", next=next, error=msg, oidc_enabled=sso.enabled())


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < settings.login_window_seconds]
    _login_hits[ip] = hits
    if len(hits) >= settings.login_max_attempts:
        return render(request, "login.html", next=next, error="Too many attempts. Wait a few minutes and try again.", oidc_enabled=sso.enabled())
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(next or "/", status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_hits.setdefault(ip, []).append(now)
    _audit(db, username, "login.failed", ip)
    return render(request, "login.html", next=next, error="Invalid credentials", oidc_enabled=sso.enabled())


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


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    open_cases = db.execute(
        select(Case).options(selectinload(Case.client), selectinload(Case.workstreams))
        .where(Case.status != "closed").order_by(desc(Case.opened_at))
    ).scalars().all()
    by_status = {s: 0 for s in CASE_STATUSES}
    for c in open_cases:
        by_status[c.status] = by_status.get(c.status, 0) + 1
    retainers = db.execute(select(Retainer).options(selectinload(Retainer.client)).where(Retainer.active.is_(True))).scalars().all()
    recent = db.execute(
        select(CaseUpdate).options(selectinload(CaseUpdate.case).selectinload(Case.client))
        .order_by(desc(CaseUpdate.at)).limit(12)
    ).scalars().all()
    n_clients = db.scalar(select(func.count(Client.id))) or 0
    return render(request, "dashboard.html", user=user, cases=open_cases, by_status=by_status,
                  retainers=retainers, recent=recent, n_clients=n_clients)


# ---------------------------------------------------------------- cases
@app.get("/cases", response_class=HTMLResponse)
def cases(request: Request, status: str = "active", client_id: str = "", user: str = auth.RequireUser, db: Session = Depends(get_db)):
    q = select(Case).options(selectinload(Case.client), selectinload(Case.workstreams))
    if status == "active":
        q = q.where(Case.status != "closed")
    elif status != "all":
        q = q.where(Case.status == status)
    if client_id:
        q = q.where(Case.client_id == client_id)
    rows = db.execute(q.order_by(desc(Case.seq)).limit(300)).scalars().all()
    clients_ = db.execute(select(Client).order_by(Client.name)).scalars().all()
    return render(request, "cases.html", user=user, cases=rows, clients=clients_, status=status, client_id=client_id, statuses=CASE_STATUSES)


@app.post("/cases")
def create_case(client_id: str = Form(...), title: str = Form(...), severity: str = Form("high"),
                incident_type: str = Form(""), lead: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, client_id)
    if not c:
        raise HTTPException(404)
    case = open_case(db, c, title, severity=severity, origin="manual", actor=user, incident_type=incident_type, lead=lead)
    _audit(db, user, "case.open", case.number)
    return RedirectResponse(f"/cases/{case.id}", status_code=302)


def _get_case(db: Session, cid: str) -> Case:
    case = db.execute(
        select(Case).options(selectinload(Case.client).selectinload(Client.retainer), selectinload(Case.workstreams),
                             selectinload(Case.updates), selectinload(Case.tasks))
        .where(Case.id == cid)
    ).scalar_one_or_none()
    if not case:
        raise HTTPException(404)
    return case


@app.get("/cases/{cid}", response_class=HTMLResponse)
def case_detail(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    latest, counts = board.card_activity(case)
    return render(request, "case.html", user=user, case=case, statuses=CASE_STATUSES, ws_statuses=WS_STATUSES,
                  lanes=board.lanes(case), latest=latest, counts=counts, bsum=board.summary(case),
                  today=dt.date.today())


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, client_id: str = "", user: str = auth.RequireUser,
                  db: Session = Depends(get_db)):
    """Cross-module findings pulled live from each enabled module, optionally scoped
    to one client. Degrades gracefully if a module is unreachable."""
    if client_id:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404)
        pulled = findings_mod.for_client(c)
        scope = c.name
    else:
        pulled = findings_mod.pull_all()
        scope = ""
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    return render(request, "findings.html", user=user, findings=pulled["findings"],
                  sources=pulled["sources"], clients=clients, scope=scope, client_id=client_id)


@app.get("/api/findings-pull")
def api_findings_pull(client_id: str = "", _: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    if client_id:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404)
        return JSONResponse(findings_mod.for_client(c))
    return JSONResponse(findings_mod.pull_all())


@app.get("/cases/{cid}/chain/verify")
def case_chain_verify(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Verify the case chain of custody and return the result as JSON (staff)."""
    from .db import case_chain_records

    case = _get_case(db, cid)
    from . import evidence

    result = evidence.verify_chain(case_chain_records(db, case.id))
    _audit(db, user, "case.chain.verify", f"{case.number} ok={result['ok']}")
    return JSONResponse(result)


@app.get("/cases/{cid}/proof.json")
def case_proof(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Download the full chain-of-custody proof for the case (staff / expert witness)."""
    from .db import build_proof

    case = _get_case(db, cid)
    proof = build_proof(db, case, client_view=False)
    _audit(db, user, "case.proof", case.number)
    return JSONResponse(proof, headers={
        "Content-Disposition": f'attachment; filename="chain_of_custody_{case.number}.json"'})


def _case_export_records(db: Session, case: Case, *, client_view: bool) -> list[dict]:
    """The case chain as export records. With client_view, internal entries are sealed
    (fields withheld) the same way the portal proof seals them, so the client's package
    still verifies linkage and signatures without revealing internal notes."""
    from .db import case_chain_records

    records = case_chain_records(db, case.id)
    if not client_view:
        return records
    out = []
    for r in records:
        reveal = not r["fields"].get("internal_only")
        out.append({"fields": r["fields"] if reveal else None, "prev_hash": r["prev_hash"],
                    "content_hash": r["content_hash"], "signature": r["signature"],
                    "chain_seq": r["chain_seq"], "sealed": not reveal})
    return out


def _build_evidence_export(db: Session, case: Case, *, client_view: bool = False) -> bytes:
    """Assemble a sealed, self-verifying evidence export package for one case: the
    signed timeline chain, the public key, a standalone verifier and, when a TSA is
    configured, a trusted timestamp. Defensible for court, audit or expert testimony."""
    from . import evidence
    from .evidence_export import build_package

    return build_package(
        records=_case_export_records(db, case, client_view=client_view),
        subject={"id": case.id, "number": case.number, "name": f"{case.number} {case.client.name}",
                 "client": case.client.name, "title": case.title},
        product="Vendetta Incident Response",
        document="incident case timeline",
        signer=evidence.sign_bytes,
        public_key_hex=evidence.public_key_hex(),
        key_id=evidence.key_id(),
        scheme=evidence.SCHEME,
        tsa_url=settings.tsa_url,
    )


def _export_response(data: bytes, number: str) -> Response:
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="vendetta_evidence_{number}.zip"'})


@app.get("/cases/{cid}/evidence/export.zip")
def case_evidence_export(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Download the sealed evidence package for the case (staff / expert witness)."""
    case = _get_case(db, cid)
    _audit(db, user, "case.evidence.export", case.number)
    return _export_response(_build_evidence_export(db, case), case.number)


@app.get("/api/cases/{cid}/chain/verify")
def api_case_chain_verify(cid: str, _: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Programmatic verification endpoint (bearer token), for external auditors."""
    from .db import case_chain_records

    case = db.get(Case, cid)
    if not case:
        raise HTTPException(404)
    from . import evidence

    return JSONResponse(evidence.verify_chain(case_chain_records(db, case.id)))


@app.post("/cases/{cid}/status")
def case_status(cid: str, status: str = Form(...), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    if status not in CASE_STATUSES:
        raise HTTPException(400)
    old = case.status
    case.status = status
    case.closed_at = utcnow() if status == "closed" else None
    case.updates.append(CaseUpdate(actor=user, kind="status", note=f"Status {old} to {status}.", internal_only=False))
    db.commit()
    _audit(db, user, "case.status", f"{case.number} {old}->{status}")
    return RedirectResponse(f"/cases/{cid}", status_code=302)


@app.post("/cases/{cid}/details")
def case_details(cid: str, lead: str = Form(""), severity: str = Form("high"), incident_type: str = Form(""),
                 privileged: bool = Form(False), counsel: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    case.lead, case.incident_type, case.counsel = lead.strip(), incident_type.strip(), counsel.strip()
    case.severity = severity if severity in ("low", "medium", "high", "critical") else case.severity
    case.privileged = privileged
    db.commit()
    _audit(db, user, "case.details", f"{case.number} privileged={privileged}")
    return RedirectResponse(f"/cases/{cid}", status_code=302)


@app.post("/cases/{cid}/workstreams/{wid}")
def update_workstream(cid: str, wid: str, status: str = Form(...), owner: str = Form(""), client_visible_note: str = Form(""),
                      user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ws = db.get(Workstream, wid)
    if not ws or ws.case_id != cid or status not in WS_STATUSES:
        raise HTTPException(400)
    has_cards = db.scalar(select(func.count(Task.id)).where(Task.case_id == cid, Task.workstream == ws.name))
    if has_cards:
        status = ws.status  # status follows the board for a workstream that has cards
    changed = ws.status != status
    ws.status, ws.owner, ws.client_visible_note = status, owner.strip(), client_visible_note.strip()
    if changed:
        db.add(CaseUpdate(case_id=cid, workstream=ws.name, actor=user, kind="status",
                          note=f"{ws.name}: {status.replace('_', ' ')}.", internal_only=False))
    db.commit()
    _audit(db, user, "workstream.update", f"{cid} {ws.name} {status}")
    return RedirectResponse(f"/cases/{cid}#ws", status_code=302)


@app.post("/cases/{cid}/updates")
def add_update(cid: str, note: str = Form(...), target: str = Form(""), workstream: str = Form(""),
               move_to: str = Form(""), new_card: bool = Form(False), internal_only: bool = Form(False),
               user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Log a timeline entry. `target` is "task:<id>" to attach it to a card,
    "ws:<workstream>" for a workstream, or blank for the whole case. The card moves
    by the board rules; new_card turns a workstream entry into a card."""
    case = _get_case(db, cid)
    note = note.strip()[:8000]
    if not note:
        return RedirectResponse(f"/cases/{cid}", status_code=302)
    task = None
    if target.startswith("task:"):
        task = next((t for t in case.tasks if t.id == target[5:]), None)
        if task is None:
            raise HTTPException(404, "card not on this case")
    elif target.startswith("ws:"):
        workstream = target[3:]
    workstream = workstream if workstream in WORKSTREAMS else ""
    entry = CaseUpdate(workstream=workstream, actor=user, kind="note", note=note, internal_only=internal_only)
    case.updates.append(entry)
    if task is None and new_card and workstream:
        first_line = note.splitlines()[0]
        task = board.add_task(case, workstream, first_line if len(first_line) <= 120 else first_line[:117] + "...",
                              user, status="todo", source="update", log=False)
    if task is not None:
        board.apply_update(case, entry, task, move_to, user)
    db.commit()
    return RedirectResponse(f"/cases/{cid}#timeline", status_code=302)


# ---------------------------------------------------------------- case board
def _get_task(case: Case, tid: str) -> Task:
    task = next((t for t in case.tasks if t.id == tid), None)
    if task is None:
        raise HTTPException(404, "card not on this case")
    return task


def _board_done(request: Request, cid: str):
    """Fetch calls from kanban.js get JSON; plain form posts go back to the board."""
    if request.headers.get("x-requested-with") == "fetch":
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/cases/{cid}#board", status_code=302)


@app.post("/cases/{cid}/tasks")
def add_card(cid: str, request: Request, workstream: str = Form(...), title: str = Form(...),
             owner: str = Form(""), client_visible: bool = Form(False),
             user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    try:
        board.add_task(case, workstream, title, user, owner=owner, client_visible=client_visible)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    db.commit()
    return _board_done(request, cid)


@app.post("/cases/{cid}/tasks/{tid}")
def edit_card(cid: str, tid: str, request: Request, title: str = Form(...), owner: str = Form(""),
              due_on: str = Form(""), client_visible: bool = Form(False),
              user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    task = _get_task(case, tid)
    title = " ".join(title.split())[:300]
    if not title:
        raise HTTPException(400, "card title is required")
    try:
        due = dt.date.fromisoformat(due_on) if due_on else None
    except ValueError as e:
        raise HTTPException(400, "due date must be YYYY-MM-DD") from e
    task.title, task.owner, task.due_on, task.client_visible = title, owner.strip()[:200], due, client_visible
    task.updated_at = utcnow()
    db.commit()
    return _board_done(request, cid)


@app.post("/cases/{cid}/tasks/{tid}/move")
def move_card(cid: str, tid: str, request: Request, status: str = Form(...), workstream: str = Form(""),
              before: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    task = _get_task(case, tid)
    if status not in board.TASK_STATUSES or (workstream and workstream not in WORKSTREAMS):
        raise HTTPException(400, "unknown column or lane")
    board.move_task(case, task, status, user, workstream=workstream or None, before=before or None)
    db.commit()
    return _board_done(request, cid)


@app.post("/cases/{cid}/tasks/{tid}/delete")
def delete_card(cid: str, tid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    task = _get_task(case, tid)
    board.remove_task(case, task, user)
    db.commit()
    _audit(db, user, "card.delete", f"{case.number} {task.title}")
    return _board_done(request, cid)


# ---------------------------------------------------------------- declare
@app.get("/declare", response_class=HTMLResponse)
def declare_form(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    clients_ = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    return render(request, "declare.html", user=user, clients=clients_)


def _declare(db: Session, client: Client, description: str, actor: str, severity: str = "high") -> Case:
    case = open_case(db, client, description or "Incident declared", severity=severity, origin="declared",
                     actor=actor, lead=hub.retainer_lead(client))
    db.refresh(case)
    sent = notify.page_new_case(case)
    case.updates.append(CaseUpdate(actor="system", kind="system", internal_only=True,
                                   note=f"On-call paged: {', '.join(sent) or 'no channels configured'}."))
    db.commit()
    _audit(db, actor, "case.declare", case.number)
    return case


@app.post("/declare")
def declare(client_id: str = Form(...), description: str = Form(""), severity: str = Form("high"),
            user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, client_id)
    if not c:
        raise HTTPException(404)
    case = _declare(db, c, description, user, severity)
    return RedirectResponse(f"/cases/{case.id}", status_code=302)


# ---------------------------------------------------------------- clients and retainers
@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).options(selectinload(Client.retainer), selectinload(Client.cases)).order_by(Client.name)).scalars().all()
    return render(request, "clients.html", user=user, clients=rows, platform_on=provision.configured())


@app.post("/clients/pull")
def pull_from_platform(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    """Pull the client roster from the platform control plane."""
    if not provision.configured():
        _audit(db, user, "platform.pull.skip", "no PLATFORM_URL")
        return RedirectResponse("/clients", status_code=302)
    try:
        summ = provision.pull(db)
        _audit(db, user, "platform.pull", str(summ))
    except provision.ProvisionError as e:
        _audit(db, user, "platform.pull.failed", str(e))
    return RedirectResponse("/clients", status_code=302)


@app.post("/clients")
def add_client(name: str = Form(...), industry: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = Client(name=name.strip(), industry=industry.strip())
    db.add(c)
    db.commit()
    _audit(db, user, "client.add", name)
    return RedirectResponse(f"/clients/{c.id}", status_code=302)


@app.get("/clients/{cid}", response_class=HTMLResponse)
def client_detail(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.execute(select(Client).options(selectinload(Client.retainer), selectinload(Client.cases)).where(Client.id == cid)).scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    cases_ = sorted(c.cases, key=lambda x: x.seq, reverse=True)
    return render(request, "client.html", user=user, client=c, cases=cases_)


@app.post("/clients/{cid}/retainer")
def save_retainer(cid: str, tier: str = Form(""), hours_total: int = Form(0), hours_used: int = Form(0),
                  sla_minutes: int = Form(60), named_responders: str = Form(""), renews_on: str = Form(""),
                  active: bool = Form(False), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.execute(select(Client).options(selectinload(Client.retainer)).where(Client.id == cid)).scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    r = c.retainer or Retainer(client_id=c.id, readiness=[{"item": i, "done": False} for i in DEFAULT_READINESS])
    r.tier, r.hours_total, r.hours_used, r.sla_minutes = tier.strip(), hours_total, hours_used, sla_minutes
    r.named_responders, r.active = named_responders.strip(), active
    r.renews_on = dt.date.fromisoformat(renews_on) if renews_on else None
    if not c.retainer:
        db.add(r)
    db.commit()
    _audit(db, user, "retainer.save", f"{c.name} {tier} active={active}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.post("/clients/{cid}/readiness")
def readiness(cid: str, index: int = Form(-1), new_item: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    r = db.execute(select(Retainer).where(Retainer.client_id == cid)).scalar_one_or_none()
    if not r:
        raise HTTPException(404)
    items = [dict(x) for x in (r.readiness or [])]
    if new_item.strip():
        items.append({"item": new_item.strip()[:200], "done": False})
    elif 0 <= index < len(items):
        items[index]["done"] = not items[index]["done"]
    r.readiness = items  # reassign so the JSON change is tracked
    db.commit()
    return RedirectResponse(f"/clients/{cid}#readiness", status_code=302)


@app.post("/clients/{cid}/portal")
def save_portal(cid: str, portal_enabled: bool = Form(False), portal_domains: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404)
    c.portal_enabled, c.portal_domains = portal_enabled, portal_domains.strip()
    db.commit()
    _audit(db, user, "client.portal", f"{c.name} enabled={portal_enabled}")
    return RedirectResponse(f"/clients/{cid}", status_code=302)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser):
    cfg = {
        "module_enabled": settings.module_enabled,
        "sso": f"Entra ID tenant {settings.entra_tenant_id}" if settings.oidc_enabled else "off (local admin login)",
        "sns": bool(settings.sns_topic_arn), "teams": bool(settings.teams_webhook_url),
        "case_format": f"{settings.case_prefix}-{settings.case_year}-<seq>",
    }
    return render(request, "settings.html", user=user, cfg=cfg, api_token=auth.api_token())


# ---------------------------------------------------------------- client portal
def _client_cases(db: Session, client_id: str) -> list[Case]:
    return db.execute(
        select(Case).options(selectinload(Case.workstreams), selectinload(Case.updates))
        .where(Case.client_id == client_id).order_by(desc(Case.seq)).limit(50)
    ).scalars().all()


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = db.execute(select(Client).options(selectinload(Client.retainer)).where(Client.id == ident.client_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(404)
    return render(request, "portal.html", user=ident.email, portal=True, client=c,
                  cases=_client_cases(db, c.id), exec_view=ident.is_executive)


@app.get("/portal/cases/{cid}", response_class=HTMLResponse)
def portal_case(cid: str, request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    case = _get_case(db, cid)
    auth.require_owned(ident, case)
    # Milestone-only when the matter is counsel-directed or the signed-in user is an
    # executive: progress at the workstream level, no step-by-step timeline.
    milestones_only = case.privileged or ident.is_executive
    updates = [] if milestones_only else [u for u in case.updates if not u.internal_only]
    from .db import case_chain_records
    from . import evidence

    chain = evidence.verify_chain(case_chain_records(db, case.id))
    return render(request, "portal_case.html", user=ident.email, portal=True, client=case.client, case=case,
                  updates=updates, lanes=board.lanes(case), exec_view=ident.is_executive,
                  milestones_only=milestones_only, chain=chain)


@app.get("/portal/cases/{cid}/evidence/export.zip")
def portal_case_evidence_export(cid: str, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    """The client's own sealed evidence package for a case. Internal entries are
    sealed, as in the portal proof: integrity verifiable, content withheld."""
    case = _get_case(db, cid)
    auth.require_owned(ident, case)
    _audit(db, ident.email, "portal.evidence.export", case.number)
    return _export_response(_build_evidence_export(db, case, client_view=True), case.number)


@app.get("/portal/cases/{cid}/proof.json")
def portal_case_proof(cid: str, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    """The client's own downloadable chain-of-custody proof. Internal entries are
    sealed: their content is withheld but their integrity is still verifiable."""
    from .db import build_proof

    case = _get_case(db, cid)
    auth.require_owned(ident, case)
    proof = build_proof(db, case, client_view=True)
    _audit(db, ident.email, "portal.proof", case.number)
    return JSONResponse(proof, headers={
        "Content-Disposition": f'attachment; filename="chain_of_custody_{case.number}.json"'})


@app.post("/portal/declare")
def portal_declare(description: str = Form(""), ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = db.execute(select(Client).options(selectinload(Client.retainer)).where(Client.id == ident.client_id)).scalar_one_or_none()
    if not c or not (c.retainer and c.retainer.active):
        raise HTTPException(403, "incident declaration is available to retainer clients")
    case = _declare(db, c, description or "Incident declared by client", ident.email, "high")
    return RedirectResponse(f"/portal/cases/{case.id}", status_code=302)


# ---------------------------------------------------------------- hub API
def _case_json(case: Case) -> dict:
    return {
        "id": case.id, "case_id": case.number, "number": case.number, "seq": case.seq,
        "title": case.title,
        "client": {"id": case.client_id, "name": case.client.name,
                   "platform_client_id": case.client.platform_client_id or ""},
        "severity": case.severity, "status": case.status, "origin": case.origin,
        "source_module": case.source_module, "lead": case.lead, "privileged": case.privileged,
        "opened_at": case.opened_at.isoformat(), "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "last_update_at": (case.updates[0].at.isoformat() if case.updates else case.opened_at.isoformat()),
        "workstreams": [
            {"name": w.name, "status": w.status, "owner": w.owner,
             "cards": {s: sum(1 for t in case.tasks if t.workstream == w.name and t.status == s) for s in board.TASK_STATUSES}}
            for w in case.workstreams
        ],
        "board": board.summary(case),
    }


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user)):
    return {
        "module": "incident-response", "display_name": "Incident Response and Case Management",
        "platform": "Vendetta Platform", "enabled": settings.module_enabled, "role": "engagement-hub",
        "roles": ["admin", "analyst", "client"], "workstreams": WORKSTREAMS, "case_statuses": CASE_STATUSES,
        "card_statuses": board.TASK_STATUSES,
        "readiness": readiness_mod.block(),
        "endpoints": ["/api/ir-cases", "/api/ir-cases/declare", "/api/module"],
    }


@app.get("/api/ir-cases")
def api_cases(status: str = Query("active"), client: str = Query(""), platform_client_id: str = Query(""),
              user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """status: active (default; "open" is a synonym), all, or a literal case status.
    Filter by the shared platform_client_id or a client-name substring."""
    q = select(Case).options(selectinload(Case.client), selectinload(Case.workstreams), selectinload(Case.tasks),
                             selectinload(Case.updates))
    if status in ("active", "open"):
        q = q.where(Case.status != "closed")
    elif status != "all":
        q = q.where(Case.status == status)
    if platform_client_id:
        q = q.join(Client).where(Client.platform_client_id == platform_client_id)
    elif client:
        q = q.join(Client).where(Client.name.ilike(f"%{client}%"))
    return [_case_json(c) for c in db.execute(q.order_by(desc(Case.seq)).limit(500)).scalars().all()]


@app.post("/api/ir-cases")
async def api_escalate(request: Request, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Escalation from another module. Contract matches the modules' platform.escalate payload:
    {source_module, client_id, case_ref, severity, summary, finding, workstream}."""
    payload = await request.json()
    case, linked = hub.escalate(db, payload, actor=f"module:{payload.get('source_module') or user}")
    db.refresh(case)
    if not linked:
        notify.page_new_case(case)
    return {"case_id": case.number, "id": case.id, "linked": linked}


@app.post("/api/ir-cases/declare")
async def api_declare(request: Request, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    payload = await request.json()
    # client_id here is a hub client id (this is the hub's own API); fall back to the
    # shared platform id, then the name, the same way an escalation resolves.
    c = db.get(Client, payload.get("client_id") or "") if payload.get("client_id") else None
    if c is None:
        c = hub.resolve_client(db, "", payload.get("client", ""), payload.get("platform_client_id", ""))
    db.refresh(c)
    case = _declare(db, c, payload.get("description", ""), f"api:{user}", payload.get("severity", "high"))
    return {"case_id": case.number, "id": case.id}


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}


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
