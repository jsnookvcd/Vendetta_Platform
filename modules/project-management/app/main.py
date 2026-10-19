"""Project Management console, JSON API, and remote MCP server."""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import (auth, boot, harvest, integrations, mcp, oauth, oidc, provision, readiness, service, sharepoint,
               sso)
from .config import (ENGAGEMENT_STATE_NAMES, ENGAGEMENT_STATES, IR_WORKSTREAMS, PRACTICE_NAMES, PRACTICES,
                     PRIORITIES, settings)
from .db import AuditLog, Board, Client, Engagement, MeetingNote, SessionLocal, TimeLog, init_db
from .service import ServiceError

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(app_name=settings.app_name, PRACTICE_NAMES=PRACTICE_NAMES,
                             STATE_NAMES=ENGAGEMENT_STATE_NAMES, PRIORITIES=PRIORITIES,
                             WORKSTREAMS=IR_WORKSTREAMS)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)
app.include_router(oauth.router)
app.include_router(mcp.router)


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    db = SessionLocal()
    try:
        service.ensure_practice_boards(db)
        db.commit()
    finally:
        db.close()
    provision.start_scheduler(SessionLocal)
    sharepoint.start_retry_loop(SessionLocal, settings.sharepoint_retry_seconds)


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>Project Management is turned off</h1>"
    "<p style='color:#93a0b4'>This module is currently disabled on the Vendetta Platform.</p></div></body>"
)


@app.middleware("http")
async def _access_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path == "/healthz":
        return await call_next(request)
    if not settings.module_enabled and path != "/api/module":
        if path == "/mcp":
            return JSONResponse({"error": "module disabled"}, status_code=503)
        return HTMLResponse(_DISABLED_HTML, status_code=503)
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/login?next={quote(target)}", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(ServiceError)
async def _svc_exc(request: Request, exc: ServiceError):
    return JSONResponse({"detail": exc.message}, status_code=exc.status)


def _audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail[:4000]))
    db.commit()


def _ident(request: Request) -> auth.Identity:
    return auth.require_internal(request)


def render(request: Request, name: str, **ctx):
    if ctx.get("user") and "shell" not in ctx:
        db = SessionLocal()
        try:
            ctx["shell"] = {
                "open": db.scalar(select(func.count(Engagement.id)).where(Engagement.status != "closed")) or 0,
                "mine": len(service.list_tasks(db, assignee=ctx["user"])),
            }
        except Exception:  # noqa: BLE001
            ctx["shell"] = None
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ident = auth.resolve_identity(request)
    ctx.setdefault("is_viewer", bool(ident and ident.is_viewer))
    ctx.setdefault("is_admin", bool(ident and ident.role == "admin"))
    return templates.TemplateResponse(request, name, ctx)


def back(url: str, *, msg: str = "", err: str = "") -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    if msg:
        url += f"{sep}msg={quote(msg)}"
    elif err:
        url += f"{sep}err={quote(err)}"
    return RedirectResponse(url, status_code=303)


def _form_action(db: Session, url: str, fn, ok: str = ""):
    """Run a service call from an HTML form: commit and go back with a message, or
    roll back and go back with the PM-facing error."""
    try:
        res = fn()
        db.commit()
    except ServiceError as e:
        db.rollback()
        return back(url, err=e.message)
    return res if isinstance(res, RedirectResponse) else back(url, msg=ok)


# ---------------------------------------------------------------- auth
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", sso_status: str = Query("", alias="sso")):
    msg = {"failed": "Microsoft sign-in did not complete. Try again.",
           "denied": "That account is not permitted to access this console."}.get(sso_status, "")
    return render(request, "login.html", next=oidc.safe_next(next), error=msg, oidc_enabled=sso.enabled())


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
          db: Session = Depends(get_db)):
    import time
    ip = request.client.host if request.client else "unknown"
    nxt = oidc.safe_next(next)
    if not _login_allowed(ip):
        _audit(db, username, "login.throttled", ip)
        return render(request, "login.html", next=nxt, error="Too many attempts. Wait a few minutes.",
                      oidc_enabled=sso.enabled())
    if username == settings.admin_user and auth.check_password(password):
        resp = RedirectResponse(nxt, status_code=302)
        resp.set_cookie(auth.COOKIE, auth.make_session(username), httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=12 * 3600)
        _audit(db, username, "login")
        return resp
    _login_hits.setdefault(ip, []).append(time.time())
    _audit(db, username, "login.failed", ip)
    return render(request, "login.html", next=nxt, error="Invalid credentials", oidc_enabled=sso.enabled())


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    mine = service.list_tasks(db, assignee=user)
    engs = service.list_engagements(db, pm=user)
    overdue = service.list_tasks(db, overdue=True)
    return render(request, "dashboard.html", user=user, mine=[service.card_dict(c, brief=True) for c in mine],
                  engs=[service.engagement_dict(db, e) for e in engs],
                  overdue=[service.card_dict(c, brief=True) for c in overdue[:25]],
                  st=integrations.status())


# ---------------------------------------------------------------- boards
@app.get("/boards/{practice}", response_class=HTMLResponse)
def practice_board_page(request: Request, practice: str, user: str = auth.RequireUser,
                        db: Session = Depends(get_db)):
    if practice not in PRACTICES:
        raise HTTPException(404)
    b = service.practice_board(db, practice)
    db.commit()
    return render(request, "board.html", user=user, board=service.board_dict(db, b), eng=None)


@app.post("/boards/{board_id}/columns")
def board_add_column(request: Request, board_id: str, name: str = Form(...), position: str = Form(""),
                     user: str = auth.RequireUser, db: Session = Depends(get_db)):
    b = db.get(Board, board_id) or _404()
    return _form_action(db, _board_url(db, b), lambda: service.add_column(
        db, user, b, name, int(position) if position.strip() else None), f"Column '{name}' added")


@app.post("/boards/{board_id}/columns/{column_id}")
def board_edit_column(request: Request, board_id: str, column_id: str, action: str = Form(...),
                      name: str = Form(""), wip_limit: str = Form(""), move_cards_to: str = Form(""),
                      user: str = auth.RequireUser, db: Session = Depends(get_db)):
    b = db.get(Board, board_id) or _404()
    url = _board_url(db, b)
    if action == "remove":
        return _form_action(db, url, lambda: service.delete_column(db, user, b, column_id, move_cards_to or None),
                            "Column removed")
    if action in ("left", "right"):
        col = service.resolve_column(b, column_id)
        return _form_action(db, url, lambda: service.update_column(
            db, user, b, column_id, position=max(0, col.position + (-1 if action == "left" else 1))))
    return _form_action(db, url, lambda: service.update_column(
        db, user, b, column_id, name=name or None,
        wip_limit=(int(wip_limit) if wip_limit.strip() else None)), "Column saved")


def _board_url(db: Session, b: Board) -> str:
    if b.kind == "practice":
        return f"/boards/{b.practice}"
    return f"/engagements/{b.engagement_id}"


def _404():
    raise HTTPException(404)


# JSON endpoint the board's drag and drop calls. JSON-only, so a cross-site form
# cannot reach it.
@app.post("/api/cards/{ref}/move")
async def api_move_card(ref: str, request: Request, user: str = Depends(auth.api_user),
                        db: Session = Depends(get_db)):
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "send JSON")
    body = await request.json()
    card = service.find_card(db, ref)
    service.move_card(db, user, card, body.get("column", ""), body.get("position"))
    db.commit()
    return service.card_dict(card, brief=True)


# ---------------------------------------------------------------- engagements
@app.get("/engagements", response_class=HTMLResponse)
def engagements_page(request: Request, practice: str = "", status: str = "open", q: str = "",
                     user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = service.list_engagements(db, practice=practice or None, status=status, query=q or None)
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    return render(request, "engagements.html", user=user, rows=[service.engagement_dict(db, e) for e in rows],
                  clients=clients, practice=practice, status=status, q=q,
                  phases={p: [c.name for c in service.practice_board(db, p).columns] for p in PRACTICES})


@app.post("/engagements")
def engagement_create(request: Request, practice: str = Form(...), name: str = Form(...), client: str = Form(""),
                      code: str = Form(""), pm_email: str = Form(""), budget_hours: str = Form(""),
                      starts_on: str = Form(""), ends_on: str = Form(""), harvest_project_id: str = Form(""),
                      description: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    def go():
        e = service.create_engagement(db, user, practice=practice, name=name, client=client or None,
                                      code=code or None, pm_email=pm_email or None, budget_hours=budget_hours,
                                      starts_on=starts_on, ends_on=ends_on, harvest_project_id=harvest_project_id,
                                      description=description)
        db.flush()
        return back(f"/engagements/{e.id}", msg=f"{e.code} opened")
    return _form_action(db, "/engagements", go)


@app.get("/engagements/{eid}", response_class=HTMLResponse)
def engagement_page(request: Request, eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid) or service.find_engagement(db, eid)
    board = service.engagement_board(db, e)
    db.commit()
    entries, burn, time_err = [], None, ""
    if e.harvest_project_id and harvest.configured():
        try:
            burn = service.burn(db, e)
            entries = harvest.list_entries(project_id=e.harvest_project_id,
                                           start=dt.date.today() - dt.timedelta(days=14), limit=50)
        except ServiceError as ex:
            time_err = ex.message
        except harvest.HarvestError as ex:
            time_err = str(ex)
    htasks = []
    if e.harvest_project_id and harvest.configured():
        try:
            htasks = harvest.list_tasks(e.harvest_project_id)
        except harvest.HarvestError:
            pass
    return render(request, "engagement.html", user=user, e=e, d=service.engagement_dict(db, e, detail=True),
                  board=service.board_dict(db, board), eng=e, notes=e.notes[:20], entries=entries, burn=burn,
                  time_err=time_err, htasks=htasks, states=ENGAGEMENT_STATES, sp_target=sharepoint.target(e),
                  harvest_on=harvest.configured(), today=dt.date.today().isoformat(),
                  practice_phases=[c.name for c in sorted(service.practice_board(db, e.practice).columns,
                                                          key=lambda c: c.position)])


@app.post("/engagements/{eid}/edit")
async def engagement_edit(request: Request, eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid) or _404()
    form = await request.form()
    fields = {k: form.get(k) for k in ("name", "client", "pm_email", "description", "budget_hours", "starts_on",
                                       "ends_on", "harvest_project_id", "sharepoint_site_url", "sharepoint_folder",
                                       "platform_ref", "status") if form.get(k) is not None}
    return _form_action(db, f"/engagements/{eid}", lambda: service.update_engagement(db, user, e, **fields),
                        "Engagement saved")


@app.post("/engagements/{eid}/tasks")
async def engagement_add_task(request: Request, eid: str, user: str = auth.RequireUser,
                              db: Session = Depends(get_db)):
    e = db.get(Engagement, eid) or _404()
    f = await request.form()
    return _form_action(db, f"/engagements/{eid}", lambda: service.create_task(
        db, user, e, title=f.get("title", ""), assignee=f.get("assignee") or None, due_on=f.get("due_on") or None,
        priority=f.get("priority") or None, labels=f.get("labels") or None, column=f.get("column") or None,
        description=f.get("description") or ""), "Task added")


@app.post("/engagements/{eid}/move")
def engagement_move(request: Request, eid: str, phase: str = Form(...), user: str = auth.RequireUser,
                    db: Session = Depends(get_db)):
    e = db.get(Engagement, eid) or _404()
    return _form_action(db, f"/engagements/{eid}",
                        lambda: service.move_card(db, user, service.practice_card(db, e), phase), f"Moved to {phase}")


# ---------------------------------------------------------------- tasks
@app.get("/tasks/{ref}", response_class=HTMLResponse)
def task_page(request: Request, ref: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = service.find_card(db, ref)
    if c.board.kind == "practice" and c.engagement_id:
        return RedirectResponse(f"/engagements/{c.engagement_id}", status_code=302)
    htasks = []
    if c.engagement and c.engagement.harvest_project_id and harvest.configured():
        try:
            htasks = harvest.list_tasks(c.engagement.harvest_project_id)
        except harvest.HarvestError:
            pass
    return render(request, "task.html", user=user, c=c, d=service.card_dict(c),
                  history=service.card_history(db, c.id), columns=sorted(c.board.columns, key=lambda x: x.position),
                  htasks=htasks, today=dt.date.today().isoformat())


@app.post("/tasks/{ref}/edit")
async def task_edit(request: Request, ref: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = service.find_card(db, ref)
    f = await request.form()
    fields = {k: f.get(k) for k in ("title", "description", "assignee", "priority", "labels", "estimate_hours",
                                    "column") if f.get(k) is not None}
    if f.get("due_on") is not None:
        fields["due_on"] = f.get("due_on") or "none"
    if f.get("checklist_add"):
        fields["checklist_add"] = [f.get("checklist_add")]
    return _form_action(db, f"/tasks/{c.ref}", lambda: service.update_card(db, user, c, **fields), "Task saved")


@app.post("/tasks/{ref}/check/{idx}")
def task_check(request: Request, ref: str, idx: int, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = service.find_card(db, ref)
    items = list(c.checklist or [])
    if 0 <= idx < len(items):
        items[idx] = {**items[idx], "done": not items[idx].get("done")}
        c.checklist = items
        service._event(db, c, user, "updated", f"checklist item {idx + 1} {'done' if items[idx]['done'] else 'reopened'}")
    db.commit()
    return back(f"/tasks/{c.ref}")


@app.post("/tasks/{ref}/comment")
def task_comment(request: Request, ref: str, text: str = Form(...), user: str = auth.RequireUser,
                 db: Session = Depends(get_db)):
    c = service.find_card(db, ref)
    return _form_action(db, f"/tasks/{c.ref}", lambda: service.comment(db, user, c, text))


@app.post("/tasks/{ref}/remove")
def task_remove(request: Request, ref: str, mode: str = Form("archive"), user: str = auth.RequireUser,
                db: Session = Depends(get_db)):
    c = service.find_card(db, ref)
    eid = c.engagement_id
    if mode == "delete":
        return _form_action(db, f"/engagements/{eid}", lambda: service.delete_card(db, user, c) and
                            back(f"/engagements/{eid}", msg=f"Task #{c.ref} deleted"))
    if mode == "restore":
        return _form_action(db, f"/tasks/{c.ref}", lambda: service.archive_card(db, user, c, False), "Restored")
    return _form_action(db, f"/engagements/{eid}", lambda: service.archive_card(db, user, c, True) and
                        back(f"/engagements/{eid}", msg=f"Task #{c.ref} archived"))


# ---------------------------------------------------------------- meeting notes
@app.get("/notes", response_class=HTMLResponse)
def notes_page(request: Request, q: str = "", user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = service.list_notes(db, query=q or None, limit=100)
    return render(request, "notes.html", user=user, rows=rows, q=q)


@app.post("/engagements/{eid}/notes")
async def note_create(request: Request, eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid) or _404()
    f = await request.form()
    items = [ln.strip() for ln in (f.get("action_items") or "").splitlines() if ln.strip()]
    parsed = []
    for ln in items:
        # "text @owner@vendettacd.io due 2026-10-30" (owner and due optional)
        due = owner = ""
        if " due " in ln:
            ln, due = ln.rsplit(" due ", 1)
        toks = [t for t in ln.split() if t.startswith("@") and "@" in t[1:]]
        if toks:
            owner = toks[-1][1:]
            ln = ln.replace(toks[-1], "").strip()
        parsed.append({"text": ln, "assignee": owner, "due_on": due.strip()})

    def go():
        n = service.create_note(db, user, e, title=f.get("title", ""), held_at=f.get("held_at") or None,
                                attendees=f.get("attendees") or "", body=f.get("body") or "",
                                decisions=f.get("decisions") or "", action_items=parsed,
                                create_tasks=f.get("create_tasks") == "true")
        db.flush()
        status = {"mirrored": "and written to SharePoint", "off": "(SharePoint mirror not configured)",
                  "failed": f"but the SharePoint copy failed: {n.sp_error}"}.get(n.sp_status, "")
        return back(f"/notes/{n.id}", msg=f"Note saved {status}".strip())
    return _form_action(db, f"/engagements/{eid}", go)


@app.get("/notes/{nid}", response_class=HTMLResponse)
def note_page(request: Request, nid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n = db.get(MeetingNote, nid) or _404()
    return render(request, "note.html", user=user, n=n)


@app.post("/notes/{nid}/edit")
async def note_edit(request: Request, nid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n = db.get(MeetingNote, nid) or _404()
    f = await request.form()
    fields = {k: f.get(k) for k in ("title", "attendees", "body", "decisions", "held_at") if f.get(k) is not None}
    return _form_action(db, f"/notes/{nid}", lambda: service.update_note(db, user, n, **fields), "Note saved")


@app.post("/notes/{nid}/mirror")
def note_mirror(request: Request, nid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n = db.get(MeetingNote, nid) or _404()
    sharepoint.mirror(n, n.engagement)
    db.commit()
    if n.sp_status == "mirrored":
        return back(f"/notes/{nid}", msg="Written to SharePoint")
    return back(f"/notes/{nid}", err=n.sp_error or "SharePoint copy failed")


# ---------------------------------------------------------------- time
@app.get("/time", response_class=HTMLResponse)
def time_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    start = dt.date.today() - dt.timedelta(days=dt.date.today().weekday())
    entries, err = [], ""
    if harvest.configured():
        try:
            entries = harvest.list_entries(user_email=user, start=start - dt.timedelta(days=7))
        except harvest.HarvestError as e:
            err = str(e)
    engs = [e for e in service.list_engagements(db) if e.harvest_project_id]
    week = round(sum(float(x["hours"] or 0) for x in entries if x["spent_date"] >= start.isoformat()), 2)
    return render(request, "time.html", user=user, entries=entries, week=week, time_err=err, engs=engs,
                  harvest_on=harvest.configured(), today=dt.date.today().isoformat())


@app.post("/time")
def time_log(request: Request, hours: str = Form(...), task: str = Form(...), engagement: str = Form(""),
             spent_date: str = Form(""), notes: str = Form(""), card: str = Form(""), back_to: str = Form("/time"),
             user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ident = _ident(request)
    url = oidc.safe_next(back_to)

    def go():
        try:
            h = float(hours)
        except ValueError as e:
            raise ServiceError("Hours must be a number") from e
        entry = service.log_time(db, user, ident.role, hours=h, task=task, spent_date=spent_date or None,
                                 engagement=engagement or None, notes=notes, card_ref=card or None)
        return back(url, msg=f"Logged {entry['hours']}h to {entry['project']} ({entry['task']})")
    return _form_action(db, url, go)


@app.post("/time/{entry_id}/delete")
def time_delete(request: Request, entry_id: str, back_to: str = Form("/time"), user: str = auth.RequireUser,
                db: Session = Depends(get_db)):
    ident = _ident(request)
    return _form_action(db, oidc.safe_next(back_to), lambda: service.delete_time(db, user, ident.role, entry_id),
                        "Entry deleted from Harvest")


# ---------------------------------------------------------------- connect Claude
@app.get("/connect", response_class=HTMLResponse)
def connect_page(request: Request, user: str = auth.RequireUser):
    return render(request, "connect.html", user=user, mcp_url=oauth.resource_url(request),
                  tokens=oauth.tokens_for(user), new_token=request.session.pop("new_pat", ""))


@app.post("/connect/tokens")
def connect_new_token(request: Request, name: str = Form("Claude Code"), days: str = Form("90"),
                      user: str = auth.RequireUser, db: Session = Depends(get_db)):
    raw = oauth.create_pat(user, name, int(days) if days.strip().isdigit() and int(days) > 0 else None)
    request.session["new_pat"] = raw
    _audit(db, user, "pat.create", name)
    return back("/connect", msg="Token created. Copy it now; it is not shown again.")


@app.post("/connect/tokens/{tid}/revoke")
def connect_revoke(request: Request, tid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    oauth.revoke_for(user, tid)
    _audit(db, user, "token.revoke", tid)
    return back("/connect", msg="Revoked")


@app.post("/connect/revoke-all")
def connect_revoke_all(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n = oauth.revoke_for(user)
    _audit(db, user, "token.revoke_all", str(n))
    return back("/connect", msg=f"Revoked {n} token(s). Claude will ask you to sign in again.")


# ---------------------------------------------------------------- settings
def _require_admin(request: Request) -> str:
    ident = _ident(request)
    if ident.role != "admin":
        raise HTTPException(403, "admin only")
    auth.require_write(request, ident)
    return ident.email


@app.get("/settings/integrations", response_class=HTMLResponse)
def integrations_page(request: Request, user: str = auth.RequireUser):
    return render(request, "integrations.html", user=user, st=integrations.status(), ready=readiness.block())


@app.post("/settings/integrations")
async def integrations_save(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request)
    form = await request.form()
    integrations.save({k: form.get(k) for k in integrations.FIELDS if form.get(k) is not None}, user)
    harvest._USERS.update(at=0.0)
    sharepoint._TOKEN.update(value="")
    sharepoint._SITES.clear()
    _audit(db, user, "integrations.save")
    msgs = []
    if harvest.configured():
        try:
            n = len(harvest.list_projects())
            msgs.append(f"Harvest connected ({n} active projects)")
        except harvest.HarvestError as e:
            return back("/settings/integrations", err=f"Saved, but Harvest failed: {e}")
    return back("/settings/integrations", msg="; ".join(msgs) or "Saved")


@app.get("/settings/sso", response_class=HTMLResponse)
def sso_page(request: Request, user: str = auth.RequireUser):
    q = request.query_params
    st = sso.status()
    msg = f"Microsoft 365 SSO verified. {st['last_detail']}".strip() if q.get("ok") else ""
    err = f"SSO saved but the test failed: {st['last_detail']}".strip() if q.get("testfail") else ""
    return render(request, "sso.html", user=user, st=st, msg=msg, err=err)


@app.post("/settings/sso")
async def sso_save(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request)
    form = await request.form()
    values = {k: (form.get(k) or "") for k in
              ("tenant_id", "client_id", "client_secret", "redirect_url", "allowed_group",
               "allowed_emails", "internal_email_domains", "admin_emails")}
    values["enabled"] = form.get("enabled") == "true"
    sso.save(values, user)
    ok, detail = sso.test()
    sso.set_status(ok, detail)
    _audit(db, user, "sso.save", f"{'ok' if ok else 'fail'}: {detail}")
    return RedirectResponse(f"/settings/sso?{'ok' if ok else 'testfail'}=1", status_code=302)


# ---------------------------------------------------------------- service API
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/module")
def api_module():
    return {"name": "project-management", "display_name": "Project Management", "platform": "Vendetta Platform",
            "status": "in-progress", "enabled": settings.module_enabled,
            "service_lines": ["incident-response", "professional-services"],
            "mcp": "/mcp", "readiness": readiness.block()}


@app.get("/api/engagements")
def api_engagements(practice: str = "", status: str = "open", platform_client_id: str = "",
                    user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    rows = service.list_engagements(db, practice=practice or None, status=status)
    out = [service.engagement_dict(db, e) for e in rows]
    if platform_client_id:
        out = [e for e in out if e["platform_client_id"] == platform_client_id]
    return {"engagements": out}


@app.post("/api/engagements")
async def api_engagement_create(request: Request, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Open an engagement from elsewhere on the platform (the IR hub declaring a
    case, OSP opening an engagement). Idempotent on code."""
    body = await request.json()
    code = (body.get("code") or "").strip()
    if code:
        existing = db.execute(select(Engagement).where(func.lower(Engagement.code) == code.lower())).scalar_one_or_none()
        if existing:
            return JSONResponse(service.engagement_dict(db, existing), status_code=200)
    allowed = {"practice", "name", "code", "client", "pm_email", "description", "budget_hours", "starts_on",
               "ends_on", "harvest_project_id", "sharepoint_site_url", "sharepoint_folder", "platform_ref", "column"}
    e = service.create_engagement(db, user, **{k: v for k, v in body.items() if k in allowed})
    db.commit()
    return JSONResponse(service.engagement_dict(db, e, detail=True), status_code=201)


@app.get("/api/tasks")
def api_tasks(engagement: str = "", assignee: str = "", overdue: bool = False, include_done: bool = False,
              user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    eng = service.find_engagement(db, engagement) if engagement else None
    rows = service.list_tasks(db, engagement=eng, assignee=assignee or None, overdue=overdue,
                              include_done=include_done)
    return {"tasks": [service.card_dict(c, brief=True) for c in rows]}


@app.get("/api/boards/{ref}")
def api_board(ref: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    b = service.find_board(db, ref)
    db.commit()
    return service.board_dict(db, b)


@app.get("/api/time-logs")
def api_time_logs(engagement: str = "", user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    q = select(TimeLog).order_by(TimeLog.at.desc()).limit(500)
    if engagement:
        q = q.where(TimeLog.engagement_id == service.find_engagement(db, engagement).id)
    return {"time_logs": [{"at": t.at.isoformat(), "action": t.action, "actor": t.actor, "user": t.user_email,
                           "harvest_entry_id": t.harvest_entry_id, "spent_date": str(t.spent_date or ""),
                           "hours": t.hours, "notes": t.notes} for t in db.execute(q).scalars()]}


@app.post("/api/provision/sync")
def api_provision_sync(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    try:
        return provision.pull(db)
    except provision.ProvisionError as e:
        raise HTTPException(502, str(e)) from e


@app.get("/clients/platform/{platform_client_id}")
def deep_link(platform_client_id: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.execute(select(Client).where(Client.platform_client_id == platform_client_id)).scalar_one_or_none()
    if c is None:
        return back("/engagements", err="That client is not on this module's roster yet")
    return RedirectResponse(f"/engagements?q={quote(c.name)}&status=all", status_code=302)

