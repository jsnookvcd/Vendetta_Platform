"""SABINE console and service API.

Console: the operator queue across every module, the proposals waiting on a
decision, the autonomy policy, briefs SABINE wrote, the signed ledger and a place
to ask SABINE a question. API: the same for the control plane and other agents,
plus /api/run to trigger a cycle and /api/module for the platform probe.
"""
from __future__ import annotations

import hmac
import logging
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import auth, boot, brain, ledger, narrative, oidc, perception, policy, provision, reach, sso, voice
from . import readiness as readiness_mod
from .config import settings
from .db import AuditLog, Brief, Proposal, SessionLocal, Speech, User, WorkItem, init_db, utcnow

log = logging.getLogger(__name__)
_APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
templates.env.globals.update(app_name=settings.app_name)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    provision.start_scheduler(SessionLocal)
    brain.start_scheduler()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_DISABLED_HTML = ("<!doctype html><meta charset=utf-8><title>Disabled</title><body style='background:#0A0D13;color:#e8ecf3;"
                  "font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0'><div style='text-align:center'>"
                  "<h1 style='color:#e0122f'>SABINE is turned off</h1></div></body>")


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
    ctx.setdefault("narrative_on", narrative.enabled())
    ctx.setdefault("tts_provider", voice.provider())
    return templates.TemplateResponse(request, name, ctx)


def _back(url: str, ok: bool, message: str) -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}{'msg' if ok else 'err'}={quote(message[:300])}", status_code=302)


def _is_admin(request: Request) -> bool:
    ident = auth.resolve_identity(request)
    return bool(ident and ident.role == "admin")


def _require_admin(request: Request) -> str:
    ident = auth.require_internal(request)
    if ident.role != "admin":
        raise HTTPException(403, "admin only")
    return ident.email


RequireAdmin = Depends(_require_admin)


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
        resp = RedirectResponse(next if next.startswith("/") else "/", status_code=302)
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


# ---------------------------------------------------------------- console
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _queue(db: Session, domain: str = "", state: str = "open") -> list[WorkItem]:
    q = select(WorkItem)
    if state == "open":
        q = q.where(WorkItem.state.in_(("open", "claimed")))
    elif state != "all":
        q = q.where(WorkItem.state == state)
    if domain:
        q = q.where(WorkItem.domain == domain)
    rows = db.execute(q).scalars().all()
    return sorted(rows, key=lambda w: (SEV_ORDER.get(w.severity, 9), w.first_seen))


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    pending = db.execute(select(Proposal).where(Proposal.status == "pending").order_by(desc(Proposal.created_at)).limit(12)).scalars().all()
    recent = db.execute(select(Proposal).where(Proposal.status.in_(("executed", "failed"))).order_by(desc(Proposal.executed_at)).limit(10)).scalars().all()
    snaps = perception.snapshots(db)
    return render(request, "dashboard.html", user=user, stats=brain.stats(db), queue=_queue(db)[:12],
                  pending=pending, recent=recent, last=brain.LAST, snaps=sorted(snaps.values(), key=lambda s: s.source),
                  ledger_n=ledger.count(db), directory=reach.directory())


@app.post("/run")
def run_now(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    try:
        summary = brain.cycle(db)
    except Exception as e:  # noqa: BLE001
        return _back("/", False, f"Cycle failed: {type(e).__name__}: {e}")
    _audit(db, user, "cycle.manual", str(summary))
    return _back("/", True, f"Cycle done: {summary['proposed']} proposed, {summary['executed']} done.")


@app.get("/queue", response_class=HTMLResponse)
def queue_page(request: Request, domain: str = Query(""), state: str = Query("open"),
               user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return render(request, "queue.html", user=user, items=_queue(db, domain, state), domain=domain, state=state,
                  stats=brain.stats(db))


@app.post("/queue/{wid}/claim")
def queue_claim(wid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    w = db.get(WorkItem, wid)
    if not w:
        raise HTTPException(404)
    w.state, w.owner = "claimed", user
    db.commit()
    ledger.append(db, "decision", user, f"claimed: {w.title}", {"work_item": w.key}, ref=w.id)
    return _back("/queue", True, "Claimed.")


@app.post("/queue/{wid}/done")
def queue_done(wid: str, note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    w = db.get(WorkItem, wid)
    if not w:
        raise HTTPException(404)
    w.state, w.done_at = "done", utcnow()
    db.commit()
    ledger.append(db, "decision", user, f"done: {w.title}", {"work_item": w.key, "note": note}, ref=w.id)
    return _back("/queue", True, "Marked done.")


@app.get("/proposals", response_class=HTMLResponse)
def proposals_page(request: Request, status: str = Query("pending"), user: str = auth.RequireUser,
                   db: Session = Depends(get_db)):
    q = select(Proposal).order_by(desc(Proposal.created_at)).limit(200)
    if status != "all":
        q = q.where(Proposal.status == status)
    rows = db.execute(q).scalars().all()
    return render(request, "proposals.html", user=user, proposals=rows, status=status, actions=policy.ACTIONS)


@app.get("/proposals/{pid}", response_class=HTMLResponse)
def proposal_page(pid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    p = db.get(Proposal, pid)
    if not p:
        raise HTTPException(404)
    return render(request, "proposal.html", user=user, prop=p, spec=policy.ACTIONS[p.action],
                  can_decide=_is_admin(request) or p.risk != "high")


@app.post("/proposals/{pid}/decide")
def proposal_decide(pid: str, request: Request, approve: bool = Form(False), note: str = Form(""),
                    user: str = auth.RequireUser, db: Session = Depends(get_db)):
    p = db.get(Proposal, pid)
    if not p:
        raise HTTPException(404)
    if p.risk == "high" and not _is_admin(request):
        raise HTTPException(403, "a high-risk proposal needs an admin")
    res = brain.decide(db, p, user, bool(approve), note)
    _audit(db, user, "proposal.decide", f"{p.id} {'approve' if approve else 'reject'}: {res.get('detail')}")
    return _back(f"/proposals/{pid}", bool(res.get("ok")), res.get("detail", ""))


@app.get("/policy", response_class=HTMLResponse)
def policy_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return render(request, "policy.html", user=user, rows=policy.table(db), is_admin=_is_admin(request),
                  levels=policy.AUTONOMY)


@app.post("/policy/{action}")
def policy_set(action: str, autonomy: str = Form(...), user: str = RequireAdmin, db: Session = Depends(get_db)):
    try:
        policy.set_autonomy(db, action, autonomy, user)
    except ValueError as e:
        return _back("/policy", False, str(e))
    ledger.append(db, "decision", user, f"policy: {action} -> {autonomy}", {"action": action, "autonomy": autonomy})
    return _back("/policy", True, f"{policy.ACTIONS[action]['label']}: {autonomy}.")


@app.get("/briefs", response_class=HTMLResponse)
def briefs_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Brief).order_by(desc(Brief.created_at)).limit(100)).scalars().all()
    return render(request, "briefs.html", user=user, briefs=rows)


@app.get("/briefs/{bid}", response_class=HTMLResponse)
def brief_page(bid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    b = db.get(Brief, bid)
    if not b:
        raise HTTPException(404)
    return render(request, "brief.html", user=user, b=b)


@app.get("/briefs/{bid}/download")
def brief_download(bid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    b = db.get(Brief, bid)
    if not b:
        raise HTTPException(404)
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(b.body_md, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{b.title.replace(" ", "-")}.md"'})


@app.get("/ledger", response_class=HTMLResponse)
def ledger_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    from .db import Ledger

    rows = db.execute(select(Ledger).order_by(desc(Ledger.chain_seq)).limit(200)).scalars().all()
    return render(request, "ledger.html", user=user, rows=rows, verify=ledger.verify(db))


@app.get("/ledger/export")
def ledger_export(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return ledger.export(db)


def _tagline(user: str) -> str:
    if settings.persona != "sabine":
        return "Ask about anything SABINE can see across the platform."
    first = user.split("@")[0].split(".")[0].capitalize() if "@" in user else ""
    return (f"Ask me anything, {first}. I have read every module this morning; you have not." if first
            else "Ask me anything. I have read every module this morning; you have not.")


@app.get("/ask", response_class=HTMLResponse)
def ask_page(request: Request, user: str = auth.RequireUser):
    return render(request, "ask.html", user=user, question="", answer="", source="", tagline=_tagline(user))


@app.post("/ask", response_class=HTMLResponse)
def ask(request: Request, question: str = Form(...), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    text_, source = narrative.answer(question.strip()[:1000], brain.picture(db))
    ledger.append(db, "observation", user, f"asked: {question.strip()[:200]}", {"source": source})
    return render(request, "ask.html", user=user, question=question, answer=text_, source=source, tagline=_tagline(user))


# ---------------------------------------------------------------- the board (kiosk)
KIOSK_COOKIE = "sabine_board"


def _board_ok(request: Request) -> bool:
    """A wall display: the kiosk token once in the URL sets a long-lived cookie.
    Any signed-in staff session also sees the board. Read-only either way."""
    if not settings.kiosk_token:
        return bool(auth.resolve_identity(request))
    k = request.query_params.get("k", "")
    if k and hmac.compare_digest(k, settings.kiosk_token):
        return True
    c = request.cookies.get(KIOSK_COOKIE, "")
    if c and hmac.compare_digest(c, settings.kiosk_token):
        return True
    return bool(auth.resolve_identity(request))


def _board_payload(db: Session) -> dict:
    snaps = perception.snapshots(db)
    mods = {k.split(":", 1)[1]: {"ok": s.ok, "detail": s.detail} for k, s in snaps.items() if k.startswith("module:")}
    queue = _queue(db)
    pending = db.execute(select(Proposal).where(Proposal.status == "pending").order_by(desc(Proposal.created_at)).limit(6)).scalars().all()
    recent = db.execute(select(Proposal).where(Proposal.status.in_(("executed", "failed"))).order_by(desc(Proposal.executed_at)).limit(5)).scalars().all()
    return {
        "at": utcnow().isoformat(),
        "line": brain.LAST.get("line") or ("Waiting for my first cycle." if settings.persona == "sabine" else "No cycle yet."),
        "stats": brain.stats(db),
        "last_cycle": {"at": brain.LAST["at"].isoformat() if brain.LAST["at"] else None, "ok": brain.LAST["ok"]},
        "modules": mods,
        "queue": [{"title": w.title, "severity": w.severity, "client": w.client, "domain": w.domain, "source": w.source,
                   "owner": w.owner} for w in queue[:10]],
        "pending": [{"title": p.title, "risk": p.risk, "confidence": p.confidence, "domain": p.domain} for p in pending],
        "recent": [{"title": p.title, "ok": p.status == "executed", "detail": (p.result or {}).get("detail", "")} for p in recent],
        "refresh": settings.board_refresh_seconds,
        "speak": voice.provider(),
    }


@app.get("/board", response_class=HTMLResponse)
def board(request: Request, db: Session = Depends(get_db)):
    if not _board_ok(request):
        raise HTTPException(401, "board token required")
    resp = templates.TemplateResponse(request, "board.html", {"data": _board_payload(db), "persona": settings.persona})
    k = request.query_params.get("k", "")
    if k and settings.kiosk_token and hmac.compare_digest(k, settings.kiosk_token):
        resp.set_cookie(KIOSK_COOKIE, settings.kiosk_token, httponly=True, samesite="lax",
                        secure=settings.cookie_secure, max_age=365 * 24 * 3600)
    return resp


@app.get("/api/board")
def api_board(request: Request, db: Session = Depends(get_db)):
    if not _board_ok(request):
        raise HTTPException(401, "board token required")
    return _board_payload(db)


# ---------------------------------------------------------------- voice
@app.post("/api/speak")
def api_speak(body: dict, request: Request, db: Session = Depends(get_db)):
    """Render text SABINE wrote to audio. Staff session, API token or the board
    cookie may call it. Returns {provider, url} or, for the browser provider,
    {provider: "browser"} so the page synthesizes locally."""
    if not (_board_ok(request) or request.headers.get("authorization", "").startswith("Bearer ")):
        raise HTTPException(401)
    if request.headers.get("authorization", "").startswith("Bearer "):
        auth.api_user(request)
    text_ = str(body.get("text") or "").strip()
    if not text_:
        raise HTTPException(400, "text required")
    row = voice.speak(db, text_)
    if row is None:
        return {"provider": voice.provider(), "url": None}
    return {"provider": row.provider, "url": f"/speech/{row.id}"}


@app.get("/speech/{sid}")
def speech(sid: str, request: Request, db: Session = Depends(get_db)):
    if not _board_ok(request):
        raise HTTPException(401)
    row = db.get(Speech, sid)
    if not row:
        raise HTTPException(404)
    from fastapi.responses import Response

    return Response(content=row.data, media_type=row.mime, headers={"Cache-Control": "private, max-age=86400"})


# ---------------------------------------------------------------- settings
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    n_users = db.scalar(select(func.count(User.id))) or 0
    scfg = sso.resolve()
    cfg = {
        "module_enabled": settings.module_enabled,
        "sso": (f"Entra ID tenant {scfg['tenant_id']} ({scfg['source']})" if sso.enabled() else "off (local admin login)"),
        "cycle": settings.cycle_interval_seconds,
        "narrative": settings.llm_model if narrative.enabled() else "rules only (no ANTHROPIC_API_KEY)",
        "persona": settings.persona,
        "voice": voice.voice_label(),
        "board": "on (kiosk token set)" if settings.kiosk_token else "staff sessions only (KIOSK_TOKEN unset)",
        "reach": ", ".join(sorted(reach.directory())) or "nothing (MODULE_DIRECTORY unset)",
        "platform": provision.state(),
    }
    return render(request, "settings.html", user=user, cfg=cfg, api_token=auth.api_token(), n_users=n_users)


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
    values = {k: (form.get(k) or "") for k in ("tenant_id", "client_id", "client_secret", "redirect_url", "allowed_group",
                                                "allowed_emails", "internal_email_domains", "admin_emails")}
    values["enabled"] = form.get("enabled") == "true"
    sso.save(values, user)
    ok, detail = sso.test()
    sso.set_status(ok, detail)
    _audit(db, user, "sso.save", f"{'ok' if ok else 'fail'}: {detail}")
    return RedirectResponse(f"/settings/sso?{'ok' if ok else 'testfail'}=1", status_code=302)


@app.post("/settings/sso/test")
def sso_test(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ok, detail = sso.test()
    sso.set_status(ok, detail)
    _audit(db, user, "sso.test", f"{'ok' if ok else 'fail'}: {detail}")
    return RedirectResponse(f"/settings/sso?{'ok' if ok else 'testfail'}=1", status_code=302)


# ---------------------------------------------------------------- service API
def _wi_json(w: WorkItem) -> dict:
    return {"id": w.id, "key": w.key, "source": w.source, "kind": w.kind, "domain": w.domain, "title": w.title,
            "client": w.client, "platform_client_id": w.platform_client_id, "severity": w.severity, "state": w.state,
            "owner": w.owner, "link": w.link, "first_seen": w.first_seen.isoformat(), "last_seen": w.last_seen.isoformat(),
            "due_at": w.due_at.isoformat() if w.due_at else None}


def _p_json(p: Proposal) -> dict:
    return {"id": p.id, "action": p.action, "domain": p.domain, "title": p.title, "rationale": p.rationale,
            "facts": p.facts, "target": p.target, "confidence": p.confidence, "risk": p.risk, "autonomy": p.autonomy,
            "status": p.status, "decided_by": p.decided_by, "result": p.result, "created_at": p.created_at.isoformat()}


@app.get("/api/queue")
def api_queue(domain: str = Query(""), state: str = Query("open"), user: str = Depends(auth.api_user),
              db: Session = Depends(get_db)):
    return [_wi_json(w) for w in _queue(db, domain, state)]


@app.get("/api/proposals")
def api_proposals(status: str = Query("pending"), user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    q = select(Proposal).order_by(desc(Proposal.created_at)).limit(200)
    if status != "all":
        q = q.where(Proposal.status == status)
    return [_p_json(p) for p in db.execute(q).scalars().all()]


@app.post("/api/proposals/{pid}/decide")
def api_decide(pid: str, body: dict, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    p = db.get(Proposal, pid)
    if not p:
        raise HTTPException(404)
    if p.risk == "high" and user.startswith("api"):
        raise HTTPException(403, "a high-risk proposal is decided by a person in the console")
    res = brain.decide(db, p, user, bool(body.get("approve")), str(body.get("note") or ""))
    return JSONResponse({**res, "proposal": _p_json(p)}, status_code=200 if res.get("ok") else 409)


@app.post("/api/run")
def api_run(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    try:
        return brain.cycle(db)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "detail": f"{type(e).__name__}: {e}"}, status_code=500)


@app.get("/api/briefs")
def api_briefs(kind: str = Query(""), user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    q = select(Brief).order_by(desc(Brief.created_at)).limit(100)
    if kind:
        q = q.where(Brief.kind == kind)
    return [{"id": b.id, "kind": b.kind, "client": b.client, "title": b.title, "source": b.source,
             "created_at": b.created_at.isoformat(), "body_md": b.body_md} for b in db.execute(q).scalars().all()]


@app.get("/api/ledger/verify")
def api_ledger_verify(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return ledger.verify(db)


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return {
        "module": "sabine", "display_name": "SABINE", "platform": "Vendetta Platform", "role": "agent",
        "enabled": settings.module_enabled, "public_url": settings.public_url,
        "endpoints": ["/api/queue", "/api/proposals", "/api/run", "/api/briefs", "/api/ledger/verify", "/api/module"],
        "readiness": readiness_mod.block(),
        "stats": brain.stats(db),
    }


@app.post("/api/provision/sync")
def api_provision_sync(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    if not provision.configured():
        return JSONResponse({"ok": False, "detail": "PLATFORM_URL not set"}, status_code=409)
    try:
        return {"ok": True, **provision.pull(db)}
    except provision.ProvisionError as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=502)


@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}
