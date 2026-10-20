"""Telemetry Ingest: staff console, client portal, push door and service API."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import secrets as pysecrets
import time
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import (auth, boot, connectors, hub, mappers, oidc, pipeline, provision, readiness, receipts, sigma, sso,
               stream, worker)
from .config import FINDING_STATUSES, OPEN_FINDING_STATUSES, SEVERITIES, WORKSTREAM, settings
from .db import (Anchor, AuditLog, Batch, Client, Connector, ConnectorRun, Detection, Event, Rejected,
                 SessionLocal, SigmaRule, SigmaRuleVersion, init_db, utcnow)
from .ocsf import CLASSES

log = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name, docs_url="/api/docs", redoc_url=None)
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
CLASS_NAMES = {v[0]: v[1] for v in CLASSES.values()}
templates.env.globals.update(app_name=settings.app_name, SEVERITIES=SEVERITIES, CLASS_NAMES=CLASS_NAMES,
                             FINDING_STATUSES=FINDING_STATUSES)
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.cookie_secure)
app.include_router(oidc.router)

PUSH_PREFIX = "/api/ingest/"
PUSH_SKEW_SECONDS = 300


@app.on_event("startup")
def _startup():
    boot.check()
    init_db()
    provision.start_scheduler(SessionLocal)
    worker.start(SessionLocal)


_DISABLED_HTML = (
    "<!doctype html><meta charset=utf-8><title>Module disabled</title>"
    "<body style='background:#0A0D13;color:#e8ecf3;font-family:system-ui;display:grid;"
    "place-items:center;height:100vh;margin:0'><div style='text-align:center;max-width:40ch'>"
    "<h1 style='color:#e0122f'>Telemetry Ingest is turned off</h1>"
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
    if path.startswith(PUSH_PREFIX):
        return await call_next(request)  # authenticated per connector, below
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
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < settings.login_window_seconds]
    _login_hits[ip] = hits
    return len(hits) < settings.login_max_attempts


def _login_record(ip: str) -> None:
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
        since = utcnow() - dt.timedelta(hours=24)
        ev24 = db.scalar(select(func.count()).select_from(Event).where(Event.received_at >= since)) or 0
        failing = db.scalar(select(func.count()).select_from(Connector).where(
            Connector.enabled.is_(True), Connector.last_error != "")) or 0
        open_det = db.scalar(select(func.count()).select_from(Detection).where(
            Detection.status.in_(OPEN_FINDING_STATUSES))) or 0
        return {"events_24h": ev24, "failing": failing, "open": open_det, "stream": stream.state()}
    except Exception:  # noqa: BLE001
        return {"events_24h": 0, "failing": 0, "open": 0, "stream": stream.state()}


def render(request: Request, name: str, **ctx):
    if "shell" not in ctx and ctx.get("user") and not ctx.get("portal"):
        db = SessionLocal()
        try:
            ctx["shell"] = _shell(db)
        finally:
            db.close()
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ctx.setdefault("ident", auth.resolve_identity(request))
    return templates.TemplateResponse(request, name, ctx)


def _back(path: str, ok: bool, message: str) -> RedirectResponse:
    sep = "&" if "?" in path else "?"
    return RedirectResponse(f"{path}{sep}{'msg' if ok else 'err'}={quote_plus(message)}", status_code=302)


def _client(db: Session, cid: str) -> Client:
    c = db.get(Client, cid)
    if not c:
        raise HTTPException(404, "client not found")
    return c


def _connector(db: Session, cid: str) -> Connector:
    c = db.get(Connector, cid)
    if not c:
        raise HTTPException(404, "connector not found")
    return c


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
    from . import evidence, sinks
    return render(request, "settings.html", user=user, api_token=auth.api_token(), sso_enabled=sso.enabled(),
                  platform_url=settings.platform_url or "not set", hub=settings.platform_hub_url or "not connected",
                  public_key=evidence.public_key_hex(), key_id=evidence.key_id(), sinks=sinks.configured(),
                  stats=sinks.STATS, worker=worker.state(), s=settings)


# ---------------------------------------------------------------- overview
@app.get("/", response_class=HTMLResponse)
def overview(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    now = utcnow()
    since = now - dt.timedelta(hours=24)
    by_client = dict(db.execute(select(Event.client_id, func.count()).where(Event.received_at >= since)
                                .group_by(Event.client_id)).all())
    by_class = db.execute(select(Event.class_uid, func.count()).where(Event.received_at >= since)
                          .group_by(Event.class_uid).order_by(func.count().desc())).all()
    clients = {c.id: c for c in db.execute(select(Client)).scalars()}
    dets = db.execute(select(Detection).where(Detection.status.in_(OPEN_FINDING_STATUSES))
                      .order_by(Detection.last_event_at.desc()).limit(25)).scalars().all()
    health = readiness.connector_health(db, now)
    batches = db.scalar(select(func.count()).select_from(Batch)) or 0
    unsealed = db.scalar(select(func.count()).select_from(Event).where(Event.batch_id.is_(None))) or 0
    last_anchor = db.execute(select(Anchor).order_by(Anchor.created_at.desc()).limit(1)).scalar_one_or_none()
    return render(request, "overview.html", user=user, by_client=by_client, by_class=by_class, clients=clients,
                  dets=dets, health=health, batches=batches, unsealed=unsealed, last_anchor=last_anchor,
                  total24=sum(by_client.values()))


@app.post("/seal")
def seal_now(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    summ = pipeline.seal(db)
    _audit(db, user, "seal.run", json.dumps(summ))
    return _back("/receipts", True, f"Sealed {summ['events']} events into {summ['batches']} batches.")


@app.post("/stream/run")
def stream_now(user: str = auth.RequireUser, db: Session = Depends(get_db)):
    summ = stream.run(db)
    _audit(db, user, "stream.run", json.dumps(summ))
    return _back("/detections", True, f"Detection pass: {summ.get('events', 0)} events, "
                                      f"{summ.get('sigma_new', 0) + summ.get('vendor_new', 0)} new detections.")


# ---------------------------------------------------------------- connectors
def _redacted(c: Connector) -> dict:
    return {"has_credentials": bool(c.credentials), "has_webhook_secret": bool(c.webhook_secret)}


@app.get("/connectors", response_class=HTMLResponse)
def connectors_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Connector).order_by(Connector.created_at.desc())).scalars().all()
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    names = {c.id: c.name for c in db.execute(select(Client)).scalars()}
    catalog = connectors.catalog()
    return render(request, "connectors.html", user=user, rows=rows, clients=clients, names=names, catalog=catalog,
                  by_key={m["key"]: m for m in catalog}, now=utcnow())


@app.post("/connectors")
async def connector_add(request: Request, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    form = await request.form()
    client_id = str(form.get("client_id") or "")
    source = str(form.get("source") or "")
    c = db.get(Client, client_id)
    if c is None or not c.active or not c.platform_client_id:
        return _back("/connectors", False, "Pick an active platform client.")
    m = mappers.get(source)
    if m is None:
        return _back("/connectors", False, "Unknown source.")
    cls = connectors.get(source)
    spec = cls.spec if cls else {"credentials": {}, "config": {}}
    config = {k: str(form.get(f"config.{k}") or "").strip() for k in spec.get("config", {})}
    for extra in ("bucket", "prefix"):
        v = str(form.get(f"config.{extra}") or "").strip()
        if v:
            config[extra] = v
    creds = {k: str(form.get(f"cred.{k}") or "") for k in spec.get("credentials", {})}
    secret = pysecrets.token_urlsafe(32)
    conn = Connector(client_id=c.id, source=source, name=(str(form.get("name") or "") or f"{c.name} {m.name}")[:200],
                     config={k: v for k, v in config.items() if v},
                     credentials=json.dumps({k: v for k, v in creds.items() if v}) if any(creds.values()) else "",
                     webhook_secret=secret, enabled=True, created_by=user)
    db.add(conn)
    db.commit()
    _audit(db, user, "connector.add", f"{conn.id} {source} for {c.name}")
    request.session["reveal"] = {"id": conn.id, "secret": secret}
    return RedirectResponse(f"/connectors/{conn.id}", status_code=302)


@app.get("/connectors/{cid}", response_class=HTMLResponse)
def connector_page(cid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _connector(db, cid)
    runs = db.execute(select(ConnectorRun).where(ConnectorRun.connector_id == cid)
                      .order_by(ConnectorRun.started_at.desc()).limit(30)).scalars().all()
    rejected = db.execute(select(Rejected).where(Rejected.connector_id == cid)
                          .order_by(Rejected.at.desc()).limit(20)).scalars().all()
    reveal = request.session.pop("reveal", None)
    secret = reveal["secret"] if reveal and reveal.get("id") == cid else ""
    base = (settings.public_url or "").rstrip("/")
    m = mappers.get(c.source)
    cls = connectors.get(c.source)
    spec = cls.spec if cls else {"credentials": {}, "config": {}}
    return render(request, "connector.html", user=user, c=c, runs=runs, rejected=rejected, secret=secret,
                  push_url=f"{base}{PUSH_PREFIX}{c.id}", mapper=m, can_pull=cls is not None,
                  client=db.get(Client, c.client_id), red=_redacted(c), spec_config=spec.get("config", {}),
                  spec_creds=spec.get("credentials", {}))


@app.post("/connectors/{cid}/run")
def connector_run(cid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = _connector(db, cid)
    res = connectors.run(db, c, trigger="manual")
    _audit(db, user, "connector.run", f"{cid}: {json.dumps(res)}")
    if res["ok"]:
        return _back(f"/connectors/{cid}", True, f"Pulled {res['received']} records, stored {res['stored']}.")
    return _back(f"/connectors/{cid}", False, res["error"])


@app.post("/connectors/{cid}/toggle")
def connector_toggle(cid: str, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    c = _connector(db, cid)
    c.enabled = not c.enabled
    db.commit()
    _audit(db, user, "connector.toggle", f"{cid} enabled={c.enabled}")
    return _back(f"/connectors/{cid}", True, "Connector " + ("enabled." if c.enabled else "paused."))


@app.post("/connectors/{cid}/rotate")
def connector_rotate(cid: str, request: Request, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    c = _connector(db, cid)
    secret = pysecrets.token_urlsafe(32)
    c.webhook_secret = secret
    db.commit()
    _audit(db, user, "connector.rotate_secret", cid)
    request.session["reveal"] = {"id": cid, "secret": secret}
    return _back(f"/connectors/{cid}", True, "New push secret issued. The old one stopped working.")


@app.post("/connectors/{cid}/credentials")
async def connector_credentials(cid: str, request: Request, user: str = auth.RequireAdmin,
                                db: Session = Depends(get_db)):
    c = _connector(db, cid)
    form = await request.form()
    cls = connectors.get(c.source)
    spec = cls.spec if cls else {"credentials": {}, "config": {}}
    creds = connectors.credentials_of(c)
    for k in spec.get("credentials", {}):
        v = str(form.get(f"cred.{k}") or "")
        if v:
            creds[k] = v
    config = dict(c.config or {})
    for k in list(spec.get("config", {})) + ["bucket", "prefix"]:
        if f"config.{k}" in form:
            v = str(form.get(f"config.{k}") or "").strip()
            if v:
                config[k] = v
            else:
                config.pop(k, None)
    c.credentials = json.dumps(creds) if creds else ""
    c.config = config
    db.commit()
    _audit(db, user, "connector.update", f"{cid} config keys={sorted(config)} credential keys={sorted(creds)}")
    return _back(f"/connectors/{cid}", True, "Saved.")


# ---------------------------------------------------------------- push door
def _push_authorized(request: Request, body: bytes, secret: str) -> bool:
    if not secret:
        return False
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer ") and hmac.compare_digest(authz[7:].strip(), secret):
        return True
    ts = request.headers.get("x-vendetta-timestamp", "")
    sig = request.headers.get("x-vendetta-signature", "")
    if not ts or not sig.startswith("sha256="):
        return False
    try:
        if abs(time.time() - int(ts)) > PUSH_SKEW_SECONDS:
            return False
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig[7:], expected)


def unwrap(source: str, doc) -> list:
    """Split a delivery into vendor records. Lists are taken element by element;
    known envelopes are opened: Azure diagnostic export ({records: [...]}, with the
    Graph-shaped object under `properties` for Entra), Okta event hooks
    ({data: {events: [...]}}), CloudTrail files ({Records: [...]})."""
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return [doc]
    if isinstance(doc.get("records"), list):
        recs = doc["records"]
        if source.startswith("entra_"):
            recs = [r.get("properties") if isinstance(r, dict) and isinstance(r.get("properties"), dict) else r
                    for r in recs]
        return recs
    data = doc.get("data")
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return data["events"]
    if isinstance(doc.get("Records"), list):
        return doc["Records"]
    return [doc]


@app.get("/api/ingest/{cid}")
def push_verify(cid: str, request: Request, db: Session = Depends(get_db)):
    """Okta event hooks verify an endpoint with a one-time GET carrying
    x-okta-verification-challenge; answer it only for an authorized caller."""
    c = db.get(Connector, cid)
    if c is None or not c.enabled or not _push_authorized(request, b"", c.webhook_secret):
        raise HTTPException(404)
    challenge = request.headers.get("x-okta-verification-challenge", "")
    if not challenge:
        return {"ok": True}
    return {"verification": challenge[:200]}


@app.post("/api/ingest/{cid}")
async def push(cid: str, request: Request, db: Session = Depends(get_db)):
    c = db.get(Connector, cid)
    # 404 for unknown, disabled and unauthorized alike, so the endpoint does not
    # reveal which connector ids exist.
    if c is None or not c.enabled:
        raise HTTPException(404)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_push_bytes:
        raise HTTPException(413, "body too large")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > settings.max_push_bytes:
            raise HTTPException(413, "body too large")
    if not _push_authorized(request, body, c.webhook_secret):
        raise HTTPException(404)
    try:
        doc = json.loads(body)
    except ValueError:
        raise HTTPException(400, "JSON body required")
    records = unwrap(c.source, doc)
    if len(records) > settings.max_push_records:
        raise HTTPException(413, f"at most {settings.max_push_records} records per delivery")
    try:
        counts = pipeline.ingest_records(db, c, records, trigger="push")
    except pipeline.TenantError as e:
        return JSONResponse({"accepted": False, "detail": str(e)}, status_code=409)
    c.last_ok_at = utcnow()
    c.last_received = counts["received"]
    db.commit()
    return JSONResponse({"accepted": True, **counts}, status_code=202)


# ---------------------------------------------------------------- events and proofs
def _event_query(tenant: str = "", source: str = "", class_uid: int = 0, q: str = "", hours: int = 24):
    stmt = select(Event).where(Event.time >= utcnow() - dt.timedelta(hours=max(1, min(hours, 24 * 90))))
    if tenant:
        stmt = stmt.where(Event.tenant == tenant)
    if source:
        stmt = stmt.where(Event.source == source)
    if class_uid:
        stmt = stmt.where(Event.class_uid == class_uid)
    if q:
        like = f"%{q[:100]}%"
        stmt = stmt.where(or_(Event.title.ilike(like), Event.host.ilike(like), Event.user.ilike(like),
                              Event.src_ip.ilike(like)))
    return stmt


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, tenant: str = "", source: str = "", class_uid: int = 0, q: str = "",
                hours: int = 24, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(_event_query(tenant, source, class_uid, q, hours).order_by(Event.time.desc()).limit(200)
                      ).scalars().all()
    clients = db.execute(select(Client).where(Client.platform_client_id != "").order_by(Client.name)).scalars().all()
    return render(request, "events.html", user=user, rows=rows, clients=clients,
                  names={c.platform_client_id: c.name for c in clients}, f={"tenant": tenant, "source": source,
                  "class_uid": class_uid, "q": q, "hours": hours}, catalog=connectors.catalog())


def _event(db: Session, eid: str) -> Event:
    ev = db.execute(select(Event).where(Event.id == eid)).scalar_one_or_none()
    if ev is None:
        raise HTTPException(404, "event not found (it may have aged out of the hot store)")
    return ev


@app.get("/events/{eid}", response_class=HTMLResponse)
def event_page(eid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ev = _event(db, eid)
    batch = db.get(Batch, ev.batch_id) if ev.batch_id else None
    return render(request, "event.html", user=user, ev=ev, batch=batch, client=db.get(Client, ev.client_id),
                  event_json=json.dumps(ev.event, indent=2, sort_keys=True), raw_json=_pretty(ev.raw))


def _pretty(raw: str) -> str:
    try:
        return json.dumps(json.loads(raw), indent=2, sort_keys=True)
    except ValueError:
        return raw


def _proof_response(proof: dict, ev: Event, with_raw: bool) -> Response:
    if with_raw:
        proof = {**proof, "raw": json.loads(ev.raw) if ev.raw.startswith(("{", "[")) else ev.raw}
    body = json.dumps(proof, indent=2, sort_keys=True, default=str).encode()
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="proof-{ev.id}.json"'})


@app.get("/events/{eid}/proof")
def event_proof_download(eid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    ev = _event(db, eid)
    p = pipeline.proof(db, ev)
    if p is None:
        raise HTTPException(409, "this event is waiting for its seal; try again in a minute")
    _audit(db, user, "event.proof", eid)
    return _proof_response(p, ev, with_raw=True)


@app.get("/verifier/receipts.py", response_class=PlainTextResponse)
def verifier_source(request: Request):
    """The offline verifier, readable by any signed-in staff or client user."""
    auth.require_identity(request)
    return PlainTextResponse((_APP_DIR / "receipts.py").read_text(encoding="utf-8"),
                             headers={"Content-Disposition": 'attachment; filename="receipts.py"'})


# ---------------------------------------------------------------- receipts
@app.get("/receipts", response_class=HTMLResponse)
def receipts_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    heads = db.execute(select(Batch.tenant, func.max(Batch.batch_seq), func.sum(Batch.size), func.max(Batch.sealed_at))
                       .group_by(Batch.tenant)).all()
    names = {c.platform_client_id: c.name for c in db.execute(select(Client)).scalars()}
    anchors = db.execute(select(Anchor).order_by(Anchor.created_at.desc()).limit(14)).scalars().all()
    recent = db.execute(select(Batch).order_by(Batch.sealed_at.desc()).limit(25)).scalars().all()
    unsealed = db.scalar(select(func.count()).select_from(Event).where(Event.batch_id.is_(None))) or 0
    from . import evidence
    return render(request, "receipts.html", user=user, heads=heads, names=names, anchors=anchors, recent=recent,
                  unsealed=unsealed, key_id=evidence.key_id(), public_key=evidence.public_key_hex())


@app.get("/receipts/{tenant}/verify", response_class=HTMLResponse)
def receipts_verify(tenant: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    res = pipeline.verify_tenant(db, tenant)
    _audit(db, user, "chain.verify", f"{tenant}: {res.get('reason')}")
    return _back("/receipts", res["ok"], f"Chain for {tenant}: {res['reason']} ({res.get('verified', 0)} batches).")


@app.get("/receipts/{tenant}/chain.json")
def receipts_chain(tenant: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    return _chain_download(db, tenant)


def _chain_download(db: Session, tenant: str) -> Response:
    body = json.dumps({"scheme": receipts.SCHEME, "tenant": tenant, "batches": pipeline.chain(db, tenant, 1, 100000),
                       "verify": "python receipts.py chain.json"}, indent=2).encode()
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="chain-{tenant}.json"'})


# ---------------------------------------------------------------- detections
@app.get("/detections", response_class=HTMLResponse)
def detections_page(request: Request, status: str = "open", severity: str = "", tenant: str = "", kind: str = "",
                    user: str = auth.RequireUser, db: Session = Depends(get_db)):
    q = select(Detection)
    if status == "open":
        q = q.where(Detection.status.in_(OPEN_FINDING_STATUSES))
    elif status in FINDING_STATUSES:
        q = q.where(Detection.status == status)
    if severity in SEVERITIES:
        q = q.where(Detection.severity == severity)
    if tenant:
        q = q.where(Detection.tenant == tenant)
    if kind in ("sigma", "vendor"):
        q = q.where(Detection.kind == kind)
    rows = db.execute(q.order_by(Detection.last_event_at.desc()).limit(300)).scalars().all()
    names = {c.platform_client_id: c.name for c in db.execute(select(Client)).scalars()}
    return render(request, "detections.html", user=user, rows=rows, names=names,
                  f={"status": status, "severity": severity, "tenant": tenant, "kind": kind})


def _detection(db: Session, did: str) -> Detection:
    d = db.get(Detection, did)
    if not d:
        raise HTTPException(404, "detection not found")
    return d


@app.get("/detections/{did}", response_class=HTMLResponse)
def detection_page(did: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    d = _detection(db, did)
    ids = list(d.event_ids or [])[-100:]
    evs = db.execute(select(Event).where(Event.id.in_(ids), Event.tenant == d.tenant).order_by(Event.time)
                     ).scalars().all() if ids else []
    rule = db.get(SigmaRule, d.rule_id) if d.rule_id else None
    return render(request, "detection.html", user=user, d=d, evs=evs, rule=rule, client=db.get(Client, d.client_id),
                  missing=len(ids) - len(evs))


@app.post("/detections/{did}/status")
def detection_status(did: str, status: str = Form(...), note: str = Form(""), user: str = auth.RequireUser,
                     db: Session = Depends(get_db)):
    d = _detection(db, did)
    if status not in FINDING_STATUSES:
        return _back(f"/detections/{did}", False, "unknown status")
    d.status = status
    if note.strip():
        d.note = (d.note + "\n" if d.note else "") + f"{utcnow():%Y-%m-%d %H:%M} {user}: {note.strip()[:2000]}"
    d.updated_at = utcnow()
    db.commit()
    _audit(db, user, "detection.status", f"{did} -> {status}")
    return _back(f"/detections/{did}", True, "Updated.")


@app.post("/detections/{did}/escalate")
def detection_escalate(did: str, note: str = Form(""), user: str = auth.RequireUser, db: Session = Depends(get_db)):
    d = _detection(db, did)
    res = hub.escalate(db, d, user, note)
    if res.get("escalated"):
        return _back(f"/detections/{did}", True, f"Escalated to {res['case']}.")
    return _back(f"/detections/{did}", False, res.get("reason", "escalation failed"))


# ---------------------------------------------------------------- rules
@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(SigmaRule).order_by(SigmaRule.title)).scalars().all()
    parsed = {}
    for r in rows:
        try:
            parsed[r.id] = sigma.compile(r.body)
        except sigma.SigmaError:
            parsed[r.id] = None
    return render(request, "rules.html", user=user, rows=rows, parsed=parsed)


@app.get("/rules/new", response_class=HTMLResponse)
def rule_new(request: Request, user: str = auth.RequireUser):
    return render(request, "rule.html", user=user, r=None, body=NEW_RULE_TEMPLATE, versions=[], test=None)


NEW_RULE_TEMPLATE = """title: New detection
id: replace-with-a-uuid
status: test
level: medium
description: What this catches and why it matters.
author: Vendetta Cyber
tags:
  - attack.t1078
logsource:
  product: entra_signins
detection:
  selection:
    status_id: 2
  condition: selection
falsepositives:
  - Describe the known benign causes
"""


@app.get("/rules/{rid}", response_class=HTMLResponse)
def rule_page(rid: str, request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    r = db.get(SigmaRule, rid)
    if not r:
        raise HTTPException(404)
    versions = db.execute(select(SigmaRuleVersion).where(SigmaRuleVersion.rule_id == rid)
                          .order_by(SigmaRuleVersion.version.desc()).limit(20)).scalars().all()
    return render(request, "rule.html", user=user, r=r, body=r.body, versions=versions, test=None)


@app.post("/rules/save")
async def rule_save(request: Request, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    form = await request.form()
    body = str(form.get("body") or "")
    action = str(form.get("action") or "save")
    original = str(form.get("original_id") or "")
    try:
        comp = sigma.compile(body)
    except sigma.SigmaError as e:
        return render(request, "rule.html", user=user, r=db.get(SigmaRule, original) if original else None,
                      body=body, versions=[], test=None, err=f"The rule does not compile: {e}")
    if action == "test":
        res = stream.test_rule(db, comp)
        return render(request, "rule.html", user=user, r=db.get(SigmaRule, original) if original else None,
                      body=body, versions=[], test=res,
                      msg=f"Dry run over the last {res['scanned']} stored events: {res['count']} would match.")
    if original and original != comp.id:
        return render(request, "rule.html", user=user, r=db.get(SigmaRule, original), body=body, versions=[],
                      test=None, err="A rule's id cannot change; save it as a new rule with a new id.")
    r = db.get(SigmaRule, comp.id)
    if r is None:
        r = SigmaRule(id=comp.id, title=comp.title, level=comp.level, body=body, tags=list(comp.tags),
                      origin="custom", version=1, updated_by=user, enabled=True)
        db.add(r)
    else:
        r.title, r.level, r.body, r.tags = comp.title, comp.level, body, list(comp.tags)
        r.version += 1
        r.updated_by, r.updated_at = user, utcnow()
    enabled = form.get("enabled")
    if enabled is not None:
        r.enabled = enabled == "true"
    db.flush()
    db.add(SigmaRuleVersion(rule_id=r.id, version=r.version, body=body, enabled=r.enabled, changed_by=user,
                            note=str(form.get("note") or "")[:500]))
    db.commit()
    _audit(db, user, "rule.save", f"{r.id} v{r.version}")
    return _back(f"/rules/{r.id}", True, f"Saved version {r.version}.")


@app.post("/rules/{rid}/toggle")
def rule_toggle(rid: str, user: str = auth.RequireAdmin, db: Session = Depends(get_db)):
    r = db.get(SigmaRule, rid)
    if not r:
        raise HTTPException(404)
    r.enabled = not r.enabled
    r.version += 1
    r.updated_by, r.updated_at = user, utcnow()
    db.add(SigmaRuleVersion(rule_id=r.id, version=r.version, body=r.body, enabled=r.enabled, changed_by=user,
                            note="enabled" if r.enabled else "disabled"))
    db.commit()
    _audit(db, user, "rule.toggle", f"{rid} enabled={r.enabled}")
    return _back(f"/rules/{rid}", True, "Rule " + ("enabled." if r.enabled else "disabled."))


# ---------------------------------------------------------------- clients
@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    rows = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    conn = dict(db.execute(select(Connector.client_id, func.count()).group_by(Connector.client_id)).all())
    since = utcnow() - dt.timedelta(hours=24)
    ev = dict(db.execute(select(Event.client_id, func.count()).where(Event.received_at >= since)
                         .group_by(Event.client_id)).all())
    return render(request, "clients.html", user=user, clients=rows, conn=conn, ev=ev,
                  platform_configured=provision.configured())


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
    c = _client(db, cid)
    conns = db.execute(select(Connector).where(Connector.client_id == cid)).scalars().all()
    dets = db.execute(select(Detection).where(Detection.client_id == cid).order_by(Detection.last_event_at.desc())
                      .limit(50)).scalars().all()
    head = db.execute(select(Batch).where(Batch.tenant == c.platform_client_id).order_by(Batch.batch_seq.desc())
                      .limit(1)).scalar_one_or_none() if c.platform_client_id else None
    return render(request, "client.html", user=user, client=c, conns=conns, dets=dets, head=head,
                  platform_public_url=settings.platform_public_url)


@app.post("/clients/{cid}/portal")
def client_portal_toggle(cid: str, portal_enabled: bool = Form(False), user: str = auth.RequireUser,
                         db: Session = Depends(get_db)):
    c = _client(db, cid)
    c.portal_enabled = bool(portal_enabled)
    db.commit()
    _audit(db, user, "client.portal", f"{c.name} portal={c.portal_enabled}")
    return _back(f"/clients/{cid}", True, "Portal " + ("enabled." if c.portal_enabled else "turned off."))


# ---------------------------------------------------------------- client portal
def _portal_client(db: Session, ident: auth.Identity) -> Client:
    c = db.get(Client, ident.client_id)
    if not c or not c.active or not c.portal_enabled or not c.platform_client_id:
        raise HTTPException(404)
    return c


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    t = c.platform_client_id
    head = db.execute(select(Batch).where(Batch.tenant == t).order_by(Batch.batch_seq.desc()).limit(1)
                      ).scalar_one_or_none()
    sealed = db.scalar(select(func.sum(Batch.size)).where(Batch.tenant == t)) or 0
    conns = db.execute(select(Connector).where(Connector.client_id == c.id, Connector.enabled.is_(True))
                       ).scalars().all()
    since = utcnow() - dt.timedelta(days=7)
    by_source = db.execute(select(Event.source, func.count()).where(Event.tenant == t, Event.received_at >= since)
                           .group_by(Event.source)).all()
    last_anchor = db.execute(select(Anchor).order_by(Anchor.created_at.desc()).limit(1)).scalar_one_or_none()
    anchored = bool(last_anchor and t in ((last_anchor.document or {}).get("tenants") or {}))
    return render(request, "portal.html", user=ident.email, portal=True, client=c, head=head, sealed=sealed,
                  conns=conns, by_source=by_source, anchored=anchored, last_anchor=last_anchor,
                  exec_view=ident.is_executive)


@app.get("/portal/chain.json")
def portal_chain(ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    _audit(db, ident.email, "portal.chain.export", c.platform_client_id)
    return _chain_download(db, c.platform_client_id)


@app.get("/portal/events/{eid}/proof")
def portal_event_proof(eid: str, ident: auth.Identity = Depends(auth.require_client), db: Session = Depends(get_db)):
    c = _portal_client(db, ident)
    ev = db.execute(select(Event).where(Event.id == eid)).scalar_one_or_none()
    auth.require_owned(ident, ev, extra=bool(ev and ev.tenant == c.platform_client_id))
    p = pipeline.proof(db, ev)
    if p is None:
        raise HTTPException(409, "this event is waiting for its seal")
    _audit(db, ident.email, "portal.event.proof", eid)
    return _proof_response(p, ev, with_raw=True)


# ---------------------------------------------------------------- service API
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/module")
def api_module(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    counts = {"open": 0, "by_severity": {s: 0 for s in SEVERITIES}, "events_24h": 0, "connectors": 0}
    try:
        for sev, n in db.execute(select(Detection.severity, func.count()).where(
                Detection.status.in_(OPEN_FINDING_STATUSES)).group_by(Detection.severity)).all():
            if sev in counts["by_severity"]:
                counts["by_severity"][sev] = n
        counts["open"] = sum(counts["by_severity"].values())
        counts["events_24h"] = db.scalar(select(func.count()).select_from(Event).where(
            Event.received_at >= utcnow() - dt.timedelta(hours=24))) or 0
        counts["connectors"] = db.scalar(select(func.count()).select_from(Connector).where(
            Connector.enabled.is_(True))) or 0
    except Exception:  # noqa: BLE001
        pass
    return {"module": "ingest", "display_name": "Telemetry Ingest", "platform": "Vendetta Platform",
            "enabled": settings.module_enabled, "roles": ["admin", "analyst", "viewer", "client"],
            "finding_types": ["sigma", "alert"], "statuses": FINDING_STATUSES, "workstream": WORKSTREAM,
            "counts": counts, "readiness": readiness.block(),
            "endpoints": ["/api/module", "/api/findings", "/api/findings/{id}/escalate", "/api/catalog",
                          "/api/connectors", "/api/connectors/{id}/run", "/api/ingest/{connector_id}",
                          "/api/events", "/api/events/{id}/proof", "/api/chain/{tenant}",
                          "/api/chain/{tenant}/verify", "/api/seal", "/api/stream/run", "/api/provision/sync"]}


@app.get("/api/findings")
def api_findings(status: str = Query("active"), platform_client_id: str = Query(""), client: str = Query(""),
                 user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Detections in the shared finding model. status is active (default) or open,
    all, or a literal finding status."""
    q = select(Detection, Client).join(Client, Client.id == Detection.client_id)
    if status in ("active", "open"):
        q = q.where(Detection.status.in_(OPEN_FINDING_STATUSES))
    elif status in FINDING_STATUSES:
        q = q.where(Detection.status == status)
    elif status != "all":
        raise HTTPException(400, "unknown status")
    if platform_client_id:
        q = q.where(Client.platform_client_id == platform_client_id)
    elif client:
        q = q.where(Client.name.ilike(f"%{client[:100]}%"))
    rows = db.execute(q.order_by(Detection.last_event_at.desc()).limit(1000)).all()
    return [hub.finding_dict(d, c, hub.evidence_for(db, d, limit=5)) for d, c in rows]


@app.post("/api/findings/{did}/escalate")
def api_escalate(did: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    d = _detection(db, did)
    result = hub.escalate(db, d, user)
    if result.get("escalated"):
        return result
    return JSONResponse(result, status_code=502)


@app.get("/api/catalog")
def api_catalog(user: str = Depends(auth.api_user)):
    return connectors.catalog()


@app.get("/api/connectors")
def api_connectors(platform_client_id: str = Query(""), user: str = Depends(auth.api_user),
                   db: Session = Depends(get_db)):
    health = readiness.connector_health(db)
    if platform_client_id:
        cids = {c.id for c in db.execute(select(Client).where(Client.platform_client_id == platform_client_id)
                                         ).scalars()}
        health = [h for h in health if h["client_id"] in cids]
    return health


@app.post("/api/connectors/{cid}/run")
def api_connector_run(cid: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    c = _connector(db, cid)
    res = connectors.run(db, c, trigger="manual")
    _audit(db, user, "connector.run", f"{cid}: {json.dumps(res)}")
    return JSONResponse(res, status_code=200 if res["ok"] else 502)


@app.get("/api/events")
def api_events(platform_client_id: str = Query(...), source: str = "", class_uid: int = 0, q: str = "",
               hours: int = Query(24, ge=1, le=24 * 90), limit: int = Query(100, ge=1, le=1000),
               user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    """Normalized events for one tenant. The tenant is required: the API never
    returns events across clients in one response."""
    rows = db.execute(_event_query(platform_client_id, source, class_uid, q, hours)
                      .order_by(Event.time.desc()).limit(limit)).scalars().all()
    return [{"id": e.id, "time": e.time.isoformat(), "source": e.source, "class_uid": e.class_uid,
             "event_sha256": e.event_sha256, "sealed": bool(e.batch_id), "event": e.event} for e in rows]


@app.get("/api/events/{eid}/proof")
def api_event_proof(eid: str, raw: bool = False, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    ev = _event(db, eid)
    p = pipeline.proof(db, ev)
    if p is None:
        return JSONResponse({"sealed": False, "detail": "waiting for the next seal"}, status_code=409)
    if raw:
        p["raw"] = json.loads(ev.raw) if ev.raw.startswith(("{", "[")) else ev.raw
    return p


@app.get("/api/chain/{tenant}")
def api_chain(tenant: str, since: int = Query(1, ge=1), limit: int = Query(1000, ge=1, le=10000),
              user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return {"scheme": receipts.SCHEME, "tenant": tenant, "batches": pipeline.chain(db, tenant, since, limit)}


@app.get("/api/chain/{tenant}/verify")
def api_chain_verify(tenant: str, user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return pipeline.verify_tenant(db, tenant)


@app.post("/api/seal")
def api_seal(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return pipeline.seal(db)


@app.post("/api/stream/run")
def api_stream(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    return stream.run(db)


@app.post("/api/provision/sync")
def api_provision_sync(user: str = Depends(auth.api_user), db: Session = Depends(get_db)):
    if not provision.configured():
        return JSONResponse({"ok": False, "detail": "PLATFORM_URL not set"}, status_code=409)
    try:
        return {"ok": True, **provision.pull(db)}
    except provision.ProvisionError as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=502)


@app.get("/clients/platform/{pid}")
def client_by_platform_id(pid: str, user: str = auth.RequireUser, db: Session = Depends(get_db)):
    c = db.query(Client).filter_by(platform_client_id=pid).first()
    if not c:
        raise HTTPException(404, "that client has not been provisioned into this module yet")
    return RedirectResponse(f"/clients/{c.id}", status_code=302)

