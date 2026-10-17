"""Session auth and identity. Logins come from the local admin account (break-glass)
or Entra ID SSO. Every request resolves to an Identity carrying the role and, for
client-portal users, the client they are scoped to."""
from __future__ import annotations

import dataclasses
import hashlib
import hmac

import bcrypt
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import settings

COOKIE = "vcd_session"
_signer = URLSafeTimedSerializer(settings.secret_key, salt="session")

# Internal roles, lowest to highest. A viewer can open every staff page and read
# every API but cannot change anything; the platform roster grants it.
INTERNAL_ROLES = ("viewer", "analyst", "admin")
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
READ_ONLY_DETAIL = ("read-only access: your viewer grant lets you look at every page and read every API "
                    "but not change anything. Ask a platform admin for analyst access if you need to act.")


@dataclasses.dataclass
class Identity:
    email: str
    role: str  # admin | analyst | viewer | client
    client_id: str | None = None

    @property
    def is_internal(self) -> bool:
        return self.role in INTERNAL_ROLES

    @property
    def is_viewer(self) -> bool:
        return self.role == "viewer"

    @property
    def is_client(self) -> bool:
        return self.role == "client"


def check_password(password: str) -> bool:
    if not settings.admin_password_hash:
        return False
    return bcrypt.checkpw(password.encode(), settings.admin_password_hash.encode())


def make_session(username: str) -> str:
    return _signer.dumps({"u": username})


def current_user(request: Request) -> str:
    """Identity for staff routes. A valid session that is not an internal user
    (admin, analyst or viewer) is refused, so a client-portal session can never reach a
    staff route or the service API even if the access gate is bypassed. This is the
    route-level half of the tenant boundary; the middleware gate is the other."""
    ident = require_identity(request)
    if not ident.is_internal:
        raise HTTPException(status_code=403, detail="internal access only")
    require_write(request, ident)
    return ident.email


def require_write(request: Request, ident: Identity) -> None:
    """The one place the viewer level is enforced: a viewer may read (GET, HEAD,
    OPTIONS) but every state-changing request, whether a form post, an action or
    a settings save, is refused with 403 and a plain explanation. Gating by method
    here covers every staff route and the service API without touching them."""
    if ident.is_viewer and request.method.upper() not in _SAFE_METHODS:
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)


def _session_email(request: Request) -> str | None:
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    try:
        return _signer.loads(tok, max_age=60 * 60 * 12)["u"]
    except (BadSignature, KeyError):
        return None


def resolve_identity(request: Request) -> Identity | None:
    """Look up the signed-in user's role and client scope. Returns None if not signed in."""
    email = _session_email(request)
    if not email:
        return None
    if email == settings.admin_user:
        return Identity(email=email, role="admin")
    # Look up the User row written at SSO login for role and client scope.
    from .db import SessionLocal, User  # local import to avoid a cycle

    db = SessionLocal()
    try:
        from sqlalchemy import select

        u = db.execute(select(User).where(User.email == email, User.active.is_(True))).scalar_one_or_none()
        if not u:
            return None
        return Identity(email=u.email, role=u.role, client_id=u.client_id)
    finally:
        db.close()


def require_identity(request: Request) -> Identity:
    ident = resolve_identity(request)
    if not ident:
        raise HTTPException(status_code=401, detail="login required")
    return ident


def require_internal(request: Request) -> Identity:
    ident = require_identity(request)
    if not ident.is_internal:
        raise HTTPException(status_code=403, detail="internal access only")
    return ident


def require_client(request: Request) -> Identity:
    ident = require_identity(request)
    if not ident.is_client or not ident.client_id:
        raise HTTPException(status_code=403, detail="client portal only")
    return ident


def require_owned(ident: "Identity", obj, *, extra: bool = True):
    """The single tenant check every portal detail route goes through: 404 unless
    the record exists, belongs to the signed-in client, and any extra condition
    (such as being published) holds. 404 rather than 403 so a client cannot even
    probe which record ids belong to another tenant."""
    if obj is None or getattr(obj, "client_id", None) != ident.client_id or not extra:
        raise HTTPException(status_code=404, detail="not found")
    return obj


def api_token() -> str:
    """Bearer token for the service API: API_TOKEN when the deployment set one, else
    a static value derived from SECRET_KEY. Shown on the settings page."""
    if settings.api_token.strip():
        return settings.api_token.strip()
    return hmac.new(settings.secret_key.encode(), b"api-token-v1", hashlib.sha256).hexdigest()


def _bearer(request: Request) -> str:
    h = request.headers.get("authorization", "")
    return h[7:] if h.startswith("Bearer ") else ""


def _actor_name(request: Request, default: str = "") -> str:
    return "".join(ch for ch in request.headers.get("x-vendetta-actor", "") if ch.isalnum() or ch in "-_.")[:40] or default


def is_bridge(request: Request) -> bool:
    tok, want = _bearer(request), (settings.bridge_token or "").strip()
    return bool(tok and want and hmac.compare_digest(tok, want))


def api_user(request: Request) -> str:
    """Service API: the shared bearer token, the bridge token, or an internal staff
    session. A client-portal session is refused (current_user enforces the internal
    role), so the API can never return another tenant's data to a client."""
    tok = _bearer(request)
    if tok and hmac.compare_digest(tok, api_token()):
        # A caller may name itself (SABINE does) so audit entries read api:<actor>.
        actor = _actor_name(request)
        return f"api:{actor}" if actor else "api"
    if is_bridge(request):
        return f"api:{_actor_name(request, 'bridge')}"
    return current_user(request)


def _clean_email(raw: str) -> str:
    e = "".join(ch for ch in (raw or "").strip().lower() if ch.isalnum() or ch in "@.-_+'")[:254]
    return e if e.count("@") == 1 and not e.startswith("@") and "." in e.split("@")[1] else ""


def acting_person(request: Request, caller: str) -> str:
    """Who a decision or a question is recorded against. The Slack responder
    presents BRIDGE_TOKEN and names the member of staff in X-Vendetta-On-Behalf-Of;
    the record reads "dan@vendettacd.io via slack". Under any other credential the
    header is ignored and the caller is its own person. A bridge call must name an
    active person on the mirrored staff roster with analyst or admin here.
    Callers keep using `caller` for permission checks (an "api" caller still
    cannot decide a high-risk proposal): this only changes the name on record."""
    if not is_bridge(request):
        return caller
    person = _clean_email(request.headers.get("x-vendetta-on-behalf-of", ""))
    if not person:
        raise HTTPException(status_code=403, detail="a bridge call must name the person it acts for")
    from .db import SessionLocal, User  # local import to avoid a cycle

    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == person, User.active.is_(True)).one_or_none()
        if u is not None and u.source != "platform" and db.query(User).filter(User.source == "platform").count():
            u = None
    finally:
        db.close()
    if u is None or u.role not in ("analyst", "admin"):
        raise HTTPException(status_code=403, detail=f"{person} is not on SABINE's staff roster with analyst or admin access")
    via = caller.split(":", 1)[1] if ":" in caller else "bridge"
    return f"{person} via {via}"[:320]


RequireUser = Depends(current_user)
