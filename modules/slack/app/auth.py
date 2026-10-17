"""Console and service-API auth. The console is an operator status page behind the
break-glass admin login; responders never use it, they use Slack. The service API
(manifest, readiness) takes the module's bearer token, as every module does."""
from __future__ import annotations

import hashlib
import hmac
import time

import bcrypt
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import settings

COOKIE = "vcd_session"
_signer = URLSafeTimedSerializer(settings.secret_key, salt="session")
_ATTEMPTS: dict[str, list[float]] = {}


def check_password(username: str, password: str, client_ip: str = "") -> bool:
    now = time.time()
    window = [t for t in _ATTEMPTS.get(client_ip, []) if now - t < settings.login_window_seconds]
    if len(window) >= settings.login_max_attempts:
        return False
    ok = (bool(settings.admin_password_hash) and hmac.compare_digest(username, settings.admin_user)
          and bcrypt.checkpw(password.encode(), settings.admin_password_hash.encode()))
    if not ok:
        window.append(now)
    _ATTEMPTS[client_ip] = window
    return ok


def make_session(username: str) -> str:
    return _signer.dumps({"u": username})


def current_user(request: Request) -> str:
    tok = request.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(status_code=401, detail="login required")
    try:
        user = _signer.loads(tok, max_age=60 * 60 * 12)["u"]
    except (BadSignature, KeyError):
        raise HTTPException(status_code=401, detail="login required")
    if user != settings.admin_user:
        raise HTTPException(status_code=403, detail="admin only")
    return user


def api_token() -> str:
    if settings.api_token.strip():
        return settings.api_token.strip()
    return hmac.new(settings.secret_key.encode(), b"api-token-v1", hashlib.sha256).hexdigest()


def api_user(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], api_token()):
        actor = "".join(ch for ch in request.headers.get("x-vendetta-actor", "") if ch.isalnum() or ch in "-_.")[:40]
        return f"api:{actor}" if actor else "api"
    return current_user(request)


RequireUser = Depends(current_user)
