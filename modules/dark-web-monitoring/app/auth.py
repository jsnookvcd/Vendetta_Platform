"""Single shared analyst login with a signed session cookie. The instance sits
behind SSM port forwarding or a VPN, so this is a second layer, not the only one.
Swap for Entra ID OIDC when it moves onto a public hostname."""
from __future__ import annotations

import hashlib
import hmac

import bcrypt
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import settings

COOKIE = "vcd_session"
_signer = URLSafeTimedSerializer(settings.secret_key, salt="session")


def check_password(password: str) -> bool:
    if not settings.admin_password_hash:
        return False
    return bcrypt.checkpw(password.encode(), settings.admin_password_hash.encode())


def make_session(username: str) -> str:
    return _signer.dumps({"u": username})


def current_user(request: Request) -> str:
    tok = request.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(status_code=401, detail="login required")
    try:
        return _signer.loads(tok, max_age=60 * 60 * 12)["u"]
    except (BadSignature, KeyError):
        raise HTTPException(status_code=401, detail="login required")


def api_token() -> str:
    """Static bearer token derived from SECRET_KEY. Shown on the settings page."""
    return hmac.new(settings.secret_key.encode(), b"api-token-v1", hashlib.sha256).hexdigest()


def api_user(request: Request) -> str:
    """API calls can use the session cookie or the bearer token."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], api_token()):
        return "api"
    return current_user(request)


RequireUser = Depends(current_user)
