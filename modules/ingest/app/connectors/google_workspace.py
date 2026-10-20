"""Google Workspace Admin SDK Reports API puller.

A service account in a Google Cloud project with domain-wide delegation granted in
the client's Admin console for the scope
https://www.googleapis.com/auth/admin.reports.audit.readonly. The puller signs a JWT
(RS256) with the service account key, impersonating `admin_email` (a super admin or
an admin with the Reports privilege), and exchanges it at
https://oauth2.googleapis.com/token. The token URL is fixed: the token_uri inside the
key file is not followed.

For each application (login, admin, token, drive by default) the puller walks time
windows from the cursor to now minus `lag_minutes` (default 15), because the Reports
API publishes events late and an event that lands after its window has been read
would otherwise be missed. Each window is paged with nextPageToken. Results come
newest first, so the per-application cursor moves to a window's end only after the
whole window is ingested.
"""
from __future__ import annotations

import base64
import datetime as dt
import json

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import FIRST_LOOKBACK, ConnectorError, Puller, puller
from ._util import json_body, parse_dt, z

TOKEN_URL = "https://oauth2.googleapis.com/token"
API = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
DEFAULT_APPS = ("login", "admin", "token", "drive")
ALLOWED_APPS = {"login", "admin", "token", "drive", "saml", "user_accounts", "groups", "mobile", "rules",
                "context_aware_access", "chrome", "gcp", "meet", "calendar"}

SPEC = {
    "credentials": {"service_account_json": "Service account key file (JSON) with domain-wide delegation for "
                                            "admin.reports.audit.readonly"},
    "config": {"admin_email": "Workspace administrator the service account impersonates",
               "applications": "Comma-separated Reports applications (default login,admin,token,drive)",
               "window_minutes": "Window size in minutes, 5 to 1440 (default 60)",
               "lag_minutes": "Minutes behind now the last window ends (default 15)"},
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int(v, default: int, lo: int, hi: int, what: str) -> int:
    try:
        n = int(v if v not in (None, "") else default)
    except (TypeError, ValueError):
        raise ConnectorError(f"{what} must be a number") from None
    if not lo <= n <= hi:
        raise ConnectorError(f"{what} must be between {lo} and {hi}")
    return n


@puller
class GoogleWorkspace(Puller):
    source = "google_workspace"
    spec = SPEC

    def applications(self) -> list[str]:
        raw = self.config.get("applications") or ",".join(DEFAULT_APPS)
        apps = [a.strip().lower() for a in str(raw).split(",") if a.strip()]
        if not apps or any(a not in ALLOWED_APPS for a in apps):
            raise ConnectorError("applications has an unknown Reports application")
        return list(dict.fromkeys(apps))

    def assertion(self) -> str:
        self.need("service_account_json")
        self.need("admin_email", where="config")
        admin = str(self.config["admin_email"]).strip()
        if admin.count("@") != 1 or any(ch.isspace() for ch in admin):
            raise ConnectorError("admin_email is not an email address")
        raw = self.credentials["service_account_json"]
        try:
            key = raw if isinstance(raw, dict) else json.loads(raw)
        except (TypeError, ValueError):
            raise ConnectorError("service_account_json is not valid JSON") from None
        if not isinstance(key, dict) or not key.get("client_email") or not key.get("private_key"):
            raise ConnectorError("service_account_json is not a service account key")
        try:
            pk = serialization.load_pem_private_key(str(key["private_key"]).encode(), password=None)
        except (TypeError, ValueError, UnsupportedAlgorithm):
            raise ConnectorError("service account private key could not be loaded") from None
        if not isinstance(pk, rsa.RSAPrivateKey):
            raise ConnectorError("service account private key is not an RSA key")
        iat = int(self.now.timestamp())
        header = {"alg": "RS256", "typ": "JWT"}
        if key.get("private_key_id"):
            header["kid"] = str(key["private_key_id"])
        claims = {"iss": str(key["client_email"]), "sub": admin, "scope": SCOPE, "aud": TOKEN_URL,
                  "iat": iat, "exp": iat + 3600}
        signing_input = (_b64(json.dumps(header, separators=(",", ":")).encode()) + "."
                         + _b64(json.dumps(claims, separators=(",", ":")).encode()))
        sig = pk.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + _b64(sig)

    def token(self) -> str:
        r = self.request("POST", TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                  "assertion": self.assertion()})
        body = json_body(r, "oauth2.googleapis.com")
        tok = body.get("access_token") if isinstance(body, dict) else None
        if not tok:
            raise ConnectorError("token exchange returned no access token")
        return tok

    def pages(self):
        apps = self.applications()
        step = dt.timedelta(minutes=_int(self.config.get("window_minutes"), 60, 5, 1440, "window_minutes"))
        lag = dt.timedelta(minutes=_int(self.config.get("lag_minutes"), 15, 0, 720, "lag_minutes"))
        headers = {"Authorization": f"Bearer {self.token()}"}
        state = self.cursor.get("since") if isinstance(self.cursor.get("since"), dict) else {}
        state = {k: v for k, v in state.items() if k in apps}
        horizon = self.now - lag
        pending = False
        for app in apps:
            start = parse_dt(state.get(app)) or (self.now - FIRST_LOOKBACK)
            while start < horizon:
                end = min(start + step, horizon)
                params = {"startTime": z(start, ms=True), "endTime": z(end, ms=True), "maxResults": "1000"}
                while True:
                    r = self.request("GET", f"{API}/{app}", headers=headers, params=params)
                    body = json_body(r, "admin.googleapis.com")
                    if not isinstance(body, dict):
                        raise ConnectorError("Reports API returned an unexpected response")
                    rows = body.get("items") or []
                    nxt = body.get("nextPageToken")
                    if not nxt:
                        state[app] = end.isoformat()
                    if rows:
                        yield rows, {"since": dict(state)}
                        pending = False
                    elif not nxt:
                        pending = True
                    if not nxt:
                        break
                    params = {**params, "pageToken": str(nxt)}
                start = end
        if pending:
            yield [], {"since": dict(state)}
