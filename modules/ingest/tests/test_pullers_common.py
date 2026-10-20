"""Shared helpers for the wave 1 puller tests, and checks every puller must pass.

Router is an httpx.MockTransport handler that answers by (method, host, path) with a
queue of responses per route, and records every request it saw.
"""
import datetime as dt
import json

import httpx
import pytest

from app import connectors, mappers
from app.connectors import ConnectorError, Puller

NOW = dt.datetime(2026, 10, 19, 12, 0, 0, tzinfo=dt.timezone.utc)
WAVE1_PULLERS = ["crowdstrike_alerts", "sentinelone_threats", "defender_alerts", "huntress_incidents",
                 "okta_system_log", "m365_audit", "google_workspace"]


class Router:
    def __init__(self):
        self.routes: dict[tuple[str, str, str], list] = {}
        self.calls: list[httpx.Request] = []

    def add(self, method: str, url: str, *responses):
        u = httpx.URL(url)
        self.routes.setdefault((method.upper(), u.host, u.path), []).extend(responses)
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = (request.method, request.url.host, request.url.path)
        queue = self.routes.get(key)
        if not queue:
            return httpx.Response(404, json={"error": f"no route for {key}"})
        resp = queue.pop(0) if len(queue) > 1 else queue[0]
        return resp(request) if callable(resp) else resp

    def to(self, host: str, path: str | None = None, method: str | None = None) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == host and (path is None or c.url.path == path)
                and (method is None or c.method == method)]


def make(source: str, config: dict, credentials: dict, router: Router, cursor: dict | None = None) -> Puller:
    cls = connectors.get(source)
    p = cls(config, credentials, cursor or {}, httpx.Client(transport=httpx.MockTransport(router)), now=NOW)
    p.no_sleep = True
    return p


def run(p: Puller) -> list[tuple[list, dict]]:
    return [(list(rows), dict(cur)) for rows, cur in p.pages()]


def body_json(req: httpx.Request):
    return json.loads(req.content)


def form(req: httpx.Request) -> dict:
    return dict(httpx.QueryParams(req.content.decode()))


def parse_iso(s: str) -> dt.datetime:
    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def about_24h_before_now(s: str, slack_minutes: int = 10) -> bool:
    delta = NOW - parse_iso(s)
    return dt.timedelta(hours=24) - dt.timedelta(minutes=slack_minutes) <= delta <= \
        dt.timedelta(hours=24) + dt.timedelta(minutes=slack_minutes)


def assert_secret_free(err: Exception, *secrets: str):
    msg = str(err)
    for s in secrets:
        assert s not in msg, "secret leaked into the error"
        assert s not in repr(err)


# ---------------------------------------------------------------- checks across pullers
def test_wave1_pullers_registered_with_specs_and_mappers():
    for src in WAVE1_PULLERS:
        cls = connectors.get(src)
        assert cls is not None, src
        assert cls.source == src
        spec = cls.spec
        assert set(spec) == {"credentials", "config"}
        assert spec["credentials"], f"{src} declares no credential"
        for section in ("credentials", "config"):
            for k, v in spec[section].items():
                assert isinstance(k, str) and isinstance(v, str) and v.strip(), (src, k)
        assert mappers.get(src) is not None, f"{src} has no mapper"
    cat = {c["key"]: c for c in connectors.catalog()}
    for src in WAVE1_PULLERS:
        assert "pull" in cat[src]["doors"]
    assert "pull" not in cat["crowdstrike_fdr"]["doors"]
    assert "pull" not in cat["cloudtrail"]["doors"]


@pytest.mark.parametrize("src", WAVE1_PULLERS)
def test_missing_credentials_is_a_connector_error_before_any_request(src):
    router = Router()
    cfg = {"base_url": "https://usea1-acme.sentinelone.net", "okta_domain": "acme.okta.com",
           "tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "app-id", "admin_email": "admin@acme.example"}
    p = make(src, cfg, {}, router)
    with pytest.raises(ConnectorError):
        run(p)
    assert router.calls == []


def test_router_unknown_route_is_404():
    r = Router()
    resp = r(httpx.Request("GET", "https://example.test/x"))
    assert resp.status_code == 404
