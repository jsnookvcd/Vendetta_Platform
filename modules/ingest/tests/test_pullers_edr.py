"""Puller tests for CrowdStrike Falcon alerts, SentinelOne threats and Huntress incidents."""
import base64

import httpx
import pytest

from app.connectors import ConnectorError
from test_pullers_common import NOW, Router, about_24h_before_now, assert_secret_free, body_json, form, make, run

# ---------------------------------------------------------------- CrowdStrike
CS = "https://api.crowdstrike.com"
CS_SECRET = "cs-SECRET-0f9e8d7c6b5a4"
CS_CFG = {"client_id": "a1b2c3d4e5f6", "base_url": CS}
CS_CREDS = {"client_secret": CS_SECRET}


def cs_token(status=201):
    return httpx.Response(status, json={"access_token": "falcon-token", "expires_in": 1799, "token_type": "bearer"})


def cs_alert(cid, updated):
    return {"composite_id": cid, "created_timestamp": "2026-10-19T08:00:00Z", "updated_timestamp": updated,
            "status": "new", "severity": 70, "display_name": "x"}


def test_crowdstrike_two_pages_cursor_advances():
    r = Router()
    r.add("POST", f"{CS}/oauth2/token", cs_token())
    r.add("GET", f"{CS}/alerts/queries/alerts/v2",
          httpx.Response(200, json={"meta": {"pagination": {"offset": 0, "limit": 500, "total": 3}},
                                    "resources": ["c:1", "c:2"]}),
          httpx.Response(200, json={"meta": {"pagination": {"offset": 2, "limit": 500, "total": 3}},
                                    "resources": ["c:3"]}))
    r.add("POST", f"{CS}/alerts/entities/alerts/v2",
          httpx.Response(200, json={"resources": [cs_alert("c:1", "2026-10-19T09:00:00Z"),
                                                  cs_alert("c:2", "2026-10-19T09:30:00Z")]}),
          httpx.Response(200, json={"resources": [cs_alert("c:3", "2026-10-19T10:15:00Z")]}))
    pages = run(make("crowdstrike_alerts", CS_CFG, CS_CREDS, r, cursor={"since": "2026-10-19T08:30:00+00:00"}))
    assert [len(rows) for rows, _ in pages] == [2, 1]
    assert pages[0][1] == {"since": "2026-10-19T09:30:00+00:00"}
    assert pages[1][1] == {"since": "2026-10-19T10:15:00+00:00"}
    tok = r.to("api.crowdstrike.com", "/oauth2/token")[0]
    assert form(tok) == {"client_id": "a1b2c3d4e5f6", "client_secret": CS_SECRET}
    queries = r.to("api.crowdstrike.com", "/alerts/queries/alerts/v2")
    assert queries[0].url.params["filter"] == "updated_timestamp:>='2026-10-19T08:30:00.000Z'"
    assert queries[0].url.params["sort"] == "updated_timestamp.asc"
    assert [q.url.params["offset"] for q in queries] == ["0", "2"]
    assert queries[0].headers["authorization"] == "Bearer falcon-token"
    ents = r.to("api.crowdstrike.com", "/alerts/entities/alerts/v2")
    assert body_json(ents[0]) == {"composite_ids": ["c:1", "c:2"]}


def test_crowdstrike_first_run_looks_back_24h():
    r = Router()
    r.add("POST", f"{CS}/oauth2/token", cs_token())
    r.add("GET", f"{CS}/alerts/queries/alerts/v2", httpx.Response(200, json={"resources": [], "meta": {}}))
    assert run(make("crowdstrike_alerts", CS_CFG, CS_CREDS, r)) == []
    fql = r.to("api.crowdstrike.com", "/alerts/queries/alerts/v2")[0].url.params["filter"]
    assert about_24h_before_now(fql.split("'")[1], slack_minutes=0)


def test_crowdstrike_401_is_secret_free():
    r = Router().add("POST", f"{CS}/oauth2/token", httpx.Response(401, json={"errors": [{"message": "access denied"}]}))
    with pytest.raises(ConnectorError) as e:
        run(make("crowdstrike_alerts", CS_CFG, CS_CREDS, r))
    assert "401" in str(e.value)
    assert_secret_free(e.value, CS_SECRET, "falcon-token")


def test_crowdstrike_429_retry_after_then_success():
    r = Router()
    r.add("POST", f"{CS}/oauth2/token", cs_token())
    r.add("GET", f"{CS}/alerts/queries/alerts/v2",
          httpx.Response(429, headers={"Retry-After": "2"}),
          httpx.Response(200, json={"meta": {"pagination": {"total": 1}}, "resources": ["c:1"]}))
    r.add("POST", f"{CS}/alerts/entities/alerts/v2",
          httpx.Response(200, json={"resources": [cs_alert("c:1", "2026-10-19T09:00:00Z")]}))
    pages = run(make("crowdstrike_alerts", CS_CFG, CS_CREDS, r))
    assert len(pages) == 1 and len(r.to("api.crowdstrike.com", "/alerts/queries/alerts/v2")) == 2


def test_crowdstrike_second_429_stops_the_run():
    r = Router()
    r.add("POST", f"{CS}/oauth2/token", cs_token())
    r.add("GET", f"{CS}/alerts/queries/alerts/v2", httpx.Response(429, headers={"Retry-After": "1"}))
    with pytest.raises(ConnectorError):
        run(make("crowdstrike_alerts", CS_CFG, CS_CREDS, r))


def test_crowdstrike_other_cloud_hosts_accepted():
    r = Router()
    r.add("POST", "https://api.eu-1.crowdstrike.com/oauth2/token", cs_token())
    r.add("GET", "https://api.eu-1.crowdstrike.com/alerts/queries/alerts/v2", httpx.Response(200, json={"resources": []}))
    run(make("crowdstrike_alerts", {**CS_CFG, "base_url": "https://api.eu-1.crowdstrike.com/"}, CS_CREDS, r))
    assert r.calls and all(c.url.host == "api.eu-1.crowdstrike.com" for c in r.calls)


@pytest.mark.parametrize("base", ["https://api.crowdstrike.com.evil.example", "http://api.crowdstrike.com",
                                  "https://evil.example", "https://api.crowdstrike.com/proxy",
                                  "https://user:pw@api.crowdstrike.com", "https://api.crowdstrike.com:8443"])
def test_crowdstrike_invalid_base_url(base):
    r = Router()
    with pytest.raises(ConnectorError):
        run(make("crowdstrike_alerts", {**CS_CFG, "base_url": base}, CS_CREDS, r))
    assert r.calls == []


# ---------------------------------------------------------------- SentinelOne
S1 = "https://usea1-acme.sentinelone.net"
S1_TOKEN = "s1-API-TOKEN-eyJraWQiOiJ1cy1lYXN0"
S1_CFG = {"base_url": S1}
S1_CREDS = {"api_token": S1_TOKEN}
S1_PATH = "/web/api/v2.1/threats"


def s1_threat(tid, created):
    return {"id": tid, "threatInfo": {"threatName": "x.exe", "createdAt": created, "confidenceLevel": "malicious"}}


def test_sentinelone_two_pages_cursor_advances():
    r = Router().add("GET", S1 + S1_PATH,
                     httpx.Response(200, json={"data": [s1_threat("1", "2026-10-19T09:00:00.000000Z"),
                                                        s1_threat("2", "2026-10-19T09:10:00.000000Z")],
                                               "pagination": {"nextCursor": "YWdlbnRfaWQ6MTIz", "totalItems": 3}}),
                     httpx.Response(200, json={"data": [s1_threat("3", "2026-10-19T10:00:00.000000Z")],
                                               "pagination": {"nextCursor": None, "totalItems": 3}}))
    pages = run(make("sentinelone_threats", S1_CFG, S1_CREDS, r, cursor={"since": "2026-10-19T08:00:00+00:00"}))
    assert [len(rows) for rows, _ in pages] == [2, 1]
    assert pages[0][1] == {"since": "2026-10-19T09:10:00+00:00"}
    assert pages[1][1] == {"since": "2026-10-19T10:00:00+00:00"}
    calls = r.to("usea1-acme.sentinelone.net", S1_PATH)
    assert calls[0].headers["authorization"] == f"ApiToken {S1_TOKEN}"
    assert calls[0].url.params["createdAt__gt"] == "2026-10-19T08:00:00.000Z"
    assert calls[0].url.params["sortBy"] == "createdAt" and calls[0].url.params["sortOrder"] == "asc"
    assert "cursor" not in calls[0].url.params
    assert calls[1].url.params["cursor"] == "YWdlbnRfaWQ6MTIz"
    assert calls[1].url.params["createdAt__gt"] == "2026-10-19T08:00:00.000Z"


def test_sentinelone_first_run_looks_back_24h():
    r = Router().add("GET", S1 + S1_PATH, httpx.Response(200, json={"data": [], "pagination": {"nextCursor": None}}))
    assert run(make("sentinelone_threats", S1_CFG, S1_CREDS, r)) == []
    assert about_24h_before_now(r.calls[0].url.params["createdAt__gt"], slack_minutes=0)


def test_sentinelone_401_is_secret_free():
    r = Router().add("GET", S1 + S1_PATH, httpx.Response(401, json={"errors": [{"code": 4010010}]}))
    with pytest.raises(ConnectorError) as e:
        run(make("sentinelone_threats", S1_CFG, S1_CREDS, r))
    assert_secret_free(e.value, S1_TOKEN)


def test_sentinelone_429_then_success():
    r = Router().add("GET", S1 + S1_PATH, httpx.Response(429, headers={"Retry-After": "3"}),
                     httpx.Response(200, json={"data": [s1_threat("1", "2026-10-19T09:00:00Z")],
                                               "pagination": {"nextCursor": None}}))
    pages = run(make("sentinelone_threats", S1_CFG, S1_CREDS, r))
    assert len(pages) == 1 and len(r.calls) == 2


def test_sentinelone_scope_filters():
    r = Router().add("GET", S1 + S1_PATH, httpx.Response(200, json={"data": []}))
    run(make("sentinelone_threats", {**S1_CFG, "site_ids": "111, 222"}, S1_CREDS, r))
    assert r.calls[0].url.params["siteIds"] == "111,222"
    with pytest.raises(ConnectorError):
        run(make("sentinelone_threats", {**S1_CFG, "account_ids": "1;drop"}, S1_CREDS, Router()))


@pytest.mark.parametrize("base", ["https://acme.sentinelone.net.evil.example", "http://usea1-acme.sentinelone.net",
                                  "https://evil.example", "https://sentinelone.net", "", "https://usea1-acme.sentinelone.net/web"])
def test_sentinelone_invalid_base_url(base):
    r = Router()
    with pytest.raises(ConnectorError):
        run(make("sentinelone_threats", {"base_url": base}, S1_CREDS, r))
    assert r.calls == []


# ---------------------------------------------------------------- Huntress
HU = "https://api.huntress.io/v1/incident_reports"
HU_KEY, HU_SECRET = "hk_live_4f3e2d1c", "hs_live_SECRET_9a8b7c6d"
HU_CREDS = {"api_key": HU_KEY, "api_secret": HU_SECRET}


def hu_report(i, updated):
    return {"id": i, "status": "sent", "severity": "high", "updated_at": updated, "sent_at": updated}


def test_huntress_two_pages_cursor_advances_on_last_page():
    r = Router().add("GET", HU,
                     httpx.Response(200, json={"incident_reports": [hu_report(1, "2026-10-19T09:00:00Z"),
                                                                    hu_report(2, "2026-10-19T07:00:00Z")],
                                               "pagination": {"next_page_token": "tok2",
                                                              "next_page_url": "https://api.huntress.io/v1/incident_reports?page_token=tok2"}}),
                     httpx.Response(200, json={"incident_reports": [hu_report(3, "2026-10-19T10:30:00Z")],
                                               "pagination": {}}))
    pages = run(make("huntress_incidents", {}, HU_CREDS, r, cursor={"since": "2026-10-19T08:00:00+00:00"}))
    # report 2 is older than the cursor and is dropped in case the API ignored the filter
    assert [[x["id"] for x in rows] for rows, _ in pages] == [[1], [3]]
    assert pages[0][1] == {"since": "2026-10-19T08:00:00+00:00"}
    assert pages[1][1] == {"since": "2026-10-19T10:30:00+00:00"}
    expected = "Basic " + base64.b64encode(f"{HU_KEY}:{HU_SECRET}".encode()).decode()
    assert r.calls[0].headers["authorization"] == expected
    assert r.calls[0].url.params["updated_at_min"] == "2026-10-19T08:00:00Z"
    assert r.calls[1].url.params["page_token"] == "tok2"


def test_huntress_first_run_looks_back_24h():
    r = Router().add("GET", HU, httpx.Response(200, json={"incident_reports": [], "pagination": {}}))
    run(make("huntress_incidents", {}, HU_CREDS, r))
    assert about_24h_before_now(r.calls[0].url.params["updated_at_min"], slack_minutes=0)


def test_huntress_401_is_secret_free():
    r = Router().add("GET", HU, httpx.Response(401, json={"error": "invalid credentials"}))
    with pytest.raises(ConnectorError) as e:
        run(make("huntress_incidents", {}, HU_CREDS, r))
    assert_secret_free(e.value, HU_KEY, HU_SECRET, base64.b64encode(f"{HU_KEY}:{HU_SECRET}".encode()).decode())


def test_huntress_429_then_success():
    r = Router().add("GET", HU, httpx.Response(429, headers={"Retry-After": "1"}),
                     httpx.Response(200, json={"incident_reports": [hu_report(1, "2026-10-19T09:00:00Z")]}))
    assert len(run(make("huntress_incidents", {}, HU_CREDS, r))) == 1
    assert len(r.calls) == 2


def test_huntress_next_url_to_foreign_host_refused():
    r = Router().add("GET", HU, httpx.Response(200, json={
        "incident_reports": [], "pagination": {"next_page_token": "t", "next_page_url": "https://evil.example/v1/incident_reports?page_token=t"}}))
    with pytest.raises(ConnectorError):
        run(make("huntress_incidents", {}, HU_CREDS, r))
    assert all(c.url.host == "api.huntress.io" for c in r.calls)


def test_huntress_invalid_config():
    r = Router()
    with pytest.raises(ConnectorError):
        run(make("huntress_incidents", {"organization_id": "55012&status=closed"}, HU_CREDS, r))
    assert r.calls == []
    r = Router().add("GET", HU, httpx.Response(200, json={"incident_reports": []}))
    run(make("huntress_incidents", {"organization_id": "55012"}, HU_CREDS, r))
    assert r.calls[0].url.params["organization_id"] == "55012"


def test_now_is_fixed():
    assert NOW.isoformat() == "2026-10-19T12:00:00+00:00"
