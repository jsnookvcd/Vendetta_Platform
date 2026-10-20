"""Puller tests for Defender XDR alerts (Graph alerts_v2) and the Office 365
Management Activity API."""
import datetime as dt

import httpx
import pytest

from app.connectors import ConnectorError
from test_pullers_common import NOW, Router, about_24h_before_now, assert_secret_free, form, make, parse_iso, run

TID = "11111111-2222-3333-4444-555555555555"
LOGIN = f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
SECRET = "ms~SECRET~Q8f7e6d5c4b3a2"
CFG = {"tenant_id": TID, "client_id": "22222222-3333-4444-5555-666666666666"}
CREDS = {"client_secret": SECRET}


def token():
    return httpx.Response(200, json={"access_token": "graph-access-token", "token_type": "Bearer", "expires_in": 3599})


# ---------------------------------------------------------------- Defender
ALERTS = "https://graph.microsoft.com/v1.0/security/alerts_v2"


def alert(i, updated):
    return {"id": i, "title": "t", "severity": "high", "createdDateTime": updated, "lastUpdateDateTime": updated}


def test_defender_two_pages_cursor_advances_after_last_page():
    nxt = f"{ALERTS}?$filter=lastUpdateDateTime+ge+2026-10-19T07:55:00Z&$top=500&$skip=500"
    r = Router().add("POST", LOGIN, token())
    r.add("GET", ALERTS,
          httpx.Response(200, json={"value": [alert("a1", "2026-10-19T09:00:00Z"), alert("a2", "2026-10-19T11:00:00Z")],
                                    "@odata.nextLink": nxt}),
          httpx.Response(200, json={"value": [alert("a3", "2026-10-19T10:00:00Z")]}))
    pages = run(make("defender_alerts", CFG, CREDS, r, cursor={"since": "2026-10-19T08:00:00+00:00"}))
    assert [len(rows) for rows, _ in pages] == [2, 1]
    assert pages[0][1] == {"since": "2026-10-19T08:00:00+00:00"}  # unordered API: hold until the last page
    assert pages[1][1] == {"since": "2026-10-19T11:00:00+00:00"}
    tok = form(r.to("login.microsoftonline.com")[0])
    assert tok["scope"] == "https://graph.microsoft.com/.default" and tok["grant_type"] == "client_credentials"
    calls = r.to("graph.microsoft.com")
    assert calls[0].url.params["$filter"] == "lastUpdateDateTime ge 2026-10-19T07:55:00Z"
    assert "$orderby" not in calls[0].url.params
    assert calls[0].headers["authorization"] == "Bearer graph-access-token"
    assert calls[1].url.params["$skip"] == "500"


def test_defender_first_run_looks_back_24h():
    r = Router().add("POST", LOGIN, token()).add("GET", ALERTS, httpx.Response(200, json={"value": []}))
    run(make("defender_alerts", CFG, CREDS, r))
    since = r.to("graph.microsoft.com")[0].url.params["$filter"].split(" ge ")[1]
    assert about_24h_before_now(since)


def test_defender_401_is_secret_free():
    r = Router().add("POST", LOGIN, httpx.Response(401, json={"error": "invalid_client",
                                                               "error_description": "AADSTS7000215: Invalid client secret"}))
    with pytest.raises(ConnectorError) as e:
        run(make("defender_alerts", CFG, CREDS, r))
    assert_secret_free(e.value, SECRET)


def test_defender_403_on_alerts_is_secret_free():
    r = Router().add("POST", LOGIN, token()).add("GET", ALERTS, httpx.Response(403, json={"error": {"code": "Forbidden"}}))
    with pytest.raises(ConnectorError) as e:
        run(make("defender_alerts", CFG, CREDS, r))
    assert "403" in str(e.value)
    assert_secret_free(e.value, SECRET, "graph-access-token")


def test_defender_429_then_success():
    r = Router().add("POST", LOGIN, token())
    r.add("GET", ALERTS, httpx.Response(429, headers={"Retry-After": "4"}),
          httpx.Response(200, json={"value": [alert("a1", "2026-10-19T09:00:00Z")]}))
    assert len(run(make("defender_alerts", CFG, CREDS, r))) == 1
    assert len(r.to("graph.microsoft.com")) == 2


@pytest.mark.parametrize("nxt", ["https://graph.microsoft.com.evil.example/v1.0/security/alerts_v2?$skip=1",
                                 "https://evil.example/v1.0/security/alerts_v2", "http://graph.microsoft.com/v1.0/x"])
def test_defender_foreign_next_link_refused(nxt):
    r = Router().add("POST", LOGIN, token())
    r.add("GET", ALERTS, httpx.Response(200, json={"value": [], "@odata.nextLink": nxt}))
    with pytest.raises(ConnectorError):
        run(make("defender_alerts", CFG, CREDS, r))
    assert all(c.url.host in ("login.microsoftonline.com", "graph.microsoft.com") for c in r.calls)


def test_defender_invalid_tenant_id():
    r = Router()
    with pytest.raises(ConnectorError):
        run(make("defender_alerts", {**CFG, "tenant_id": "evil.example/x?"}, CREDS, r))
    assert r.calls == []


# ---------------------------------------------------------------- Office 365 Management Activity
FEED = f"https://manage.office.com/api/v1.0/{TID}/activity/feed"
CONTENT = f"{FEED}/subscriptions/content"


def blob(n):
    return {"contentType": "Audit.Exchange", "contentId": f"20261019{n}",
            "contentUri": f"{FEED}/audit/20261019{n}", "contentCreated": "2026-10-19T00:00:00.000Z"}


def audit(i):
    return {"Id": i, "CreationTime": "2026-10-19T00:00:00", "Operation": "New-InboxRule", "Workload": "Exchange"}


def m365_router(subs=None):
    r = Router().add("POST", LOGIN, token())
    r.add("GET", f"{FEED}/subscriptions/list", httpx.Response(200, json=subs if subs is not None else []))
    r.add("POST", f"{FEED}/subscriptions/start", httpx.Response(200, json={"contentType": "Audit.Exchange",
                                                                          "status": "enabled"}))
    return r


def test_m365_windows_pages_blobs_and_cursor():
    r = m365_router()
    nxt = f"{CONTENT}?contentType=Audit.Exchange&startTime=x&endTime=y&nextPage=2026101900"
    r.add("GET", CONTENT,
          httpx.Response(200, json=[blob("01")], headers={"NextPageUri": nxt}),   # window 1, listing page 1
          httpx.Response(200, json=[blob("02")]),                                 # window 1, listing page 2
          httpx.Response(200, json=[]))                                           # window 2, empty
    r.add("GET", f"{FEED}/audit/2026101901", httpx.Response(200, json=[audit("e1"), audit("e2")]))
    r.add("GET", f"{FEED}/audit/2026101902", httpx.Response(200, json=[audit("e3")]))
    cfg = {**CFG, "contentTypes": "Audit.Exchange", "window_minutes": "720"}
    pages = run(make("m365_audit", cfg, CREDS, r))
    assert [[x["Id"] for x in rows] for rows, _ in pages] == [["e1", "e2"], ["e3"], []]
    w1_end = (NOW - dt.timedelta(hours=12)).isoformat()
    assert pages[0][1] == {"since": {}, "subscribed": True}
    assert pages[1][1] == {"since": {"Audit.Exchange": w1_end}, "subscribed": True}
    assert pages[2][1] == {"since": {"Audit.Exchange": NOW.isoformat()}, "subscribed": True}
    tok = form(r.to("login.microsoftonline.com")[0])
    assert tok["scope"] == "https://manage.office.com/.default"
    started = r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/start")
    assert [s.url.params["contentType"] for s in started] == ["Audit.Exchange"]
    listings = r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/content")
    assert listings[0].url.params["startTime"] == "2026-10-18T12:00:00"
    assert listings[0].url.params["endTime"] == "2026-10-19T00:00:00"
    assert listings[1].url.params["nextPage"] == "2026101900"
    assert listings[2].url.params["startTime"] == "2026-10-19T00:00:00"
    assert listings[2].url.params["endTime"] == "2026-10-19T12:00:00"
    assert all(c.headers["authorization"] == "Bearer graph-access-token" for c in r.to("manage.office.com"))


def test_m365_first_run_lookback_and_window_cap():
    r = m365_router(subs=[{"contentType": t, "status": "enabled"}
                          for t in ("Audit.Exchange", "Audit.SharePoint", "Audit.General")])
    r.add("GET", CONTENT, httpx.Response(200, json=[]))
    pages = run(make("m365_audit", CFG, CREDS, r))
    assert r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/start") == []
    listings = r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/content")
    by_type: dict = {}
    for c in listings:
        by_type.setdefault(c.url.params["contentType"], []).append(c)
    assert set(by_type) == {"Audit.Exchange", "Audit.SharePoint", "Audit.General"}  # the default types
    for calls in by_type.values():
        assert about_24h_before_now(calls[0].url.params["startTime"], slack_minutes=0)
        assert len(calls) == 24  # one-hour windows by default
        for c in calls:
            span = parse_iso(c.url.params["endTime"]) - parse_iso(c.url.params["startTime"])
            assert dt.timedelta(0) < span <= dt.timedelta(hours=24)
    # empty windows spend no pages, and the cursor still reaches now
    assert len(pages) == 1 and pages[0][0] == []
    assert set(pages[0][1]["since"].values()) == {NOW.isoformat()}


def test_m365_cursor_older_than_retention_is_clamped():
    r = m365_router(subs=[{"contentType": "Audit.General", "status": "enabled"}])
    r.add("GET", CONTENT, httpx.Response(200, json=[]))
    old = (NOW - dt.timedelta(days=30)).isoformat()
    run(make("m365_audit", {**CFG, "contentTypes": "Audit.General", "window_minutes": "1440"}, CREDS, r,
             cursor={"since": {"Audit.General": old}, "subscribed": True}))
    first = r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/content")[0]
    assert NOW - parse_iso(first.url.params["startTime"]) < dt.timedelta(days=7)
    assert r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/subscriptions/list") == []


def test_m365_401_is_secret_free():
    r = Router().add("POST", LOGIN, httpx.Response(401, json={"error": "invalid_client"}))
    with pytest.raises(ConnectorError) as e:
        run(make("m365_audit", CFG, CREDS, r))
    assert_secret_free(e.value, SECRET)


def test_m365_429_on_blob_then_success():
    r = m365_router(subs=[{"contentType": "Audit.Exchange", "status": "enabled"}])
    r.add("GET", CONTENT, httpx.Response(200, json=[blob("01")]), httpx.Response(200, json=[]))
    r.add("GET", f"{FEED}/audit/2026101901", httpx.Response(429, headers={"Retry-After": "1"}),
          httpx.Response(200, json=[audit("e1")]))
    pages = run(make("m365_audit", {**CFG, "contentTypes": "Audit.Exchange", "window_minutes": "720"}, CREDS, r))
    assert pages[0][0] == [audit("e1")]
    assert len(r.to("manage.office.com", f"/api/v1.0/{TID}/activity/feed/audit/2026101901")) == 2


@pytest.mark.parametrize("where", ["contentUri", "NextPageUri"])
def test_m365_foreign_uris_refused(where):
    r = m365_router(subs=[{"contentType": "Audit.Exchange", "status": "enabled"}])
    evil = "https://manage.office.com.evil.example/api/v1.0/x/activity/feed/audit/1"
    if where == "contentUri":
        r.add("GET", CONTENT, httpx.Response(200, json=[{**blob("01"), "contentUri": evil}]))
    else:
        r.add("GET", CONTENT, httpx.Response(200, json=[], headers={"NextPageUri": evil}))
    with pytest.raises(ConnectorError):
        run(make("m365_audit", {**CFG, "contentTypes": "Audit.Exchange"}, CREDS, r))
    assert all(c.url.host in ("login.microsoftonline.com", "manage.office.com") for c in r.calls)


@pytest.mark.parametrize("cfg", [{"contentTypes": "Audit.Exchange,Audit.Everything"}, {"window_minutes": "2000"},
                                 {"window_minutes": "soon"}, {"tenant_id": "../../evil"},
                                 {"publisher_id": "x&y=z"}])
def test_m365_invalid_config(cfg):
    r = Router().add("POST", LOGIN, token())
    with pytest.raises(ConnectorError):
        run(make("m365_audit", {**CFG, **cfg}, CREDS, r))
    assert r.to("manage.office.com") == []
