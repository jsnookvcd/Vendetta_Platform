"""Connector contracts against canned vendor-shaped responses (httpx.MockTransport):
request shapes (auth headers, bodies, filters) and the normalization promised to
the sync engine."""
import json

import httpx
import pytest

from app.connectors import ConnectorError
from app.connectors.acronis import Acronis
from app.connectors.crowdstrike import CrowdStrike
from app.connectors.huntress import Huntress
from app.connectors.sentinelone import SentinelOne
from app.connectors.superops import SuperOps


# ---------------------------------------------------------------- SuperOps
def test_superops_devices_sends_client_condition_and_normalizes():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        seen["sub"] = req.headers.get("customersubdomain")
        seen["cond"] = json.loads(req.content)["variables"]["input"].get("condition")
        return httpx.Response(200, json={"data": {"getAssetList": {"assets": [{
            "assetId": "77", "name": "FS01", "hostName": "FS01", "platform": "Windows Server 2022",
            "status": "ONLINE", "lastCommunicatedTime": "2026-10-12T15:54:16.270",
            "agentVersion": "9.1", "client": {"accountId": "acc1", "name": "Riverbend"},
        }], "listInfo": {"hasMore": None}}}})

    so = SuperOps(transport=httpx.MockTransport(handler))
    devs = so.devices("acc1")
    assert seen["auth"] == "Bearer t" and seen["sub"] == "vendetta"
    assert seen["cond"] == {"attribute": "client", "operator": "includes", "value": ["acc1"]}
    assert devs[0]["hostname"] == "FS01" and devs[0]["status"] == "online" and devs[0]["last_seen"].year == 2026


def test_superops_alerts_filtered_by_client_and_app_errors_raise():
    def handler(req: httpx.Request) -> httpx.Response:
        if "getAlertList" in json.loads(req.content)["query"]:
            return httpx.Response(200, json={"data": {"getAlertList": {"alerts": [
                {"id": "1", "message": "Disk space critical", "severity": "Critical", "status": "Open",
                 "createdTime": "2026-10-12T10:00:00",
                 "asset": {"assetId": "77", "name": "FS01", "client": {"accountId": "acc1"}}},
                {"id": "2", "message": "Other client's alert", "severity": "Low", "status": "Open",
                 "createdTime": "2026-10-12T10:00:00", "asset": {"client": {"accountId": "zzz"}}},
            ], "listInfo": {"hasMore": None}}}})
        return httpx.Response(200, json={"errors": [{"message": "x", "extensions": {
            "clientError": [{"code": "rate_limit_exceeded"}]}}]})

    so = SuperOps(transport=httpx.MockTransport(handler))
    alerts = so.alerts("acc1")
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical" and alerts[0]["kind"] == "rmm"
    with pytest.raises(ConnectorError, match="rate_limit_exceeded"):
        so.resolve_alert("1")


def test_superops_create_ticket_contract():
    def handler(req: httpx.Request) -> httpx.Response:
        inp = json.loads(req.content)["variables"]["input"]
        assert inp["source"] == "INTEGRATION" and inp["client"] == {"accountId": "acc1"}
        return httpx.Response(200, json={"data": {"createTicket": {"ticketId": "900", "displayId": "101226-0007"}}})

    t = SuperOps(transport=httpx.MockTransport(handler)).create_ticket("acc1", "VPN down", "Cannot reach VPN")
    assert t == {"ticket_id": "900", "display_id": "101226-0007"}


# ---------------------------------------------------------------- SentinelOne
def test_sentinelone_normalizes_agents_and_threats():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "ApiToken t"
        if req.url.path.endswith("/agents"):
            assert req.url.params["siteIds"] == "111,222"
            return httpx.Response(200, json={"data": [
                {"id": "a1", "computerName": "WS01", "osName": "Windows 11", "agentVersion": "24.1",
                 "networkStatus": "connected", "isActive": True,
                 "lastActiveDate": "2026-10-12T20:00:00.000000Z"},
                {"id": "a2", "computerName": "WS02", "networkStatus": "disconnected", "isActive": True},
                {"id": "a3", "computerName": "OLD", "isDecommissioned": True},
            ], "pagination": {"nextCursor": "null"}})
        return httpx.Response(200, json={"data": [{
            "id": "t9", "threatInfo": {"threatId": "t9", "threatName": "Credential theft tool detected",
                                       "classification": "Malware", "confidenceLevel": "malicious",
                                       "mitigationStatus": "not_mitigated", "incidentStatus": "unresolved",
                                       "createdAt": "2026-10-12T19:00:00.000000Z"},
            "agentRealtimeInfo": {"agentComputerName": "WS01", "agentId": "a1"},
        }], "pagination": {"nextCursor": None}})

    s1 = SentinelOne(transport=httpx.MockTransport(handler))
    devs = s1.devices("111,222")
    assert [d["status"] for d in devs] == ["online", "isolated"]  # decommissioned dropped
    t = s1.alerts("111,222")[0]
    assert t["severity"] == "critical" and t["device_external_id"] == "a1" and not t["resolved"]
    assert t["link"].endswith("/incidents/threats/t9/overview")


def test_sentinelone_actions_post_ids_filter_and_refuse_empty():
    posted = {}

    def handler(req: httpx.Request) -> httpx.Response:
        posted[req.url.path] = json.loads(req.content)
        return httpx.Response(200, json={"data": {"affected": 1}})

    s1 = SentinelOne(transport=httpx.MockTransport(handler))
    assert s1.mitigate(["t9"], "quarantine") == 1
    assert posted["/web/api/v2.1/threats/mitigate/quarantine"] == {"filter": {"ids": ["t9"]}}
    s1.set_incident(["t9"], "resolved", "true_positive")
    assert posted["/web/api/v2.1/threats/incident"]["data"] == {
        "incidentStatus": "resolved", "analystVerdict": "true_positive"}
    s1.disconnect(["a1"])
    assert posted["/web/api/v2.1/agents/actions/disconnect"] == {"filter": {"ids": ["a1"]}}
    with pytest.raises(ConnectorError, match="no target ids"):
        s1.mitigate([], "quarantine")
    with pytest.raises(ConnectorError, match="unknown mitigation"):
        s1.mitigate(["t9"], "not-an-action")


# ---------------------------------------------------------------- CrowdStrike
def _cs_handler(state):
    def handler(req: httpx.Request) -> httpx.Response:
        state.append((req.method, req.url.path))
        if req.url.path == "/oauth2/token":
            assert b"member_cid=aabbccdd" in req.content and b"client_id=cid" in req.content
            return httpx.Response(201, json={"access_token": "tok", "expires_in": 1799, "token_type": "bearer"})
        assert req.headers["authorization"] == "Bearer tok"
        if req.url.path == "/devices/combined/devices/v1":
            return httpx.Response(200, json={"resources": [
                {"device_id": "d1", "hostname": "DC01", "platform_name": "Windows",
                 "os_version": "Server 2019", "agent_version": "7.2",
                 "last_seen": "2020-01-01T00:00:00Z", "status": "contained"}], "meta": {"pagination": {}}})
        if req.url.path == "/alerts/combined/alerts/v1":
            body = json.loads(req.content)
            assert body["filter"].startswith("product:'epp'")
            return httpx.Response(200, json={"resources": [
                {"composite_id": "cid:ind:aid:1", "severity_name": "High", "status": "new",
                 "display_name": "Suspicious persistence", "description": "Registry run key",
                 "tactic": "Persistence", "technique": "Run keys",
                 "created_timestamp": "2026-10-12T18:00:00Z",
                 "device": {"hostname": "DC01", "device_id": "d1"},
                 "falcon_host_link": "https://falcon.crowdstrike.com/x/1"}], "meta": {"pagination": {}}})
        if req.url.path == "/alerts/entities/alerts/v3":
            body = json.loads(req.content)
            assert body["composite_ids"] == ["cid:ind:aid:1"]
            assert {"name": "update_status", "value": "closed"} in body["action_parameters"]
            return httpx.Response(200, json={"meta": {"writes": {"resources_affected": 1}}})
        if req.url.path == "/devices/entities/devices-actions/v2":
            assert req.url.params["action_name"] in ("contain", "lift_containment")
            assert json.loads(req.content) == {"ids": ["d1"]}
            return httpx.Response(202, json={"resources": []})
        return httpx.Response(404)
    return handler


def test_crowdstrike_child_token_cached_and_devices_normalize():
    calls: list = []
    cs = CrowdStrike(transport=httpx.MockTransport(_cs_handler(calls)))
    devs = cs.devices("AABBCCDD-11")
    assert devs[0]["status"] == "isolated" and devs[0]["platform"] == "Windows Server 2019"
    cs.devices("AABBCCDD-11")
    assert sum(1 for _, p in calls if p == "/oauth2/token") == 1  # token cached per child


def test_crowdstrike_alerts_update_and_containment():
    cs = CrowdStrike(transport=httpx.MockTransport(_cs_handler([])))
    a = cs.alerts("AABBCCDD-11")[0]
    assert a["severity"] == "high" and a["external_id"] == "cid:ind:aid:1"
    assert a["link"] == "https://falcon.crowdstrike.com/x/1" and a["device_external_id"] == "d1"
    assert cs.update_alert("AABBCCDD-11", ["cid:ind:aid:1"], "closed", "triaged") == 1
    cs.contain("AABBCCDD-11", ["d1"])
    with pytest.raises(ConnectorError, match="no target ids"):
        cs.contain("AABBCCDD-11", [])
    with pytest.raises(ConnectorError, match="unknown alert status"):
        cs.update_alert("AABBCCDD-11", ["x"], "wontfix")


# ---------------------------------------------------------------- Huntress
def test_huntress_reads_paginate_and_normalize():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"].startswith("Basic ")
        if req.url.path == "/v1/agents":
            if "page_token" not in str(req.url):
                return httpx.Response(200, json={"agents": [
                    {"id": 5, "hostname": "WS05", "platform": "windows", "os": "Windows 11",
                     "version": "1.2", "last_callback_at": "2026-10-12T22:00:00Z",
                     "firewall_status": "Isolated", "edr_version": "3.0"}],
                    "pagination": {"next_page_url": "https://api.huntress.io/v1/agents?page_token=abc"}})
            return httpx.Response(200, json={"agents": [
                {"id": 6, "hostname": "WS06", "platform": "windows", "last_callback_at": None}],
                "pagination": {}})
        assert req.url.params["organization_id"] == "42"
        return httpx.Response(200, json={"incident_reports": [
            {"id": 31, "organization_id": 42, "agent_id": 5, "status": "sent", "severity": "critical",
             "subject": "Active threat isolated on WS05", "summary": "SOC analyst summary here.",
             "sent_at": "2026-10-12T21:00:00Z",
             "remediations": {"total_count": 1, "items": [
                 {"id": 1, "type": "assisted", "action": "Delete file", "status": "unapproved"}]}}],
            "pagination": {}})

    h = Huntress(transport=httpx.MockTransport(handler))
    devs = h.devices("42")
    assert [d["status"] for d in devs] == ["isolated", "offline"]
    ir = h.alerts("42")[0]
    assert ir["severity"] == "critical" and ir["kind"] == "incident" and not ir["resolved"]
    assert ir["raw"]["remediations"][0]["status"] == "unapproved"


def test_huntress_writes_hit_documented_paths_and_409_reads_well():
    hits = []

    def handler(req: httpx.Request) -> httpx.Response:
        hits.append((req.method, req.url.path))
        if req.url.path.endswith("/bulk_rejection"):
            assert json.loads(req.content)["comment"]
            return httpx.Response(201, json={})
        if req.url.path.endswith("/resolution") and req.method == "POST":
            return httpx.Response(409)
        return httpx.Response(201, json={})

    h = Huntress(transport=httpx.MockTransport(handler))
    h.approve_remediations("31")
    h.reject_remediations("31", "not applicable")
    h.isolate("5", "containment during investigation")
    h.release("5")
    with pytest.raises(ConnectorError, match="current state"):
        h.resolve_report("31")
    assert ("POST", "/v1/incident_reports/31/remediations/bulk_approval") in hits
    assert ("POST", "/v1/agents/5/isolation") in hits
    assert ("DELETE", "/v1/agents/5/isolation") in hits


# ---------------------------------------------------------------- Acronis
def _acronis_handler(seen):
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        if req.url.path == "/api/2/idp/token":
            assert req.headers["authorization"].startswith("Basic ")
            assert b"grant_type=client_credentials" in req.content
            return httpx.Response(200, json={"access_token": "atok", "expires_in": 7200, "token_type": "bearer"})
        assert req.headers["authorization"] == "Bearer atok"
        if req.url.path == "/api/alert_manager/v1/alerts":
            assert req.url.params["tenant"] == "ten-1"
            return httpx.Response(200, json={"items": [
                {"id": "al-1", "type": "BackupFailed", "category": "Backup", "severity": "error",
                 "createdAt": "2026-10-12T03:00:00Z",
                 "details": {"title": "Backup failed", "description": "Destination unreachable",
                             "resourceName": "SQL01", "resourceId": "res-9"}}],
                "paging": {"cursors": {}}})
        if req.url.path == "/api/resource_management/v4/resource_statuses":
            return httpx.Response(200, json={"items": [
                {"context": {"id": "res-9", "name": "SQL01", "type": "resource.machine"},
                 "aggregate": {"status": "error"},
                 "policies": [{"type": "policy.backup.machine",
                               "last_success_run_time": "2026-10-01T02:00:00Z"}]}],
                "paging": {"cursors": {}}})
        if req.url.path == "/api/policy_management/v4/applications":
            return httpx.Response(200, json={"items": [
                {"policy": {"id": "child", "type": "policy.backup.machine", "parent_ids": ["plan-7"]}}]})
        if req.url.path == "/api/policy_management/v4/applications/run":
            body = json.loads(req.content)
            assert body == {"state": "running", "policy_id": "plan-7", "context_ids": ["res-9"]}
            return httpx.Response(202)
        if req.method == "DELETE" and "/alerts/" in req.url.path:
            return httpx.Response(204)
        return httpx.Response(404)
    return handler


def test_acronis_alerts_devices_and_run_backup():
    seen: list = []
    ac = Acronis(transport=httpx.MockTransport(_acronis_handler(seen)))
    alerts = ac.alerts("ten-1")
    assert alerts[0]["severity"] == "high" and alerts[0]["kind"] == "backup"
    assert alerts[0]["raw"]["resourceId"] == "res-9"
    devs = ac.devices("ten-1")
    assert devs[0]["hostname"] == "SQL01" and devs[0]["status"] == "offline"  # backups stale
    assert ac.run_backup_for_resource("res-9") == "plan-7"
    ac.dismiss_alert("al-1")
    assert sum(1 for _, p in seen if p == "/api/2/idp/token") == 1  # token cached
    with pytest.raises(ConnectorError, match="refusing to dismiss"):
        ac.dismiss_alert("")
