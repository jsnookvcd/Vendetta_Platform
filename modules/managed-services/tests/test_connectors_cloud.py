"""Identity (Entra / Microsoft 365) and cloud (AWS GuardDuty) connectors: the request
shapes and the normalization into the shared Alert shape the sync engine consumes."""
import json

import httpx

from app.connectors import ConnectorError
from app.connectors.aws import AWS, _severity
from app.connectors.entra import Entra


# ---------------------------------------------------------------- Entra / M365
def test_entra_fetches_token_per_tenant_and_normalizes_risk():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/oauth2/v2.0/token"):
            seen["tenant"] = req.url.path.split("/")[1]
            seen["scope"] = dict(x.split("=") for x in req.content.decode().split("&")).get("scope")
            return httpx.Response(200, json={"access_token": "graph-tok", "expires_in": 3599})
        seen["auth"] = req.headers.get("authorization")
        seen["path"] = req.url.path
        return httpx.Response(200, json={"value": [
            {"id": "rd1", "riskEventType": "unfamiliarFeatures", "riskLevel": "high",
             "riskState": "atRisk", "userPrincipalName": "cfo@acme.com", "ipAddress": "5.6.7.8",
             "location": {"city": "Minsk", "countryOrRegion": "BY"},
             "detectedDateTime": "2026-10-15T12:00:00Z"},
            {"id": "rd2", "riskEventType": "leakedCredentials", "riskLevel": "medium",
             "riskState": "confirmedCompromised", "userPrincipalName": "it@acme.com",
             "detectedDateTime": "2026-10-15T13:00:00Z"},
        ]})

    e = Entra(transport=httpx.MockTransport(handler))
    alerts = e.alerts("tenant-acme-123")
    assert seen["tenant"] == "tenant-acme-123"
    assert seen["scope"] == "https%3A%2F%2Fgraph.microsoft.com%2F.default" or "graph.microsoft.com" in seen["scope"]
    assert seen["auth"] == "Bearer graph-tok"
    assert "identityProtection/riskDetections" in seen["path"]
    assert alerts[0]["kind"] == "identity" and alerts[0]["severity"] == "high"
    assert "cfo@acme.com" in alerts[0]["title"] and alerts[0]["occurred_at"].year == 2026
    # confirmedCompromised escalates to critical regardless of riskLevel
    assert alerts[1]["severity"] == "critical"
    assert e.devices("tenant-acme-123") == []


def test_entra_token_failure_raises_connector_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client",
                                         "error_description": "bad secret"})

    e = Entra(transport=httpx.MockTransport(handler))
    try:
        e.alerts("tenant-x")
        assert False, "expected ConnectorError"
    except ConnectorError as err:
        assert "token request failed" in str(err)


# ---------------------------------------------------------------- AWS GuardDuty
class _FakeGuardDuty:
    """A minimal stand-in for a boto3 guardduty client."""

    def __init__(self, findings):
        self._findings = findings
        self.calls = []

    def list_detectors(self):
        return {"DetectorIds": ["det-1"]}

    def list_findings(self, DetectorId, FindingCriteria=None):  # noqa: N803
        self.calls.append(("list_findings", DetectorId, FindingCriteria))
        return {"FindingIds": [f["Id"] for f in self._findings]}

    def get_findings(self, DetectorId, FindingIds):  # noqa: N803
        return {"Findings": [f for f in self._findings if f["Id"] in FindingIds]}


def test_aws_guardduty_normalizes_findings():
    findings = [
        {"Id": "f1", "Type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "Severity": 8.0,
         "Region": "us-east-1", "Title": "API called from a malicious IP",
         "Resource": {"ResourceType": "AccessKey"}, "Service": {"Count": 3, "Archived": False},
         "UpdatedAt": "2026-10-15T09:00:00Z"},
        {"Id": "f2", "Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 2.0,
         "Region": "us-east-1", "Title": "Unprotected port probed",
         "Resource": {"ResourceType": "Instance"}, "Service": {"Count": 1, "Archived": True},
         "UpdatedAt": "2026-10-15T10:00:00Z"},
    ]
    aws = AWS(guardduty=_FakeGuardDuty(findings))
    alerts = aws.alerts("arn:aws:iam::123456789012:role/VendettaReadOnly")
    assert len(alerts) == 2
    assert alerts[0]["kind"] == "cloud" and alerts[0]["severity"] == "critical"
    assert "MaliciousIPCaller" in alerts[0]["title"] and alerts[0]["occurred_at"].year == 2026
    assert alerts[1]["severity"] == "low" and alerts[1]["resolved"] is True
    assert aws.devices("arn:...") == []


def test_aws_severity_mapping():
    assert _severity(9.1) == "critical"
    assert _severity(7.5) == "high"
    assert _severity(5.0) == "medium"
    assert _severity(1.0) == "low"
    assert _severity(None) == "medium"


def test_aws_no_role_raises():
    aws = AWS()  # no injected client, no role arn
    try:
        aws.alerts("")
        assert False, "expected ConnectorError"
    except ConnectorError as err:
        assert "role" in str(err).lower()
