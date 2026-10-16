"""Amazon Web Services cloud-signal connector.

Pulls Amazon GuardDuty findings and normalizes them into the shared Alert shape, so a
cloud detection (compromised credentials, crypto-mining, data exfiltration signals) lands
in the managed-services console and portal alongside endpoint and identity alerts.

MSP base credentials assume each client's cross-account IAM role; the client's role ARN
is its per-client ref, guarded by an external id. GuardDuty is pulled for the configured
region. Read-only: this connector only reads findings, it takes no action in a client
account.

boto3 is used for signing and STS. For tests, inject `guardduty` (and optionally `sts`)
clients so no network or real credentials are needed."""
from __future__ import annotations

import logging

from .. import creds
from .base import ConnectorError, parse_dt

log = logging.getLogger(__name__)


def _severity(score) -> str:
    """GuardDuty numeric severity (1..10) to the shared scale."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 8.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


class AWS:
    tool = "aws"

    def __init__(self, guardduty=None, sts=None):
        self.cfg = creds.resolve("aws")
        self.configured = creds.configured("aws")
        self.region = self.cfg.get("region") or "us-east-1"
        self._guardduty = guardduty   # injectable for tests
        self._sts = sts               # injectable for tests

    def _assume(self, role_arn: str):
        """Return a GuardDuty client for the client's account. Uses an injected client
        when provided (tests); otherwise assumes the client's role with boto3."""
        if self._guardduty is not None:
            return self._guardduty
        if not role_arn:
            raise ConnectorError("AWS: no role ARN for this client")
        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise ConnectorError("AWS: boto3 is not installed") from e
        try:
            sts = self._sts or boto3.client(
                "sts",
                aws_access_key_id=self.cfg.get("access_key_id"),
                aws_secret_access_key=self.cfg.get("secret_access_key"),
                region_name=self.region,
            )
            kwargs = {"RoleArn": role_arn, "RoleSessionName": "vendetta-managed-services"}
            if self.cfg.get("external_id"):
                kwargs["ExternalId"] = self.cfg["external_id"]
            c = sts.assume_role(**kwargs)["Credentials"]
            return boto3.client(
                "guardduty",
                aws_access_key_id=c["AccessKeyId"],
                aws_secret_access_key=c["SecretAccessKey"],
                aws_session_token=c["SessionToken"],
                region_name=self.region,
            )
        except ConnectorError:
            raise
        except Exception as e:  # noqa: BLE001  (botocore errors vary)
            raise ConnectorError(f"AWS: could not assume {role_arn}: {type(e).__name__}") from e

    def devices(self, ref: str) -> list[dict]:
        # Cloud findings are not device inventory; the device list stays the EDR/RMM view.
        return []

    def alerts(self, ref: str, since=None) -> list[dict]:
        gd = self._assume(ref)
        try:
            detectors = (gd.list_detectors() or {}).get("DetectorIds") or []
        except Exception as e:  # noqa: BLE001
            raise ConnectorError(f"AWS: GuardDuty list_detectors failed: {type(e).__name__}") from e
        out: list[dict] = []
        for det in detectors:
            criteria = {}
            if since:
                criteria = {"Criterion": {"updatedAt": {"GreaterThanOrEqual": int(since.timestamp() * 1000)}}}
            try:
                ids = (gd.list_findings(DetectorId=det, FindingCriteria=criteria) if criteria
                       else gd.list_findings(DetectorId=det)).get("FindingIds") or []
                if not ids:
                    continue
                findings = (gd.get_findings(DetectorId=det, FindingIds=ids[:50])).get("Findings") or []
            except Exception as e:  # noqa: BLE001
                raise ConnectorError(f"AWS: GuardDuty findings failed: {type(e).__name__}") from e
            for f in findings:
                res = f.get("Resource") or {}
                rtype = res.get("ResourceType") or ""
                svc = f.get("Service") or {}
                out.append({
                    "external_id": str(f.get("Id") or ""),
                    "kind": "cloud",
                    "severity": _severity(f.get("Severity")),
                    "title": f"{f.get('Type') or 'GuardDuty finding'}",
                    "detail": " · ".join(x for x in [
                        f.get("Title") or "", f"resource {rtype}" if rtype else "",
                        f"count {svc.get('Count')}" if svc.get("Count") else "",
                        f.get("Region") or ""] if x)[:8000],
                    "tool_status": "archived" if (svc.get("Archived")) else "active",
                    "occurred_at": parse_dt(f.get("UpdatedAt") or f.get("CreatedAt")),
                    "link": f"https://{self.region}.console.aws.amazon.com/guardduty/home?"
                            f"region={self.region}#/findings",
                    "resolved": bool(svc.get("Archived")),
                    "raw": {k: f.get(k) for k in ("Id", "Type", "Severity", "Region", "Title")},
                })
        return out
