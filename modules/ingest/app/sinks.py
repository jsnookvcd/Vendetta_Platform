"""Where normalized events go after the hot store.

All sinks are optional and best effort from the pipeline's point of view: the event
is already stored and will be sealed whatever happens here, and a failed publish is
logged and counted, never raised into the connector. With nothing configured (local
development, the test suite) every function is a no-op.

- Kinesis (KINESIS_STREAM): one record per event, partitioned by tenant. Firehose
  reads the stream into the raw archive (partitioned tenant/source/date), the
  streaming detection service and the Security Lake custom-source writer read it too.
  Each record carries tenant_id and source at the top level because Firehose's
  dynamic partitioning and Lake Formation's per-tenant row filters key on them.
- OpenSearch (OPENSEARCH_URL): bulk indexing into one index per tenant and month,
  `<prefix>-<tenant>-events-YYYY.MM`, so document-level security and retention both
  work per tenant.
- Batch headers go to Kinesis too (kind=batch), so the archive holds the signed chain
  next to the events it covers.
"""
from __future__ import annotations

import json
import logging
import threading

from .config import settings

log = logging.getLogger(__name__)

STATS = {"kinesis_records": 0, "kinesis_errors": 0, "opensearch_docs": 0, "opensearch_errors": 0}
_lock = threading.Lock()
_clients: dict = {}


def configured() -> dict:
    return {"kinesis": bool(settings.kinesis_stream), "opensearch": bool(settings.opensearch_url),
            "raw_bucket": bool(settings.raw_bucket), "anchor_bucket": bool(settings.anchor_bucket)}


def _boto(service: str):
    with _lock:
        if service not in _clients:
            import boto3  # imported lazily so the module runs without AWS libraries configured
            _clients[service] = boto3.client(service, region_name=settings.aws_region)
        return _clients[service]


def envelope(row: dict) -> dict:
    return {"kind": "event", "tenant_id": row["tenant"], "source": row["source"], "event_id": row["id"],
            "raw_sha256": row["raw_sha256"], "event_sha256": row["event_sha256"],
            "received_at": row["received_at"].isoformat(), "event": row["event"], "raw": row["raw"]}


def _bump(key: str, n: int) -> None:
    with _lock:
        STATS[key] += n


def publish(rows: list[dict]) -> None:
    if settings.kinesis_stream:
        _kinesis([envelope(r) for r in rows], [r["tenant"] for r in rows])
    if settings.opensearch_url:
        _opensearch(rows)


def publish_batch(record: dict) -> None:
    if settings.kinesis_stream:
        _kinesis([{"kind": "batch", "tenant_id": record["header"]["tenant"], "source": "vendetta-receipts",
                   **record}], [record["header"]["tenant"]])


def _kinesis(docs: list[dict], keys: list[str]) -> None:
    try:
        k = _boto("kinesis")
        for i in range(0, len(docs), 500):  # PutRecords takes at most 500 records
            chunk = docs[i:i + 500]
            resp = k.put_records(StreamName=settings.kinesis_stream, Records=[
                {"Data": (json.dumps(d, separators=(",", ":"), default=str) + "\n").encode(),
                 "PartitionKey": keys[i + j]} for j, d in enumerate(chunk)])
            failed = int(resp.get("FailedRecordCount") or 0)
            _bump("kinesis_records", len(chunk) - failed)
            if failed:
                _bump("kinesis_errors", failed)
                log.warning("kinesis: %d of %d records failed", failed, len(chunk))
    except Exception as e:  # noqa: BLE001
        _bump("kinesis_errors", len(docs))
        log.warning("kinesis publish failed: %s", type(e).__name__)


def index_name(tenant: str, when) -> str:
    safe = "".join(ch for ch in tenant.lower() if ch.isalnum() or ch == "-")[:40] or "unknown"
    return f"{settings.opensearch_index_prefix}-{safe}-events-{when:%Y.%m}"


def _opensearch(rows: list[dict]) -> None:
    lines = []
    for r in rows:
        lines.append(json.dumps({"index": {"_index": index_name(r["tenant"], r["time"]), "_id": r["id"]}}))
        doc = dict(r["event"])
        doc["@timestamp"] = r["time"].isoformat()
        doc["tenant_id"] = r["tenant"]
        doc["vendetta"] = {"event_id": r["id"], "source": r["source"], "raw_sha256": r["raw_sha256"],
                           "event_sha256": r["event_sha256"]}
        lines.append(json.dumps(doc, default=str))
    body = ("\n".join(lines) + "\n").encode()
    try:
        import httpx
        url = settings.opensearch_url.rstrip("/") + "/_bulk"
        headers = {"Content-Type": "application/x-ndjson"}
        auth = _sigv4(url, body, headers)
        with httpx.Client(timeout=30.0) as http:
            resp = http.post(url, content=body, headers={**headers, **auth})
        if resp.status_code >= 300 or resp.json().get("errors"):
            _bump("opensearch_errors", len(rows))
            log.warning("opensearch bulk: HTTP %s", resp.status_code)
        else:
            _bump("opensearch_docs", len(rows))
    except Exception as e:  # noqa: BLE001
        _bump("opensearch_errors", len(rows))
        log.warning("opensearch publish failed: %s", type(e).__name__)


def _sigv4(url: str, body: bytes, headers: dict) -> dict:
    """SigV4 headers for the OpenSearch domain using the task role. Empty when
    botocore is not present (a local OpenSearch without IAM)."""
    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.session import Session as BotoSession
    except ImportError:
        return {}
    creds = BotoSession().get_credentials()
    if creds is None:
        return {}
    req = AWSRequest(method="POST", url=url, data=body, headers=headers)
    SigV4Auth(creds.get_frozen_credentials(), "es", settings.aws_region).add_auth(req)
    return {k: v for k, v in req.headers.items() if k.lower() in ("authorization", "x-amz-date",
                                                                  "x-amz-security-token", "x-amz-content-sha256")}


def put_anchor(key: str, body: bytes) -> str:
    """Write a daily anchor document to the evidence account's Object Lock bucket.
    Returns its s3:// URI, or "" when no bucket is configured or the write failed."""
    if not settings.anchor_bucket:
        return ""
    try:
        _boto("s3").put_object(Bucket=settings.anchor_bucket, Key=key, Body=body,
                               ContentType="application/json", ChecksumAlgorithm="SHA256")
        return f"s3://{settings.anchor_bucket}/{key}"
    except Exception as e:  # noqa: BLE001
        log.warning("anchor write failed: %s", type(e).__name__)
        return ""
