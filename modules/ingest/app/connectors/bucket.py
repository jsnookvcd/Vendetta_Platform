"""Bucket door: vendor files dropped in S3, announced on SQS.

CloudTrail, CrowdStrike Falcon Data Replicator and GuardDuty exports land as objects
in a bucket. S3 event notifications (directly, through SNS, or through EventBridge)
go to an SQS queue; BucketReader receives them, fetches each new object, splits it
into one record per vendor event with split_object(), and hands the records to a
sink callback that ingests them for the connector the object's bucket and prefix
route to.

Rules:

- Only buckets on the allowlist passed to the reader are ever read. A notification
  for any other bucket is left on the queue, so it reaches the dead letter queue and
  an operator sees it.
- A message is deleted only after the sink accepted every object it names. A crash
  or a sink error leaves the message to be delivered again; the pipeline drops the
  duplicate records by vendor id.
- Every record handed on is a JSON object. Anything else in a file (a bare number, a
  string, a line that is not JSON) is skipped and counted.
- boto3 is imported only by BucketReader.from_boto3(), so the module imports without
  it and the reader is tested with fake clients.
"""
from __future__ import annotations

import gzip
import io
import json
import logging
import urllib.parse
from typing import Callable, Iterable

log = logging.getLogger(__name__)

MAX_OBJECT_BYTES = 512 * 1024 * 1024  # decompressed; a CloudTrail or FDR file is far smaller


class BucketError(Exception):
    """An object could not be read or split. Carries no object content."""


class Records(list):
    """The records split out of one object, plus how many entries were skipped."""

    def __init__(self, items=(), skipped: int = 0):
        super().__init__(items)
        self.skipped = skipped


def _gunzip(body: bytes) -> bytes:
    out = io.BytesIO()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            while True:
                chunk = gz.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                if out.tell() > MAX_OBJECT_BYTES:
                    raise BucketError("object is larger than the decompressed size limit")
    except (OSError, EOFError) as e:
        raise BucketError(f"object is not valid gzip ({type(e).__name__})") from None
    return out.getvalue()


def split_object(key: str, body: bytes) -> Records:
    """Split one bucket object into JSON object records.

    Handles gzip (by .gz suffix or magic bytes), CloudTrail files ({"Records": [...]}),
    JSON arrays, a single JSON object, and JSON lines (FDR, GuardDuty exports). The
    result is a list of dicts with a `skipped` count of entries that were not JSON
    objects. CloudTrail digest files are not events and split to nothing."""
    if "/CloudTrail-Digest/" in key or key.endswith("ConfigWritabilityCheckFile"):
        return Records()
    if key.endswith(".gz") or body[:2] == b"\x1f\x8b":
        body = _gunzip(body)
    if len(body) > MAX_OBJECT_BYTES:
        raise BucketError("object is larger than the size limit")
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise BucketError("object is not UTF-8 text") from None
    stripped = text.strip()
    if not stripped:
        return Records()
    whole = None
    if stripped[0] in "[{":
        try:
            whole = json.loads(stripped)
        except ValueError:
            whole = None  # not one JSON document: read it as JSON lines below
    if isinstance(whole, dict):
        if isinstance(whole.get("Records"), list):
            return _keep(whole["Records"])
        return Records([whole])
    if isinstance(whole, list):
        return _keep(whole)
    items, skipped = [], 0
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if isinstance(v, dict):
            items.append(v)
        else:
            skipped += 1
    return Records(items, skipped)


def _keep(values: list) -> Records:
    items = [v for v in values if isinstance(v, dict)]
    return Records(items, len(values) - len(items))


# ---------------------------------------------------------------- notifications
def object_refs(message_body: str) -> tuple[list[tuple[str, str]], bool]:
    """(bucket, key) pairs of created objects in one SQS message body, and whether the
    body was understood. Unwraps SNS. Reads S3 event notifications and EventBridge
    "Object Created" events. An s3:TestEvent is understood and names no objects."""
    try:
        doc = json.loads(message_body)
    except (TypeError, ValueError):
        return [], False
    if isinstance(doc, dict) and doc.get("Type") == "Notification" and isinstance(doc.get("Message"), str):
        try:
            doc = json.loads(doc["Message"])
        except ValueError:
            return [], False
    if not isinstance(doc, dict):
        return [], False
    if doc.get("Event") == "s3:TestEvent":
        return [], True
    if doc.get("source") == "aws.s3" and isinstance(doc.get("detail"), dict):
        d = doc["detail"]
        if doc.get("detail-type") != "Object Created":
            return [], True
        b, k = (d.get("bucket") or {}).get("name"), (d.get("object") or {}).get("key")
        return ([(str(b), str(k))] if b and k else []), bool(b and k)
    recs = doc.get("Records")
    if not isinstance(recs, list):
        return [], False
    out = []
    for rec in recs:
        if not isinstance(rec, dict) or not str(rec.get("eventName") or "").startswith("ObjectCreated"):
            continue
        s3 = rec.get("s3") or {}
        b, k = (s3.get("bucket") or {}).get("name"), (s3.get("object") or {}).get("key")
        if not b or not k:
            return [], False
        # S3 event notifications URL-encode the key, with "+" for spaces.
        out.append((str(b), urllib.parse.unquote_plus(str(k))))
    return out, True


Sink = Callable[[str, list], object]


class BucketReader:
    """Receive S3 notifications from SQS, read allowlisted objects, call the sink.

    routes maps "bucket" or "bucket/prefix" to the route key the sink receives (the
    connector id or source the records belong to). The longest matching prefix wins.
    An object with no route is treated like a refused bucket: nothing is read and the
    message stays on the queue."""

    def __init__(self, sqs, s3, queue_url: str, allowed_buckets: Iterable[str], sink: Sink,
                 routes: dict[str, str] | None = None, default_route: str | None = None,
                 max_messages: int = 10, wait_seconds: int = 10):
        self.sqs, self.s3 = sqs, s3
        self.queue_url = queue_url
        self.allowed = {b.strip() for b in allowed_buckets if b and b.strip()}
        self.sink = sink
        self.routes = dict(routes or {})
        self.default_route = default_route
        self.max_messages = max(1, min(10, int(max_messages)))
        self.wait_seconds = max(0, min(20, int(wait_seconds)))

    @classmethod
    def from_boto3(cls, queue_url: str, allowed_buckets: Iterable[str], sink: Sink, region: str | None = None,
                   **kw) -> "BucketReader":
        import boto3  # imported here so the module never needs boto3 at import time

        session = boto3.session.Session(region_name=region)
        return cls(session.client("sqs"), session.client("s3"), queue_url, allowed_buckets, sink, **kw)

    def route_for(self, bucket: str, key: str) -> str | None:
        best, best_len = None, -1
        for pattern, route in self.routes.items():
            b, _, prefix = pattern.partition("/")
            if b == bucket and key.startswith(prefix) and len(prefix) > best_len:
                best, best_len = route, len(prefix)
        return best if best is not None else self.default_route

    def poll_once(self) -> dict:
        """Receive one batch of messages and process each. Returns counts."""
        resp = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=self.max_messages,
                                        WaitTimeSeconds=self.wait_seconds)
        counts = {"messages": 0, "deleted": 0, "kept": 0, "objects": 0, "records": 0, "skipped": 0, "refused": 0,
                  "errors": 0}
        for msg in resp.get("Messages") or []:
            counts["messages"] += 1
            if self.handle(msg, counts):
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=msg["ReceiptHandle"])
                counts["deleted"] += 1
            else:
                counts["kept"] += 1
        return counts

    def handle(self, msg: dict, counts: dict) -> bool:
        """Process one message; True when it may be deleted."""
        refs, understood = object_refs(msg.get("Body") or "")
        if not understood:
            counts["errors"] += 1
            log.warning("bucket door: message %s is not an S3 notification", msg.get("MessageId"))
            return False
        plan = []
        for bucket, key in refs:
            route = self.route_for(bucket, key) if bucket in self.allowed else None
            if route is None:
                counts["refused"] += 1
                log.warning("bucket door: refused object in bucket %s (not allowlisted or no route)", bucket)
                return False
            plan.append((bucket, key, route))
        for bucket, key, route in plan:
            try:
                obj = self.s3.get_object(Bucket=bucket, Key=key)
                body = obj["Body"].read()
                records = split_object(key, body)
            except BucketError as e:
                counts["errors"] += 1
                log.warning("bucket door: %s/%s: %s", bucket, key, e)
                return False
            except Exception as e:  # noqa: BLE001 - an S3 client error must not stop the reader
                counts["errors"] += 1
                log.warning("bucket door: reading %s/%s failed (%s)", bucket, key, type(e).__name__)
                return False
            counts["objects"] += 1
            counts["skipped"] += records.skipped
            if records:
                try:
                    self.sink(route, list(records))
                except Exception as e:  # noqa: BLE001 - keep the message for redelivery
                    counts["errors"] += 1
                    log.warning("bucket door: sink failed for %s/%s (%s)", bucket, key, type(e).__name__)
                    return False
                counts["records"] += len(records)
        return True
