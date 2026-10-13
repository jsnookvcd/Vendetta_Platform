"""Evidence preservation. Every capture is stored as raw bytes plus a JSON manifest
with SHA-256, timestamp, URL, HTTP status and response headers. S3 Object Lock in
compliance mode (see Terraform) keeps the objects immutable for the retention period."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .db import Evidence, utcnow
from .fetch import FetchResult, fetch, html_to_text

log = logging.getLogger(__name__)


def _s3():
    import boto3

    return boto3.client("s3", region_name=settings.aws_region)


def _store(key: str, data: bytes, content_type: str) -> str:
    if settings.evidence_bucket:
        _s3().put_object(
            Bucket=settings.evidence_bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            ChecksumAlgorithm="SHA256",
        )
        return f"s3://{settings.evidence_bucket}/{key}"
    path = Path(settings.evidence_local_dir) / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return f"file://{path}"


def preserve(
    db: Session,
    url: str,
    client_id: str | None = None,
    item_id: str | None = None,
    captured_by: str = "system",
    note: str = "",
    result: FetchResult | None = None,
) -> Evidence:
    """Fetch (or reuse a fetch) and preserve the response with hashes."""
    res = result or fetch(url)
    ts = utcnow()
    sha = hashlib.sha256(res.content).hexdigest()
    stamp = ts.strftime("%Y/%m/%d/%H%M%S")
    base = f"captures/{client_id or 'unassigned'}/{stamp}-{sha[:12]}"
    ctype = res.headers.get("content-type", "application/octet-stream").split(";")[0]
    raw_uri = _store(f"{base}/response.bin", res.content, ctype)
    manifest = {
        "url": url,
        "final_url": res.url,
        "captured_at": ts.isoformat(),
        "captured_by": captured_by,
        "http_status": res.status,
        "sha256": sha,
        "size_bytes": len(res.content),
        "headers": res.headers,
        "error": res.error,
        "note": note,
        "tool": settings.app_name,
    }
    _store(f"{base}/manifest.json", json.dumps(manifest, indent=2).encode(), "application/json")
    excerpt = html_to_text(res.text)[:4000] if res.text else ""
    ev = Evidence(
        client_id=client_id,
        item_id=item_id,
        url=url,
        captured_at=ts,
        captured_by=captured_by,
        http_status=res.status,
        sha256=sha,
        size_bytes=len(res.content),
        storage_uri=raw_uri,
        text_excerpt=excerpt,
        note=note,
        headers=res.headers,
    )
    db.add(ev)
    db.commit()
    log.info("preserved %s sha256=%s -> %s", url, sha[:12], raw_uri)
    return ev


def read_evidence_bytes(ev: Evidence) -> bytes:
    if ev.storage_uri.startswith("s3://"):
        _, _, rest = ev.storage_uri.partition("s3://")
        bucket, _, key = rest.partition("/")
        return _s3().get_object(Bucket=bucket, Key=key)["Body"].read()
    return Path(ev.storage_uri.removeprefix("file://")).read_bytes()


def verify(ev: Evidence) -> bool:
    return hashlib.sha256(read_evidence_bytes(ev)).hexdigest() == ev.sha256
