"""RFC 3161 trusted timestamping (optional).

A trusted timestamp anchors sha256(MANIFEST.json) to an independent Time-Stamp
Authority, so the moment the package was sealed is attested by a third party rather
than only by Vendetta's own clock. It is optional: when no TSA is configured, or the
TSA is unreachable, or the asn1crypto library is absent, the package is still fully
sealed and chain-verifiable; it simply carries no third-party time anchor.

Build with a configured TSA_URL in production (for example a commercial or
FreeTSA-style RFC 3161 endpoint). The request and response are standard RFC 3161, so
any compliant authority works.
"""
from __future__ import annotations

import datetime as dt
import logging
import secrets
import urllib.request

log = logging.getLogger(__name__)

_SHA256_OID = "2.16.840.1.101.3.4.2.1"


def timestamp(digest: bytes, tsa_url: str, timeout: float = 15.0) -> tuple[bytes | None, dict]:
    """Request an RFC 3161 token over ``digest`` (a 32-byte sha256) from ``tsa_url``.

    Returns (token_der_or_None, metadata). On any failure it returns (None, meta) with
    a reason, so the caller omits the timestamp rather than failing the export.
    """
    meta = {"tsa_url": tsa_url, "hashed": "sha256(MANIFEST.json)",
            "requested_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        from asn1crypto import tsp
    except ImportError:
        meta["error"] = "asn1crypto not installed; no timestamp requested"
        return None, meta
    try:
        nonce = int.from_bytes(secrets.token_bytes(8), "big")
        req = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": {
                "hash_algorithm": {"algorithm": _SHA256_OID},
                "hashed_message": digest,
            },
            "nonce": nonce,
            "cert_req": True,
        })
        http_req = urllib.request.Request(
            tsa_url, data=req.dump(),
            headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
        # Validate it parses and the imprint matches before trusting it.
        parsed = tsp.TimeStampResp.load(body)
        tst = parsed["time_stamp_token"]
        signed = tst["content"]["encap_content_info"]["content"].parsed
        if signed["message_imprint"]["hashed_message"].native != digest:
            meta["error"] = "TSA returned a token for a different digest"
            return None, meta
        meta["obtained_at"] = str(signed["gen_time"].native)
        meta["serial"] = str(signed["serial_number"].native)
        return body, meta
    except Exception as e:  # noqa: BLE001
        meta["error"] = f"timestamp request failed: {type(e).__name__}: {e}"
        return None, meta
