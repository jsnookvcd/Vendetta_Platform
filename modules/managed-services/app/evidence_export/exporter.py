"""Build a court-admissible, self-verifying evidence export package.

A package is a single zip that seals a subject's signed chain of custody so it can be
handed to a client, an auditor or opposing counsel and verified by them with no access
to the Vendetta Platform. It carries:

  MANIFEST.json       metadata plus the sha256 of every other file in the package
  MANIFEST.sig        an Ed25519 signature over sha256(MANIFEST.json) by the platform
                      signing key (the same key that signed the chain), sealing the set
  proof.json          the chain: every record with its immutable fields, prev_hash,
                      content_hash and signature, plus a self-check run at export time
  public_key.txt      the signing key's public half (hex), so the seal and chain verify
  verify_evidence.py  a standalone verifier that reproduces every check offline
  README.txt          what the package is and how to verify it by hand
  timestamp.tsr       (optional) an RFC 3161 token anchoring the manifest hash to a
  timestamp.json      (optional) third-party time authority, with its metadata

Because the manifest records the hash of proof.json and is itself signed, and because
proof.json's records are a hash chain each committing to the one before it, changing
any record, file or the manifest is detectable. WORM (write-once) storage, such as S3
Object Lock, is applied at rest in production; the manifest signature makes tampering
detectable wherever the package travels afterward.

This builder is platform-independent: it takes the records (as client_event_records
produces them), a signer callable, and the public key. Each module wires its own
one-click export route to it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Callable

from . import verifier

SCHEME = "ed25519-sha256-v1"
_VERIFIER_FILE = Path(__file__).resolve().parent.parent / "verify_evidence.py"


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _canonical_manifest(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), default=str,
                      ensure_ascii=False).encode("utf-8")


def _readme(product: str, document: str, subject_name: str, scheme: str) -> str:
    return f"""VENDETTA CYBER DEFENSE — EVIDENCE EXPORT PACKAGE

Subject:   {subject_name}
Source:    {product}
Contents:  {document} chain of custody
Scheme:    {scheme}

WHAT THIS IS
This package is a sealed, self-contained copy of a cryptographic chain of custody.
Each record in proof.json is bound to the record before it by a SHA-256 hash, and
each record is signed with Vendetta's Ed25519 signing key. Because every hash commits
to the one before it, inserting, removing, reordering or editing any record breaks the
chain, and the signatures prove the records were produced by the holder of the key.

HOW TO VERIFY IT YOURSELF
You do not need the Vendetta Platform or any network connection.

  1. Install Python 3.9+ and the 'cryptography' package:
         pip install cryptography
     (optional, to also check the RFC 3161 timestamp:  pip install asn1crypto)

  2. Run the bundled verifier against this package:
         python verify_evidence.py <this package .zip or folder>

  It prints PASS or FAIL for each check: the package seal, the integrity of every
  file, the chain of custody, that the manifest and chain share one signing key, and
  the trusted timestamp if one is present. Exit code 0 means the package verified.

WHAT EACH CHECK MEANS
  Package seal       MANIFEST.sig is a valid signature, by the published key, over
                     sha256(MANIFEST.json). Editing the manifest breaks it.
  File integrity     Every file listed in MANIFEST.json hashes to the recorded sha256.
  Chain of custody   The records in proof.json form an unbroken signed hash chain.
  Same signing key   The key that sealed the manifest also signed the chain.
  Trusted timestamp  If present, an RFC 3161 token fixes sha256(MANIFEST.json) to an
                     independent time authority.

The verifier is plain, auditable Python; the exact bytes that are hashed for each
record are described in its source so the check can be reproduced by hand.
"""


def build_package(
    *,
    records: list[dict],
    subject: dict,
    product: str,
    document: str,
    signer: Callable[[bytes], str],
    public_key_hex: str,
    key_id: str,
    scheme: str = SCHEME,
    tsa_url: str = "",
    generated_at: str | None = None,
) -> bytes:
    """Return the bytes of a sealed evidence export zip.

    records           list of {fields, prev_hash, content_hash, signature}, in order
                      (exactly what client_event_records returns)
    subject           {"id", "name", ...} the chain belongs to
    product           the originating module, e.g. "Vendetta Office of Special Projects"
    document          short description of what the chain records, e.g. "deliverable sign-off"
    signer            signs raw bytes with the platform key, returns a hex signature
    public_key_hex    the signing key's public half (hex)
    key_id            short fingerprint of the signing key
    tsa_url           optional RFC 3161 Time-Stamp Authority URL; omitted on failure
    """
    generated_at = generated_at or _utcnow_iso()

    # The self-check embedded in the proof, run now, so the export states its own result.
    self_check = verifier.verify_chain(records, public_key_hex, scheme)
    proof = {
        "document": f"Vendetta Cyber Defense {document} proof",
        "product": product,
        "scheme": scheme,
        "generated_at": generated_at,
        "key_id": key_id,
        "public_key": public_key_hex,
        "subject": subject,
        "record_count": len(records),
        "verification": self_check,
        "records": records,
    }
    proof_bytes = json.dumps(proof, indent=2, default=str, ensure_ascii=False).encode("utf-8")
    pubkey_bytes = (public_key_hex + "\n").encode("utf-8")
    verifier_bytes = _VERIFIER_FILE.read_bytes()
    readme_bytes = _readme(product, document, subject.get("name", "(unknown)"), scheme).encode("utf-8")

    content_files = {
        "proof.json": proof_bytes,
        "public_key.txt": pubkey_bytes,
        "verify_evidence.py": verifier_bytes,
        "README.txt": readme_bytes,
    }

    manifest = {
        "format": "vendetta-evidence-package-v1",
        "product": product,
        "document": document,
        "scheme": scheme,
        "generated_at": generated_at,
        "key_id": key_id,
        "public_key": public_key_hex,
        "subject": subject,
        "record_count": len(records),
        "chain_verified_at_export": bool(self_check.get("ok")),
        "files": {name: {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}
                  for name, b in content_files.items()},
    }
    manifest_bytes = _canonical_manifest(manifest)
    manifest_digest = hashlib.sha256(manifest_bytes)
    manifest_sig = signer(manifest_digest.digest())

    # Optional trusted timestamp over sha256(MANIFEST.json).
    ts_files: dict[str, bytes] = {}
    if tsa_url:
        from . import tsa
        token, meta = tsa.timestamp(manifest_digest.digest(), tsa_url)
        if token:
            ts_files["timestamp.tsr"] = token
            ts_files["timestamp.json"] = json.dumps(meta, indent=2, default=str).encode("utf-8")

    stamp = generated_at[:10]
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in subject.get("name", "subject"))[:40]
    root = f"vendetta-evidence-{safe}-{stamp}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{root}/MANIFEST.json", manifest_bytes)
        z.writestr(f"{root}/MANIFEST.sig", manifest_sig + "\n")
        for name, b in content_files.items():
            z.writestr(f"{root}/{name}", b)
        for name, b in ts_files.items():
            z.writestr(f"{root}/{name}", b)
    return buf.getvalue()
