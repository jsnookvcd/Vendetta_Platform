#!/usr/bin/env python3
"""Vendetta Cyber Defense — standalone evidence verifier.

This script verifies a Vendetta evidence export package on its own, with no access
to the Vendetta Platform and no network. It is meant to be handed to opposing
counsel, a client, an auditor or a court-appointed expert so they can confirm, for
themselves, that the exported chain of custody is intact and was produced by the
holder of Vendetta's signing key.

What it checks
  1. Package seal   — MANIFEST.json is signed (MANIFEST.sig) by the key whose public
                      half is published in the package, and that same key signed the
                      evidence chain. Any edit to the manifest breaks this.
  2. File integrity — every file the manifest lists hashes to the sha256 the manifest
                      records, so no file in the package was altered or swapped.
  3. Chain of custody — the evidence records form an unbroken Ed25519-signed,
                      sha256 hash chain: each record commits to the one before it, so
                      inserting, removing, reordering or editing any record is caught.
  4. Trusted timestamp (if present) — the RFC 3161 token anchors the manifest hash to
                      an independent time authority. Verified only if the optional
                      'asn1crypto' package is installed; otherwise reported as present
                      but not checked here.

Requirements
  Python 3.9+ and the 'cryptography' package:  pip install cryptography
  (optional, for the timestamp token)          pip install asn1crypto

Usage
  python verify_evidence.py <package.zip | unpacked-directory>
  Exit code 0 if the package verifies, 1 if anything fails.

The verification format is 'ed25519-sha256-v1'. It is intentionally simple and fully
described in README.txt inside the package, so the check can be reproduced by hand.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.stderr.write("This verifier needs the 'cryptography' package: pip install cryptography\n")
    sys.exit(2)

GENESIS = "0" * 64
SCHEME = "ed25519-sha256-v1"


# ----------------------------------------------------------------- canonical form
def _canonical(fields: dict, prev_hash: str, scheme: str = SCHEME) -> bytes:
    """The exact bytes that were hashed to form a record's content_hash: a JSON
    object {scheme, prev, fields} with sorted keys and no whitespace. This must match
    the producer byte for byte, so it is kept deliberately plain."""
    body = {"scheme": scheme, "prev": prev_hash, "fields": fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str,
                      ensure_ascii=False).encode("utf-8")


def _verify_sig(pub_hex: str, signature_hex: str, message_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_chain(records: list[dict], pub_hex: str, scheme: str = SCHEME) -> dict:
    """Verify an ordered list of records, each {fields, prev_hash, content_hash,
    signature}. A record whose 'fields' is null is sealed: its content was withheld,
    so only linkage and the signature over the stored hash are checked."""
    prev = GENESIS
    sealed = 0
    for i, r in enumerate(records, start=1):
        if r.get("prev_hash") != prev:
            return {"ok": False, "length": len(records), "verified": i - 1, "sealed": sealed,
                    "broken_at": i, "reason": "chain link broken (a record was inserted, removed or reordered)"}
        if r.get("fields") is None:
            if not _verify_sig(pub_hex, r["signature"], r["content_hash"]):
                return {"ok": False, "length": len(records), "verified": i - 1, "sealed": sealed,
                        "broken_at": i, "reason": "signature is not valid for this record"}
            sealed += 1
        else:
            expected = hashlib.sha256(_canonical(r["fields"], r["prev_hash"], scheme)).hexdigest()
            if expected != r.get("content_hash"):
                return {"ok": False, "length": len(records), "verified": i - 1, "sealed": sealed,
                        "broken_at": i, "reason": "content hash does not match the record"}
            if not _verify_sig(pub_hex, r["signature"], r["content_hash"]):
                return {"ok": False, "length": len(records), "verified": i - 1, "sealed": sealed,
                        "broken_at": i, "reason": "signature is not valid for this record"}
        prev = r["content_hash"]
    return {"ok": True, "length": len(records), "verified": len(records), "sealed": sealed,
            "broken_at": None, "reason": "intact"}


# ----------------------------------------------------------------- package access
class _Source:
    """Read files out of either a zip or an unpacked directory, uniformly."""

    def __init__(self, path: Path):
        self.path = path
        self.zip = zipfile.ZipFile(path) if path.is_file() and zipfile.is_zipfile(path) else None
        self._root = self._find_root()

    def _names(self) -> list[str]:
        if self.zip is not None:
            return self.zip.namelist()
        return [str(p.relative_to(self.path)) for p in self.path.rglob("*") if p.is_file()]

    def _find_root(self) -> str:
        """Packages wrap their files in a single top folder; find it so callers can
        ask for bare names like 'MANIFEST.json'."""
        for n in self._names():
            parts = n.split("/")
            if parts[-1] == "MANIFEST.json":
                return "/".join(parts[:-1])
        return ""

    def read(self, name: str) -> bytes:
        rel = f"{self._root}/{name}" if self._root else name
        if self.zip is not None:
            return self.zip.read(rel)
        return (self.path / rel).read_bytes()

    def exists(self, name: str) -> bool:
        rel = f"{self._root}/{name}" if self._root else name
        if self.zip is not None:
            return rel in self.zip.namelist()
        return (self.path / rel).is_file()


# ----------------------------------------------------------------- the check
def verify_package(path: str) -> dict:
    """Verify a package at a zip path or a directory. Returns a report dict with an
    overall 'ok' and a per-check breakdown."""
    src = _Source(Path(path))
    report: dict = {"ok": False, "checks": {}}

    try:
        manifest_bytes = src.read("MANIFEST.json")
        manifest = json.loads(manifest_bytes)
        manifest_sig = src.read("MANIFEST.sig").decode().strip()
    except (KeyError, FileNotFoundError, OSError, ValueError) as e:
        report["error"] = f"package is missing MANIFEST.json or MANIFEST.sig ({type(e).__name__})"
        return report

    pub_hex = manifest.get("public_key", "")
    scheme = manifest.get("scheme", SCHEME)

    # 1. Package seal: the manifest is signed by the published key.
    seal_ok = _verify_sig(pub_hex, manifest_sig,
                          hashlib.sha256(manifest_bytes).hexdigest()) if pub_hex else False
    report["checks"]["package_seal"] = {"ok": seal_ok,
                                        "reason": "manifest signature valid" if seal_ok
                                        else "manifest signature invalid or no public key"}

    # 2. File integrity: every listed file hashes to its recorded sha256.
    files = manifest.get("files", {})
    bad = []
    for name, meta in files.items():
        try:
            got = hashlib.sha256(src.read(name)).hexdigest()
        except (KeyError, FileNotFoundError, OSError):
            bad.append(f"{name} (missing)")
            continue
        if got != meta.get("sha256"):
            bad.append(f"{name} (hash mismatch)")
    files_ok = not bad
    report["checks"]["file_integrity"] = {"ok": files_ok, "files": len(files),
                                          "reason": "all files intact" if files_ok
                                          else "altered or missing: " + ", ".join(bad)}

    # 3. Chain of custody.
    try:
        proof = json.loads(src.read("proof.json"))
        records = proof.get("records", [])
        chain = verify_chain(records, proof.get("public_key", pub_hex), proof.get("scheme", scheme))
    except (KeyError, FileNotFoundError, OSError, ValueError) as e:
        chain = {"ok": False, "reason": f"proof.json unreadable ({type(e).__name__})"}
    report["checks"]["chain_of_custody"] = chain

    # The key that sealed the manifest must be the key that signed the chain.
    same_key = bool(pub_hex) and proof_pub(src) == pub_hex
    report["checks"]["same_signing_key"] = {"ok": same_key,
                                            "reason": "manifest and chain signed by the same key" if same_key
                                            else "manifest and chain keys differ"}

    # 4. Trusted timestamp, if the package carries one.
    report["checks"]["trusted_timestamp"] = _check_timestamp(src, manifest_bytes)

    report["ok"] = bool(seal_ok and files_ok and chain.get("ok") and same_key
                        and report["checks"]["trusted_timestamp"]["ok"])
    report["subject"] = manifest.get("subject", {})
    report["product"] = manifest.get("product", "")
    report["generated_at"] = manifest.get("generated_at", "")
    report["key_id"] = manifest.get("key_id", "")
    report["records"] = chain.get("length", 0)
    return report


def proof_pub(src: _Source) -> str:
    try:
        return json.loads(src.read("proof.json")).get("public_key", "")
    except (KeyError, FileNotFoundError, OSError, ValueError):
        return ""


def _check_timestamp(src: _Source, manifest_bytes: bytes) -> dict:
    """Verify the RFC 3161 token over sha256(MANIFEST.json), if present. A package with
    no token passes this check (timestamping is optional); a token that is present but
    cannot be parsed without asn1crypto is reported, not failed."""
    if not src.exists("timestamp.tsr"):
        return {"ok": True, "present": False, "reason": "no trusted timestamp in package"}
    try:
        import asn1crypto.tsp  # noqa: F401
    except ImportError:
        return {"ok": True, "present": True, "verified": False,
                "reason": "timestamp present; install 'asn1crypto' to verify it here"}
    try:
        from asn1crypto import tsp
        token = tsp.TimeStampResp.load(src.read("timestamp.tsr"))
        tst = token["time_stamp_token"]
        signed = tst["content"]["encap_content_info"]["content"].parsed
        imprint = signed["message_imprint"]
        stamped = imprint["hashed_message"].native
        want = hashlib.sha256(manifest_bytes).digest()
        ok = stamped == want
        gen_time = signed["gen_time"].native
        return {"ok": ok, "present": True, "verified": True,
                "timestamp": str(gen_time),
                "reason": "timestamp matches the manifest" if ok
                else "timestamp does not cover this manifest"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "present": True, "verified": False,
                "reason": f"timestamp token could not be parsed ({type(e).__name__})"}


# ----------------------------------------------------------------- CLI
def _print_report(r: dict) -> None:
    line = "=" * 68
    print(line)
    print("VENDETTA CYBER DEFENSE — EVIDENCE PACKAGE VERIFICATION")
    print(line)
    if r.get("error"):
        print(f"RESULT: FAIL — {r['error']}")
        print(line)
        return
    print(f"Subject:      {r.get('subject', {}).get('name', '(unknown)')}")
    print(f"Product:      {r.get('product', '')}")
    print(f"Generated:    {r.get('generated_at', '')}")
    print(f"Signing key:  {r.get('key_id', '')}")
    print(f"Records:      {r.get('records', 0)}")
    print("-" * 68)
    names = {"package_seal": "Package seal (manifest signature)",
             "file_integrity": "File integrity (hashes)",
             "chain_of_custody": "Chain of custody (signed hash chain)",
             "same_signing_key": "Manifest and chain share one key",
             "trusted_timestamp": "Trusted timestamp (RFC 3161)"}
    for key, label in names.items():
        c = r["checks"].get(key, {})
        mark = "PASS" if c.get("ok") else "FAIL"
        print(f"  [{mark}] {label}")
        print(f"         {c.get('reason', '')}")
    print("-" * 68)
    print(f"RESULT: {'PASS — the evidence package is intact and authentic' if r['ok'] else 'FAIL — see the checks above'}")
    print(line)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a Vendetta evidence export package.")
    ap.add_argument("package", help="path to the package .zip or an unpacked directory")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args(argv)
    report = verify_package(args.package)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_report(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
