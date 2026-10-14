"""The export package seals a chain, and the standalone verifier confirms it and
catches tampering with any part: a record, a bundled file, or the manifest."""
import io
import json
import zipfile

import pytest

from evidence_export import build_package, verify_package


@pytest.fixture()
def records(make_chain):
    return make_chain([
        {"kind": "engagement_opened", "actor": "admin", "detail": "vCISO: Retainer"},
        {"kind": "deliverable_created", "actor": "admin", "detail": "Policy: ISP v1"},
        {"kind": "deliverable_status", "actor": "admin", "detail": "planned -> delivered"},
        {"kind": "deliverable_accepted", "actor": "ciso@acme.test", "detail": "accepted: ISP v1"},
    ])


@pytest.fixture()
def package(records, signer, public_key_hex, key_id):
    return build_package(records=records, subject={"id": "c1", "name": "Acme Robotics"},
                         product="Vendetta Office of Special Projects", document="deliverable sign-off",
                         signer=signer, public_key_hex=public_key_hex, key_id=key_id)


def _rezip(package_bytes, mutate):
    """Unpack, let mutate(dict_of_name->bytes) change files, repack."""
    files = {}
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as z:
        for n in z.namelist():
            files[n] = z.read(n)
    mutate(files)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)
    return out.getvalue()


def _write(tmp_path, package_bytes, name="pkg.zip"):
    p = tmp_path / name
    p.write_bytes(package_bytes)
    return str(p)


def test_valid_package_verifies(tmp_path, package):
    r = verify_package(_write(tmp_path, package))
    assert r["ok"] is True
    assert r["checks"]["package_seal"]["ok"]
    assert r["checks"]["file_integrity"]["ok"]
    assert r["checks"]["chain_of_custody"]["ok"]
    assert r["checks"]["same_signing_key"]["ok"]
    assert r["checks"]["trusted_timestamp"]["ok"]  # absent timestamp passes
    assert r["records"] == 4


def test_package_is_self_contained(tmp_path, package):
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        names = [n.split("/", 1)[1] for n in z.namelist()]
    for want in ("MANIFEST.json", "MANIFEST.sig", "proof.json", "public_key.txt",
                 "verify_evidence.py", "README.txt"):
        assert want in names


def test_tampered_record_detected(tmp_path, package):
    def mutate(files):
        pj = [n for n in files if n.endswith("proof.json")][0]
        proof = json.loads(files[pj])
        proof["records"][2]["fields"]["detail"] = "planned -> accepted"  # rewrite history
        files[pj] = json.dumps(proof, indent=2).encode()
    bad = _rezip(package, mutate)
    r = verify_package(_write(tmp_path, bad, "bad.zip"))
    assert r["ok"] is False
    # File integrity catches the edited proof.json (its hash no longer matches manifest).
    assert r["checks"]["file_integrity"]["ok"] is False


def test_tampered_record_without_manifest_catch_breaks_chain(tmp_path, records, signer,
                                                             public_key_hex, key_id):
    # Edit a record AND rewrite the manifest hash for proof.json, so only the chain
    # check (not file integrity) can catch it.
    package = build_package(records=records, subject={"id": "c1", "name": "Acme"},
                            product="OSP", document="deliverable sign-off", signer=signer,
                            public_key_hex=public_key_hex, key_id=key_id)
    import hashlib

    def mutate(files):
        root = files_keys_root(files)
        proof = json.loads(files[f"{root}/proof.json"])
        proof["records"][1]["fields"]["actor"] = "attacker"
        new_pj = json.dumps(proof, indent=2).encode()
        files[f"{root}/proof.json"] = new_pj
        manifest = json.loads(files[f"{root}/MANIFEST.json"])
        manifest["files"]["proof.json"]["sha256"] = hashlib.sha256(new_pj).hexdigest()
        manifest["files"]["proof.json"]["bytes"] = len(new_pj)
        # re-canonicalize the manifest the same way the builder does
        files[f"{root}/MANIFEST.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    bad = _rezip(package, mutate)
    r = verify_package(_write(tmp_path, bad, "bad2.zip"))
    assert r["ok"] is False
    # The manifest was edited, so its signature no longer matches.
    assert r["checks"]["package_seal"]["ok"] is False


def test_tampered_bundled_file_detected(tmp_path, package):
    def mutate(files):
        rn = [n for n in files if n.endswith("README.txt")][0]
        files[rn] = files[rn] + b"\nappended text\n"
    bad = _rezip(package, mutate)
    r = verify_package(_write(tmp_path, bad, "bad3.zip"))
    assert r["ok"] is False
    assert r["checks"]["file_integrity"]["ok"] is False


def test_verifies_from_unpacked_directory(tmp_path, package):
    import zipfile as zf
    d = tmp_path / "unpacked"
    d.mkdir()
    with zf.ZipFile(io.BytesIO(package)) as z:
        z.extractall(d)
    r = verify_package(str(d))
    assert r["ok"] is True


def test_wrong_key_fails_seal(tmp_path, records, key_id):
    # Sign with one key but publish a different public key.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate()
    other_pub = other.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    package = build_package(records=records, subject={"id": "c1", "name": "Acme"},
                            product="OSP", document="deliverable sign-off",
                            signer=lambda d: other.sign(d).hex(),
                            public_key_hex=other_pub, key_id=key_id)
    # The chain in `records` was signed by the conftest key, not `other`, so the chain
    # signatures will not verify against other_pub.
    r = verify_package(_write(tmp_path, package))
    assert r["ok"] is False
    assert r["checks"]["chain_of_custody"]["ok"] is False


def files_keys_root(files):
    for n in files:
        if n.endswith("/MANIFEST.json"):
            return n.rsplit("/", 1)[0]
    return ""
