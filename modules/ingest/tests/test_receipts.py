"""The receipt scheme on its own: RFC 6962 trees, audit paths, signed headers,
chains, and the offline verifier's verdict on every kind of tampering."""
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import receipts as R

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
OTHER_PUB = OTHER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _recursive_mth(leaves):
    """RFC 6962 section 2.1, written literally, as the oracle."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + _recursive_mth(leaves[:k]) + _recursive_mth(leaves[k:])).digest()


def _leaves(n):
    return [R.leaf_hash(hashlib.sha256(f"raw{i}".encode()).hexdigest(),
                        hashlib.sha256(f"ev{i}".encode()).hexdigest()) for i in range(n)]


@pytest.mark.parametrize("n", list(range(0, 34)) + [64, 100, 257])
def test_root_matches_rfc6962(n):
    assert R.merkle_root(_leaves(n)) == _recursive_mth(_leaves(n))


@pytest.mark.parametrize("n", [1, 2, 3, 5, 7, 8, 9, 16, 31, 33, 100])
def test_every_audit_path_verifies_and_only_at_its_index(n):
    leaves = _leaves(n)
    root = R.merkle_root(leaves)
    for i in range(n):
        path = R.audit_path(leaves, i)
        assert R.root_from_path(leaves[i], i, n, path) == root
        if n > 1:
            j = (i + 1) % n
            assert R.root_from_path(leaves[i], j, n, path) != root
        assert len(path) <= max(1, n.bit_length())


def test_path_shape_errors_return_none():
    leaves = _leaves(5)
    path = R.audit_path(leaves, 2)
    assert R.root_from_path(leaves[2], 5, 5, path) is None          # index out of range
    assert R.root_from_path(leaves[2], 2, 5, path + [path[0]]) is None  # too long
    assert R.root_from_path(leaves[2], 2, 5, path[:-1]) is None     # too short
    with pytest.raises(IndexError):
        R.audit_path(leaves, 5)


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = "11" * 32, "22" * 32
    leaf = R.leaf_hash(a, b)
    node = hashlib.sha256(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b)).digest()
    assert leaf != node  # a leaf can never be passed off as an interior node


def test_event_hash_ignores_receipt_and_key_order():
    ev = {"b": 1, "a": {"y": 2, "x": 3}, "receipt": {"anything": 1}}
    assert R.event_hash(ev) == R.event_hash({"a": {"x": 3, "y": 2}, "b": 1})


def _batch(tenant="t1", n=5, seq=1, prev=R.GENESIS, key=KEY, pub=PUB):
    raws = [{"id": i, "msg": f"record {i}", "tenant_claim": "someone-else"} for i in range(n)]
    events = [{"class_uid": 3002, "time": 1000 + i, "metadata": {"tenant_uid": tenant}, "n": i} for i in range(n)]
    rh = [R.raw_hash(r) for r in raws]
    eh = [R.event_hash(e) for e in events]
    leaves = [R.leaf_hash(a, b) for a, b in zip(rh, eh)]
    header = R.make_header(tenant=tenant, batch_seq=seq, leaves=leaves, first_seq=1, last_seq=n,
                           first_event_time="2026-10-19T00:00:00+00:00", last_event_time="2026-10-19T00:01:00+00:00",
                           sealed_at="2026-10-19T00:02:00+00:00", prev_batch_hash=prev, key_id=R.key_id_for(pub))
    bh = R.header_hash(header)
    batch = {"header": header, "batch_hash": bh, "signature": key.sign(bytes.fromhex(bh)).hex(), "public_key": pub}
    proofs = [{"event": events[i], "receipt": {"tenant": tenant, "raw_sha256": rh[i], "event_sha256": eh[i],
                                               "leaf_index": i, "audit_path": R.audit_path(leaves, i)},
               "batch": batch} for i in range(n)]
    return batch, proofs, raws


def test_valid_proof_with_raw_verifies():
    _, proofs, raws = _batch()
    for p, raw in zip(proofs, raws):
        out = R.verify_proof(p, raw)
        assert out["ok"] and out["reason"] == "verified"
        assert [c["name"] for c in out["checks"]][:2] == ["event hash", "raw record hash"]


@pytest.mark.parametrize("tamper,reason", [
    (lambda p: p["event"].__setitem__("n", 99), "the event does not match its recorded hash"),
    (lambda p: p["receipt"].__setitem__("leaf_index", 1), "the event is not included in the sealed batch"),
    (lambda p: p["receipt"]["audit_path"].__setitem__(0, "00" * 32), "the event is not included in the sealed batch"),
    (lambda p: p["batch"]["header"].__setitem__("size", 6), "the batch header was altered"),
    (lambda p: p["batch"]["header"].__setitem__("size", 9), "the event is not included in the sealed batch"),
    (lambda p: p["batch"]["header"].__setitem__("sealed_at", "2027-01-01T00:00:00+00:00"), "the batch header was altered"),
    (lambda p: p["batch"]["header"].__setitem__("tenant", "t2"), "the proof's batch belongs to a different tenant"),
    (lambda p: p["batch"].__setitem__("signature", "00" * 64), "the batch signature is not valid"),
])
def test_tampering_is_named(tamper, reason):
    _, proofs, _ = _batch()
    p = copy.deepcopy(proofs[2])
    tamper(p)
    out = R.verify_proof(p)
    assert out["ok"] is False and out["reason"] == reason


def test_raw_record_that_differs_is_caught():
    _, proofs, raws = _batch()
    raw = dict(raws[0], msg="edited after the fact")
    assert R.verify_proof(proofs[0], raw)["reason"] == "the raw record does not match its recorded hash"


def test_pinned_key_rejects_a_proof_signed_by_another_key():
    _, proofs, _ = _batch(key=OTHER, pub=OTHER_PUB)
    assert R.verify_proof(proofs[0])["ok"] is True                     # self-consistent
    assert R.verify_proof(proofs[0], public_key_hex=PUB)["reason"] == "the batch was signed by a different key"


def test_malformed_proof_is_rejected_cleanly():
    assert R.verify_proof({"event": {}})["reason"] == "malformed proof"


def test_chain_verifies_and_names_every_break():
    b1, _, _ = _batch(seq=1)
    b2, _, _ = _batch(seq=2, prev=b1["batch_hash"])
    b3, _, _ = _batch(seq=3, prev=b2["batch_hash"])
    assert R.verify_chain([b1, b2, b3]) == {"ok": True, "length": 3, "verified": 3, "broken_at": None,
                                            "reason": "intact", "head": b3["batch_hash"]}
    assert R.verify_chain([b1, b3])["reason"] == "a batch is missing or out of order"
    assert R.verify_chain([b2, b3])["ok"] is True  # a window that starts mid-chain
    forged, _, _ = _batch(seq=2, prev=R.GENESIS)
    assert R.verify_chain([b1, forged])["reason"] == "chain link broken"
    other, _, _ = _batch(tenant="t2", seq=2, prev=b1["batch_hash"])
    assert R.verify_chain([b1, other])["reason"] == "batches from more than one tenant"
    bad = copy.deepcopy(b2)
    bad["header"]["root"] = "00" * 32
    assert R.verify_chain([b1, bad])["reason"] == "header altered"


def test_offline_verifier_cli(tmp_path):
    """receipts.py runs on its own, with no access to the application."""
    _, proofs, raws = _batch()
    src = Path(R.__file__)
    (tmp_path / "receipts.py").write_text(src.read_text())
    (tmp_path / "proof.json").write_text(json.dumps(proofs[1]))
    (tmp_path / "raw.json").write_text(json.dumps(raws[1]))
    ok = subprocess.run([sys.executable, "-I", "receipts.py", "proof.json", "raw.json", "--key", PUB],
                        cwd=tmp_path, capture_output=True, text=True)
    assert ok.returncode == 0 and "VERIFIED" in ok.stdout
    (tmp_path / "raw.json").write_text(json.dumps(dict(raws[1], msg="changed")))
    bad = subprocess.run([sys.executable, "-I", "receipts.py", "proof.json", "raw.json"], cwd=tmp_path,
                         capture_output=True, text=True)
    assert bad.returncode == 1 and "raw record does not match" in bad.stdout
    b1, _, _ = _batch(seq=1)
    b2, _, _ = _batch(seq=2, prev=b1["batch_hash"])
    (tmp_path / "chain.json").write_text(json.dumps({"batches": [b1, b2]}))
    chain = subprocess.run([sys.executable, "-I", "receipts.py", "chain.json"], cwd=tmp_path, capture_output=True,
                           text=True)
    assert chain.returncode == 0 and '"intact"' in chain.stdout
