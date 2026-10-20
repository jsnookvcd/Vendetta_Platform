"""Provable telemetry: signed Merkle receipts for every event the SOC ingests.

Every raw record a connector receives is hashed the moment it arrives, before any
parsing. The record is then normalized to OCSF and the normalized event is hashed
too. Each event's two hashes form one leaf. On a schedule, every tenant's unsealed
events are sealed into a batch: the leaves become an RFC 6962 Merkle tree, the root
goes into a batch header together with the hash of the tenant's previous header, and
the header is signed with Ed25519. Batches therefore form one signed, append-only
chain per tenant.

What that buys a client, a regulator, a carrier or a court:

- Any single event can be proven to be part of a sealed batch with a short audit
  path (log2 of the batch size hashes), without disclosing any other event.
- The raw record proves the normalized event was derived from what the vendor sent,
  because both hashes sit in the same leaf.
- The header chain proves no batch was removed, inserted or reordered after sealing.
- Daily anchors of each chain head are signed and written to WORM storage, so even
  Vendetta cannot rewrite history after the anchor. A chain export carries the
  latest anchor for its tenant, and verification checks the chain reaches it.

This file has no dependency on the rest of the application on purpose. It is the
offline verifier too: copy it next to an exported proof and run

    python receipts.py proof.json [raw_record.json]

It needs Python 3.10+ and the `cryptography` package, nothing else. Pass the
public key Vendetta published (--key) so the check does not rest on the key the
file carries; without it the verifier says UNPINNED and exits 3.

Hashing conventions (all SHA-256, hex in JSON):

  canonical(x)   = RFC 8785 JSON Canonicalization Scheme, UTF-8
  raw_sha256     = sha256(canonical(raw record as parsed from the delivery))
  event_sha256   = sha256(canonical(OCSF event without its "receipt" block))
  leaf_hash      = sha256(0x00 || raw_sha256 bytes || event_sha256 bytes)
  node           = sha256(0x01 || left || right)            (RFC 6962 section 2.1)
  batch_hash     = sha256(canonical(header))
  signature      = Ed25519(private key, batch_hash bytes)
"""
from __future__ import annotations

import hashlib
import json
import sys

SCHEME = "vcd-telemetry-merkle-v1"
GENESIS = "0" * 64

HEADER_FIELDS = ("scheme", "tenant", "batch_seq", "size", "first_seq", "last_seq", "first_event_time",
                 "last_event_time", "sealed_at", "root", "prev_batch_hash", "key_id")


# ---------------------------------------------------------------- hashing
def canonical(obj) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme) bytes: keys sorted by UTF-16 code
    units, no whitespace, strings escaped as JSON requires and nothing more, numbers
    in ECMAScript shortest form (1e16 is 10000000000000000, 8.0 is 8, -0.0 is 0).
    Integers are written exactly. NaN, Infinity and lone surrogates are refused with
    ValueError because no canonical form exists for them."""
    try:
        return _jcs(obj).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("text contains a lone surrogate") from None


def _jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _es_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        items = []
        for k in v:
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            items.append(k)
        items.sort(key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k]) for k in items) + "}"
    return json.dumps(str(v), ensure_ascii=False)


def _es_number(f: float) -> str:
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity have no canonical JSON form")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))
    mant, _, exp = r.partition("e")
    ip, _, fp = mant.partition(".")
    digits = ip + fp
    point = len(ip) + (int(exp) if exp else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    s = stripped.rstrip("0") or "0"
    k, n = len(s), point
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        e = n - 1
        out = (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raw_hash(raw) -> str:
    """Hash of a raw record as received. Bytes are hashed as-is; anything else is
    hashed in canonical JSON form."""
    if isinstance(raw, (bytes, bytearray)):
        return sha256_hex(bytes(raw))
    return sha256_hex(canonical(raw))


def event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "receipt"}
    return sha256_hex(canonical(body))


def leaf_hash(raw_sha256: str, event_sha256: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(raw_sha256) + bytes.fromhex(event_sha256)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-hashed leaves."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    # Iterative bottom-up build matching the recursive definition: RFC 6962 trees are
    # left-complete, so pairing adjacent nodes and promoting an odd last node gives
    # the same root as the recursive split.
    level = list(leaves)
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def audit_path(leaves: list[bytes], index: int) -> list[str]:
    """RFC 6962 PATH(m, D[n]) as hex, ordered leaf to root."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")

    def path(m: int, d: list[bytes]) -> list[bytes]:
        n = len(d)
        if n <= 1:
            return []
        k = _split(n)
        if m < k:
            return path(m, d[:k]) + [merkle_root(d[k:])]
        return path(m - k, d[k:]) + [merkle_root(d[:k])]

    return [h.hex() for h in path(index, leaves)]


def root_from_path(leaf: bytes, index: int, size: int, path_hex: list[str]) -> bytes | None:
    """RFC 9162 section 2.1.3.2 inclusion verification. Returns the computed root, or
    None when the path has the wrong shape for (index, size)."""
    if not 0 <= index < size:
        return None
    fn, sn = index, size - 1
    r = leaf
    for p_hex in path_hex:
        p = bytes.fromhex(p_hex)
        if sn == 0:
            return None
        if fn % 2 == 1 or fn == sn:
            r = _node(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return r


# ---------------------------------------------------------------- headers and signatures
def make_header(*, tenant: str, batch_seq: int, leaves: list[bytes], first_seq: int, last_seq: int,
                first_event_time: str, last_event_time: str, sealed_at: str, prev_batch_hash: str,
                key_id: str) -> dict:
    return {
        "scheme": SCHEME, "tenant": tenant, "batch_seq": int(batch_seq), "size": len(leaves),
        "first_seq": int(first_seq), "last_seq": int(last_seq), "first_event_time": first_event_time,
        "last_event_time": last_event_time, "sealed_at": sealed_at, "root": merkle_root(leaves).hex(),
        "prev_batch_hash": prev_batch_hash, "key_id": key_id,
    }


def header_hash(header: dict) -> str:
    return sha256_hex(canonical({k: header[k] for k in HEADER_FIELDS}))


def key_id_for(public_key_hex: str) -> str:
    return sha256_hex(bytes.fromhex(public_key_hex))[:16]


def verify_signature(public_key_hex: str, digest_hex: str, signature_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(digest_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- verification
def verify_proof(proof: dict, raw=None, public_key_hex: str | None = None) -> dict:
    """Check one event's inclusion proof end to end. `proof` is what
    GET /api/events/{id}/proof returns. Pass the raw record (as JSON or bytes) to
    also prove the normalized event came from it. Pass public_key_hex to pin the
    key you expect instead of trusting the one in the proof.

    Returns {ok, checks: [{name, ok, detail}], reason}."""
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    def done(reason: str) -> dict:
        return {"ok": all(c["ok"] for c in checks) and reason == "verified", "checks": checks, "reason": reason,
                "pinned": bool(public_key_hex)}

    try:
        event = proof["event"]
        rcpt = proof["receipt"]
        header = proof["batch"]["header"]
        bhash = proof["batch"]["batch_hash"]
        sig = proof["batch"]["signature"]
        pub = public_key_hex or proof["batch"]["public_key"]
    except (KeyError, TypeError):
        check("proof shape", False, "missing event, receipt or batch fields")
        return done("malformed proof")

    ev_h = event_hash(event)
    if not check("event hash", ev_h == rcpt["event_sha256"], ev_h):
        return done("the event does not match its recorded hash")
    if raw is not None:
        r_h = raw_hash(raw)
        if not check("raw record hash", r_h == rcpt["raw_sha256"], r_h):
            return done("the raw record does not match its recorded hash")
    if not check("tenant", header.get("tenant") == rcpt.get("tenant"), header.get("tenant", "")):
        return done("the proof's batch belongs to a different tenant")
    leaf = leaf_hash(rcpt["raw_sha256"], rcpt["event_sha256"])
    root = root_from_path(leaf, int(rcpt["leaf_index"]), int(header["size"]), rcpt["audit_path"])
    if not check("merkle inclusion", root is not None and root.hex() == header["root"],
                 root.hex() if root else "path shape invalid"):
        return done("the event is not included in the sealed batch")
    hh = header_hash(header)
    if not check("batch header hash", hh == bhash, hh):
        return done("the batch header was altered")
    if not check("key id", key_id_for(pub) == header.get("key_id"), key_id_for(pub)):
        return done("the batch was signed by a different key")
    if not check("signature", verify_signature(pub, bhash, sig)):
        return done("the batch signature is not valid")
    return done("verified")


def verify_anchor(anchor: dict, public_key_hex: str | None = None) -> tuple[bool, str]:
    """Check a daily anchor ({document, digest, signature}) on its own."""
    try:
        doc, digest, sig = anchor["document"], anchor["digest"], anchor["signature"]
    except (KeyError, TypeError):
        return False, "malformed anchor"
    pub = public_key_hex or doc.get("public_key", "")
    if sha256_hex(canonical(doc)) != digest:
        return False, "anchor document altered"
    if key_id_for(pub) != doc.get("key_id"):
        return False, "anchor signed by a different key"
    if not verify_signature(pub, digest, sig):
        return False, "anchor signature invalid"
    return True, "ok"


def verify_chain(batches: list[dict], public_key_hex: str | None = None, anchor: dict | None = None) -> dict:
    """Verify an ordered list of a tenant's batches ({header, batch_hash, signature,
    public_key}): each header hash, each signature, sequence numbers and links, and
    that one key signed them all. With an anchor, also check the anchor's signature
    and that the chain contains the anchored head: a chain cut short before the
    anchor, or rewritten under it, fails."""
    def fail(i: int, reason: str) -> dict:
        return {"ok": False, "length": len(batches), "verified": max(0, i - 1), "broken_at": i, "reason": reason,
                "pinned": bool(public_key_hex)}

    if not batches:
        return fail(1, "the chain is empty")
    prev = GENESIS
    expected_seq = None
    tenant = None
    key = public_key_hex
    seen: dict[int, str] = {}
    for i, b in enumerate(batches, start=1):
        h = b["header"]
        pub = key or b.get("public_key", "")
        if tenant is None:
            tenant = h["tenant"]
            key = pub
            expected_seq = int(h["batch_seq"])
            if expected_seq != 1:
                prev = h["prev_batch_hash"]  # a window that starts mid-chain
        reason = None
        if h["tenant"] != tenant:
            reason = "batches from more than one tenant"
        elif int(h["batch_seq"]) != expected_seq:
            reason = "a batch is missing or out of order"
        elif h["prev_batch_hash"] != prev:
            reason = "chain link broken"
        elif header_hash(h) != b["batch_hash"]:
            reason = "header altered"
        elif key_id_for(pub) != h.get("key_id"):
            reason = "signed by a different key"
        elif not verify_signature(pub, b["batch_hash"], b["signature"]):
            reason = "signature invalid"
        if reason:
            return fail(i, reason)
        seen[int(h["batch_seq"])] = b["batch_hash"]
        prev = b["batch_hash"]
        expected_seq += 1
    out = {"ok": True, "length": len(batches), "verified": len(batches), "broken_at": None, "reason": "intact",
           "head": prev, "head_seq": expected_seq - 1, "pinned": bool(public_key_hex), "anchored": False}
    if anchor is not None:
        ok, why = verify_anchor(anchor, key)
        if not ok:
            return {**out, "ok": False, "reason": why}
        head = ((anchor["document"].get("tenants") or {}).get(tenant)) or {}
        seq, bh = int(head.get("batch_seq") or 0), head.get("batch_hash")
        if not seq:
            return {**out, "ok": False, "reason": "the anchor does not cover this tenant"}
        if seq > out["head_seq"]:
            return {**out, "ok": False, "reason": "the chain ends before the anchored head: batches were removed"}
        if seq in seen and seen[seq] != bh:
            return {**out, "ok": False, "reason": "the chain differs from the anchored head"}
        if seq not in seen:
            return {**out, "ok": False, "reason": "the anchored batch is not in this window of the chain"}
        out["anchored"] = True
        out["anchor_created_at"] = anchor["document"].get("created_at")
    return out


def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python receipts.py proof.json|chain.json [raw_record.json] --key <public key hex>")
        print("       add --trust-embedded-key to check against the key inside the file (not recommended)")
        return 2
    args = list(argv[1:])
    key = None
    trust = "--trust-embedded-key" in args
    if trust:
        args.remove("--trust-embedded-key")
    if "--key" in args:
        i = args.index("--key")
        key = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
    if not key and not trust:
        print("UNPINNED: pass --key with the public key Vendetta published. A file can carry any key, so a")
        print("check against the key inside it proves only that the file is self-consistent.")
        return 3
    with open(args[0], encoding="utf-8") as fh:
        doc = json.load(fh)
    raw = None
    if len(args) > 1:
        with open(args[1], "rb") as fh:
            data = fh.read()
        try:
            raw = json.loads(data)
        except ValueError:
            raw = data
    if isinstance(doc, dict) and "batches" in doc:
        result = verify_chain(doc["batches"], key, doc.get("anchor"))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    result = verify_proof(doc, raw, key)
    for c in result["checks"]:
        print(f"[{'PASS' if c['ok'] else 'FAIL'}] {c['name']}")
    print(result["reason"].upper() if result["ok"] else f"FAILED: {result['reason']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
