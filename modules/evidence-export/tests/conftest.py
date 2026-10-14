"""Shared fixtures: an Ed25519 signer and a helper that builds a signed chain exactly
the way the platform's evidence module does, so the export and verifier are tested
against real chain records rather than mocks."""
import hashlib
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

GENESIS = "0" * 64
SCHEME = "ed25519-sha256-v1"


def _canonical(fields, prev):
    body = {"scheme": SCHEME, "prev": prev, "fields": fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str,
                      ensure_ascii=False).encode("utf-8")


@pytest.fixture()
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def signer(key):
    def _sign(data: bytes) -> str:
        return key.sign(data).hex()
    return _sign


@pytest.fixture()
def public_key_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


@pytest.fixture()
def key_id(public_key_hex):
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


@pytest.fixture()
def make_chain(key):
    """Return a function that turns a list of field dicts into signed chain records."""
    def _build(field_dicts):
        records = []
        prev = GENESIS
        for i, fields in enumerate(field_dicts, start=1):
            fields = {"chain_seq": i, **fields}
            content_hash = hashlib.sha256(_canonical(fields, prev)).hexdigest()
            signature = key.sign(bytes.fromhex(content_hash)).hex()
            records.append({"fields": fields, "prev_hash": prev,
                            "content_hash": content_hash, "signature": signature})
            prev = content_hash
        return records
    return _build
