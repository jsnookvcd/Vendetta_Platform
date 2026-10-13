"""Per-module bearer tokens are encrypted at rest and plain through the ORM."""
from sqlalchemy import text

from app import crypto
from app.db import Module, SessionLocal, engine


def test_module_token_is_ciphertext_at_rest_but_plain_via_orm(fresh_db):
    secret = "super-secret-bearer-token-value-123"
    db = SessionLocal()
    m = db.get(Module, "managed-services")
    assert m is not None  # seeded by the registry
    m.api_token = secret
    db.commit()

    # Through the ORM: plaintext.
    assert SessionLocal().get(Module, "managed-services").api_token == secret

    # On disk: not plaintext, and carries the scheme prefix.
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT api_token FROM modules WHERE key='managed-services'")).scalar()
    assert raw != secret
    assert raw.startswith("enc:v1:")
    assert secret not in raw


def test_legacy_plaintext_is_read_tolerantly(fresh_db):
    # A row written before encryption (no prefix) must still read back unchanged.
    with engine.begin() as conn:
        conn.execute(text("UPDATE modules SET api_token='legacy-plain' WHERE key='managed-services'"))
    assert SessionLocal().get(Module, "managed-services").api_token == "legacy-plain"


def test_roundtrip_helpers():
    ct = crypto.encrypt("hello")
    assert ct.startswith("enc:v1:") and ct != "hello"
    assert crypto.decrypt(ct) == "hello"
    assert crypto.decrypt("") == ""
    assert crypto.decrypt("plain-unprefixed") == "plain-unprefixed"
