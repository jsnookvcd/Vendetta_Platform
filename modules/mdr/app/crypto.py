"""Encryption at rest for the few secrets the control plane stores, namely the
per-module bearer tokens. A SQLAlchemy type transparently encrypts on write and
decrypts on read, so application code keeps handling plain strings.

The key comes from ENCRYPTION_KEY (a Fernet key, urlsafe base64 of 32 bytes). When
unset, a key is derived from secret_key so a deployment still protects
its own data; production should set a dedicated key so it can be rotated and so the
tokens are not readable from the session secret alone.

Reads are tolerant of legacy plaintext: a value that is not a valid ciphertext is
returned as-is, so existing rows keep working and are re-encrypted the next time
they are written.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from .config import settings

log = logging.getLogger(__name__)
_PREFIX = "enc:v1:"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    raw = (settings.encryption_key or "").strip()
    if raw:
        return Fernet(raw.encode())
    log.warning("mdr: no ENCRYPTION_KEY set; deriving a storage key from secret_key. "
                "Set a dedicated key in production.")
    key = base64.urlsafe_b64encode(hashlib.sha256(b"vendetta-mdr-enc-v1:" + settings.secret_key.encode()).digest())
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    if plaintext is None or plaintext == "":
        return plaintext
    return _PREFIX + _fernet().encrypt(plaintext.encode()).decode()


def decrypt(stored: str) -> str:
    if not stored or not stored.startswith(_PREFIX):
        return stored  # legacy plaintext or empty: return unchanged
    try:
        return _fernet().decrypt(stored[len(_PREFIX):].encode()).decode()
    except (InvalidToken, ValueError):
        log.warning("platform: a stored secret could not be decrypted; returning empty")
        return ""


class EncryptedStr(TypeDecorator):
    """A text column whose value is encrypted at rest and plain in Python."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return encrypt(value) if value is not None else value

    def process_result_value(self, value, dialect):
        return decrypt(value) if value is not None else value
