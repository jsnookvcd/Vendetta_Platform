"""Tests for redaction and IAB scoring."""
import os
import sys

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost/x")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.iab import _revenue_musd, match_iab  # noqa: E402
from app.redact import redact  # noqa: E402


def test_redact_masks_passwords_keeps_identifiers():
    out = redact("jdoe@acme.com:SuperSecret123\nadmin:hunter2")
    assert "acme.com" in out
    assert "SuperSecret123" not in out
    assert "hunter2" not in out
    assert "jdoe@acme.com" in out


def test_redact_keeps_urls_and_domains():
    out = redact("https://portal.acme.com login leaked")
    assert "portal.acme.com" in out


def test_redact_masks_long_tokens():
    out = redact("key AKIA1234567890ABCDEFXYZ found")
    assert "AKIA1234567890ABCDEFXYZ" not in out


def test_revenue_parsing():
    vals = _revenue_musd("US credit union revenue $420M, asking $25k")
    assert 420 in vals
    assert 25 not in vals  # k is price, not revenue
