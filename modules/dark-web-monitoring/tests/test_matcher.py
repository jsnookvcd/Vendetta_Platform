"""Unit tests for term compilation and the CT lookalike generator. Run: pytest tests/"""
import os
import sys

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost/x")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.collectors.ct_logs import permutations  # noqa: E402
from app.db import WatchTerm  # noqa: E402
from app.matcher import _compile, _match_cidr  # noqa: E402


def t(term, kind):
    return WatchTerm(term=term, kind=kind)


def test_domain_matches_subdomains_only():
    p = _compile(t("acme.com", "domain"))
    assert p.search("leaked from mail.acme.com today")
    assert p.search("ACME.COM")
    assert not p.search("notacme.com")
    assert not p.search("acme.community")


def test_email_domain():
    p = _compile(t("acme.com", "email_domain"))
    assert p.search("creds: j.doe@acme.com:Winter2026")
    assert not p.search("acme.com homepage")


def test_brand_squashed():
    p = _compile(t("Acme Corp", "brand"))
    assert p.search("victim: acmecorp")
    assert p.search("Acme Corp data")


def test_person_middle_initial():
    p = _compile(t("Jane Doe", "person"))
    assert p.search("CFO Jane Q. Doe")
    assert p.search("jane doe")
    assert not p.search("Jane Roe")


def test_cidr():
    assert _match_cidr(t("10.20.0.0/16", "ip_cidr"), "host 10.20.5.9 open") == "10.20.5.9"
    assert _match_cidr(t("10.20.0.0/16", "ip_cidr"), "host 10.21.5.9") is None


def test_bad_regex_is_ignored():
    assert _compile(t("(unclosed", "regex")) is None


def test_lookalikes():
    perms = permutations("acme.com")
    assert "secure-acme.com" in perms
    assert "acme.net" in perms
    assert "acme.com" not in perms
    assert any("4" in p for p in perms)
