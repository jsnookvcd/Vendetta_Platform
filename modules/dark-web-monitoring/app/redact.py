"""Credential redaction. Applied at ingest to item kinds that carry secrets
(paste, stealer, credential, message) so the database stores the exposure finding,
the affected identifier and the source, but not usable plaintext secrets.

This is the "match and redact" posture: we can tell a client which of their
accounts and which sites are exposed without becoming a holder of working
credentials. If a specific matter needs the full record, the research console
re-fetches and preserves the raw bytes to the Object Lock bucket with chain of
custody, and that copy is access-controlled and auditable.

What is kept: email addresses, usernames, domains, URLs, breach/source names.
What is masked: the secret in identifier:secret pairs, and standalone high-entropy
tokens that look like passwords, hashes or keys."""
from __future__ import annotations

import re

# user:secret or email:secret, optionally url:user:secret (stealer log format).
# Keep everything up to the last colon group that precedes the secret; mask the secret.
_PAIR = re.compile(
    r"(?P<id>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|[A-Za-z0-9._\-]{3,})"
    r"(?P<sep>\s*[:|]\s*)"
    r"(?P<secret>\S{3,})"
)
# Standalone long tokens (hashes, api keys) not containing @ or a dot-domain shape.
_TOKEN = re.compile(r"\b(?=[A-Za-z0-9+/=_\-]{16,}\b)(?![A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)[A-Za-z0-9+/=_\-]{16,}\b")


def _mask(s: str) -> str:
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def _pair_sub(m: re.Match) -> str:
    ident = m.group("id")
    secret = m.group("secret")
    # Leave URLs intact: a scheme (http:) or a secret that is really the rest of a URL (//host...).
    if ident.lower() in ("http", "https", "ftp", "ftps", "ssh") or secret.startswith("//"):
        return m.group(0)
    # Leave bare domains intact (they are context, not secrets).
    if re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", ident):
        return m.group(0)
    return f"{ident}{m.group('sep')}{_mask(secret)}"


def redact(text: str) -> str:
    if not text:
        return text
    out = _PAIR.sub(_pair_sub, text)
    out = _TOKEN.sub(lambda m: _mask(m.group(0)), out)
    return out


SENSITIVE_KINDS = {"paste", "stealer", "credential", "message"}


def redact_for_kind(kind: str, text: str) -> str:
    return redact(text) if kind in SENSITIVE_KINDS else text
