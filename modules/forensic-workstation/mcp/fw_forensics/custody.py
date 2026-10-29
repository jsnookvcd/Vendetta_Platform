"""Hash-chained, append-only JSONL logs for custody and audit.

Each entry carries the SHA-256 of the previous entry, so any edit, deletion or
reordering breaks verification from that point on. The same format is used for
two logs per case:

  custody.jsonl  written by fw-helper as root: case creation, evidence intake,
                 mounts. Analysts cannot write it.
  audit.jsonl    written by the MCP server and the Claude Code hook as the
                 analyst: every tool run, note and export.

Every line is also mirrored to /var/log/forensic-audit/ which the CloudWatch
agent ships off the box in near real time, so local tampering is evident by
comparison with the shipped copy.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CENTRAL_LOG_DIR = Path(os.environ.get("FW_CENTRAL_LOG_DIR", "/var/log/forensic-audit"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def valid_case_id(case_id: str) -> bool:
    return bool(CASE_ID_RE.match(case_id or "")) and ".." not in case_id


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _last_entry(path: Path) -> dict[str, Any] | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 65536)
        f.seek(size - block)
        lines = f.read().splitlines()
    for raw in reversed(lines):
        raw = raw.strip()
        if raw:
            return json.loads(raw)
    return None


def append(path: Path, action: str, case_id: str, details: dict[str, Any], actor: str | None = None) -> dict[str, Any]:
    """Append one chained entry under an exclusive lock and mirror it centrally."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            last = _last_entry(path)
            entry = {
                "seq": (last["seq"] + 1) if last else 1,
                "ts": utc_now(),
                "case_id": case_id,
                "log": path.name,
                "host": socket.gethostname(),
                "actor": actor or os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid()),
                "action": action,
                "details": details,
                "prev_hash": last["hash"] if last else GENESIS,
            }
            entry["hash"] = entry_hash(entry)
            f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    _mirror(entry)
    return entry


def _mirror(entry: dict[str, Any]) -> None:
    try:
        CENTRAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (CENTRAL_LOG_DIR / "audit.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass  # the per-case chain is authoritative; the mirror is best effort


def verify(path: Path) -> dict[str, Any]:
    """Walk the chain. Returns ok, entry count, and the first break if any."""
    if not path.exists():
        return {"ok": True, "entries": 0, "log": str(path)}
    prev = GENESIS
    count = 0
    with path.open(encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                return {"ok": False, "entries": count, "log": str(path), "break_at_line": lineno, "reason": "unparseable line"}
            if entry.get("prev_hash") != prev:
                return {"ok": False, "entries": count, "log": str(path), "break_at_line": lineno, "reason": "prev_hash mismatch (entry removed or reordered)"}
            if entry_hash(entry) != entry.get("hash"):
                return {"ok": False, "entries": count, "log": str(path), "break_at_line": lineno, "reason": "hash mismatch (entry modified)"}
            prev = entry["hash"]
            count += 1
    return {"ok": True, "entries": count, "log": str(path), "head": prev}


def hash_file(path: Path, algos: tuple[str, ...] = ("md5", "sha1", "sha256")) -> dict[str, Any]:
    hashers = {a: hashlib.new(a) for a in algos}
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            size += len(chunk)
            for h in hashers.values():
                h.update(chunk)
    return {"size": size, **{a: h.hexdigest() for a, h in hashers.items()}}
