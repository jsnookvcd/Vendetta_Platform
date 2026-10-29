"""Vendetta forensic workstation MCP server.

Gives Claude Code a case-scoped, audited way to work evidence:
open a case, pull evidence from the intake bucket with hashing and custody,
mount images read-only, run allowlisted free DFIR tools, page through output,
record findings with their source artifact, and export the case to S3.

Evidence handling that needs root goes through fw-helper (sudo). Everything
else runs as the analyst. Every call is written to the case's hash-chained
audit log.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from . import catalog, custody

CASES = Path(os.environ.get("FW_CASES_ROOT", "/cases"))
MNT = Path(os.environ.get("FW_MOUNT_ROOT", "/mnt/fw"))
HELPER = os.environ.get("FW_HELPER", "/usr/local/sbin/fw-helper")
HELPER_CMD = os.environ.get("FW_HELPER_CMD", f"sudo -n {HELPER}").split()
CONF = Path(os.environ.get("FW_CONF", "/etc/forensic-workstation.env"))
MAX_INLINE = int(os.environ.get("FW_MAX_INLINE", "20000"))

mcp = _Server(
    "forensics",
    instructions=(
        "Vendetta forensic workstation. Always work inside a case: case_open first, "
        "evidence_pull to bring evidence in, evidence_mount for disk images, run_tool for "
        "analysis, finding_add for every conclusion with the artifact path it rests on. "
        "Evidence is read-only; write outputs under the case work directory."
    ),
)


# ------------------------------------------------------------------ helpers
def _conf() -> dict[str, str]:
    vals: dict[str, str] = {}
    if CONF.exists():
        for line in CONF.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip('"')
    return vals


def _case(case_id: str) -> Path:
    if not custody.valid_case_id(case_id):
        raise ValueError("invalid case id; use letters, digits, dot, dash, underscore (max 64)")
    d = CASES / case_id
    if not (d / "evidence").is_dir():
        raise ValueError(f"case {case_id} does not exist; call case_open first")
    return d


def _audit(case_id: str, action: str, details: dict[str, Any]) -> dict[str, Any]:
    return custody.append(CASES / case_id / "audit.jsonl", action, case_id, details, actor=f"claude-mcp:{os.environ.get('USER', 'analyst')}")


def _helper(*args: str) -> dict[str, Any]:
    p = subprocess.run([*HELPER_CMD, *args], capture_output=True, text=True, timeout=3600)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": (p.stderr or p.stdout).strip()[-2000:]}


def _allowed_roots(case_id: str) -> list[Path]:
    return [(CASES / case_id).resolve(), (MNT / case_id).resolve(), Path("/opt/forensics").resolve()]


def _inside(path: Path, roots: list[Path]) -> bool:
    rp = path.resolve()
    return any(rp == r or r in rp.parents for r in roots)


def _check_args(case_id: str, tool: str, args: list[str], cwd: Path) -> None:
    roots = _allowed_roots(case_id)
    banned = catalog.FORBIDDEN_ARGS.get(tool, set())
    for a in args:
        if tool == "sqlite3":
            if any(b in a for b in banned):
                raise ValueError(f"argument not allowed for sqlite3: {a}")
        elif a in banned:
            raise ValueError(f"argument {a} not allowed for {tool}")
        # Any absolute path, including inside --opt=/path, must stay in this case.
        for m in re.findall(r"(/[^\s,;:=]+)", a):
            if m.startswith(("/cases", "/mnt", "/home", "/root", "/etc", "/var", "/tmp")) and not _inside(Path(m), roots):
                raise ValueError(f"path {m} is outside case {case_id}; tools may only touch this case and /opt/forensics")
        if ".." in Path(a.split("=", 1)[-1]).parts and not _inside(cwd / a.split("=", 1)[-1], roots):
            raise ValueError(f"relative path {a} escapes case {case_id}")


def _rel_or_abs(case_dir: Path, path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (case_dir / path)


def _sha256(path: Path) -> str:
    return custody.hash_file(path, ("sha256",))["sha256"]


# ------------------------------------------------------------------ cases
@mcp.tool()
def case_open(case_id: str, client: str = "", summary: str = "") -> dict[str, Any]:
    """Create (or reopen) a case workspace at /cases/<case_id> with evidence/, work/, reports/, notes/.
    Use the Vendetta case number as case_id, for example VCD-IR-2026-445-IFB."""
    res = _helper("case-init", case_id)
    if not res.get("ok"):
        return res
    meta = CASES / case_id / "notes" / "case.json"
    if res.get("created") or not meta.exists():
        meta.write_text(json.dumps({"case_id": case_id, "client": client, "summary": summary, "opened": custody.utc_now()}, indent=2))
    _audit(case_id, "case_open", {"client": client, "summary": summary, "created": res.get("created")})
    return {**res, "next": "intake_list to see what has been uploaded, then evidence_pull"}


@mcp.tool()
def case_list() -> list[dict[str, Any]]:
    """List cases on this workstation with evidence count."""
    rows = []
    if CASES.exists():
        for d in sorted(CASES.iterdir()):
            if (d / "evidence").is_dir():
                meta = d / "notes" / "case.json"
                info = json.loads(meta.read_text()) if meta.exists() else {}
                rows.append({"case_id": d.name, "client": info.get("client", ""), "evidence_items": sum(1 for p in (d / "evidence").rglob("*") if p.is_file())})
    return rows


@mcp.tool()
def case_status(case_id: str) -> dict[str, Any]:
    """Evidence with acquisition hashes, current mounts, findings count and log integrity for a case."""
    d = _case(case_id)
    acquired = []
    cust = d / "custody.jsonl"
    if cust.exists():
        for line in cust.read_text().splitlines():
            e = json.loads(line)
            if e["action"] == "evidence_acquired":
                det = e["details"]
                acquired.append({"path": det["path"], "sha256": det["sha256"], "md5": det["md5"], "size": det["size"], "source": det["source"], "acquired": e["ts"]})
    findings = d / "notes" / "findings.jsonl"
    return {
        "case_id": case_id,
        "evidence": acquired,
        "mounts": _helper("mounts", case_id).get("mounts", []),
        "findings": sum(1 for _ in findings.open()) if findings.exists() else 0,
        "custody_log": custody.verify(cust),
        "audit_log": custody.verify(d / "audit.jsonl"),
    }


# ------------------------------------------------------------------ evidence
@mcp.tool()
def intake_list(case_id: str) -> dict[str, Any]:
    """List objects uploaded to s3://<evidence bucket>/intake/<case_id>/ that can be pulled."""
    _case(case_id)
    bucket = _conf().get("EVIDENCE_BUCKET")
    if not bucket:
        return {"ok": False, "error": "EVIDENCE_BUCKET not configured"}
    import boto3

    s3 = boto3.client("s3")
    items = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"intake/{case_id}/"):
        for o in page.get("Contents", []):
            items.append({"key": o["Key"], "size": o["Size"], "last_modified": o["LastModified"].isoformat()})
    return {"ok": True, "bucket": bucket, "items": items}


@mcp.tool()
def evidence_pull(case_id: str, s3_key: str) -> dict[str, Any]:
    """Copy evidence from intake/<case_id>/ into the case as read-only, hashing MD5/SHA-1/SHA-256 and
    recording the S3 version in the custody log. A key ending in / pulls everything under that prefix.
    Existing evidence is never overwritten."""
    _case(case_id)
    res = _helper("pull", case_id, s3_key)
    _audit(case_id, "evidence_pull", {"s3_key": s3_key, "ok": res.get("ok"), "items": [{k: i.get(k) for k in ("path", "sha256", "ok", "error")} for i in res.get("items", [])]})
    return res


@mcp.tool()
def evidence_verify(case_id: str, relative_path: str) -> dict[str, Any]:
    """Re-hash an evidence file and compare with the SHA-256 recorded at acquisition."""
    d = _case(case_id)
    target = (d / "evidence" / relative_path).resolve()
    if not _inside(target, [(d / "evidence").resolve()]) or not target.is_file():
        return {"ok": False, "error": "not an evidence file in this case"}
    recorded = None
    for line in (d / "custody.jsonl").read_text().splitlines():
        e = json.loads(line)
        if e["action"] == "evidence_acquired" and Path(e["details"]["path"]).resolve() == target:
            recorded = e["details"]["sha256"]
    now = _sha256(target)
    res = {"ok": recorded == now, "path": str(target), "recorded_sha256": recorded, "current_sha256": now}
    _audit(case_id, "evidence_verify", res)
    return res


@mcp.tool()
def evidence_mount(case_id: str, evidence_name: str) -> dict[str, Any]:
    """Mount a disk image (E01/Ex01, raw/dd/img/001, VMDK/VHD/VHDX/QCOW2) read-only under
    /mnt/fw/<case_id>/<name>/. Returns each partition's mountpoint and the raw image path for TSK."""
    _case(case_id)
    res = _helper("mount", case_id, evidence_name)
    _audit(case_id, "evidence_mount", {"evidence": evidence_name, "ok": res.get("ok"), "mounts": res.get("mounts"), "skipped": res.get("skipped")})
    return res


@mcp.tool()
def evidence_unmount(case_id: str, evidence_name: str) -> dict[str, Any]:
    """Unmount a previously mounted image."""
    _case(case_id)
    res = _helper("umount", case_id, evidence_name)
    _audit(case_id, "evidence_unmount", {"evidence": evidence_name, "ok": res.get("ok")})
    return res


# ------------------------------------------------------------------ analysis
@mcp.tool()
def tool_catalog(category: str = "") -> list[dict[str, Any]]:
    """Free DFIR tools available to run_tool, with install status and usage hints.
    Categories: disk, memory, windows, detection, timeline, malware, files, network, text, collection."""
    rows = catalog.available()
    return [r for r in rows if not category or r["category"] == category]


@mcp.tool()
def run_tool(case_id: str, tool: str, args: list[str], output_name: str = "", timeout_sec: int = 1800, workdir: str = "work") -> dict[str, Any]:
    """Run one allowlisted tool (see tool_catalog) with args as a list, no shell. cwd is
    /cases/<case_id>/<workdir>. stdout is saved to work/runs/ (or work/<output_name> when given) and
    hashed; the first part is returned inline. Paths in args must stay inside this case, its mounts,
    or /opt/forensics. Redirection and pipes are not available; use output_name and follow with
    read_output or search_output."""
    d = _case(case_id)
    if tool not in catalog.TOOLS:
        return {"ok": False, "error": f"{tool} is not allowlisted; see tool_catalog"}
    cwd = (d / workdir).resolve()
    _check_args(case_id, tool, args, cwd)
    exe = catalog.resolve(tool)
    if not exe:
        return {"ok": False, "error": f"{tool} is allowlisted but not installed on this workstation"}
    if not _inside(cwd, [(d / "work").resolve(), (d / "reports").resolve()]):
        return {"ok": False, "error": "workdir must be work or reports (or a folder inside them)"}
    cwd.mkdir(parents=True, exist_ok=True)
    runs = d / "work" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if output_name:
        if "/" in output_name or output_name.startswith("."):
            return {"ok": False, "error": "output_name is a file name, not a path"}
        out_path = d / "work" / output_name
        if out_path.exists():
            return {"ok": False, "error": f"{output_name} exists; choose a new name so earlier output is preserved"}
    else:
        out_path = runs / f"{stamp}_{tool}.out"
    err_path = runs / f"{stamp}_{tool}.err"
    env = {**os.environ, "PATH": os.pathsep.join(catalog.EXTRA_PATH), "TZ": "UTC", "DOTNET_ROLL_FORWARD": "Major"}
    started = time.time()
    with out_path.open("wb") as fo, err_path.open("wb") as fe:
        try:
            p = subprocess.run([exe, *args], cwd=cwd, stdout=fo, stderr=fe, stdin=subprocess.DEVNULL, timeout=timeout_sec, env=env)
            rc = p.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            rc, timed_out = -9, True
    elapsed = round(time.time() - started, 1)
    stdout_head = out_path.read_bytes()[:MAX_INLINE].decode("utf-8", "replace")
    stderr_tail = err_path.read_bytes()[-4000:].decode("utf-8", "replace")
    result = {
        "ok": rc == 0,
        "returncode": rc,
        "timed_out": timed_out,
        "seconds": elapsed,
        "stdout_file": str(out_path),
        "stdout_bytes": out_path.stat().st_size,
        "stdout_sha256": _sha256(out_path),
        "stderr_file": str(err_path),
        "stdout_head": stdout_head,
        "stdout_truncated": out_path.stat().st_size > MAX_INLINE,
        "stderr_tail": stderr_tail,
    }
    _audit(case_id, "run_tool", {"tool": tool, "exe": exe, "args": args, "cwd": str(cwd), **{k: result[k] for k in ("returncode", "timed_out", "seconds", "stdout_file", "stdout_sha256", "stdout_bytes")}})
    return result


@mcp.tool()
def read_output(case_id: str, path: str, offset_lines: int = 0, max_lines: int = 200) -> dict[str, Any]:
    """Page through a text file in this case (outputs, CSVs, notes) or under its mounts. Relative paths
    are taken from /cases/<case_id>."""
    d = _case(case_id)
    p = _rel_or_abs(d, path)
    if not _inside(p, _allowed_roots(case_id)) or not p.is_file():
        return {"ok": False, "error": "file not found inside this case"}
    lines = []
    total = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            total = i + 1
            if offset_lines <= i < offset_lines + max(1, min(max_lines, 2000)):
                lines.append(line.rstrip("\n")[:4000])
    return {"ok": True, "path": str(p), "offset": offset_lines, "returned": len(lines), "total_lines": total, "lines": lines}


@mcp.tool()
def search_output(case_id: str, path: str, pattern: str, ignore_case: bool = True, max_matches: int = 200) -> dict[str, Any]:
    """Regex search one file in this case and return matching lines with line numbers."""
    d = _case(case_id)
    p = _rel_or_abs(d, path)
    if not _inside(p, _allowed_roots(case_id)) or not p.is_file():
        return {"ok": False, "error": "file not found inside this case"}
    rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    hits = []
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if rx.search(line):
                hits.append({"line": n, "text": line.rstrip("\n")[:2000]})
                if len(hits) >= max_matches:
                    break
    return {"ok": True, "path": str(p), "matches": hits, "capped": len(hits) >= max_matches}


# ------------------------------------------------------------------ findings and export
@mcp.tool()
def finding_add(case_id: str, title: str, detail: str, source_artifacts: list[str], event_time_utc: str = "", severity: str = "info", confidence: str = "confirmed", mitre: list[str] | None = None) -> dict[str, Any]:
    """Record a finding. source_artifacts must name the evidence or output files (and row, offset or
    record id) the finding rests on. confidence is confirmed (directly shown by an artifact) or
    assessed (an inference across artifacts); state which. Times in UTC ISO 8601."""
    d = _case(case_id)
    if not source_artifacts:
        return {"ok": False, "error": "a finding needs at least one source artifact"}
    if confidence not in ("confirmed", "assessed"):
        return {"ok": False, "error": "confidence must be confirmed or assessed"}
    row = {
        "id": f"F{int(time.time() * 1000)}",
        "recorded": custody.utc_now(),
        "title": title,
        "detail": detail,
        "event_time_utc": event_time_utc,
        "severity": severity,
        "confidence": confidence,
        "mitre": mitre or [],
        "source_artifacts": source_artifacts,
        "analyst_review": "pending",
    }
    with (d / "notes" / "findings.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    _audit(case_id, "finding_add", row)
    return {"ok": True, **row}


@mcp.tool()
def findings_list(case_id: str) -> list[dict[str, Any]]:
    """All findings for a case in the order recorded."""
    p = _case(case_id) / "notes" / "findings.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


@mcp.tool()
def audit_verify(case_id: str) -> dict[str, Any]:
    """Verify the hash chains of the custody and audit logs for a case."""
    d = _case(case_id)
    return {"custody": custody.verify(d / "custody.jsonl"), "audit": custody.verify(d / "audit.jsonl")}


@mcp.tool()
def case_export(case_id: str, include_work: bool = True) -> dict[str, Any]:
    """Package notes, reports, custody and audit logs (and work/ unless include_work is false) into a
    tar.gz with a SHA-256 manifest, and upload it to s3://<bucket>/cases/<case_id>/exports/.
    Evidence itself is not re-uploaded; it already sits under Object Lock in intake/."""
    d = _case(case_id)
    bucket = _conf().get("EVIDENCE_BUCKET")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    parts = ["notes", "reports", "custody.jsonl", "audit.jsonl"] + (["work"] if include_work else [])
    manifest = []
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for part in parts:
            base = d / part
            if not base.exists():
                continue
            files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
            for fp in files:
                rel = fp.relative_to(d).as_posix()
                manifest.append({"path": rel, "sha256": _sha256(fp), "size": fp.stat().st_size})
                tar.add(fp, arcname=f"{case_id}/{rel}")
        mbytes = json.dumps({"case_id": case_id, "exported": custody.utc_now(), "files": manifest, "audit_head": custody.verify(d / "audit.jsonl").get("head"), "custody_head": custody.verify(d / "custody.jsonl").get("head")}, indent=2).encode()
        info = tarfile.TarInfo(f"{case_id}/MANIFEST.json")
        info.size = len(mbytes)
        tar.addfile(info, io.BytesIO(mbytes))
    data = buf.getvalue()
    local = d / "reports" / f"export_{stamp}.tar.gz"
    local.write_bytes(data)
    sha = _sha256(local)
    result: dict[str, Any] = {"ok": True, "local": str(local), "sha256": sha, "files": len(manifest)}
    if bucket:
        import boto3

        key = f"cases/{case_id}/exports/{stamp}.tar.gz"
        resp = boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=data, ChecksumAlgorithm="SHA256", Metadata={"sha256": sha})
        result.update({"s3": f"s3://{bucket}/{key}", "s3_version_id": resp.get("VersionId")})
    _audit(case_id, "case_export", result)
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
