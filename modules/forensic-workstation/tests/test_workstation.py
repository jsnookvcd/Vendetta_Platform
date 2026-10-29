"""End-to-end tests for custody logging, fw-helper and the MCP tools.

fw-helper runs as a subprocess with a fake `aws` CLI that serves objects from a
local folder, so the intake, hashing and custody path is exercised without AWS.
Mounting needs real block devices and is not covered here.
"""

import grp
import hashlib
import json
import os
import pwd
import stat
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE / "mcp"))

FAKE_AWS = r'''#!/usr/bin/env python3
import json, os, shutil, sys, hashlib
root = os.environ["FAKE_S3_ROOT"]
a = sys.argv[1:]
def opt(name):
    return a[a.index(name) + 1] if name in a else None
key = opt("--key"); prefix = opt("--prefix")
if a[:2] == ["s3api", "head-object"]:
    p = os.path.join(root, key)
    print(json.dumps({"ContentLength": os.path.getsize(p), "ETag": '"etag"', "VersionId": "v1", "LastModified": "2026-10-29T00:00:00Z", "ObjectLockMode": "GOVERNANCE"}))
elif a[:2] == ["s3api", "get-object"]:
    shutil.copy(os.path.join(root, key), a[-1]); print("{}")
elif a[:2] == ["s3api", "list-objects-v2"]:
    out = []
    for d, _, fs in os.walk(os.path.join(root, prefix)):
        for f in fs:
            out.append({"Key": os.path.relpath(os.path.join(d, f), root)})
    print(json.dumps({"Contents": out}))
'''


@pytest.fixture()
def env(tmp_path, monkeypatch):
    cases, s3, central, bindir = tmp_path / "cases", tmp_path / "s3", tmp_path / "central", tmp_path / "bin"
    for p in (cases, s3, central, bindir):
        p.mkdir()
    (bindir / "aws").write_text(FAKE_AWS)
    (bindir / "aws").chmod(0o755)
    conf = tmp_path / "fw.env"
    conf.write_text("EVIDENCE_BUCKET=test-bucket\n")
    me = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    env = {
        "FW_CASES_ROOT": str(cases), "FW_MOUNT_ROOT": str(tmp_path / "mnt"), "FW_STATE_DIR": str(tmp_path / "state"),
        "FW_CENTRAL_LOG_DIR": str(central), "FW_ANALYST_USER": me, "FW_GROUP": group, "FW_TEST": "1",
        "FW_LIB": str(MODULE / "mcp"), "FAKE_S3_ROOT": str(s3), "FW_CONF": str(conf),
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FW_HELPER_CMD": f"/usr/bin/python3 -I {MODULE / 'mcp' / 'fw-helper'}",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # fw-helper reads its config from a fixed path; point it at the test file.
    helper_src = (MODULE / "mcp" / "fw-helper").read_text().replace('Path("/etc/forensic-workstation.env")', f'Path("{conf}")')
    helper = tmp_path / "fw-helper"
    helper.write_text(helper_src)
    monkeypatch.setenv("FW_HELPER_CMD", f"/usr/bin/python3 -I {helper}")
    import importlib
    from fw_forensics import custody, server
    importlib.reload(custody)
    importlib.reload(server)
    return {"cases": cases, "s3": s3, "central": central, "server": server, "custody": custody}


def _upload(s3: Path, key: str, data: bytes) -> str:
    p = s3 / key
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_full_case_flow(env):
    srv, cases = env["server"], env["cases"]
    res = srv.case_open("VCD-IR-TEST-001", client="Test CU", summary="BEC")
    assert res["ok"] and res["created"]
    ev = cases / "VCD-IR-TEST-001" / "evidence"
    assert oct(ev.stat().st_mode & 0o777) == "0o750"

    sha = _upload(env["s3"], "intake/VCD-IR-TEST-001/HOST01/Security.evtx", b"EVTX" * 1000)
    _upload(env["s3"], "intake/VCD-IR-TEST-001/HOST01/System.evtx", b"SYS" * 10)
    pulled = srv.evidence_pull("VCD-IR-TEST-001", "intake/VCD-IR-TEST-001/HOST01/")
    assert pulled["ok"], pulled
    assert len(pulled["items"]) == 2
    target = ev / "HOST01" / "Security.evtx"
    assert target.exists() and stat.S_IMODE(target.stat().st_mode) == 0o440
    assert next(i for i in pulled["items"] if i["path"] == str(target))["sha256"] == sha

    again = srv.evidence_pull("VCD-IR-TEST-001", "intake/VCD-IR-TEST-001/HOST01/Security.evtx")
    assert not again["ok"] and "never overwritten" in again["items"][0]["error"]

    assert srv.evidence_verify("VCD-IR-TEST-001", "HOST01/Security.evtx")["ok"]

    run = srv.run_tool("VCD-IR-TEST-001", "sha256sum", [str(target)])
    assert run["ok"] and sha in run["stdout_head"]
    named = srv.run_tool("VCD-IR-TEST-001", "ls", ["-la", str(ev)], output_name="evidence_listing.txt")
    assert named["ok"] and Path(named["stdout_file"]).name == "evidence_listing.txt"
    assert not srv.run_tool("VCD-IR-TEST-001", "ls", [], output_name="evidence_listing.txt")["ok"]

    page = srv.read_output("VCD-IR-TEST-001", "work/evidence_listing.txt", max_lines=5)
    assert page["ok"] and page["returned"] >= 1
    hits = srv.search_output("VCD-IR-TEST-001", "work/evidence_listing.txt", r"HOST01")
    assert hits["matches"]

    f = srv.finding_add("VCD-IR-TEST-001", "Logon from foreign IP", "4624 type 10 from 203.0.113.9",
                        ["evidence/HOST01/Security.evtx record 1234"], event_time_utc="2026-10-01T03:04:05Z")
    assert f["ok"]
    assert not srv.finding_add("VCD-IR-TEST-001", "x", "y", [])["ok"]
    assert len(srv.findings_list("VCD-IR-TEST-001")) == 1

    status = srv.case_status("VCD-IR-TEST-001")
    assert len(status["evidence"]) == 2 and status["findings"] == 1
    assert status["custody_log"]["ok"] and status["audit_log"]["ok"]

    srv._conf = lambda: {}  # export locally, no S3
    exp = srv.case_export("VCD-IR-TEST-001")
    assert exp["ok"] and Path(exp["local"]).exists() and exp["files"] >= 4

    # every action was mirrored centrally
    assert (env["central"] / "audit.jsonl").read_text().count("\n") >= 8


def test_tool_guardrails(env):
    srv, cases = env["server"], env["cases"]
    srv.case_open("CASE-A")
    srv.case_open("CASE-B")
    other = cases / "CASE-B" / "notes" / "case.json"
    with pytest.raises(ValueError):
        srv.run_tool("CASE-A", "file", [str(other)])
    with pytest.raises(ValueError):
        srv.run_tool("CASE-A", "file", ["../../CASE-B/notes/case.json"])
    with pytest.raises(ValueError):
        srv.run_tool("CASE-A", "find", [".", "-delete"])
    with pytest.raises(ValueError):
        srv.run_tool("CASE-A", "sqlite3", ["x.db", ".shell id"])
    assert not srv.run_tool("CASE-A", "bash", ["-c", "id"])["ok"]
    assert not srv.run_tool("CASE-A", "ls", [], workdir="evidence")["ok"]
    assert not srv.read_output("CASE-A", str(other))["ok"]
    with pytest.raises(ValueError):
        srv.case_status("../etc")
    assert not srv.evidence_pull("CASE-A", "intake/CASE-B/x.E01")["ok"]


def test_chain_detects_tampering(env, tmp_path):
    custody = env["custody"]
    log = tmp_path / "audit.jsonl"
    for i in range(5):
        custody.append(log, "step", "C1", {"i": i})
    assert custody.verify(log) == {**custody.verify(log), "ok": True, "entries": 5}

    lines = log.read_text().splitlines()
    edited = json.loads(lines[2]); edited["details"]["i"] = 99
    log.write_text("\n".join(lines[:2] + [json.dumps(edited)] + lines[3:]) + "\n")
    r = custody.verify(log)
    assert not r["ok"] and r["break_at_line"] == 3 and "modified" in r["reason"]

    log.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    r = custody.verify(log)
    assert not r["ok"] and "removed" in r["reason"]


def test_catalog_hints_cover_every_tool():
    from fw_forensics import catalog
    assert all(meta["hint"] and meta["cat"] for meta in catalog.TOOLS.values())
    assert catalog.resolve("bash") is None
