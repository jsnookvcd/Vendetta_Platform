"""Unit tests of the Sigma compiler and matcher on hand built OCSF events."""
import copy

import pytest
import yaml

from app import sigma
from app.sigma import SigmaError


def R(detection, logsource=None, **top):
    doc = {"title": "Test rule", "logsource": logsource if logsource is not None else {}, "detection": detection}
    doc.update(top)
    return sigma.compile(yaml.safe_dump(doc, sort_keys=False))


def proc(cmd="", name="cmd.exe", path=None, **extra):
    ev = {
        "class_uid": 1007, "activity_id": 1, "time": 1760000000000, "severity_id": 1,
        "metadata": {"product": {"name": "Falcon", "vendor_name": "CrowdStrike"}, "log_name": "crowdstrike_fdr",
                     "tenant_uid": "t1"},
        "process": {"name": name, "cmd_line": cmd,
                    "file": {"name": name, "path": path or f"C:\\Windows\\System32\\{name}",
                             "hashes": [{"algorithm": "SHA-256", "value": "aa" * 32},
                                        {"algorithm": "MD5", "value": "bb" * 16}]},
                    "parent_process": {"cmd_line": "explorer.exe", "file": {"path": "C:\\Windows\\explorer.exe"}}},
        "device": {"hostname": "WS01"},
        "actor": {"user": {"name": "alice"}},
    }
    ev.update(extra)
    return ev


def auth(user="bob", ip="203.0.113.9", ok=False, log="entra_signins", **extra):
    ev = {
        "class_uid": 3002, "activity_id": 1, "time": 1760000000000, "severity_id": 2,
        "status_id": 1 if ok else 2,
        "metadata": {"product": {"name": "Entra ID", "vendor_name": "Microsoft"}, "log_name": log,
                     "tenant_uid": "t1"},
        "user": {"name": user}, "src_endpoint": {"ip": ip, "port": 443},
        "dst_endpoint": {"ip": "10.0.0.5", "port": 443, "hostname": "login.example"},
        "unmapped": {"risk_level": "none"},
    }
    ev.update(extra)
    return ev


def api(op, service="cloudtrail.amazonaws.com", log="cloudtrail", **extra):
    ev = {
        "class_uid": 6003, "activity_id": 99, "time": 1760000000000, "severity_id": 1,
        "metadata": {"product": {"name": "CloudTrail", "vendor_name": "AWS"}, "log_name": log, "tenant_uid": "t1"},
        "api": {"operation": op, "service": {"name": service}},
        "actor": {"user": {"name": "deploy", "type": "IAMUser"}},
    }
    ev.update(extra)
    return ev


# ---------------------------------------------------------------- metadata
def test_basic_metadata_and_mitre():
    r = R({"sel": {"process.cmd_line": "x"}, "condition": "sel"},
          id="11111111-2222-3333-4444-555555555555", level="critical", status="test", description="d",
          tags=["attack.execution", "attack.t1059.001", "attack.T1003", "attack.t1059.001", "cve.2021-1"],
          fields=["process.cmd_line"])
    assert r.id == "11111111-2222-3333-4444-555555555555"
    assert r.level == "critical" and r.status == "test" and r.description == "d"
    assert r.mitre == ("T1059.001", "T1003")
    assert r.tags[0] == "attack.execution"
    assert r.fields == ("process.cmd_line",)
    assert r.timeframe_seconds == 0 and r.threshold is None
    assert r.logsource == {}


def test_id_slug_from_title():
    r = sigma.compile("title: 'Weird Title: with/slashes & spaces!!'\nlogsource: {}\n"
                      "detection: {s: {a: 1}, condition: s}\n")
    assert r.id == "weird-title-with-slashes-spaces"
    long = sigma.compile("title: " + "a" * 200 + "\nlogsource: {}\ndetection: {s: {a: 1}, condition: s}\n")
    assert len(long.id) == 80


def test_invalid_id_rejected():
    with pytest.raises(SigmaError, match="id"):
        R({"s": {"a": 1}, "condition": "s"}, id="bad id; drop table")
    with pytest.raises(SigmaError, match="id"):
        R({"s": {"a": 1}, "condition": "s"}, id="x" * 81)


def test_defaults_level_status():
    r = R({"s": {"a": 1}, "condition": "s"})
    assert r.level == "medium" and r.status == "experimental"


@pytest.mark.parametrize("level,sev", [("informational", "low"), ("low", "low"), ("medium", "medium"),
                                       ("high", "high"), ("critical", "critical")])
def test_severity_mapping(level, sev):
    assert R({"s": {"a": 1}, "condition": "s"}, level=level).severity() == sev


def test_bad_level_and_status():
    with pytest.raises(SigmaError, match="level"):
        R({"s": {"a": 1}, "condition": "s"}, level="urgent")
    with pytest.raises(SigmaError, match="status"):
        R({"s": {"a": 1}, "condition": "s"}, status="bogus")


def test_rule_is_hashable_and_frozen():
    r = R({"s": {"a": 1}, "condition": "s"})
    assert hash(r) == hash(r.id)
    with pytest.raises(Exception):
        r.title = "x"


# ---------------------------------------------------------------- values
def test_plain_string_case_insensitive_exact():
    r = R({"s": {"process.file.name": "CMD.EXE"}, "condition": "s"})
    assert r.matches(proc(name="cmd.exe"))
    assert not r.matches(proc(name="cmd.exe.bak"))


def test_wildcards():
    r = R({"s": {"process.file.name": "p?wer*.exe"}, "condition": "s"})
    assert r.matches(proc(name="powershell.exe"))
    assert r.matches(proc(name="PxWER.exe"))
    assert not r.matches(proc(name="pwershell.exe"))
    assert not r.matches(proc(name="powershell.exe2"))


def test_wildcard_escaping():
    r = R({"s": {"process.cmd_line": r"a\*b"}, "condition": "s"})
    assert r.matches(proc("a*b"))
    assert not r.matches(proc("axxb"))
    r = R({"s": {"process.cmd_line": r"a\?b"}, "condition": "s"})
    assert r.matches(proc("a?b"))
    assert not r.matches(proc("axb"))
    r = R({"s": {"process.cmd_line": "C:\\\\dir\\*"}, "condition": "s"})  # \\ then \* in Sigma
    assert r.matches(proc("C:\\dir*"))
    r = R({"s": {"process.cmd_line": "C:\\Windows\\x"}, "condition": "s"})  # lone backslash is literal
    assert r.matches(proc("c:\\windows\\X"))


def test_regex_metacharacters_are_literal():
    r = R({"s": {"process.cmd_line|contains": "a.b(c)[d]+"}, "condition": "s"})
    assert r.matches(proc("xx a.b(c)[d]+ yy"))
    assert not r.matches(proc("aXb(c)[d]+"))


def test_numbers_numeric_or_string():
    r = R({"s": {"dst_endpoint.port": 443}, "condition": "s"})
    assert r.matches(auth())
    ev = auth()
    ev["dst_endpoint"]["port"] = "443"
    assert r.matches(ev)
    ev["dst_endpoint"]["port"] = 443.0
    assert r.matches(ev)
    ev["dst_endpoint"]["port"] = 80
    assert not r.matches(ev)
    r = R({"s": {"dst_endpoint.port": "443"}, "condition": "s"})
    assert r.matches(auth())


def test_booleans():
    r = R({"s": {"is_mfa": True}, "condition": "s"})
    assert r.matches(auth(is_mfa=True))
    assert r.matches(auth(is_mfa="TRUE"))
    assert not r.matches(auth(is_mfa=False))
    assert not r.matches(auth(is_mfa=1))
    assert not r.matches(auth())


def test_null_means_absent():
    r = R({"s": {"process.cmd_line": None}, "condition": "s"})
    ev = proc()
    del ev["process"]["cmd_line"]
    assert r.matches(ev)
    assert not r.matches(proc("x"))
    r = R({"s": {"process.cmd_line": [None, "abc"]}, "condition": "s"})
    assert r.matches(ev) and r.matches(proc("ABC")) and not r.matches(proc("x"))


def test_absent_field_does_not_match_values():
    r = R({"s": {"nothing.here": "*"}, "condition": "s"})
    assert not r.matches(proc())


def test_value_list_is_or_and_all():
    r = R({"s": {"process.cmd_line|contains": ["foo", "bar"]}, "condition": "s"})
    assert r.matches(proc("a foo")) and r.matches(proc("a bar")) and not r.matches(proc("baz"))
    r = R({"s": {"process.cmd_line|contains|all": ["foo", "bar"]}, "condition": "s"})
    assert r.matches(proc("bar and foo")) and not r.matches(proc("a foo"))
    r = R({"s": {"process.cmd_line|all|contains": ["foo", "bar"]}, "condition": "s"})
    assert r.matches(proc("foobar"))


def test_map_keys_are_and():
    r = R({"s": {"process.file.name": "cmd.exe", "device.hostname": "ws01"}, "condition": "s"})
    assert r.matches(proc())
    ev = proc()
    ev["device"]["hostname"] = "ws02"
    assert not r.matches(ev)


def test_list_of_maps_is_or():
    r = R({"s": [{"process.file.name": "a.exe"}, {"device.hostname": "WS01"}], "condition": "s"})
    assert r.matches(proc(name="cmd.exe"))
    ev = proc(name="a.exe")
    ev["device"]["hostname"] = "x"
    assert r.matches(ev)
    ev["process"]["file"]["name"] = "b.exe"
    assert not r.matches(ev)


def test_list_fan_out():
    r = R({"s": {"process.file.hashes.value": "bb" * 16}, "condition": "s"})
    assert r.matches(proc())
    r = R({"s": {"privileges": "Global Administrator"}, "condition": "s"})
    assert r.matches(auth(privileges=["Reader", "Global Administrator"]))
    assert not r.matches(auth(privileges=["Reader"]))
    r = R({"s": {"unmapped.targets.name|endswith": "admin"}, "condition": "s"})
    ev = auth()
    ev["unmapped"]["targets"] = [{"name": "x"}, {"name": "superadmin"}]
    assert r.matches(ev)


def test_all_with_fan_out_each_value_some_element():
    r = R({"s": {"privileges|all": ["A", "B"]}, "condition": "s"})
    assert r.matches(auth(privileges=["B", "C", "A"]))
    assert not r.matches(auth(privileges=["A", "C"]))


def test_dict_leaf_matches_as_json_text():
    r = R({"s": {"unmapped.parameters|contains": "ForwardTo"}, "condition": "s"})
    ev = auth()
    ev["unmapped"]["parameters"] = [{"Name": "Identity", "Value": "x"}, {"Name": "ForwardTo", "Value": "e@x.io"}]
    assert r.matches(ev)
    ev["unmapped"]["parameters"] = "-Name x -ForwardTo e@x.io"
    assert r.matches(ev)
    ev["unmapped"]["parameters"] = [{"Name": "Identity", "Value": "x"}]
    assert not r.matches(ev)


def test_date_values_become_strings():
    r = sigma.compile("title: t\nlogsource: {}\ndetection:\n  s: {day: 2026-10-19}\n  condition: s\n")
    assert r.matches({"day": "2026-10-19"})


# ---------------------------------------------------------------- modifiers
def test_contains_startswith_endswith():
    c = R({"s": {"process.cmd_line|contains": "DELETE"}, "condition": "s"})
    s = R({"s": {"process.cmd_line|startswith": "vss"}, "condition": "s"})
    e = R({"s": {"process.cmd_line|endswith": "quiet"}, "condition": "s"})
    ev = proc("VSSadmin delete shadows /all /QUIET")
    assert c.matches(ev) and s.matches(ev) and e.matches(ev)
    ev2 = proc("x vssadmin quiet y")
    assert not s.matches(ev2) and not e.matches(ev2) and not c.matches(ev2)


def test_contains_with_inner_wildcard():
    r = R({"s": {"process.cmd_line|contains": "net*user"}, "condition": "s"})
    assert r.matches(proc("cmd /c NET1 USER x")) and not r.matches(proc("user net"))


def test_cased():
    r = R({"s": {"process.cmd_line|contains|cased": "Invoke-"}, "condition": "s"})
    assert r.matches(proc("Invoke-Mimikatz")) and not r.matches(proc("invoke-mimikatz"))
    r = R({"s": {"process.cmd_line|cased": "A*"}, "condition": "s"})
    assert r.matches(proc("Abc")) and not r.matches(proc("abc"))


def test_re_case_sensitive_by_default_and_flags():
    r = R({"s": {"process.cmd_line|re": r"Mimi[a-z]+"}, "condition": "s"})
    assert r.matches(proc("run Mimikatz now")) and not r.matches(proc("run mimikatz now"))
    r = R({"s": {"process.cmd_line|re": r"(?i)mimi[a-z]+"}, "condition": "s"})
    assert r.matches(proc("MIMIKATZ"))
    r = R({"s": {"process.cmd_line|re|i": r"^mimi"}, "condition": "s"})
    assert r.matches(proc("MimiKatz"))
    r = R({"s": {"process.cmd_line|re|m": r"^second"}, "condition": "s"})
    assert r.matches(proc("first\nsecond"))
    r = R({"s": {"process.cmd_line|re|s": r"a.b"}, "condition": "s"})
    assert r.matches(proc("a\nb"))


def test_re_matches_numbers_as_text():
    r = R({"s": {"dst_endpoint.port|re": r"^44\d$"}, "condition": "s"})
    assert r.matches(auth())


def test_bad_regex_rejected():
    with pytest.raises(SigmaError, match="invalid regular expression"):
        R({"s": {"process.cmd_line|re": "(unclosed"}, "condition": "s"})


def test_long_regex_rejected():
    with pytest.raises(SigmaError, match="longer than 1024"):
        R({"s": {"process.cmd_line|re": "a" * 1025}, "condition": "s"})


def test_cidr():
    r = R({"s": {"src_endpoint.ip|cidr": ["10.0.0.0/8", "2001:db8::/32"]}, "condition": "s"})
    assert r.matches(auth(ip="10.1.2.3"))
    assert r.matches(auth(ip="2001:db8::1"))
    assert not r.matches(auth(ip="11.0.0.1"))
    assert not r.matches(auth(ip="not an ip"))
    with pytest.raises(SigmaError, match="invalid network"):
        R({"s": {"src_endpoint.ip|cidr": "10.0.0.0/33"}, "condition": "s"})


def test_exists():
    t = R({"s": {"process.cmd_line|exists": True}, "condition": "s"})
    f = R({"s": {"process.cmd_line|exists": False}, "condition": "s"})
    ev = proc("x")
    assert t.matches(ev) and not f.matches(ev)
    del ev["process"]["cmd_line"]
    assert not t.matches(ev) and f.matches(ev)
    with pytest.raises(SigmaError, match="true or false"):
        R({"s": {"process.cmd_line|exists": "yes"}, "condition": "s"})
    with pytest.raises(SigmaError):
        R({"s": {"process.cmd_line|exists|contains": True}, "condition": "s"})


@pytest.mark.parametrize("mod,value,hits,misses", [
    ("gt", 3, [4, "5"], [3, 2]),
    ("gte", 3, [3, 4], [2]),
    ("lt", 3, [2, "1.5"], [3, 4]),
    ("lte", 3, [3, 2], [4]),
])
def test_numeric_comparisons(mod, value, hits, misses):
    r = R({"s": {f"severity_id|{mod}": value}, "condition": "s"})
    for h in hits:
        assert r.matches(auth(severity_id=h)), h
    for m in misses:
        assert not r.matches(auth(severity_id=m)), m
    assert not r.matches(auth(severity_id="high"))
    assert not r.matches(auth(severity_id=True))


def test_numeric_needs_number():
    with pytest.raises(SigmaError, match="needs a number"):
        R({"s": {"severity_id|gt": "abc"}, "condition": "s"})
    with pytest.raises(SigmaError):
        R({"s": {"severity_id|gt|lt": 3}, "condition": "s"})


def test_windash():
    r = R({"s": {"process.cmd_line|windash|contains": " -enc "}, "condition": "s"})
    for cmd in ("powershell -enc AAA", "powershell /enc AAA", "powershell \u2013enc AAA",
                "powershell \u2014enc AAA", "powershell \u2015enc AAA"):
        assert r.matches(proc(cmd)), cmd
    assert not r.matches(proc("powershell xenc AAA"))
    r = R({"s": {"process.cmd_line|windash|contains": "/s"}, "condition": "s"})
    assert r.matches(proc("cmd -s")) and r.matches(proc("cmd /S"))
    # A dash inside a word is left alone.
    r = R({"s": {"process.cmd_line|windash": "a-b"}, "condition": "s"})
    assert r.matches(proc("a-b")) and not r.matches(proc("a/b"))


@pytest.mark.parametrize("mod", ["base64", "base64offset", "utf16le", "wide", "expand", "fieldref"])
def test_unsupported_modifiers(mod):
    with pytest.raises(SigmaError, match="unsupported modifier"):
        R({"s": {f"process.cmd_line|{mod}|contains": "x"}, "condition": "s"})


def test_unknown_modifier_and_bad_combinations():
    with pytest.raises(SigmaError, match="unknown modifier"):
        R({"s": {"process.cmd_line|bogus": "x"}, "condition": "s"})
    with pytest.raises(SigmaError, match="combined"):
        R({"s": {"process.cmd_line|startswith|endswith": "x"}, "condition": "s"})
    with pytest.raises(SigmaError, match="re"):
        R({"s": {"process.cmd_line|re|contains": "x"}, "condition": "s"})
    with pytest.raises(SigmaError, match="sub-modifiers"):
        R({"s": {"process.cmd_line|i": "x"}, "condition": "s"})
    with pytest.raises(SigmaError, match="cidr"):
        R({"s": {"src_endpoint.ip|cidr|contains": "10.0.0.0/8"}, "condition": "s"})


# ---------------------------------------------------------------- keywords
def test_keywords_search_string_values():
    r = R({"kw": ["mimikatz", "sekurlsa::*"], "condition": "kw"})
    assert r.matches(proc("run MIMIKATZ.exe"))
    assert r.matches(proc("x", message="saw sekurlsa::logonpasswords"))
    assert not r.matches(proc("notepad"))


def test_keywords_numbers_and_nested():
    r = R({"kw": [4625], "condition": "kw"})
    ev = auth()
    ev["unmapped"]["event_id"] = 4625
    assert r.matches(ev)
    assert not r.matches(auth())


def test_keyword_with_modifiers():
    r = R({"kw": {"|re": r"lsass\.(exe|dmp)"}, "condition": "kw"})
    assert r.matches(proc("procdump lsass.dmp"))
    assert not r.matches(proc("LSASS.DMP"))
    r = R({"kw": {"|contains|all": ["alpha", "beta"]}, "condition": "kw"})
    assert r.matches(proc("alpha", message="beta"))
    assert not r.matches(proc("alpha"))


def test_keyword_list_errors():
    with pytest.raises(SigmaError, match="mixes"):
        R({"kw": ["a", {"b": 1}], "condition": "kw"})
    with pytest.raises(SigmaError, match="null"):
        R({"kw": ["a", None], "condition": "kw"})


# ---------------------------------------------------------------- field mapping
@pytest.mark.parametrize("sigma_field,value,event", [
    ("Image|endswith", "\\cmd.exe", proc()),
    ("OriginalFileName", "cmd.exe", proc()),
    ("ProcessName", "cmd.exe", proc()),
    ("CommandLine|contains", "whoami", proc("whoami /all")),
    ("ParentImage|endswith", "explorer.exe", proc()),
    ("ParentCommandLine", "explorer.exe", proc()),
    ("User", "alice", proc()),
    ("SubjectUserName", "alice", proc()),
    ("TargetUserName", "bob", auth()),
    ("SourceIp", "203.0.113.9", auth()),
    ("src_ip", "203.0.113.9", auth()),
    ("ClientIP", "203.0.113.9", auth()),
    ("DestinationIp", "10.0.0.5", auth()),
    ("dst_ip", "10.0.0.5", auth()),
    ("DestinationPort", 443, auth()),
    ("dst_port", 443, auth()),
    ("DestinationHostname", "login.example", auth()),
    ("QueryName", "evil.example", {"query": {"hostname": "evil.example"}}),
    ("Hashes", "aa" * 32, proc()),
    ("sha256", "aa" * 32, proc()),
    ("eventName", "StopLogging", api("StopLogging")),
    ("eventSource", "cloudtrail.amazonaws.com", api("StopLogging")),
    ("Operation", "StopLogging", api("StopLogging")),
    ("eventType", "StopLogging", api("StopLogging")),
    ("Computer", "ws01", proc()),
    ("ComputerName", "ws01", proc()),
    ("Hostname", "ws01", proc()),
])
def test_sigma_field_mapping(sigma_field, value, event):
    r = R({"s": {sigma_field: value}, "condition": "s"})
    assert r.matches(event)
    assert not r.matches({"class_uid": 1})


def test_process_name_reads_process_name_too():
    r = R({"s": {"ProcessName": "x.exe"}, "condition": "s"})
    assert r.matches({"process": {"name": "x.exe"}})


def test_unknown_plain_name_reads_top_level_and_unmapped():
    r = R({"s": {"risk_level": "none"}, "condition": "s"})
    assert r.matches(auth())
    r = R({"s": {"status_id": 2}, "condition": "s"})
    assert r.matches(auth())
    assert sigma.resolve_field("risk_level") == ("risk_level", "unmapped.risk_level")
    assert sigma.resolve_field("a.b") == ("a.b",)


def test_invalid_field_name():
    with pytest.raises(SigmaError, match="invalid field name"):
        R({"s": {"a b": 1}, "condition": "s"})


# ---------------------------------------------------------------- conditions
def _cond(cond):
    return R({"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1}, "sel_one": {"p": 1}, "sel_two": {"q": 1},
              "_hidden": {"h": 1}, "condition": cond})


def test_condition_and_or_not():
    assert _cond("a and b").matches({"x": 1, "y": 1})
    assert not _cond("a and b").matches({"x": 1})
    assert _cond("a or b").matches({"y": 1})
    assert _cond("not a").matches({"y": 1})
    assert not _cond("not a").matches({"x": 1})
    assert _cond("a and not b").matches({"x": 1})
    assert _cond("not not a").matches({"x": 1})
    assert _cond("A AND b".replace("A", "a")).matches({"x": 1, "y": 1})


def test_condition_precedence():
    # and binds tighter than or: a or (b and c)
    r = _cond("a or b and c")
    assert r.matches({"x": 1})
    assert not r.matches({"y": 1})
    # not binds tighter than and: (not a) and b
    r = _cond("not a and b")
    assert r.matches({"y": 1})
    assert not r.matches({"x": 1, "y": 1})
    assert not r.matches({})


def test_condition_parentheses():
    r = _cond("(a or b) and c")
    assert r.matches({"y": 1, "z": 1})
    assert not r.matches({"x": 1})
    r = _cond("not (a or b)")
    assert r.matches({"z": 1}) and not r.matches({"y": 1})


def test_one_of_and_all_of_patterns():
    assert _cond("1 of sel*").matches({"q": 1})
    assert not _cond("1 of sel*").matches({"x": 1})
    assert _cond("all of sel*").matches({"p": 1, "q": 1})
    assert not _cond("all of sel*").matches({"p": 1})
    assert _cond("1 of a").matches({"x": 1})


def test_them_excludes_underscore():
    assert _cond("1 of them").matches({"x": 1})
    assert not _cond("1 of them").matches({"h": 1})
    assert _cond("all of them").matches({"x": 1, "y": 1, "z": 1, "p": 1, "q": 1})
    assert _cond("1 of _*").matches({"h": 1})


def test_condition_list_is_or():
    r = R({"a": {"x": 1}, "b": {"y": 1}, "condition": ["a", "b"]})
    assert r.matches({"y": 1}) and not r.matches({})


def test_identifier_evaluated_once_per_event_and_short_circuits():
    r = _cond("a or (a and b) or 1 of sel*")
    assert r.matches({"x": 1})


@pytest.mark.parametrize("cond", [
    "__import__('os').system('id')",
    "a; b",
    "a and",
    "or a",
    "(a",
    "a)",
    "a b",
    "1 of",
    "1 of nothing*",
    "2 of a",
    "a*",
    "unknown_ident",
    "a == b",
    "eval(a)",
    "",
    "   ",
    "a and $b",
    "lambda: a",
])
def test_bad_conditions_rejected(cond):
    with pytest.raises(SigmaError):
        _cond(cond)


def test_condition_not_string():
    with pytest.raises(SigmaError, match="condition"):
        R({"a": {"x": 1}, "condition": {"a": 1}})
    with pytest.raises(SigmaError, match="condition"):
        R({"a": {"x": 1}})


def test_condition_length_guard():
    cond = " or ".join(["a"] * 600)
    assert len(cond) > 2000
    with pytest.raises(SigmaError, match="longer than 2000"):
        _cond(cond)


def test_condition_nesting_guard():
    with pytest.raises(SigmaError, match="nests deeper"):
        _cond("(" * 60 + "a" + ")" * 60)
    with pytest.raises(SigmaError, match="nests deeper"):
        _cond("not " * 60 + "a")
    assert _cond("(" * 20 + "a" + ")" * 20).matches({"x": 1})


def test_reserved_and_invalid_identifier_names():
    for name in ("and", "them", "1", "bad-name"):
        with pytest.raises(SigmaError, match="identifier"):
            R({name: {"x": 1}, "condition": "1 of them"})


# ---------------------------------------------------------------- logsource
def test_logsource_process_creation():
    r = R({"s": {"process.file.name": "cmd.exe"}, "condition": "s"}, {"category": "process_creation",
                                                                       "product": "windows"})
    assert r.matches(proc())
    ev = proc()
    ev["activity_id"] = 2
    assert not r.matches(ev)
    ev = proc()
    ev["class_uid"] = 1001
    assert not r.matches(ev)


@pytest.mark.parametrize("ls,event_patch,ok", [
    ({"category": "authentication"}, {"class_uid": 3002}, True),
    ({"category": "authentication"}, {"class_uid": 6003}, False),
    ({"category": "network_connection"}, {"class_uid": 4001}, True),
    ({"category": "firewall"}, {"class_uid": 4001}, True),
    ({"category": "dns"}, {"class_uid": 4003}, True),
    ({"category": "webserver"}, {"class_uid": 4002}, True),
    ({"category": "proxy"}, {"class_uid": 4002}, True),
    ({"category": "proxy"}, {"class_uid": 4001}, False),
    ({"category": "file_event"}, {"class_uid": 1001}, True),
    ({"category": "detection"}, {"class_uid": 2004}, True),
    ({"category": "alert"}, {"class_uid": 2004}, True),
    ({"category": "something_new"}, {"class_uid": 9999}, True),
    ({"product": "aws", "service": "cloudtrail"}, {"class_uid": 6003, "log": "cloudtrail"}, True),
    ({"product": "aws", "service": "cloudtrail"}, {"class_uid": 3002, "log": "cloudtrail"}, True),
    ({"product": "aws", "service": "cloudtrail"}, {"class_uid": 2004, "log": "cloudtrail"}, False),
    ({"product": "aws", "service": "cloudtrail"}, {"class_uid": 6003, "log": "m365_audit"}, False),
    ({"product": "aws"}, {"class_uid": 2004, "log": "guardduty"}, True),
    ({"service": "guardduty"}, {"class_uid": 2004, "log": "guardduty"}, True),
    ({"service": "guardduty"}, {"class_uid": 6003, "log": "guardduty"}, False),
    ({"product": "m365"}, {"class_uid": 6003, "log": "m365_audit"}, True),
    ({"service": "exchange"}, {"class_uid": 6003, "log": "m365_audit"}, True),
    ({"service": "audit"}, {"class_uid": 6003, "log": "cloudtrail"}, False),
    ({"product": "okta"}, {"class_uid": 3005, "log": "okta_system_log"}, True),
    ({"product": "okta"}, {"class_uid": 3002, "log": "entra_signins"}, False),
    ({"service": "okta"}, {"class_uid": 3005, "log": "okta_system_log"}, False),
    ({"product": "azure", "service": "auditlogs"}, {"class_uid": 3005, "log": "entra_audit"}, True),
    ({"product": "azure", "service": "auditlogs"}, {"class_uid": 3002, "log": "entra_signins"}, False),
    ({"product": "azure", "service": "signinlogs"}, {"class_uid": 3002, "log": "entra_signins"}, True),
    ({"product": "entra"}, {"class_uid": 3002, "log": "entra_signins"}, True),
    ({"product": "gcp"}, {"class_uid": 6003, "log": "google_workspace"}, True),
    ({"product": "google_workspace"}, {"class_uid": 6003, "log": "cloudtrail"}, False),
    ({"product": "crowdstrike_fdr"}, {"class_uid": 1007, "log": "crowdstrike_fdr"}, True),
    ({"product": "crowdstrike_fdr"}, {"class_uid": 1007, "log": "sentinelone_threats"}, False),
    ({"service": "huntress_incidents"}, {"class_uid": 2004, "log": "huntress_incidents"}, True),
    ({"product": "cef"}, {"class_uid": 4001, "log": "cef"}, True),
    ({"product": "cef"}, {"class_uid": 4001, "log": "cloudtrail"}, False),
    ({"product": "windows", "service": "security"}, {"class_uid": 3002, "log": "anything"}, True),
])
def test_logsource_table(ls, event_patch, ok):
    r = R({"s": {"x": 1}, "condition": "s"}, ls)
    ev = {"x": 1, "class_uid": event_patch["class_uid"], "activity_id": 1,
          "metadata": {"log_name": event_patch.get("log", "whatever")}}
    assert r.matches(ev) is ok


def test_logsource_missing_or_bad():
    with pytest.raises(SigmaError, match="logsource"):
        sigma.compile("title: t\ndetection: {s: {x: 1}, condition: s}\n")
    with pytest.raises(SigmaError, match="logsource"):
        R({"s": {"x": 1}, "condition": "s"}, {"category": 5})
    with pytest.raises(SigmaError, match="logsource"):
        R({"s": {"x": 1}, "condition": "s"}, ["x"])


def test_matches_non_dict_event():
    r = R({"s": {"x": 1}, "condition": "s"})
    assert r.matches(None) is False
    assert r.matches([1]) is False


# ---------------------------------------------------------------- correlation
def test_threshold_vendetta_extension():
    r = R({"f": {"status_id": 2}, "condition": "f"}, {"category": "authentication"}, timeframe="10m",
          vendetta={"threshold": {"count": 10, "group_by": ["src_endpoint.ip"], "distinct": "user.name"}})
    assert r.timeframe_seconds == 600
    assert r.threshold == {"count": 10, "group_by": ["src_endpoint.ip"], "distinct": "user.name"}
    ev = auth(user="carol", ip="198.51.100.1")
    assert r.matches(ev)
    assert r.group_key(ev) == "198.51.100.1"
    assert r.distinct_value(ev) == "carol"


def test_threshold_group_by_string_and_sigma_names():
    r = R({"f": {"status_id": 2}, "condition": "f"}, timeframe="1h",
          vendetta={"threshold": {"count": 3, "group_by": "SourceIp", "distinct": "TargetUserName"}})
    assert r.threshold == {"count": 3, "group_by": ["src_endpoint.ip"], "distinct": "user.name"}
    assert r.timeframe_seconds == 3600


def test_threshold_multiple_group_fields_and_fan_out():
    r = R({"f": {"status_id": 2}, "condition": "f"}, timeframe="30s",
          vendetta={"threshold": {"count": 2, "group_by": ["src_endpoint.ip", "user.name", "privileges",
                                                             "missing.path"]}})
    ev = auth(privileges=["b", "a", "b"])
    assert r.group_key(ev) == "203.0.113.9|bob|a,b|"
    assert r.distinct_value(ev) == ""
    assert r.timeframe_seconds == 30


def test_group_key_empty_without_threshold():
    r = R({"f": {"status_id": 2}, "condition": "f"})
    assert r.group_key(auth()) == "" and r.distinct_value(auth()) == ""


def test_group_key_truncated():
    r = R({"f": {"status_id": 2}, "condition": "f"}, timeframe="1d",
          vendetta={"threshold": {"count": 2, "group_by": ["user.name"], "distinct": "user.name"}})
    ev = auth(user="u" * 1000)
    assert len(r.group_key(ev)) == 300 and len(r.distinct_value(ev)) == 300


def test_pipe_count_by():
    r = R({"selection": {"status_id": 2}, "condition": "selection | count() by src_endpoint.ip > 10"},
          timeframe="5m")
    assert r.threshold == {"count": 11, "group_by": ["src_endpoint.ip"], "distinct": ""}
    assert r.timeframe_seconds == 300
    assert r.matches(auth())


def test_pipe_count_distinct_gte():
    r = R({"selection": {"status_id": 2}, "condition": "selection | count(user.name) by src_endpoint.ip >= 5"},
          timeframe="10m")
    assert r.threshold == {"count": 5, "group_by": ["src_endpoint.ip"], "distinct": "user.name"}


def test_pipe_count_sigma_names_multiple_by_and_no_by():
    r = R({"s": {"status_id": 2}, "condition": "s | count(TargetUserName) by SourceIp, device.hostname > 0"},
          timeframe="1m")
    assert r.threshold == {"count": 1, "group_by": ["src_endpoint.ip", "device.hostname"], "distinct": "user.name"}
    r = R({"s": {"status_id": 2}, "condition": "s | count() > 4"}, timeframe="1m")
    assert r.threshold == {"count": 5, "group_by": [], "distinct": ""}


def test_timeframe_inside_detection():
    r = R({"s": {"status_id": 2}, "timeframe": "2d", "condition": "s | count() > 1"})
    assert r.timeframe_seconds == 172800


@pytest.mark.parametrize("cond", [
    "s | count() by x < 5",
    "s | count() by x == 5",
    "s | min(x) > 5",
    "s | near t",
    "s | count() > 1 | count() > 2",
    "s | count() >= 0",
    "s | __import__('os')",
])
def test_bad_pipe_expressions(cond):
    with pytest.raises(SigmaError):
        R({"s": {"status_id": 2}, "t": {"x": 1}, "condition": cond}, timeframe="5m")


def test_pipe_with_condition_list_rejected():
    with pytest.raises(SigmaError, match="single condition"):
        R({"s": {"x": 1}, "condition": ["s | count() > 1", "s"]}, timeframe="5m")


def test_threshold_needs_timeframe():
    with pytest.raises(SigmaError, match="timeframe"):
        R({"s": {"x": 1}, "condition": "s | count() > 1"})
    with pytest.raises(SigmaError, match="timeframe"):
        R({"s": {"x": 1}, "condition": "s"}, vendetta={"threshold": {"count": 2}})


def test_threshold_both_forms_rejected():
    with pytest.raises(SigmaError, match="either"):
        R({"s": {"x": 1}, "condition": "s | count() > 1"}, timeframe="5m",
          vendetta={"threshold": {"count": 2}})


@pytest.mark.parametrize("th", [
    {"count": 0}, {"count": "5"}, {"count": True}, {"count": 2, "group_by": [1]},
    {"count": 2, "bogus": 1}, {"count": 2, "distinct": "a b"}, {"count": 2, "group_by": {"a": 1}},
])
def test_bad_threshold_extension(th):
    with pytest.raises(SigmaError):
        R({"s": {"x": 1}, "condition": "s"}, timeframe="5m", vendetta={"threshold": th})


@pytest.mark.parametrize("tf", ["5", "5w", "abc", "0s", "31d", "-5m"])
def test_bad_timeframes(tf):
    with pytest.raises(SigmaError, match="timeframe"):
        R({"s": {"x": 1}, "condition": "s"}, timeframe=tf)


def test_vendetta_without_threshold_is_plain_rule():
    r = R({"s": {"x": 1}, "condition": "s"}, vendetta={"note": "x"})
    assert r.threshold is None


# ---------------------------------------------------------------- guards
def test_oversized_yaml():
    text = "title: t\nlogsource: {}\ndetection: {s: {x: 1}, condition: s}\ndescription: " + "a" * 70000 + "\n"
    with pytest.raises(SigmaError, match="64 KB"):
        sigma.compile(text)


def test_too_many_identifiers():
    det = {f"s{i}": {"x": i} for i in range(51)}
    det["condition"] = "1 of them"
    with pytest.raises(SigmaError, match="more than 50 search identifiers"):
        R(det)
    det = {f"s{i}": {"x": i} for i in range(50)}
    det["condition"] = "1 of them"
    assert R(det).matches({"x": 49})


def test_too_many_values():
    with pytest.raises(SigmaError, match="more than 200 values"):
        R({"s": {"x": list(range(201))}, "condition": "s"})
    assert R({"s": {"x": list(range(200))}, "condition": "s"}).matches({"x": 199})
    with pytest.raises(SigmaError, match="200"):
        R({"s": [f"k{i}" for i in range(201)], "condition": "s"})
    with pytest.raises(SigmaError, match="200"):
        R({"s": [{"x": i} for i in range(201)], "condition": "s"})


def test_multiple_documents():
    text = "title: a\nlogsource: {}\ndetection: {s: {x: 1}, condition: s}\n---\ntitle: b\n"
    with pytest.raises(SigmaError, match="single YAML document"):
        sigma.compile(text)


@pytest.mark.parametrize("text", [
    "",
    "just a string",
    "- a\n- b\n",
    "title: [unclosed",
    "!!python/object/apply:os.system ['id']",
    "title: t\nlogsource: {}\ndetection: [a]\n",
    "title: t\nlogsource: {}\ndetection: {condition: s}\n",
    "logsource: {}\ndetection: {s: {x: 1}, condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: 5, condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: {}, condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: [], condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: {x: {y: 1}}, condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: {x: []}, condition: s}\n",
    "title: t\nlogsource: {}\ndetection: {s: {x: 1}, condition: s}\ntags: notalist\n",
    "title: t\nlogsource: {}\ndetection: {s: {x: 1}, condition: s}\nfields: [1, 2]\n",
    "title: t\nlogsource: {}\ndetection: {s: {1: 1}, condition: s}\n",
])
def test_invalid_documents(text):
    with pytest.raises(SigmaError):
        sigma.compile(text)


def test_non_string_input():
    with pytest.raises(SigmaError):
        sigma.compile(None)  # type: ignore[arg-type]


def test_sigma_error_is_value_error():
    assert issubclass(SigmaError, ValueError)


def test_matching_does_not_mutate_event():
    r = R({"kw": ["x"], "s": {"process.cmd_line|contains": "a"}, "condition": "kw or s"})
    ev = proc("abc")
    before = copy.deepcopy(ev)
    r.matches(ev)
    assert ev == before
