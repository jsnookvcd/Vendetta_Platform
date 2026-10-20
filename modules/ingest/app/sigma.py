"""Sigma detection engine: compile a Sigma rule once, then test OCSF events against it.

This module is pure. It reads no database, network or clock, so a rule and an event
always give the same answer and every behavior is unit tested on plain dicts.

    rule = compile(yaml_text)        # raises SigmaError for anything invalid
    rule.matches(event)              # True when the event satisfies logsource and condition
    rule.threshold                   # None, or the correlation the stream evaluates
    rule.group_key(event)            # the threshold bucket this event counts toward
    rule.distinct_value(event)       # the value counted distinctly inside that bucket

Supported Sigma (specification v2 subset)
-----------------------------------------
Fields are OCSF dotted paths (Vendetta native rules) read with ocsf.get_path, so a path
that crosses a list fans out and the field matches when any element matches. Common
Sigma field names are accepted through FIELD_MAP below. An unknown name without a dot
is looked up at the top level of the event and inside `unmapped`.

Values: strings match case insensitively (use the `cased` modifier for exact case),
`*` and `?` are wildcards and a backslash escapes them (`\\*`, `\\?`, `\\\\`), numbers
compare numerically or as strings, booleans compare with booleans or "true"/"false",
null means the field is absent, and a list of values is OR (AND with `all`). A dict leaf
(for example a list of {Name, Value} parameters) is compared as its compact JSON text,
so `contains` works on structured vendor parameters.

Modifiers: contains, startswith, endswith, all, cased, windash, re (with the i, m and
s sub-modifiers; case sensitive unless `(?i)` or `re|i`; at most 1 KB; compiled at load
time), cidr, exists (true or false), gt, gte, lt, lte. Modifiers chain, as in
contains|all or windash|contains. base64, base64offset, utf16le, utf16be, utf16, wide,
expand and fieldref raise SigmaError("unsupported modifier: ...").

Search identifiers: a map (every key must match), a list of maps (any map), or a list
of plain values, which is a keyword search for each value as a substring of any string
value in the event. A map key that is only modifiers (for example `'|re'`) is a keyword
search with those modifiers.

Condition: a string or a list of strings (OR). Grammar: identifiers, and, or, not,
parentheses, `1 of <pattern>`, `all of <pattern>`, `1 of them`, `all of them`, where a
pattern may end in `*`. Precedence is not > and > or. `them` excludes identifiers that
start with an underscore, as the Sigma specification says. Parsing is a small recursive
descent parser; nothing is ever evaluated as code.

Logsource pre-filter
--------------------
Each logsource key adds a constraint; all constraints must hold. A key whose value is
not in the table adds no constraint, except that a `product` or `service` value that is
a Vendetta source key (in SOURCE_KEYS, or any lowercase name with an underscore) filters
on metadata.log_name equal to it.

    category process_creation        class_uid 1007 and activity_id 1
    category authentication          class_uid 3002
    category network_connection      class_uid 4001
    category firewall                class_uid 4001
    category dns                     class_uid 4003
    category webserver, proxy        class_uid 4002
    category file_event              class_uid 1001
    category detection, alert        class_uid 2004
    product aws                      log_name cloudtrail or guardduty
    product m365, office365          log_name m365_audit
    product okta                     log_name okta_system_log
    product azure, entra             log_name entra_signins or entra_audit
    product gcp, google_workspace    log_name google_workspace
    service cloudtrail               class_uid 6003 or 3002, log_name cloudtrail
    service exchange, audit          log_name m365_audit
    service auditlogs                log_name entra_audit
    service signinlogs, entra        class_uid 3002, log_name entra_signins
    service okta                     class_uid 3002, log_name okta_system_log
    service guardduty                class_uid 2004, log_name guardduty
    service google_workspace         log_name google_workspace

So `product: aws, service: cloudtrail` selects CloudTrail API and console sign-in events,
and `product: azure, service: auditlogs` selects Entra directory audits. `product okta`
filters only on the source so it covers Okta admin and MFA events as well as sign-ins.

Correlation (Vendetta extension)
--------------------------------
A rule may count matching events over a window:

    timeframe: 10m                   # Ns, Nm, Nh or Nd; also accepted inside detection
    vendetta:
      threshold:
        count: 10                    # fire when the bucket holds this many
        group_by: [src_endpoint.ip]  # bucket key paths (Sigma field names are mapped)
        distinct: user.name          # optional: count distinct values of this path

The deprecated Sigma aggregation in the condition is translated into the same dict:
`selection | count() by src_endpoint.ip > 10` becomes count 11 grouped by the IP, and
`selection | count(user.name) by src_endpoint.ip >= 5` becomes count 5 of distinct
user.name. Only `> N` and `>= N` are accepted; any other pipe expression is an error. A
threshold rule must have a timeframe. matches() reports only whether one event counts
toward the threshold; the stream keeps the window.

Guards
------
A rule is under 64 KB of YAML, holds one YAML document, at most 50 search identifiers,
200 values per field (and 200 maps or keywords per identifier), a condition of at most
2000 characters nested at most 50 deep, regular expressions of at most 1 KB, and a
timeframe of at most 30 days.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import json
import re
from typing import Any, Callable

import yaml

from .ocsf import get_path

MAX_YAML_BYTES = 64 * 1024
MAX_IDENTIFIERS = 50
MAX_VALUES = 200
MAX_CONDITION = 2000
MAX_NESTING = 50
MAX_REGEX = 1024
MAX_TIMEFRAME = 30 * 86400
MAX_KEY_LEN = 300

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")

# Sigma field name -> OCSF paths. Several paths are read and their values pooled.
FIELD_MAP: dict[str, tuple[str, ...]] = {
    "Image": ("process.file.path",),
    "OriginalFileName": ("process.file.name", "process.name"),
    "ProcessName": ("process.file.name", "process.name"),
    "CommandLine": ("process.cmd_line",),
    "ParentImage": ("process.parent_process.file.path",),
    "ParentCommandLine": ("process.parent_process.cmd_line",),
    "User": ("actor.user.name",),
    "SubjectUserName": ("actor.user.name",),
    "TargetUserName": ("user.name",),
    "SourceIp": ("src_endpoint.ip",),
    "src_ip": ("src_endpoint.ip",),
    "ClientIP": ("src_endpoint.ip",),
    "DestinationIp": ("dst_endpoint.ip",),
    "dst_ip": ("dst_endpoint.ip",),
    "DestinationPort": ("dst_endpoint.port",),
    "dst_port": ("dst_endpoint.port",),
    "DestinationHostname": ("dst_endpoint.hostname",),
    "QueryName": ("query.hostname",),
    "Hashes": ("process.file.hashes.value",),
    "sha256": ("process.file.hashes.value",),
    "eventName": ("api.operation",),
    "eventSource": ("api.service.name",),
    "Operation": ("api.operation",),
    "eventType": ("api.operation",),
    "Computer": ("device.hostname",),
    "ComputerName": ("device.hostname",),
    "Hostname": ("device.hostname",),
}

# Vendetta connector source keys, as the pipeline stamps them into metadata.log_name.
SOURCE_KEYS = frozenset({
    "entra_signins", "entra_audit", "crowdstrike_alerts", "crowdstrike_fdr", "cloudtrail", "okta_system_log",
    "m365_audit", "guardduty", "sentinelone_threats", "defender_alerts", "huntress_incidents",
    "google_workspace", "cef",
})

_LN = "metadata.log_name"
_CATEGORY: dict[str, dict[str, frozenset]] = {
    "process_creation": {"class_uid": frozenset({1007}), "activity_id": frozenset({1})},
    "authentication": {"class_uid": frozenset({3002})},
    "network_connection": {"class_uid": frozenset({4001})},
    "firewall": {"class_uid": frozenset({4001})},
    "dns": {"class_uid": frozenset({4003})},
    "webserver": {"class_uid": frozenset({4002})},
    "proxy": {"class_uid": frozenset({4002})},
    "file_event": {"class_uid": frozenset({1001})},
    "detection": {"class_uid": frozenset({2004})},
    "alert": {"class_uid": frozenset({2004})},
}
_ENTRA = frozenset({"entra_signins", "entra_audit"})
_PRODUCT: dict[str, dict[str, frozenset]] = {
    "aws": {_LN: frozenset({"cloudtrail", "guardduty"})},
    "m365": {_LN: frozenset({"m365_audit"})},
    "office365": {_LN: frozenset({"m365_audit"})},
    "okta": {_LN: frozenset({"okta_system_log"})},
    "azure": {_LN: _ENTRA},
    "entra": {_LN: _ENTRA},
    "gcp": {_LN: frozenset({"google_workspace"})},
    "google_workspace": {_LN: frozenset({"google_workspace"})},
}
_SERVICE: dict[str, dict[str, frozenset]] = {
    "cloudtrail": {"class_uid": frozenset({6003, 3002}), _LN: frozenset({"cloudtrail"})},
    "exchange": {_LN: frozenset({"m365_audit"})},
    "audit": {_LN: frozenset({"m365_audit"})},
    "auditlogs": {_LN: frozenset({"entra_audit"})},
    "signinlogs": {"class_uid": frozenset({3002}), _LN: frozenset({"entra_signins"})},
    "entra": {"class_uid": frozenset({3002}), _LN: frozenset({"entra_signins"})},
    "okta": {"class_uid": frozenset({3002}), _LN: frozenset({"okta_system_log"})},
    "guardduty": {"class_uid": frozenset({2004}), _LN: frozenset({"guardduty"})},
    "google_workspace": {_LN: frozenset({"google_workspace"})},
}
_SOURCE_LIKE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$")

_STRING_MODS = {"contains", "startswith", "endswith"}
_NUMERIC_MODS = {"gt", "gte", "lt", "lte"}
_UNSUPPORTED = {"base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "expand", "fieldref"}
_KNOWN_MODS = _STRING_MODS | _NUMERIC_MODS | {"all", "re", "i", "m", "s", "cidr", "exists", "windash", "cased"}
_RESERVED = {"and", "or", "not", "of", "them", "all"}
_IDENT = re.compile(r"^[A-Za-z0-9_]+$")
_FIELD = re.compile(r"^[A-Za-z0-9_.@$-]*$")
_RULE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_TIMEFRAME = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_ATTACK = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_DASHES = "-/\u2013\u2014\u2015"  # hyphen, slash, en dash, em dash, horizontal bar


class SigmaError(ValueError):
    """The rule is not valid Sigma, or uses something this engine does not support."""


# ---------------------------------------------------------------- event access
def _flatten(v: Any, out: list, depth: int = 0) -> None:
    if v is None:
        return
    if isinstance(v, list):
        if depth > 8:
            return
        for x in v:
            _flatten(x, out, depth + 1)
    else:
        out.append(v)


def _values(event: dict, paths: tuple[str, ...]) -> list:
    out: list = []
    for p in paths:
        _flatten(get_path(event, p), out)
    return out


# Rules evaluate at most this many characters of any one value. Vendor fields are
# attacker-influenced (a command line, a subject), and every pattern below runs in
# time that grows with the value's length, so the cap bounds the cost of one event
# for every rule and tenant. Values longer than this are matched on their first
# MAX_MATCH_CHARS characters.
MAX_MATCH_CHARS = 16384


def _text(v: Any) -> str:
    return _full_text(v)[:MAX_MATCH_CHARS]


def _full_text(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            return str(v)
    return str(v)


def _number(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _strings(v: Any, out: list, depth: int = 0) -> None:
    if depth > 12 or len(out) >= 5000:
        return
    if isinstance(v, dict):
        for x in v.values():
            _strings(x, out, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _strings(x, out, depth + 1)
    elif isinstance(v, str):
        out.append(v)
    elif isinstance(v, (int, float)) and not isinstance(v, bool):
        out.append(str(v))


class _Ctx:
    __slots__ = ("event", "memo", "_kw", "idents")

    def __init__(self, event: dict, idents: dict):
        self.event = event
        self.idents = idents
        self.memo: dict[str, bool] = {}
        self._kw: list | None = None

    def keywords(self) -> list:
        if self._kw is None:
            self._kw = []
            _strings(self.event, self._kw)
        return self._kw

    def ident(self, name: str) -> bool:
        r = self.memo.get(name)
        if r is None:
            r = self.memo[name] = bool(self.idents[name](self))
        return r


# ---------------------------------------------------------------- field resolution
def resolve_field(name: str) -> tuple[str, ...]:
    """OCSF paths a rule field name reads."""
    if name in FIELD_MAP:
        return FIELD_MAP[name]
    if "." in name:
        return (name,)
    return (name, "unmapped." + name)


def _ocsf_path(name: Any, what: str) -> str:
    if not isinstance(name, str) or not name or not _FIELD.match(name) or len(name) > 200:
        raise SigmaError(f"{what} must be a field path, got {name!r}")
    return FIELD_MAP[name][0] if name in FIELD_MAP else name


# ---------------------------------------------------------------- value patterns
Pattern = Callable[[Any], bool]


def _wild_tokens(value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            buf.append(value[i + 1])
            i += 2
            continue
        if c in "*?":
            if buf:
                out.append(("lit", "".join(buf)))
                buf = []
            out.append(("wild", c))
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        out.append(("lit", "".join(buf)))
    return out


def _string_pattern(value: str, mods: set) -> Pattern:
    tokens = _wild_tokens(value)
    if "contains" in mods:
        tokens = [("wild", "*")] + tokens + [("wild", "*")]
    elif "startswith" in mods:
        tokens = tokens + [("wild", "*")]
    elif "endswith" in mods:
        tokens = [("wild", "*")] + tokens
    cased = "cased" in mods
    windash = "windash" in mods
    has_wild = any(t == "wild" for t, _ in tokens)

    # Fast paths for plain literals.
    if not windash:
        lits = [v for t, v in tokens if t == "lit"]
        literal = "".join(lits)
        norm = literal if cased else literal.lower()
        kinds = [t if t == "lit" else v for t, v in tokens]
        fn: Callable[[str, str], bool] | None = None
        if not has_wild:
            fn = lambda s, n: s == n  # noqa: E731
        elif kinds == ["*", "lit", "*"]:
            fn = lambda s, n: n in s  # noqa: E731
        elif kinds == ["lit", "*"]:
            fn = lambda s, n: s.startswith(n)  # noqa: E731
        elif kinds == ["*", "lit"]:
            fn = lambda s, n: s.endswith(n)  # noqa: E731
        elif kinds == ["*", "*"] or kinds == ["*"]:
            return lambda leaf: True
        if fn is not None:
            if cased:
                return lambda leaf: fn(_text(leaf), norm)
            return lambda leaf: fn(_text(leaf).lower(), norm)

    parts: list[str] = []
    prev = ""
    for kind, v in tokens:
        if kind == "wild":
            parts.append(".*" if v == "*" else ".")
            prev = ""
            continue
        for j, ch in enumerate(v):
            nxt = v[j + 1] if j + 1 < len(v) else ""
            if windash and ch in "-/" and not prev.isalnum() and nxt.isalnum():
                parts.append("[" + re.escape(_DASHES) + "]")
            else:
                parts.append(re.escape(ch))
            prev = ch
    if not windash:
        # Wildcards without windash use a backtracking-free glob matcher, linear in
        # the value for each literal segment, instead of a regular expression whose
        # cost grows polynomially with the number of `*` in the pattern.
        segments = _glob_segments(tokens, cased)
        if cased:
            return lambda leaf: _glob_match(_text(leaf), segments)
        return lambda leaf: _glob_match(_text(leaf).lower(), segments)
    flags = re.DOTALL | (0 if cased else re.IGNORECASE)
    rx = re.compile("".join(parts), flags)
    return lambda leaf: rx.fullmatch(_text(leaf)) is not None


def _glob_segments(tokens: list[tuple[str, str]], cased: bool) -> tuple:
    """Split wildcard tokens into literal segments separated by `*`. Each segment is
    a string where None stands for `?` (any one character). Returns (segments,
    anchored_start, anchored_end)."""
    segs: list[list] = [[]]
    for kind, v in tokens:
        if kind == "wild" and v == "*":
            segs.append([])
        elif kind == "wild":
            segs[-1].append(None)
        else:
            segs[-1].extend(v if cased else v.lower())
    return tuple(tuple(x) for x in segs)


def _seg_at(text: str, seg: tuple, i: int) -> bool:
    if i + len(seg) > len(text):
        return False
    for k, ch in enumerate(seg):
        if ch is not None and text[i + k] != ch:
            return False
    return True


def _seg_find(text: str, seg: tuple, start: int) -> int:
    if not seg:
        return start
    if None not in seg:
        return text.find("".join(seg), start)
    # Anchor on the longest literal run, then check the whole segment there.
    runs, cur, off, best = [], [], 0, (0, 0, "")
    for k, ch in enumerate(seg):
        if ch is None:
            if cur:
                runs.append((off, "".join(cur)))
            cur = []
        else:
            if not cur:
                off = k
            cur.append(ch)
    if cur:
        runs.append((off, "".join(cur)))
    if not runs:
        return start if start + len(seg) <= len(text) else -1
    off, lit = max(runs, key=lambda r: len(r[1]))
    pos = text.find(lit, start + off)
    while pos != -1:
        i = pos - off
        if i >= start and _seg_at(text, seg, i):
            return i
        pos = text.find(lit, pos + 1)
    return -1


def _glob_match(text: str, segments: tuple) -> bool:
    """Full match of text against segments joined by `*` (leftmost-first, which is
    exact for glob patterns because `*` absorbs any gap)."""
    if len(segments) == 1:
        seg = segments[0]
        return len(text) == len(seg) and _seg_at(text, seg, 0)
    first, last, middle = segments[0], segments[-1], segments[1:-1]
    if not _seg_at(text, first, 0):
        return False
    pos = len(first)
    end_limit = len(text) - len(last)
    if end_limit < pos:
        return False
    for seg in middle:
        i = _seg_find(text, seg, pos)
        if i == -1 or i + len(seg) > end_limit:
            return False
        pos = i + len(seg)
    return _seg_at(text, last, end_limit)


def _scalar_pattern(value: Any, mods: set, where: str) -> Pattern:
    if isinstance(value, (_dt.date, _dt.datetime)):
        value = value.isoformat()
    if isinstance(value, (dict, list)):
        raise SigmaError(f"{where}: a value must be a string, number, boolean or null")

    if "re" in mods:
        if not isinstance(value, str):
            raise SigmaError(f"{where}: a regular expression must be a string")
        if len(value) > MAX_REGEX:
            raise SigmaError(f"{where}: regular expression is longer than {MAX_REGEX} characters")
        flags = (re.IGNORECASE if "i" in mods else 0) | (re.MULTILINE if "m" in mods else 0) | \
                (re.DOTALL if "s" in mods else 0)
        try:
            rx = re.compile(value, flags)
        except re.error as exc:
            raise SigmaError(f"{where}: invalid regular expression: {exc}") from None
        return lambda leaf: rx.search(_text(leaf)) is not None

    if "cidr" in mods:
        if not isinstance(value, str):
            raise SigmaError(f"{where}: cidr value must be a network string")
        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            raise SigmaError(f"{where}: invalid network {value!r}") from None

        def _in_net(leaf: Any) -> bool:
            try:
                return ipaddress.ip_address(_text(leaf).strip()) in net
            except ValueError:
                return False
        return _in_net

    num_mods = mods & _NUMERIC_MODS
    if num_mods:
        n = _number(value)
        if n is None:
            raise SigmaError(f"{where}: {'|'.join(sorted(num_mods))} needs a number, got {value!r}")
        op = next(iter(num_mods))
        cmp = {"gt": lambda a: a > n, "gte": lambda a: a >= n, "lt": lambda a: a < n, "lte": lambda a: a <= n}[op]

        def _num_cmp(leaf: Any) -> bool:
            a = _number(leaf)
            return a is not None and cmp(a)
        return _num_cmp

    if isinstance(value, bool) and not (mods & (_STRING_MODS | {"windash"})):
        want = value

        def _bool(leaf: Any) -> bool:
            if isinstance(leaf, bool):
                return leaf is want
            if isinstance(leaf, str):
                return leaf.strip().lower() == ("true" if want else "false")
            return False
        return _bool

    if isinstance(value, (int, float)) and not isinstance(value, bool) and \
            not (mods & (_STRING_MODS | {"windash"})):
        n = float(value)
        as_text = str(value)

        def _num_eq(leaf: Any) -> bool:
            if isinstance(leaf, bool):
                return False
            a = _number(leaf)
            if a is not None:
                return a == n
            return _text(leaf).strip() == as_text
        return _num_eq

    return _string_pattern(_text(value), mods)


class _FieldMatch:
    __slots__ = ("paths", "keyword", "exists", "patterns", "all", "null_ok")

    def __init__(self, key: str, raw: Any, where: str):
        name, *mod_list = key.split("|")
        if not _FIELD.match(name) or len(name) > 200:
            raise SigmaError(f"{where}: invalid field name {name!r}")
        mods = set()
        for m in mod_list:
            m = m.strip().lower()
            if m in _UNSUPPORTED:
                raise SigmaError(f"unsupported modifier: {m} (in {where})")
            if m not in _KNOWN_MODS:
                raise SigmaError(f"{where}: unknown modifier {m!r}")
            mods.add(m)
        if len(mods & _STRING_MODS) > 1:
            raise SigmaError(f"{where}: contains, startswith and endswith cannot be combined")
        if len(mods & _NUMERIC_MODS) > 1:
            raise SigmaError(f"{where}: only one of gt, gte, lt and lte may be used")
        if mods & {"i", "m", "s"} and "re" not in mods:
            raise SigmaError(f"{where}: i, m and s are sub-modifiers of re")
        if "re" in mods and mods & (_STRING_MODS | _NUMERIC_MODS | {"cidr", "windash", "cased"}):
            raise SigmaError(f"{where}: re cannot be combined with other value modifiers")
        if "cidr" in mods and mods - {"cidr", "all"}:
            raise SigmaError(f"{where}: cidr cannot be combined with other value modifiers")
        if mods & _NUMERIC_MODS and mods - _NUMERIC_MODS - {"all"}:
            raise SigmaError(f"{where}: numeric comparisons cannot be combined with other modifiers")

        self.keyword = name == ""
        self.paths = () if self.keyword else resolve_field(name)
        self.all = "all" in mods
        self.exists: bool | None = None
        self.null_ok = False
        self.patterns: list[Pattern] = []

        if "exists" in mods:
            if mods != {"exists"} or self.keyword:
                raise SigmaError(f"{where}: exists stands alone on a named field")
            if not isinstance(raw, bool):
                raise SigmaError(f"{where}: exists takes true or false")
            self.exists = raw
            return

        values = raw if isinstance(raw, list) else [raw]
        if not values:
            raise SigmaError(f"{where}: empty value list")
        if len(values) > MAX_VALUES:
            raise SigmaError(f"{where}: more than {MAX_VALUES} values")
        for v in values:
            if v is None:
                if self.all or self.keyword or mods:
                    raise SigmaError(f"{where}: null cannot be combined with modifiers")
                self.null_ok = True
                continue
            self.patterns.append(_scalar_pattern(v, mods, where))

    def __call__(self, ctx: _Ctx) -> bool:
        leaves = ctx.keywords() if self.keyword else _values(ctx.event, self.paths)
        if self.exists is not None:
            return bool(leaves) == self.exists
        if not leaves:
            return self.null_ok
        if self.all:
            return all(any(p(x) for x in leaves) for p in self.patterns)
        return any(p(x) for p in self.patterns for x in leaves)


def _compile_map(m: dict, where: str) -> Callable[[_Ctx], bool]:
    if not m:
        raise SigmaError(f"{where}: empty map")
    if len(m) > MAX_VALUES:
        raise SigmaError(f"{where}: more than {MAX_VALUES} fields")
    matchers = []
    for k, v in m.items():
        if not isinstance(k, str):
            raise SigmaError(f"{where}: field names must be strings, got {k!r}")
        if isinstance(v, dict):
            raise SigmaError(f"{where}: field {k!r} has a nested map as its value")
        matchers.append(_FieldMatch(k, v, f"{where}.{k}"))
    return lambda ctx: all(f(ctx) for f in matchers)


def _compile_identifier(name: str, body: Any) -> Callable[[_Ctx], bool]:
    where = f"detection.{name}"
    if isinstance(body, dict):
        return _compile_map(body, where)
    if isinstance(body, list):
        if not body:
            raise SigmaError(f"{where}: empty list")
        if len(body) > MAX_VALUES:
            raise SigmaError(f"{where}: more than {MAX_VALUES} entries")
        if all(isinstance(x, dict) for x in body):
            groups = [_compile_map(x, f"{where}[{i}]") for i, x in enumerate(body)]
            return lambda ctx: any(g(ctx) for g in groups)
        if any(isinstance(x, (dict, list)) for x in body):
            raise SigmaError(f"{where}: a list mixes maps and plain values")
        if any(x is None for x in body):
            raise SigmaError(f"{where}: keywords cannot be null")
        kw = _FieldMatch("|contains", body, where)
        return kw
    raise SigmaError(f"{where}: must be a map, a list of maps or a list of keywords")


# ---------------------------------------------------------------- condition parser
_TOKEN = re.compile(r"\s*(?:(\()|(\))|([A-Za-z0-9_]+\*?))")


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            bad = text[pos:].lstrip()[:1]
            raise SigmaError(f"condition: unexpected character {bad!r}")
        out.append(m.group(1) or m.group(2) or m.group(3))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens: list[str], idents: list[str]):
        self.t = tokens
        self.i = 0
        self.idents = idents
        self.depth = 0

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def kw(self, word: str) -> bool:
        p = self.peek()
        return p is not None and p.lower() == word

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaError("condition: unexpected end")
        self.i += 1
        return tok

    def parse(self) -> Callable[[_Ctx], bool]:
        if not self.t:
            raise SigmaError("condition is empty")
        node = self.expr()
        if self.peek() is not None:
            raise SigmaError(f"condition: unexpected {self.peek()!r}")
        return node

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_NESTING:
            raise SigmaError(f"condition nests deeper than {MAX_NESTING}")

    def expr(self):
        self._enter()
        nodes = [self.and_expr()]
        while self.kw("or"):
            self.take()
            nodes.append(self.and_expr())
        self.depth -= 1
        if len(nodes) == 1:
            return nodes[0]
        return lambda ctx: any(n(ctx) for n in nodes)

    def and_expr(self):
        nodes = [self.not_expr()]
        while self.kw("and"):
            self.take()
            nodes.append(self.not_expr())
        if len(nodes) == 1:
            return nodes[0]
        return lambda ctx: all(n(ctx) for n in nodes)

    def not_expr(self):
        if self.kw("not"):
            self.take()
            self._enter()
            inner = self.not_expr()
            self.depth -= 1
            return lambda ctx: not inner(ctx)
        return self.primary()

    def primary(self):
        tok = self.take()
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise SigmaError("condition: expected ')'")
            return node
        if tok == ")":
            raise SigmaError("condition: unexpected ')'")
        low = tok.lower()
        if low in ("1", "all") and self.kw("of"):
            self.take()
            target = self.take()
            names = self._pattern(target)
            if low == "1":
                return lambda ctx: any(ctx.ident(n) for n in names)
            return lambda ctx: all(ctx.ident(n) for n in names)
        if low in _RESERVED:
            raise SigmaError(f"condition: unexpected {tok!r}")
        if tok.endswith("*"):
            raise SigmaError(f"condition: wildcard {tok!r} is only allowed after '1 of' or 'all of'")
        if tok not in self.idents:
            raise SigmaError(f"condition: unknown search identifier {tok!r}")
        return lambda ctx: ctx.ident(tok)

    def _pattern(self, target: str) -> list[str]:
        if target in ("(", ")"):
            raise SigmaError("condition: expected a pattern after 'of'")
        if target.lower() == "them":
            names = [n for n in self.idents if not n.startswith("_")]
        elif target.endswith("*"):
            prefix = target[:-1]
            names = [n for n in self.idents if n.startswith(prefix)]
        else:
            names = [n for n in self.idents if n == target]
        if not names:
            raise SigmaError(f"condition: {target!r} matches no search identifier")
        return names


_AGG = re.compile(
    r"^\s*count\s*\(\s*([A-Za-z0-9_.@$-]*)\s*\)\s*"
    r"(?:by\s+([A-Za-z0-9_.@$-]+(?:\s*,\s*[A-Za-z0-9_.@$-]+)*)\s*)?"
    r"(>=|>)\s*(\d{1,7})\s*$", re.IGNORECASE)


def _aggregation(text: str) -> dict:
    m = _AGG.match(text)
    if not m:
        raise SigmaError("condition: the only pipe expression supported is "
                         "'count([field]) [by field[, field]] > N' (or >= N)")
    field, by, op, n = m.group(1), m.group(2), m.group(3), int(m.group(4))
    count = n + 1 if op == ">" else n
    if count < 1:
        raise SigmaError("condition: count threshold must be at least 1")
    group_by = [_ocsf_path(b.strip(), "count() by") for b in by.split(",")] if by else []
    return {"count": count, "group_by": group_by, "distinct": _ocsf_path(field, "count()") if field else ""}


def _threshold_ext(raw: Any) -> dict | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SigmaError("vendetta must be a map")
    th = raw.get("threshold")
    if th is None:
        return None
    if not isinstance(th, dict):
        raise SigmaError("vendetta.threshold must be a map")
    extra = set(th) - {"count", "group_by", "distinct"}
    if extra:
        raise SigmaError(f"vendetta.threshold: unknown keys {sorted(extra)}")
    count = th.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1 or count > 1_000_000:
        raise SigmaError("vendetta.threshold.count must be a whole number from 1 to 1000000")
    gb = th.get("group_by") or []
    if isinstance(gb, str):
        gb = [gb]
    if not isinstance(gb, list) or len(gb) > 10:
        raise SigmaError("vendetta.threshold.group_by must be a path or a list of at most 10 paths")
    distinct = th.get("distinct") or ""
    return {"count": count, "group_by": [_ocsf_path(g, "vendetta.threshold.group_by") for g in gb],
            "distinct": _ocsf_path(distinct, "vendetta.threshold.distinct") if distinct else ""}


# ---------------------------------------------------------------- logsource
def _logsource(ls: Any) -> tuple[tuple[str, frozenset], ...]:
    if ls is None:
        raise SigmaError("logsource is required")
    if not isinstance(ls, dict):
        raise SigmaError("logsource must be a map")
    cons: dict[str, frozenset] = {}

    def add(table: dict[str, frozenset]) -> None:
        for path, allowed in table.items():
            cons[path] = cons[path] & allowed if path in cons else allowed

    for key in ("category", "product", "service"):
        v = ls.get(key)
        if v is None:
            continue
        if not isinstance(v, str):
            raise SigmaError(f"logsource.{key} must be a string")
        v = v.strip().lower()
        table = {"category": _CATEGORY, "product": _PRODUCT, "service": _SERVICE}[key].get(v)
        if table:
            add(table)
        elif key != "category" and (v in SOURCE_KEYS or _SOURCE_LIKE.match(v)):
            add({_LN: frozenset({v})})
    return tuple(cons.items())


def _prefilter_ok(event: dict, cons: tuple) -> bool:
    for path, allowed in cons:
        v = get_path(event, path)
        if isinstance(v, str) and path != _LN and v.isdigit():
            v = int(v)
        if isinstance(v, (list, dict)) or v not in allowed:
            return False
    return True


# ---------------------------------------------------------------- rule
def _slug(title: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", title.strip().lower()).strip("-.")
    s = re.sub(r"-{2,}", "-", s)[:80].strip("-")
    return s


def _parse_timeframe(v: Any) -> int:
    if v is None or v == "":
        return 0
    m = _TIMEFRAME.match(str(v))
    if not m:
        raise SigmaError(f"timeframe {v!r} must look like 30s, 5m, 1h or 1d")
    secs = int(m.group(1)) * _UNITS[m.group(2)]
    if secs < 1 or secs > MAX_TIMEFRAME:
        raise SigmaError("timeframe must be between 1 second and 30 days")
    return secs


def _key_text(event: dict, path: str) -> str:
    vals = sorted({_text(v) for v in _values(event, (path,))})
    return ",".join(vals)


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: tuple
    mitre: tuple
    logsource: dict
    timeframe_seconds: int
    threshold: dict | None
    fields: tuple
    _prefilter: tuple = dataclasses.field(default=(), repr=False, compare=False)
    _condition: Any = dataclasses.field(default=None, repr=False, compare=False)
    _idents: Any = dataclasses.field(default=None, repr=False, compare=False)

    def __hash__(self) -> int:
        return hash(self.id)

    def matches(self, event: dict) -> bool:
        if not isinstance(event, dict) or self._condition is None:
            return False
        if not _prefilter_ok(event, self._prefilter):
            return False
        return bool(self._condition(_Ctx(event, self._idents)))

    def group_key(self, event: dict) -> str:
        if not self.threshold or not self.threshold["group_by"]:
            return ""
        return "|".join(_key_text(event, p) for p in self.threshold["group_by"])[:MAX_KEY_LEN]

    def distinct_value(self, event: dict) -> str:
        if not self.threshold or not self.threshold["distinct"]:
            return ""
        return _key_text(event, self.threshold["distinct"])[:MAX_KEY_LEN]

    def severity(self) -> str:
        return "low" if self.level == "informational" else self.level


def _str_field(doc: dict, key: str, default: str = "", limit: int = 5000) -> str:
    v = doc.get(key, default)
    if v is None:
        return default
    if isinstance(v, (_dt.date, _dt.datetime)):
        v = v.isoformat()
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        raise SigmaError(f"{key} must be a string")
    return str(v).strip()[:limit]


def compile(text: str) -> Rule:  # noqa: A001 - the public name the platform codes against
    """Parse and validate one Sigma rule. Raises SigmaError with the reason."""
    if not isinstance(text, str):
        raise SigmaError("rule text must be a string")
    if len(text.encode("utf-8", "replace")) >= MAX_YAML_BYTES:
        raise SigmaError("rule is larger than 64 KB")
    try:
        doc = yaml.safe_load(text)
    except yaml.composer.ComposerError as exc:
        if "single document" in str(exc):
            raise SigmaError("rule must be a single YAML document") from None
        raise SigmaError(f"invalid YAML: {exc}") from None
    except yaml.YAMLError as exc:
        raise SigmaError(f"invalid YAML: {exc}") from None
    if not isinstance(doc, dict):
        raise SigmaError("rule must be a YAML map")

    title = _str_field(doc, "title", limit=10_000)
    if not title:
        raise SigmaError("title is required")
    if len(title) > 300:
        raise SigmaError("title is longer than 300 characters")

    raw_id = doc.get("id")
    if raw_id is None or raw_id == "":
        rid = _slug(title)
        if not rid:
            raise SigmaError("title gives no usable id; set id")
    else:
        rid = str(raw_id).strip()
        if not _RULE_ID.match(rid):
            raise SigmaError("id must be 1 to 80 characters of letters, digits, '_', '.' or '-'")

    level = (_str_field(doc, "level", "medium") or "medium").lower()
    if level not in LEVELS:
        raise SigmaError(f"level must be one of {', '.join(LEVELS)}")
    status = (_str_field(doc, "status", "experimental") or "experimental").lower()
    if status not in STATUSES:
        raise SigmaError(f"status must be one of {', '.join(STATUSES)}")
    description = _str_field(doc, "description")

    tags = doc.get("tags") or []
    if not isinstance(tags, list) or len(tags) > 100 or not all(isinstance(t, str) for t in tags):
        raise SigmaError("tags must be a list of at most 100 strings")
    mitre: list[str] = []
    for t in tags:
        m = _ATTACK.match(t.strip())
        if m and m.group(1).upper() not in mitre:
            mitre.append(m.group(1).upper())

    fields = doc.get("fields") or []
    if not isinstance(fields, list) or len(fields) > 100 or not all(isinstance(f, str) for f in fields):
        raise SigmaError("fields must be a list of at most 100 strings")

    ls = doc.get("logsource")
    prefilter = _logsource(ls)

    det = doc.get("detection")
    if not isinstance(det, dict):
        raise SigmaError("detection must be a map")
    det = dict(det)
    cond_raw = det.pop("condition", None)
    det_tf = det.pop("timeframe", None)
    if cond_raw is None:
        raise SigmaError("detection.condition is required")
    if len(det) > MAX_IDENTIFIERS:
        raise SigmaError(f"more than {MAX_IDENTIFIERS} search identifiers")
    if not det:
        raise SigmaError("detection has no search identifiers")
    idents: dict[str, Callable[[_Ctx], bool]] = {}
    for name, body in det.items():
        if not isinstance(name, str) or not _IDENT.match(name) or name.isdigit() or name.lower() in _RESERVED:
            raise SigmaError(f"invalid search identifier name {name!r}")
        idents[name] = _compile_identifier(name, body)

    conds = cond_raw if isinstance(cond_raw, list) else [cond_raw]
    if not conds or not all(isinstance(c, str) for c in conds):
        raise SigmaError("condition must be a string or a list of strings")
    if sum(len(c) for c in conds) > MAX_CONDITION:
        raise SigmaError(f"condition is longer than {MAX_CONDITION} characters")

    agg: dict | None = None
    nodes = []
    for c in conds:
        if "|" in c:
            if len(conds) > 1:
                raise SigmaError("an aggregation needs a single condition")
            left, _, right = c.partition("|")
            if "|" in right:
                raise SigmaError("condition: only one pipe is allowed")
            agg = _aggregation(right)
            c = left
        nodes.append(_Parser(_tokenize(c), list(idents)).parse())
    condition = nodes[0] if len(nodes) == 1 else (lambda ctx: any(n(ctx) for n in nodes))

    ext = _threshold_ext(doc.get("vendetta"))
    if ext and agg:
        raise SigmaError("use either vendetta.threshold or a count() aggregation, not both")
    threshold = ext or agg
    if doc.get("timeframe") is not None and det_tf is not None:
        raise SigmaError("timeframe is set twice")
    tf = _parse_timeframe(doc.get("timeframe") if doc.get("timeframe") is not None else det_tf)
    if threshold and not tf:
        raise SigmaError("a threshold rule needs a timeframe")

    return Rule(
        id=rid, title=title, level=level, status=status, description=description,
        tags=tuple(t.strip() for t in tags), mitre=tuple(mitre),
        logsource={str(k): v for k, v in ls.items()}, timeframe_seconds=tf, threshold=threshold,
        fields=tuple(fields), _prefilter=prefilter, _condition=condition, _idents=idents,
    )
