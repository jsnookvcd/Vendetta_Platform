"""Generic ArcSight Common Event Format (CEF) over syslog.

Vector receives the syslog stream on TLS 6514 and posts each line to the push door
as {"message": "<line>"}. The deploy/vector.toml shipped with this module also adds
"timestamp" (Vector's receive time), because an RFC 3164 header has no year and a
mapper may not read the clock, and "peer" (the sender's address). A "host" field,
when a collector sends one, names the device. The line normally carries its syslog
header; everything before "CEF:" is treated as that header.

CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Header fields escape "|" and "\\" with a backslash. Extension values escape "=",
"\\", and encode newlines as \\n and \\r; values may contain spaces, so a value runs
until the next unescaped `key=`.

Class choice: network_activity when the extension names a source or destination
address, detection_finding when the severity is 7 or more, otherwise api_activity
Other. There is no stable vendor id, so the raw hash is the dedupe key.
"""
from __future__ import annotations

import datetime as dt
import re

from .. import ocsf
from . import Mapper, register
from ._util import guarded, ip, text

_KEY_CHARS = re.compile(r"[A-Za-z0-9_.\[\]-]")
_SEV_WORDS = {"unknown": 0, "low": 2, "medium": 5, "high": 7, "very-high": 9, "very high": 9}
_EXT_UNESCAPE = {"=": "=", "\\": "\\", "n": "\n", "r": "\r", "|": "|"}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_RFC5424_TS = re.compile(r"^<\d{1,3}>\d{1,2} (\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2}))\s")
_RFC5424_HOST = re.compile(r"^<\d{1,3}>\d{1,2} \S+ (\S+)\s")
_RFC3164_HOST = re.compile(r"^(?:<\d{1,3}>)?[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} (\S+)\s")


def parse_header(s: str) -> tuple[list[str], str]:
    """Split 'CEF:0|a|b|c|d|e|f|ext' into seven unescaped header fields and the raw extension."""
    fields: list[str] = []
    cur: list[str] = []
    i, n = 0, len(s)
    while i < n and len(fields) < 7:
        ch = s[i]
        if ch == "\\" and i + 1 < n and s[i + 1] in "|\\":
            cur.append(s[i + 1])
            i += 2
            continue
        if ch == "|":
            fields.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if len(fields) < 7:
        raise ocsf.MappingError("CEF header has fewer than seven fields")
    return fields, s[i:]


def parse_extension(ext: str) -> dict[str, str]:
    """key=value pairs; a value runs to the start of the next unescaped key=."""
    # Positions of unescaped '=' that are preceded by a key that starts the string or follows a space.
    marks: list[tuple[int, int]] = []  # (key_start, eq_index)
    i, n = 0, len(ext)
    while i < n:
        ch = ext[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "=":
            j = i
            while j > 0 and _KEY_CHARS.match(ext[j - 1]):
                j -= 1
            if j < i and (j == 0 or ext[j - 1] == " "):
                marks.append((j, i))
        i += 1
    out: dict[str, str] = {}
    for k, (ks, eq) in enumerate(marks):
        end = marks[k + 1][0] - 1 if k + 1 < len(marks) else n
        key = ext[ks:eq]
        raw = ext[eq + 1:max(end, eq + 1)]
        out[key] = _unescape(raw.rstrip(" ") if k + 1 < len(marks) else raw.rstrip())
    return out


def _unescape(v: str) -> str:
    out, i = [], 0
    while i < len(v):
        if v[i] == "\\" and i + 1 < len(v) and v[i + 1] in _EXT_UNESCAPE:
            out.append(_EXT_UNESCAPE[v[i + 1]])
            i += 2
        else:
            out.append(v[i])
            i += 1
    return "".join(out)


def cef_severity(v: str) -> int:
    """CEF severity (0 to 10 or a word) on CEF's own 0 to 10 scale."""
    s = (v or "").strip()
    if s.isdigit():
        return max(0, min(10, int(s)))
    return _SEV_WORDS.get(s.lower(), 0)


def _ocsf_sev(n: int) -> int:
    if n >= 9:
        return 5
    if n >= 7:
        return 4
    if n >= 4:
        return 3
    if n >= 2:
        return 2
    return 1


def _cef_time(v: str | None) -> int | None:
    """rt/start/end: epoch milliseconds, or 'MMM dd yyyy HH:mm:ss[.SSS][ zone]'."""
    s = (v or "").strip()
    if not s:
        return None
    if s.isdigit():
        return ocsf.to_epoch_ms(int(s))
    parts = s.split(" ")
    if len(parts) >= 4 and parts[0][:3] in _MONTHS:
        base = " ".join(parts[:4])
        zone = parts[4] if len(parts) > 4 else "UTC"
        for fmt in ("%b %d %Y %H:%M:%S.%f", "%b %d %Y %H:%M:%S"):
            try:
                d = dt.datetime.strptime(base, fmt)
            except ValueError:
                continue
            if zone.upper() in ("UTC", "GMT", "Z"):
                return int(d.replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
            m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", zone)
            if m:
                off = dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
                tz = dt.timezone(off if m.group(1) == "+" else -off)
                return int(d.replace(tzinfo=tz).timestamp() * 1000)
            return None  # a named zone (EST, CEST) cannot be resolved without a zone database lookup
    return ocsf.to_epoch_ms(s)


def _int(v):
    s = str(v or "").strip()
    return int(s) if s.isdigit() else None


# Extension keys mapped to OCSF fields above; every other key is kept under unmapped.extension.
_KNOWN = {"src", "dst", "spt", "dpt", "proto", "act", "suser", "suid", "shost", "dhost", "smac", "dmac", "rt",
          "start", "end", "msg", "cat", "outcome", "dvchost", "dvc", "deviceExternalId", "in", "out"}
_BLOCKED = ("deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "reset")


@guarded
def _cef(r: dict) -> dict | None:
    msg = r.get("message")
    if not isinstance(msg, str) or "CEF:" not in msg:
        raise ocsf.MappingError("message has no CEF payload")
    at = msg.index("CEF:")
    prefix, body = msg[:at], msg[at + 4:]
    header, ext_raw = parse_header(body)
    version, vendor, product, dev_version, sig_id, name, sev_raw = header
    ext = parse_extension(ext_raw)
    cef_sev = cef_severity(sev_raw)
    sev = _ocsf_sev(cef_sev)

    when = _cef_time(ext.get("rt")) or _cef_time(ext.get("end")) or _cef_time(ext.get("start"))
    if when is None:
        m = _RFC5424_TS.match(prefix)
        when = ocsf.to_epoch_ms(m.group(1)) if m else None
    if when is None:
        when = ocsf.to_epoch_ms(r.get("timestamp"))
    if when is None:
        raise ocsf.MappingError("CEF event has no rt, start, end or usable syslog timestamp")
    m = _RFC5424_HOST.match(prefix) or _RFC3164_HOST.match(prefix)
    host = text(r.get("host")) or (m.group(1) if m else None) or text(ext.get("dvchost"))

    vendor = vendor.strip() or "Unknown"
    product = product.strip() or "CEF"
    custom = {}
    for i in range(1, 7):
        for kind in ("cs", "cn", "cfp", "flexString", "c6a"):
            label, val = ext.get(f"{kind}{i}Label"), ext.get(f"{kind}{i}")
            if val is not None:
                custom[label or f"{kind}{i}"] = val
    used = _KNOWN | {k for k in ext if re.fullmatch(r"(cs|cn|cfp|flexString|c6a)\d(Label)?", k)}
    unmapped = ocsf.prune({"cef_version": version, "device_version": dev_version, "signature_id": sig_id,
                           "cef_severity": sev_raw, "category": ext.get("cat"), "outcome": ext.get("outcome"),
                           "action": ext.get("act"), "custom": custom or None,
                           "extension": {k: v for k, v in ext.items() if k not in used} or None,
                           "device_host": host, "device_ip": ip(ext.get("dvc")),
                           "syslog_peer": text(r.get("peer"))})
    common = dict(time=when, product=product, vendor=vendor, severity=sev, message=ext.get("msg") or name,
                  device=ocsf.device(hostname=host, ip=ip(ext.get("dvc")), uid=text(ext.get("deviceExternalId"))),
                  actor={"user": ocsf.user(name=text(ext.get("suser")), uid=text(ext.get("suid")))},
                  unmapped=unmapped)
    src = ip(ext.get("src"))
    dst = ip(ext.get("dst"))
    src_ep = ocsf.endpoint(ip=src, hostname=text(ext.get("shost")), port=ext.get("spt"), mac=text(ext.get("smac")))
    dst_ep = ocsf.endpoint(ip=dst, hostname=text(ext.get("dhost")), port=ext.get("dpt"), mac=text(ext.get("dmac")))
    if src or dst:
        act = (ext.get("act") or ext.get("outcome") or "").strip().lower()
        blocked = any(act.startswith(b) for b in _BLOCKED)
        return ocsf.event("network_activity", 5 if blocked else 6, status_id=2 if blocked else None,
                          src_endpoint=src_ep, dst_endpoint=dst_ep,
                          connection_info={"protocol_name": (ext.get("proto") or "").lower() or None},
                          traffic={"bytes_in": _int(ext.get("in")), "bytes_out": _int(ext.get("out"))},
                          finding_info=ocsf.finding_info(name, types=[sig_id] if sig_id else None)
                          if cef_sev >= 7 else None,
                          **common)
    if cef_sev >= 7:
        return ocsf.event("detection_finding", 1,
                          finding_info=ocsf.finding_info(name or sig_id or "CEF event",
                                                         types=[sig_id] if sig_id else None,
                                                         desc=ext.get("msg")),
                          src_endpoint=src_ep or None, dst_endpoint=dst_ep or None, **common)
    return ocsf.event("api_activity", 99, api={"operation": name or sig_id, "service": {"name": product}},
                      src_endpoint=src_ep or None, **common)


register(Mapper(
    key="cef", name="Generic CEF over syslog", vendor="ArcSight CEF", product="CEF", family="network",
    classes=("network_activity", "detection_finding", "api_activity"), map=_cef, uid=lambda r: "",
    doors=("syslog", "push")))
