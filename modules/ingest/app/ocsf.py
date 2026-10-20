"""Open Cybersecurity Schema Framework (OCSF) building blocks.

Every connector's mapper turns a vendor record into one OCSF event built here, so the
detection rules, the hot store, the Security Lake and any client exit all read one
schema. The subset below follows OCSF 1.3: the classes the SOC uses, the base
attributes every event carries, and the severity and status enumerations.

Vendetta adds two things every event carries:

- metadata.tenant_uid and unmapped.tenant_id: the control plane's platform client id.
  It is stamped by the pipeline from the connector that received the record, never
  from the record itself, so a vendor payload cannot claim another tenant.
- receipt: added after normalization (see receipts.py). It is excluded from the
  event hash.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

OCSF_VERSION = "1.3.0"

# class key -> (class_uid, class_name, category_uid, category_name, activities {id: name})
CLASSES: dict[str, tuple] = {
    "file_activity": (1001, "File System Activity", 1, "System Activity",
                      {1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Rename", 99: "Other"}),
    "registry_value_activity": (201004, "Registry Value Activity", 1, "System Activity",
                                {1: "Create", 2: "Read", 3: "Modify", 4: "Delete", 99: "Other"}),
    "process_activity": (1007, "Process Activity", 1, "System Activity",
                         {1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 5: "Set User ID", 99: "Other"}),
    "detection_finding": (2004, "Detection Finding", 2, "Findings",
                          {1: "Create", 2: "Update", 3: "Close", 99: "Other"}),
    "vulnerability_finding": (2002, "Vulnerability Finding", 2, "Findings",
                              {1: "Create", 2: "Update", 3: "Close", 99: "Other"}),
    "account_change": (3001, "Account Change", 3, "Identity & Access Management",
                       {1: "Create", 2: "Enable", 3: "Password Change", 4: "Password Reset", 5: "Disable",
                        6: "Delete", 7: "Attach Policy", 8: "Detach Policy", 9: "Lock", 10: "MFA Factor Enable",
                        11: "MFA Factor Disable", 99: "Other"}),
    "authentication": (3002, "Authentication", 3, "Identity & Access Management",
                       {1: "Logon", 2: "Logoff", 3: "Authentication Ticket", 4: "Service Ticket Request",
                        5: "Service Ticket Renew", 6: "Preauth", 99: "Other"}),
    "authorize_session": (3003, "Authorize Session", 3, "Identity & Access Management",
                          {1: "Assign Privileges", 2: "Assign Groups", 99: "Other"}),
    "user_access": (3005, "User Access Management", 3, "Identity & Access Management",
                    {1: "Assign Privileges", 2: "Revoke Privileges", 99: "Other"}),
    "group_management": (3006, "Group Management", 3, "Identity & Access Management",
                         {1: "Assign Privileges", 2: "Revoke Privileges", 3: "Add User", 4: "Remove User",
                          5: "Delete", 6: "Create", 99: "Other"}),
    "network_activity": (4001, "Network Activity", 4, "Network Activity",
                         {1: "Open", 2: "Close", 3: "Reset", 4: "Fail", 5: "Refuse", 6: "Traffic", 7: "Listen",
                          99: "Other"}),
    "http_activity": (4002, "HTTP Activity", 4, "Network Activity",
                      {1: "Connect", 2: "Delete", 3: "Get", 4: "Head", 5: "Options", 6: "Post", 7: "Put",
                       8: "Trace", 99: "Other"}),
    "dns_activity": (4003, "DNS Activity", 4, "Network Activity",
                     {1: "Query", 2: "Response", 6: "Traffic", 99: "Other"}),
    "email_activity": (4009, "Email Activity", 4, "Network Activity",
                       {1: "Send", 2: "Receive", 3: "Scan", 99: "Other"}),
    "web_resources_activity": (6001, "Web Resources Activity", 6, "Application Activity",
                               {1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Search", 6: "Import",
                                7: "Export", 8: "Share", 99: "Other"}),
    "api_activity": (6003, "API Activity", 6, "Application Activity",
                     {1: "Create", 2: "Read", 3: "Update", 4: "Delete", 99: "Other"}),
}

CLASS_BY_UID = {v[0]: k for k, v in CLASSES.items()}

SEVERITY_IDS = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal"}
SEVERITY_FROM_WORD = {
    "unknown": 0, "info": 1, "informational": 1, "low": 2, "medium": 3, "moderate": 3, "high": 4,
    "critical": 5, "fatal": 6, "severe": 4,
}
STATUS_IDS = {0: "Unknown", 1: "Success", 2: "Failure", 99: "Other"}

REQUIRED = ("class_uid", "category_uid", "activity_id", "type_uid", "time", "severity_id", "metadata")


class MappingError(ValueError):
    """A record cannot be normalized. The pipeline keeps the raw record and counts it."""


def to_epoch_ms(value: Any) -> int | None:
    """Accept ISO 8601 strings, epoch seconds or milliseconds, or datetimes."""
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        v = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
        return int(v.timestamp() * 1000)
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e14:  # microseconds
            return int(v / 1000)
        if v > 1e11:  # milliseconds
            return int(v)
        return int(v * 1000)
    s = str(value).strip()
    if s.isdigit():
        return to_epoch_ms(int(s))
    try:
        # Python handles fractional seconds up to 6 digits; trim longer ones (Graph uses 7).
        if "." in s:
            head, _, tail = s.partition(".")
            frac = "".join(ch for ch in tail if ch.isdigit())
            zone = tail[len(frac):]
            s = f"{head}.{frac[:6]}{zone}"
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return int(d.timestamp() * 1000)


def iso(ms: int) -> str:
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def severity_id(word_or_id: Any) -> int:
    if isinstance(word_or_id, int) and word_or_id in SEVERITY_IDS:
        return word_or_id
    return SEVERITY_FROM_WORD.get(str(word_or_id or "").strip().lower(), 0)


def finding_severity(sev_id: int) -> str:
    """OCSF severity to the platform's four-level finding severity."""
    if sev_id >= 5:
        return "critical"
    if sev_id == 4:
        return "high"
    if sev_id == 3:
        return "medium"
    return "low"


def event(cls: str, activity_id: int, *, time: Any, product: str, vendor: str, uid: str | None = None,
          severity: Any = 1, status_id: int | None = None, message: str = "", **attrs) -> dict:
    """Build an OCSF event. `attrs` are class attributes merged at the top level
    (actor, user, src_endpoint, process, finding_info, ...). None values are dropped
    so the stored event carries only what the vendor gave us."""
    if cls not in CLASSES:
        raise MappingError(f"unknown OCSF class {cls}")
    class_uid, class_name, cat_uid, cat_name, activities = CLASSES[cls]
    if activity_id not in activities:
        activity_id = 99
    t = to_epoch_ms(time)
    if t is None:
        raise MappingError("record has no usable time")
    sev = severity_id(severity)
    ev: dict = {
        "class_uid": class_uid, "class_name": class_name,
        "category_uid": cat_uid, "category_name": cat_name,
        "activity_id": activity_id, "activity_name": activities[activity_id],
        "type_uid": class_uid * 100 + activity_id,
        "type_name": f"{class_name}: {activities[activity_id]}",
        "time": t, "time_dt": iso(t),
        "severity_id": sev, "severity": SEVERITY_IDS.get(sev, "Unknown"),
        "metadata": {"version": OCSF_VERSION, "product": {"name": product, "vendor_name": vendor},
                     "original_time": iso(t)},
    }
    if uid:
        ev["metadata"]["uid"] = str(uid)
    if status_id is not None:
        ev["status_id"] = status_id
        ev["status"] = STATUS_IDS.get(status_id, "Other")
    if message:
        ev["message"] = str(message)[:2000]
    for k, v in attrs.items():
        pv = prune(v)
        if pv is not None and pv != "" and pv != {} and pv != []:
            ev[k] = pv
    return ev


def prune(value):
    """Drop None, empty strings and empty containers recursively."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            pv = prune(v)
            if pv is None or pv == "" or pv == {} or pv == []:
                continue
            out[k] = pv
        return out
    if isinstance(value, list):
        return [p for p in (prune(v) for v in value) if p is not None and p != "" and p != {}]
    return value


# ---------------------------------------------------------------- common objects
def user(name=None, uid=None, email=None, domain=None, type_=None, groups=None) -> dict:
    return prune({"name": name, "uid": uid, "email_addr": email, "domain": domain, "type": type_,
                  "groups": [{"name": g} for g in groups or []]})


def endpoint(ip=None, hostname=None, port=None, uid=None, os_name=None, location=None, mac=None) -> dict:
    return prune({"ip": ip, "hostname": hostname, "port": int(port) if str(port or "").isdigit() else None,
                  "uid": uid, "os": {"name": os_name} if os_name else None, "location": location, "mac": mac})


def location(country=None, city=None, region=None, lat=None, lon=None) -> dict:
    coords = [lon, lat] if lat is not None and lon is not None else None
    return prune({"country": country, "city": city, "region": region, "coordinates": coords})


def process(name=None, path=None, cmd_line=None, pid=None, uid=None, sha256=None, md5=None, user_=None,
            parent=None) -> dict:
    hashes = []
    if sha256:
        hashes.append({"algorithm_id": 3, "algorithm": "SHA-256", "value": sha256})
    if md5:
        hashes.append({"algorithm_id": 1, "algorithm": "MD5", "value": md5})
    return prune({"name": name, "pid": int(pid) if str(pid or "").isdigit() else None, "uid": uid,
                  "cmd_line": cmd_line, "file": {"name": name, "path": path, "hashes": hashes},
                  "user": user_, "parent_process": parent})


def finding_info(title, uid=None, desc=None, types=None, attacks=None, src_url=None, created=None) -> dict:
    """attacks: list of ATT&CK technique ids (T1059.001) or dicts already in OCSF form."""
    att = []
    for a in attacks or []:
        if isinstance(a, dict):
            att.append(a)
        elif a:
            att.append({"technique": {"uid": str(a)}})
    return prune({"title": title, "uid": uid, "desc": desc, "types": types, "attacks": att,
                  "src_url": src_url, "created_time": to_epoch_ms(created) if created else None})


def device(hostname=None, ip=None, uid=None, os_name=None, type_=None) -> dict:
    return prune({"hostname": hostname, "ip": ip, "uid": uid, "os": {"name": os_name} if os_name else None,
                  "type": type_})


def cloud(provider=None, account=None, region=None) -> dict:
    return prune({"provider": provider, "account": {"uid": account} if account else None, "region": region})


def validate(ev: dict) -> list[str]:
    """Cheap structural check before an event is stored. Returns problems."""
    out = [f"missing {k}" for k in REQUIRED if k not in ev]
    if ev.get("class_uid") not in CLASS_BY_UID:
        out.append("unknown class_uid")
    if not isinstance(ev.get("time"), int):
        out.append("time must be epoch milliseconds")
    md = ev.get("metadata") or {}
    if not (md.get("product") or {}).get("name"):
        out.append("metadata.product.name missing")
    return out


def get_path(ev: dict, path: str):
    """Read a dotted path; a list along the way yields a list of the leaf values."""
    cur: Any = ev
    for part in path.split("."):
        if isinstance(cur, list):
            vals = []
            for item in cur:
                v = get_path(item, part) if isinstance(item, dict) else None
                if isinstance(v, list):
                    vals.extend(v)
                elif v is not None:
                    vals.append(v)
            cur = vals or None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


# Fields every event summary in the console and the finding model reads.
def summary(ev: dict) -> dict:
    host = (get_path(ev, "device.hostname") or get_path(ev, "src_endpoint.hostname")
            or get_path(ev, "dst_endpoint.hostname") or "")
    usr = (get_path(ev, "actor.user.email_addr") or get_path(ev, "actor.user.name")
           or get_path(ev, "user.email_addr") or get_path(ev, "user.name") or "")
    title = (get_path(ev, "finding_info.title") or get_path(ev, "api.operation") or ev.get("message")
             or ev.get("type_name") or "")
    ip = get_path(ev, "src_endpoint.ip") or ""
    return {"host": str(host)[:255], "user": str(usr)[:320], "title": str(title)[:600], "src_ip": str(ip)[:64]}
