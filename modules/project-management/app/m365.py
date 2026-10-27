"""Microsoft 365 engagement workspace (Microsoft Graph, app-only).

One engagement gets one private Microsoft 365 group. The group carries:

- the engagement mailbox (ir-781@vendettacd.io / ps-012@vendettacd.io). Graph sets the
  address; the Exchange settings Graph cannot make (external senders, Send As) are
  queued for the host mailbox worker, see kickoff.py and worker/.
- a Team with the engagement's channels in the threads layout, private channels where
  the work calls for it, and tags that split the people the way channels split the work.
- the SharePoint site with the folder tree, a Client Uploads folder shared to named
  client contacts with sign-in required, and the client toolset copied in.

Every function here is safe to call again. Each takes the refs a previous call
returned and skips what already exists, which is what makes a kickoff retry safe.

Graph application permissions: Group.ReadWrite.All, User.Read.All, Team.Create,
TeamMember.ReadWrite.All, Channel.Create, ChannelMember.ReadWrite.All,
TeamworkTag.ReadWrite.All, Sites.ReadWrite.All (or Files.ReadWrite.All plus
Sites.Selected on the tools library).
"""
from __future__ import annotations

import logging
import re
import time
from urllib.parse import quote, urlparse

import httpx

from . import integrations
from .config import settings

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"
TRANSPORT: httpx.BaseTransport | None = None
SLEEP = time.sleep  # tests replace this
_TOKEN: dict = {"value": "", "exp": 0.0, "key": ""}

# Channels, tags and folders per practice. The kickoff can name a different channel
# set; General always exists. A channel marked private gets its own membership.
CHANNELS = {
    "ir": [
        {"name": "Forensics and Analysis", "description": "Collection, triage, timeline, findings"},
        {"name": "Containment and Recovery", "description": "Containment actions, eradication, restoration"},
        {"name": "Threat Intel", "description": "Attribution, IOCs, leak site monitoring, actor contact"},
        {"name": "Client Communications", "description": "Drafts and approvals for anything that leaves the engagement mailbox"},
        {"name": "Case Management", "description": "Scope, staffing, billing, carrier panel, change orders", "private": True},
    ],
    "proserv": [
        {"name": "Delivery", "description": "Day to day delivery work"},
        {"name": "QA and Reporting", "description": "Peer review, report drafting and sign-off"},
        {"name": "Client Communications", "description": "Drafts and approvals for anything that leaves the engagement mailbox"},
        {"name": "Engagement Management", "description": "Scope, staffing, budget, change requests", "private": True},
    ],
}
OPTIONAL_CHANNELS = {
    "ir": ["Notification and Legal", "Recovery Tracking", "Insurance and Carrier"],
    "proserv": ["Testing", "Remediation Tracking", "Executive Briefings"],
}
TAGS = {"ir": ["Forensics", "Containment", "Threat Intel", "Case Management"],
        "proserv": ["Delivery", "QA", "Engagement Management"]}
# Which tag gets into which private channel.
PRIVATE_CHANNEL_TAG = {"Case Management": "Case Management", "Engagement Management": "Engagement Management"}
FOLDERS = {
    "ir": ["Client Uploads", "Evidence/Intake", "Evidence/Images", "Evidence/Logs", "Evidence/Memory",
           "Evidence/Malware", "Analysis", "Deliverables/Drafts", "Deliverables/Final", "Correspondence",
           "Case Admin", "Meeting Notes"],
    "proserv": ["Client Uploads", "Working Files", "Deliverables/Drafts", "Deliverables/Final", "Correspondence",
                "Engagement Admin", "Meeting Notes"],
}
UPLOADS = "Client Uploads"
TOOLS_SUBFOLDER = "Client Uploads/Vendetta Tools"


class GraphError(Exception):
    pass


def configured() -> bool:
    cfg = integrations.resolve()
    return settings.kickoff_m365_enabled and bool(cfg["graph_tenant_id"] and cfg["graph_client_id"]
                                                  and cfg["graph_client_secret"])


# ---------------------------------------------------------------- transport
class Graph:
    def __init__(self):
        self.http = httpx.Client(timeout=30.0, transport=TRANSPORT)

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _token(self) -> str:
        cfg = integrations.resolve()
        key = f"{cfg['graph_tenant_id']}|{cfg['graph_client_id']}"
        if _TOKEN["value"] and _TOKEN["key"] == key and time.time() < _TOKEN["exp"] - 120:
            return _TOKEN["value"]
        r = self.http.post(f"https://login.microsoftonline.com/{cfg['graph_tenant_id']}/oauth2/v2.0/token",
                           data={"client_id": cfg["graph_client_id"], "client_secret": cfg["graph_client_secret"],
                                 "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
        if r.status_code != 200:
            raise GraphError(f"Graph token request failed (HTTP {r.status_code}); check the app credentials")
        body = r.json()
        _TOKEN.update(value=body["access_token"], exp=time.time() + int(body.get("expires_in", 3600)), key=key)
        return _TOKEN["value"]

    def call(self, method: str, path: str, *, json: dict | None = None, ok=(200, 201, 202, 204),
             params: dict | None = None) -> httpx.Response:
        url = path if path.startswith("http") else f"{GRAPH}/{path.lstrip('/')}"
        r = self.http.request(method, url, json=json, params=params,
                              headers={"Authorization": f"Bearer {self._token()}"})
        if r.status_code in ok:
            return r
        try:
            msg = (r.json().get("error") or {}).get("message") or ""
        except ValueError:
            msg = ""
        if r.status_code in (401, 403):
            raise GraphError(f"Graph refused {method} {path.split('?')[0]} (HTTP {r.status_code}); the app "
                             f"registration is missing a permission. {msg}".strip())
        raise GraphError(f"Graph {method} {path.split('?')[0]} failed (HTTP {r.status_code}) {msg}".strip())

    def json(self, method: str, path: str, **kw) -> dict:
        r = self.call(method, path, **kw)
        return r.json() if r.content else {}


# ---------------------------------------------------------------- helpers
def nickname(code: str, practice: str) -> str:
    """ir-781 for VCD-IR-2026-781, ps-012 for VCD-PS-2026-012; falls back to a slug."""
    m = re.search(r"(\d+)$", code or "")
    prefix = "ir" if practice == "ir" else "ps"
    if m:
        return f"{prefix}-{m.group(1)}"
    return (prefix + "-" + re.sub(r"[^a-z0-9]+", "-", (code or "").lower())).strip("-")[:56]


def display_name(practice: str, client: str, codename: str = "") -> str:
    label = (codename or client or "Engagement").strip()
    return f"{'Incident Response' if practice == 'ir' else 'Professional Services'}-{label}"


def user_ids(g: Graph, emails: list[str]) -> dict[str, str]:
    out = {}
    for e in emails:
        e = (e or "").strip().lower()
        if not e or e in out:
            continue
        r = g.call("GET", f"users/{quote(e)}", params={"$select": "id,mail,userPrincipalName"}, ok=(200, 404))
        if r.status_code == 404:
            raise GraphError(f"No Microsoft 365 user has the address {e}")
        out[e] = r.json()["id"]
    return out


# ---------------------------------------------------------------- group and team
def ensure_group(g: Graph, refs: dict, *, name: str, description: str, mail_nickname: str,
                 owners: list[str], members: list[str]) -> dict:
    """The private Microsoft 365 group (and so the mailbox and the SharePoint site)."""
    if refs.get("group_id"):
        return refs
    found = g.json("GET", "groups", params={"$filter": f"mailNickname eq '{mail_nickname}'", "$select": "id,mail"})
    if found.get("value"):
        grp = found["value"][0]
    else:
        ids = user_ids(g, owners + members)
        body = {"displayName": name, "description": description[:1000], "mailNickname": mail_nickname,
                "mailEnabled": True, "securityEnabled": False, "groupTypes": ["Unified"], "visibility": "Private",
                "owners@odata.bind": [f"{GRAPH}/users/{ids[o.lower()]}" for o in owners],
                "members@odata.bind": [f"{GRAPH}/users/{ids[m.lower()]}" for m in dict.fromkeys(owners + members)]}
        grp = g.json("POST", "groups", json=body)
    refs.update(group_id=grp["id"], mailbox=grp.get("mail") or f"{mail_nickname}@{settings.kickoff_mail_domain}")
    return refs


def ensure_team(g: Graph, refs: dict) -> dict:
    """Team-enable the group. A new group takes a while to replicate, so a 404 is retried."""
    if refs.get("team_id"):
        return refs
    body = {"memberSettings": {"allowCreateUpdateChannels": False, "allowDeleteChannels": False,
                               "allowAddRemoveApps": False, "allowCreatePrivateChannels": False},
            "messagingSettings": {"allowUserEditMessages": True, "allowUserDeleteMessages": False,
                                  "allowOwnerDeleteMessages": False},
            "guestSettings": {"allowCreateUpdateChannels": False, "allowDeleteChannels": False}}
    last = None
    for _ in range(max(1, settings.kickoff_team_poll_attempts)):
        r = g.call("PUT", f"groups/{refs['group_id']}/team", json=body, ok=(200, 201, 404, 409))
        if r.status_code in (200, 201, 409):
            refs["team_id"] = refs["group_id"]
            if r.status_code != 409 and r.content:
                refs["team_url"] = r.json().get("webUrl", "")
            return refs
        last = r.status_code
        SLEEP(settings.kickoff_team_poll_seconds)
    raise GraphError(f"The group was created but Teams could not attach yet (HTTP {last}); retry the step")


def ensure_channels(g: Graph, refs: dict, *, practice: str, channels: list[dict], owner_ids: list[str],
                    tag_members: dict[str, list[str]]) -> dict:
    existing = {c["displayName"].lower(): c["id"]
                for c in g.json("GET", f"teams/{refs['team_id']}/channels").get("value", [])}
    made = refs.setdefault("channels", {})
    for ch in channels:
        key = ch["name"].lower()
        if key in existing:
            made[ch["name"]] = existing[key]
            continue
        body = {"displayName": ch["name"], "description": ch.get("description", "")[:1024],
                "membershipType": "private" if ch.get("private") else "standard"}
        if settings.kickoff_channel_layout:
            body["layoutType"] = settings.kickoff_channel_layout
        if ch.get("private"):
            # A private channel needs at least one owner at creation; the rest are added below.
            body["members"] = [{"@odata.type": "#microsoft.graph.aadUserConversationMember", "roles": ["owner"],
                                "user@odata.bind": f"{GRAPH}/users('{uid}')"} for uid in owner_ids[:1]]
        r = g.call("POST", f"teams/{refs['team_id']}/channels", json=body, ok=(200, 201, 400))
        if r.status_code == 400 and "layoutType" in body:
            body.pop("layoutType")  # tenants without the threads layout reject the property
            r = g.call("POST", f"teams/{refs['team_id']}/channels", json=body)
            refs["layout_note"] = "threads layout not accepted by this tenant; channels use the default layout"
        elif r.status_code == 400:
            raise GraphError(f"Graph rejected channel '{ch['name']}' (HTTP 400)")
        made[ch["name"]] = r.json()["id"]
        if ch.get("private"):
            tag = PRIVATE_CHANNEL_TAG.get(ch["name"])
            for uid in dict.fromkeys(owner_ids[1:] + (tag_members.get(tag, []) if tag else [])):
                g.call("POST", f"teams/{refs['team_id']}/channels/{made[ch['name']]}/members",
                       json={"@odata.type": "#microsoft.graph.aadUserConversationMember",
                             "roles": ["owner"] if uid in owner_ids else [],
                             "user@odata.bind": f"{GRAPH}/users('{uid}')"}, ok=(200, 201, 409))
    if practice == "ir" and settings.kickoff_channel_layout:
        g.call("PATCH", f"teams/{refs['team_id']}/primaryChannel", json={"layoutType": settings.kickoff_channel_layout},
               ok=(200, 204, 400, 403))
    return refs


def ensure_tags(g: Graph, refs: dict, tag_members: dict[str, list[str]]) -> dict:
    existing = {t["displayName"].lower(): t["id"]
                for t in g.json("GET", f"teams/{refs['team_id']}/tags").get("value", [])}
    made = refs.setdefault("tags", {})
    for tag, uids in tag_members.items():
        uids = list(dict.fromkeys(uids))
        if not uids:
            continue
        if tag.lower() in existing:
            made[tag] = existing[tag.lower()]
            continue
        t = g.json("POST", f"teams/{refs['team_id']}/tags",
                   json={"displayName": tag, "members": [{"userId": u} for u in uids]})
        made[tag] = t["id"]
    return refs


# ---------------------------------------------------------------- SharePoint
def ensure_site(g: Graph, refs: dict) -> dict:
    if refs.get("drive_id"):
        return refs
    for _ in range(max(1, settings.kickoff_team_poll_attempts)):
        r = g.call("GET", f"groups/{refs['group_id']}/sites/root", ok=(200, 404))
        if r.status_code == 200:
            site = r.json()
            drive = g.json("GET", f"groups/{refs['group_id']}/drive")
            refs.update(site_id=site["id"], site_url=site.get("webUrl", ""), drive_id=drive["id"])
            return refs
        SLEEP(settings.kickoff_team_poll_seconds)
    raise GraphError("The group's SharePoint site is not ready yet; retry the step")


def _ensure_folder(g: Graph, drive_id: str, path: str) -> dict:
    parent, _, name = path.rpartition("/")
    r = g.call("GET", f"drives/{drive_id}/root:/{quote(path)}", ok=(200, 404))
    if r.status_code == 200:
        return r.json()
    where = f"drives/{drive_id}/root:/{quote(parent)}:/children" if parent else f"drives/{drive_id}/root/children"
    r = g.call("POST", where, json={"name": name, "folder": {}, "@microsoft.graph.conflictBehavior": "fail"},
               ok=(200, 201, 409))
    if r.status_code == 409:
        return g.json("GET", f"drives/{drive_id}/root:/{quote(path)}")
    return r.json()


def ensure_folders(g: Graph, refs: dict, practice: str, extra: list[str] | None = None) -> dict:
    paths: list[str] = []
    for p in FOLDERS[practice] + list(extra or []):
        parts = p.split("/")
        for i in range(1, len(parts) + 1):
            sub = "/".join(parts[:i])
            if sub not in paths:
                paths.append(sub)
    made = refs.setdefault("folders", {})
    for p in paths:
        if p not in made:
            made[p] = _ensure_folder(g, refs["drive_id"], p)["id"]
    uploads = g.json("GET", f"drives/{refs['drive_id']}/items/{made[UPLOADS]}")
    refs["uploads_url"] = uploads.get("webUrl", "")
    return refs


def share_uploads(g: Graph, refs: dict, client_contacts: list[str], message: str) -> dict:
    """Share Client Uploads with each named client contact: edit rights, sign-in
    required, no anonymous links. Each address is invited once."""
    done = refs.setdefault("uploads_shared_with", [])
    todo = [e.strip().lower() for e in client_contacts if e and e.strip().lower() not in done]
    if not todo:
        return refs
    g.json("POST", f"drives/{refs['drive_id']}/items/{refs['folders'][UPLOADS]}/invite",
           json={"recipients": [{"email": e} for e in todo], "requireSignIn": True, "sendInvitation": True,
                 "roles": ["write"], "message": message[:2000]})
    done.extend(todo)
    return refs


def copy_client_tools(g: Graph, refs: dict, tools: list[str]) -> dict:
    """Copy each selected tool folder from the Vendetta tools library into Client
    Uploads/Vendetta Tools. The library is a folder per tool, named by its key."""
    if not tools:
        return refs
    lib_site = settings_value("kickoff_tools_site_url")
    lib_path = settings_value("kickoff_tools_folder")
    if not (lib_site and lib_path):
        raise GraphError("Client tools were selected but KICKOFF_TOOLS_SITE_URL and KICKOFF_TOOLS_FOLDER are not set")
    u = urlparse(lib_site)
    site = g.json("GET", f"sites/{u.hostname}:{u.path.rstrip('/')}" if u.path.strip("/") else f"sites/{u.hostname}")
    lib_drive = g.json("GET", f"sites/{site['id']}/drive")["id"]
    dest = refs["folders"].get(TOOLS_SUBFOLDER) or _ensure_folder(g, refs["drive_id"], TOOLS_SUBFOLDER)["id"]
    refs["folders"][TOOLS_SUBFOLDER] = dest
    done = refs.setdefault("tools_copied", [])
    for key in tools:
        if key in done:
            continue
        src = g.call("GET", f"drives/{lib_drive}/root:/{quote(lib_path.strip('/') + '/' + key)}", ok=(200, 404))
        if src.status_code == 404:
            raise GraphError(f"The tools library has no folder named '{key}'")
        g.call("POST", f"drives/{lib_drive}/items/{src.json()['id']}/copy",
               json={"parentReference": {"driveId": refs["drive_id"], "id": dest}},
               params={"@microsoft.graph.conflictBehavior": "replace"})
        done.append(key)
    return refs


def settings_value(name: str) -> str:
    return (getattr(settings, name, "") or "").strip()


def tool_library() -> list[str]:
    """Tool keys the kickoff offers, from KICKOFF_CLIENT_TOOLS."""
    return [t.strip() for t in settings_value("kickoff_client_tools").split(",") if t.strip()]
