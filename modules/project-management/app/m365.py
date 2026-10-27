"""Microsoft 365 setup for a kickoff (Microsoft Graph, app-only).

Each practice has one parent team, "Vendetta Incident Response" and "Vendetta
Professional Services". An engagement is a private channel in its practice's team.
The private channel gets its own SharePoint site, so case files stay separated by
engagement, and only the people added to the channel can see it.

The engagement email is a plus address on the practice's shared mailbox
(ir+vcd-ir-2026-014@vendettacd.io). Mail sent or CC'd to it lands in that mailbox,
and an inbox rule files it into a folder named for the engagement.

Each practice team also has one standard "Time Entry" channel whose Vendetta Time tab
is left unlocked, so people can log time against any engagement they are on.

Private channel sites and files folders appear some minutes after the channel, so the
calls that need them raise Wait and the kickoff runner tries again later.

Every call here is safe to repeat: an existing channel is found by its name, existing
members, folders, tabs, mail folders, rules and list rows are left alone.

Application permissions the app registration needs (admin consent):
User.Read.All, GroupMember.ReadWrite.All (adds people to the practice team),
Channel.Create, Channel.ReadBasic.All, ChannelMember.ReadWrite.All,
ChannelSettings.ReadWrite.All (threads layout), Files.ReadWrite.All (case folders),
TeamsTab.Create, TeamsAppInstallation.ReadWriteForTeam.All (only for the Vendetta Time
tab), Mail.ReadWrite and MailboxSettings.ReadWrite (the engagement mail folder and
rule, and the client email draft). Scope the two mail permissions to the practice
mailboxes and PMs with an Exchange application access policy.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import quote

import httpx

from . import integrations, sharepoint

log = logging.getLogger(__name__)
GRAPH = sharepoint.GRAPH
CHANNEL_LIMIT = 1000  # standard, private and shared combined, deleted ones for 30 days


class GraphError(Exception):
    pass


class Wait(Exception):
    """Microsoft 365 has not finished creating something yet; try again later."""


def configured() -> bool:
    cfg = integrations.resolve()
    return bool(cfg["graph_tenant_id"] and cfg["graph_client_id"] and cfg["graph_client_secret"])


def _client() -> httpx.Client:
    http = httpx.Client(timeout=30.0, transport=sharepoint.TRANSPORT)
    try:
        http.headers["Authorization"] = f"Bearer {sharepoint._token(http)}"
    except sharepoint.SharePointError as e:
        http.close()
        raise GraphError(str(e)) from e
    return http


def _check(r: httpx.Response, what: str) -> dict:
    if r.status_code in (401, 403):
        raise GraphError(f"The app is not allowed to {what}. Grant the Graph permission and admin consent.")
    if r.status_code >= 400:
        try:
            msg = (r.json().get("error") or {}).get("message") or ""
        except ValueError:
            msg = ""
        raise GraphError(f"Graph HTTP {r.status_code} trying to {what}{': ' + msg[:200] if msg else ''}")
    if r.status_code == 204 or not r.content:
        return {}
    return r.json()


def nickname(code: str) -> str:
    """A mail nickname from an engagement code: VCD-IR-2026-014 -> vcd-ir-2026-014."""
    n = re.sub(r"[^A-Za-z0-9-]+", "-", code or "").strip("-").lower()
    return n[:60] or "engagement"


# ---------------------------------------------------------------- people
def resolve_users(http: httpx.Client, emails: list[str]) -> tuple[dict[str, str], list[str]]:
    """Directory object ids for staff emails, matched on UPN, then mail."""
    found, missing = {}, []
    for email in emails:
        e = email.strip().lower()
        if not e or e in found:
            continue
        r = http.get(f"{GRAPH}/users/{quote(e)}", params={"$select": "id,userPrincipalName,mail"})
        if r.status_code == 404:
            r = http.get(f"{GRAPH}/users", params={"$filter": f"mail eq '{e}'", "$select": "id,mail"})
            rows = _check(r, "look up users").get("value") or []
            if rows:
                found[e] = rows[0]["id"]
            else:
                missing.append(e)
            continue
        found[e] = _check(r, "look up users")["id"]
    return found, missing


# ---------------------------------------------------------------- practice team
def add_members(http: httpx.Client, group_id: str, user_ids: list[str]) -> int:
    """Add anyone not already a member of the practice team (its group). Returns how
    many were added. Private channel members must be members of the parent team."""
    r = http.get(f"{GRAPH}/groups/{group_id}/members", params={"$select": "id", "$top": "999"})
    have = {m["id"] for m in _check(r, "read the practice team's members").get("value") or []}
    n = 0
    for uid in dict.fromkeys(user_ids):
        if uid in have:
            continue
        r = http.post(f"{GRAPH}/groups/{group_id}/members/$ref",
                      json={"@odata.id": f"{GRAPH}/directoryObjects/{uid}"})
        if r.status_code == 400 and "already exist" in r.text:
            continue
        _check(r, "add people to the practice team")
        n += 1
    return n


def practice_team(http: httpx.Client, team_id: str) -> dict:
    """The practice's parent team, with how many channels it holds."""
    r = http.get(f"{GRAPH}/teams/{team_id}", params={"$select": "id,displayName,webUrl"})
    if r.status_code == 404:
        raise GraphError(f"The practice team {team_id} was not found. Check KICKOFF_IR_TEAM_ID "
                         "or KICKOFF_PROSERV_TEAM_ID.")
    t = _check(r, "read the practice team")
    r = http.get(f"{GRAPH}/teams/{team_id}/channels", params={"$select": "id,displayName,membershipType"})
    chans = _check(r, "list the practice team's channels").get("value") or []
    return {"id": t.get("id") or team_id, "name": t.get("displayName") or "", "url": t.get("webUrl") or "",
            "channels": chans}


# ---------------------------------------------------------------- channels
_BAD = re.compile(r'[~#%&*{}+/\\:<>?|\'",]')


def channel_name(code: str, label: str) -> str:
    """A legal channel name: "VCD-IR-2026-014 Atlantic Credit Union", at most 50
    characters, without the characters Teams rejects."""
    name = _BAD.sub(" ", f"{code} {label}".strip())
    name = re.sub(r"\.{2,}", ".", re.sub(r"\s+", " ", name)).strip(" ._")
    return name[:50].rstrip(" .") or code[:50]


def find_channel(http: httpx.Client, team_id: str, name: str) -> dict | None:
    safe = name.replace("'", "''")
    r = http.get(f"{GRAPH}/teams/{team_id}/channels",
                 params={"$filter": f"displayName eq '{safe}'", "$select": "id,displayName,webUrl,membershipType"})
    rows = _check(r, "search the practice team's channels").get("value") or []
    return rows[0] if rows else None


def _member(uid: str, owner: bool) -> dict:
    return {"@odata.type": "#microsoft.graph.aadUserConversationMember",
            "user@odata.bind": f"{GRAPH}/users('{uid}')", "roles": ["owner"] if owner else []}


def ensure_private_channel(http: httpx.Client, team_id: str, *, name: str, description: str,
                           owner_ids: list[str]) -> tuple[dict, bool]:
    """The engagement's private channel. Returns (channel, created)."""
    existing = find_channel(http, team_id, name)
    if existing:
        return existing, False
    if not owner_ids:
        raise GraphError("A private channel needs at least one owner")
    body = {"@odata.type": "#Microsoft.Graph.channel", "membershipType": "private",
            "displayName": name, "description": description[:1024],
            "members": [_member(owner_ids[0], True)]}
    r = http.post(f"{GRAPH}/teams/{team_id}/channels", json=body)
    if r.status_code == 400 and "limit" in r.text.lower():
        raise GraphError("The practice team has reached its channel limit. Point the practice at a new "
                         "team (KICKOFF_IR_TEAM_ID or KICKOFF_PROSERV_TEAM_ID) and retry.")
    ch = _check(r, "create the private channel")
    return {"id": ch["id"], "displayName": ch.get("displayName") or name, "webUrl": ch.get("webUrl") or ""}, True


def ensure_standard_channel(http: httpx.Client, team_id: str, *, name: str, description: str) -> tuple[dict, bool]:
    existing = find_channel(http, team_id, name)
    if existing:
        return existing, False
    r = http.post(f"{GRAPH}/teams/{team_id}/channels",
                  json={"displayName": name, "description": description[:1024], "membershipType": "standard"})
    ch = _check(r, f"create the {name} channel")
    return {"id": ch["id"], "displayName": ch.get("displayName") or name, "webUrl": ch.get("webUrl") or ""}, True


def ensure_channel_members(http: httpx.Client, team_id: str, channel_id: str, *, owner_ids: list[str],
                           member_ids: list[str]) -> int:
    """Add the engagement team to its private channel. Owners get the owner role.
    Returns how many were added."""
    base = f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id)}/members"
    r = http.get(base)
    if r.status_code == 404:
        raise Wait("Teams is still creating the private channel")
    have = {m.get("userId") for m in _check(r, "read the channel's members").get("value") or []}
    n = 0
    owners = set(owner_ids)
    for uid in dict.fromkeys(owner_ids + member_ids):
        if uid in have:
            continue
        r = http.post(base, json=_member(uid, uid in owners))
        if r.status_code == 409:
            continue
        if r.status_code == 404:
            raise Wait("The person has not replicated to the practice team yet")
        _check(r, "add people to the private channel")
        n += 1
    return n


def set_threads_layout(http: httpx.Client, team_id: str, channel_id: str) -> str:
    """Switch the channel to the threads (chat style) layout. Returns a warning, or ""."""
    r = http.patch(f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id)}", json={"layoutType": "chat"})
    if r.status_code < 300:
        return ""
    return f"Could not switch the channel to the threads layout (Graph HTTP {r.status_code}); set it in Teams"


def channel_files(http: httpx.Client, team_id: str, channel_id: str) -> dict:
    """The channel's files folder: drive id, folder item id, folder name, and the URL
    of the SharePoint site that holds it (a private channel has its own site)."""
    r = http.get(f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id)}/filesFolder")
    if r.status_code in (400, 404, 423, 503):
        raise Wait("SharePoint is still creating the private channel's site")
    f = _check(r, "read the channel's files folder")
    drive_id = (f.get("parentReference") or {}).get("driveId") or ""
    if not drive_id or not f.get("id"):
        raise Wait("SharePoint is still creating the private channel's site")
    r = http.get(f"{GRAPH}/drives/{drive_id}", params={"$select": "id,webUrl"})
    if r.status_code == 404:
        raise Wait("SharePoint is still creating the private channel's site")
    lib = _check(r, "read the channel's document library").get("webUrl") or ""
    site_url = lib.rsplit("/", 1)[0] if lib else ""
    return {"drive_id": drive_id, "folder_id": f["id"], "folder_name": f.get("name") or "",
            "folder_url": f.get("webUrl") or "", "site_url": site_url}


def ensure_folders(http: httpx.Client, drive_id: str, root_id: str, paths: list[str]) -> list[str]:
    """Create each folder path under the channel's files folder, parents first.
    Returns the paths that were created (existing ones are skipped)."""
    made = []
    for path in paths:
        parts = [p.strip() for p in path.split("/") if p.strip()]
        for i in range(len(parts)):
            parent = "/".join(parts[:i])
            url = (f"{GRAPH}/drives/{drive_id}/items/{root_id}:/{quote(parent)}:/children" if parent
                   else f"{GRAPH}/drives/{drive_id}/items/{root_id}/children")
            r = http.post(url, json={"name": parts[i], "folder": {}, "@microsoft.graph.conflictBehavior": "fail"})
            if r.status_code == 409:
                continue
            if r.status_code == 404:
                raise Wait("The channel's document library is not ready yet")
            _check(r, "create folders")
            made.append("/".join(parts[: i + 1]))
    return made


def ensure_tab(http: httpx.Client, team_id: str, channel_id: str, *, name: str, app_id: str,
               content_url: str, website_url: str = "", entity_id: str = "") -> bool:
    """Add a tab to a channel unless one with this name is there. Returns True if added."""
    r = http.get(f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id)}/tabs", params={"$select": "displayName"})
    if any((t.get("displayName") or "").lower() == name.lower()
           for t in _check(r, "read channel tabs").get("value") or []):
        return False
    cfg = {"contentUrl": content_url, "websiteUrl": website_url or content_url}
    if entity_id:
        cfg["entityId"] = entity_id
    r = http.post(f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id)}/tabs",
                  json={"displayName": name, "configuration": cfg,
                        "teamsApp@odata.bind": f"{GRAPH}/appCatalogs/teamsApps/{app_id}"})
    _check(r, f"add the {name} tab")
    return True


def install_app(http: httpx.Client, team_id: str, app_id: str) -> None:
    r = http.post(f"{GRAPH}/teams/{team_id}/installedApps",
                  json={"teamsApp@odata.bind": f"{GRAPH}/appCatalogs/teamsApps/{app_id}"})
    if r.status_code == 409:
        return
    _check(r, "install the app in the team")


WEBSITE_TAB_APP = "com.microsoft.teamspace.tab.web"


# ---------------------------------------------------------------- SharePoint list rows
_HONOR = {"Prefer": "HonorNonIndexedQueriesWarningMayFailRandomly"}


def list_find(http: httpx.Client, site_id: str, list_name: str, field: str, value: str) -> dict | None:
    safe = str(value).replace("'", "''")
    r = http.get(f"{GRAPH}/sites/{site_id}/lists/{quote(list_name)}/items",
                 params={"$expand": "fields", "$filter": f"fields/{field} eq '{safe}'"}, headers=_HONOR)
    if r.status_code == 404:
        raise GraphError(f"The list '{list_name}' was not found on the site")
    rows = _check(r, f"read the {list_name} list").get("value") or []
    return rows[0] if rows else None


def list_add(http: httpx.Client, site_id: str, list_name: str, fields: dict) -> dict:
    r = http.post(f"{GRAPH}/sites/{site_id}/lists/{quote(list_name)}/items", json={"fields": fields})
    return _check(r, f"add a row to the {list_name} list")


def list_update(http: httpx.Client, site_id: str, list_name: str, item_id: str, fields: dict) -> None:
    r = http.patch(f"{GRAPH}/sites/{site_id}/lists/{quote(list_name)}/items/{item_id}/fields", json=fields)
    _check(r, f"update the {list_name} list")


def site_user_lookup_id(http: httpx.Client, site_id: str, email: str) -> str | None:
    """A person's lookup id on a site (for a Person column), from the site's hidden
    User Information List. None when they have never been added to the site."""
    row = None
    try:
        row = list_find(http, site_id, "User Information List", "EMail", email.lower())
    except GraphError:
        row = None
    return str(row["id"]) if row else None


# ---------------------------------------------------------------- mail
def draft_mail(http: httpx.Client, mailbox: str, *, subject: str, html: str, to: list[str],
               cc: list[str]) -> dict:
    """A draft in the mailbox's Drafts folder. Never sent."""
    body = {"subject": subject[:250], "body": {"contentType": "HTML", "content": html},
            "toRecipients": [{"emailAddress": {"address": a}} for a in to],
            "ccRecipients": [{"emailAddress": {"address": a}} for a in cc if a]}
    m = _check(http.post(f"{GRAPH}/users/{quote(mailbox)}/messages", json=body), "draft the client email")
    return {"id": m.get("id", ""), "webLink": m.get("webLink", "")}


def plus_address(mailbox: str, tag: str) -> str:
    """ir@vendettacd.io + vcd-ir-2026-014 -> ir+vcd-ir-2026-014@vendettacd.io"""
    local, _, domain = mailbox.strip().lower().partition("@")
    if not local or not domain:
        raise GraphError(f"'{mailbox}' is not a mailbox address")
    return f"{local.split('+', 1)[0]}+{tag}@{domain}"


def ensure_mail_folder(http: httpx.Client, mailbox: str, name: str) -> tuple[str, bool]:
    """A folder under the mailbox's Inbox. Returns (folder id, created)."""
    base = f"{GRAPH}/users/{quote(mailbox)}/mailFolders/inbox/childFolders"
    safe = name.replace("'", "''")
    r = http.get(base, params={"$filter": f"displayName eq '{safe}'", "$select": "id,displayName"})
    if r.status_code == 404:
        raise GraphError(f"The mailbox {mailbox} was not found")
    rows = _check(r, f"read {mailbox}'s folders").get("value") or []
    if rows:
        return rows[0]["id"], False
    f = _check(http.post(base, json={"displayName": name}), f"create a folder in {mailbox}")
    return f["id"], True


def ensure_mail_rule(http: httpx.Client, mailbox: str, *, name: str, address: str, folder_id: str) -> bool:
    """An inbox rule that files mail sent or copied to the engagement address into its
    folder. Returns True when the rule was created."""
    base = f"{GRAPH}/users/{quote(mailbox)}/mailFolders/inbox/messageRules"
    rules = _check(http.get(base), f"read {mailbox}'s inbox rules").get("value") or []
    if any((x.get("displayName") or "").lower() == name.lower() for x in rules):
        return False
    seq = max([int(x.get("sequence") or 0) for x in rules] + [0]) + 1
    body = {"displayName": name[:250], "sequence": seq, "isEnabled": True,
            "conditions": {"headerContains": [address]},
            "actions": {"moveToFolder": folder_id, "stopProcessingRules": True}}
    _check(http.post(base, json=body), f"add an inbox rule to {mailbox}")
    return True
