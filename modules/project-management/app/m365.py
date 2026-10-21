"""Microsoft 365 setup for a kickoff (Microsoft Graph, app-only).

Each engagement gets one Microsoft 365 group. The group gives it a SharePoint site
(the engagement's document library, where meeting notes already mirror), a group
mailbox to CC on client mail, and a Team for the engagement team. The site and team
appear some minutes after the group, so the calls that need them raise Wait and the
kickoff runner tries again later.

Every call here is safe to repeat: an existing group is found by its mail nickname,
existing folders, tabs and list rows are left alone, and a team that already exists
is reused.

Application permissions the app registration needs (admin consent):
Group.ReadWrite.All, User.Read.All, Sites.ReadWrite.All, Team.Create,
TeamsTab.Create, TeamsAppInstallation.ReadWriteForTeam.All (only for the Vendetta
Time tab), and Mail.ReadWrite (only for the client email draft).
"""
from __future__ import annotations

import logging
import re
from urllib.parse import quote

import httpx

from . import integrations, sharepoint

log = logging.getLogger(__name__)
GRAPH = sharepoint.GRAPH


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


# ---------------------------------------------------------------- group, site, team
def find_group(http: httpx.Client, nick: str) -> dict | None:
    r = http.get(f"{GRAPH}/groups", params={"$filter": f"mailNickname eq '{nick}'",
                                            "$select": "id,displayName,mail,mailNickname"})
    rows = _check(r, "search groups").get("value") or []
    return rows[0] if rows else None


def display_name_taken(http: httpx.Client, name: str) -> bool:
    safe = name.replace("'", "''")
    r = http.get(f"{GRAPH}/groups", params={"$filter": f"displayName eq '{safe}'", "$select": "id"})
    return bool(_check(r, "search groups").get("value"))


def create_group(http: httpx.Client, *, display_name: str, nick: str, description: str,
                 owner_ids: list[str], member_ids: list[str]) -> tuple[dict, bool]:
    """The engagement's group (private, Microsoft 365). Returns (group, created)."""
    existing = find_group(http, nick)
    if existing:
        return existing, False
    owners = [f"{GRAPH}/users/{i}" for i in dict.fromkeys(owner_ids)][:20]
    members = [f"{GRAPH}/users/{i}" for i in dict.fromkeys(member_ids + owner_ids)][:20]
    body = {"displayName": display_name[:256], "mailNickname": nick, "description": description[:1000],
            "groupTypes": ["Unified"], "mailEnabled": True, "securityEnabled": False, "visibility": "Private"}
    if owners:
        body["owners@odata.bind"] = owners
    if members:
        body["members@odata.bind"] = members
    g = _check(http.post(f"{GRAPH}/groups", json=body), "create the Microsoft 365 group")
    return {"id": g["id"], "displayName": g.get("displayName"), "mail": g.get("mail") or "",
            "mailNickname": g.get("mailNickname") or nick}, True


def add_members(http: httpx.Client, group_id: str, user_ids: list[str]) -> int:
    """Add anyone not already a member. Returns how many were added."""
    r = http.get(f"{GRAPH}/groups/{group_id}/members", params={"$select": "id", "$top": "999"})
    have = {m["id"] for m in _check(r, "read group members").get("value") or []}
    n = 0
    for uid in dict.fromkeys(user_ids):
        if uid in have:
            continue
        r = http.post(f"{GRAPH}/groups/{group_id}/members/$ref",
                      json={"@odata.id": f"{GRAPH}/directoryObjects/{uid}"})
        if r.status_code == 400 and "already exist" in r.text:
            continue
        _check(r, "add group members")
        n += 1
    return n


def group_site(http: httpx.Client, group_id: str) -> dict:
    r = http.get(f"{GRAPH}/groups/{group_id}/sites/root", params={"$select": "id,webUrl,displayName"})
    if r.status_code in (400, 404):
        raise Wait("SharePoint is still creating the group's site")
    s = _check(r, "read the group's site")
    if not s.get("webUrl"):
        raise Wait("SharePoint is still creating the group's site")
    return {"id": s["id"], "webUrl": s["webUrl"]}


def ensure_folders(http: httpx.Client, site_id: str, paths: list[str]) -> list[str]:
    """Create each folder path in the site's default document library, parents first.
    Returns the paths that were created (existing ones are skipped)."""
    made = []
    for path in paths:
        parts = [p.strip() for p in path.split("/") if p.strip()]
        for i in range(len(parts)):
            parent = "/".join(parts[:i])
            url = (f"{GRAPH}/sites/{site_id}/drive/root:/{quote(parent)}:/children" if parent
                   else f"{GRAPH}/sites/{site_id}/drive/root/children")
            r = http.post(url, json={"name": parts[i], "folder": {}, "@microsoft.graph.conflictBehavior": "fail"})
            if r.status_code == 409:
                continue
            if r.status_code == 404:
                raise Wait("The site's document library is not ready yet")
            _check(r, "create folders")
            made.append("/".join(parts[: i + 1]))
    return made


def ensure_team(http: httpx.Client, group_id: str) -> dict:
    """Team-enable the group (or find its team) and return its primary channel."""
    r = http.get(f"{GRAPH}/teams/{group_id}", params={"$select": "id,webUrl"})
    if r.status_code == 404:
        body = {"memberSettings": {"allowCreateUpdateChannels": True},
                "messagingSettings": {"allowUserEditMessages": True, "allowUserDeleteMessages": False},
                "funSettings": {"allowGiphy": False}}
        r = http.put(f"{GRAPH}/groups/{group_id}/team", json=body)
        if r.status_code == 404:
            raise Wait("The group has not replicated to Teams yet")
        if r.status_code == 409:
            raise Wait("Teams is still creating the team")
        _check(r, "create the team")
        r = http.get(f"{GRAPH}/teams/{group_id}", params={"$select": "id,webUrl"})
        if r.status_code == 404:
            raise Wait("Teams is still creating the team")
    team = _check(r, "read the team")
    r = http.get(f"{GRAPH}/teams/{group_id}/primaryChannel", params={"$select": "id,displayName,webUrl"})
    if r.status_code == 404:
        raise Wait("Teams is still creating the General channel")
    ch = _check(r, "read the General channel")
    return {"team_id": team.get("id") or group_id, "team_url": team.get("webUrl") or "",
            "channel_id": ch["id"], "channel_url": ch.get("webUrl") or ""}


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
