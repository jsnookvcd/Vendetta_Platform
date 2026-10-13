"""SuperOps PSA/RMM connector (GraphQL).

API: POST {superops_api_url} with Authorization: Bearer <token> and
CustomerSubDomain headers. List queries take ListInfoInput (page, pageSize,
condition, sort); errors come back HTTP 200 with an errors array, so every call
checks it. Rate limit is 100/min; the rate-limit error is an app code, not a 429.

Client filtering on list queries uses {"attribute": "client", "operator":
"includes", "value": [accountId]} for assets and tickets. Alerts carry the client
nested inside asset, so they are filtered here after the fetch."""
from __future__ import annotations

import logging

import httpx

from ..config import settings
from .base import ConnectorError, make_client, parse_dt

log = logging.getLogger(__name__)

_SEV = {"critical": "critical", "high": "high", "warning": "medium", "medium": "medium",
        "low": "low", "information": "info", "info": "info"}

ASSET_FIELDS = "assetId name hostName platform status lastCommunicatedTime agentVersion client site"
ALERT_FIELDS = "id message description severity status createdTime resolvedTime occurrenceCount asset"
TICKET_FIELDS = "ticketId displayId subject status priority createdTime client requester techGroup"


class SuperOps:
    tool = "superops"

    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.configured = bool(settings.superops_api_token and settings.superops_subdomain)
        self._http = make_client(
            settings.superops_api_url,
            headers={
                "Authorization": f"Bearer {settings.superops_api_token}",
                "CustomerSubDomain": settings.superops_subdomain,
                "Content-Type": "application/json",
            },
            transport=transport,
        )

    def gql(self, query: str, variables: dict | None = None) -> dict:
        r = self._http.post("", json={"query": query, "variables": variables or {}})
        if r.status_code == 401:
            raise ConnectorError("SuperOps: invalid API token")
        if r.status_code >= 400:
            raise ConnectorError(f"SuperOps: HTTP {r.status_code}")
        body = r.json()
        if body.get("errors"):
            err = body["errors"][0]
            codes = [c.get("code") for c in (err.get("extensions", {}).get("clientError") or [])]
            raise ConnectorError(f"SuperOps: {codes[0] if codes else err.get('message', 'error')}")
        return body["data"]

    def _pages(self, op: str, fields: str, items_key: str, condition: dict | None = None,
               page_size: int = 100, max_pages: int = 50) -> list[dict]:
        out: list[dict] = []
        for page in range(1, max_pages + 1):
            inp: dict = {"page": page, "pageSize": page_size}
            if condition:
                inp["condition"] = condition
            data = self.gql(
                f"query q($input: ListInfoInput!) {{ {op}(input: $input) "
                f"{{ {items_key} {{ {fields} }} listInfo {{ hasMore }} }} }}",
                {"input": inp},
            )
            block = data.get(op) or {}
            out.extend(block.get(items_key) or [])
            if (block.get("listInfo") or {}).get("hasMore") is not True:
                break
        return out

    @staticmethod
    def _client_condition(account_id: str) -> dict:
        return {"attribute": "client", "operator": "includes", "value": [account_id]}

    # ---------------------------------------------------------------- reads
    def list_clients(self) -> list[dict]:
        rows = self._pages("getClientList", "accountId name stage status emailDomains", "clients")
        return [{"id": c.get("accountId"), "name": c.get("name"), "status": c.get("status")} for c in rows]

    def devices(self, account_id: str) -> list[dict]:
        rows = self._pages("getAssetList", ASSET_FIELDS, "assets", self._client_condition(account_id))
        out = []
        for a in rows:
            out.append({
                "external_id": str(a.get("assetId")),
                "hostname": a.get("hostName") or a.get("name") or "",
                "platform": a.get("platform") or "",
                "status": "online" if (a.get("status") or "").upper() == "ONLINE" else "offline",
                "agent_version": a.get("agentVersion") or "",
                "last_seen": parse_dt(a.get("lastCommunicatedTime")),
                "link": settings.superops_base_url,
                "raw": a,
            })
        return out

    def alerts(self, account_id: str) -> list[dict]:
        rows = self._pages("getAlertList", ALERT_FIELDS, "alerts")
        out = []
        for al in rows:
            asset = al.get("asset") or {}
            client = (asset.get("client") or {}) if isinstance(asset, dict) else {}
            if str(client.get("accountId")) != str(account_id):
                continue
            status = (al.get("status") or "").lower()
            out.append({
                "external_id": str(al.get("id")),
                "kind": "rmm",
                "severity": _SEV.get((al.get("severity") or "").lower(), "medium"),
                "title": al.get("message") or "RMM alert",
                "detail": " · ".join(x for x in [al.get("description"), asset.get("name")] if x),
                "tool_status": al.get("status") or "",
                "occurred_at": parse_dt(al.get("createdTime")),
                "link": settings.superops_base_url,
                "resolved": status == "resolved",
                "raw": al,
            })
        return out

    def tickets(self, account_id: str) -> list[dict]:
        return self._pages("getTicketList", TICKET_FIELDS, "tickets", self._client_condition(account_id))

    # ---------------------------------------------------------------- actions
    def resolve_alert(self, alert_id: str) -> None:
        self.gql("mutation m($input: [ResolveAlertInput]) { resolveAlerts(input: $input) }",
                 {"input": [{"id": alert_id}]})

    def create_ticket(self, account_id: str, subject: str, description: str,
                      requester_user_id: str = "", priority: str = "") -> dict:
        inp: dict = {
            "subject": subject[:250] or "Portal message",
            "description": description,
            "source": "INTEGRATION",
            "client": {"accountId": account_id},
        }
        if requester_user_id:
            inp["requester"] = {"userId": requester_user_id}
        if settings.superops_default_techgroup_id:
            inp["techGroup"] = {"groupId": settings.superops_default_techgroup_id}
        if priority:
            inp["priority"] = priority
        data = self.gql(
            "mutation m($input: CreateTicketInput!) { createTicket(input: $input) { ticketId displayId } }",
            {"input": inp},
        )
        t = data["createTicket"]
        return {"ticket_id": str(t["ticketId"]), "display_id": t.get("displayId") or ""}

    def add_ticket_reply(self, ticket_id: str, content: str) -> None:
        self.gql(
            "mutation m($input: CreateTicketConversationInput!) "
            "{ createTicketConversation(input: $input) { conversationId } }",
            {"input": {"ticket": {"ticketId": ticket_id}, "content": content, "sendMail": True}},
        )
