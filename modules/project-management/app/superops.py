"""SuperOps PSA (GraphQL API).

At kickoff the engagement gets one SuperOps ticket against the client's account,
routed to the practice's tech group, so the service desk, SLAs and the client's
ticket history see the engagement. The ticket number is written back onto the
engagement and the kickoff run.

When SUPEROPS_API_TOKEN is blank the step is skipped here and the new-engagement
Claude skill makes the ticket through the SuperOps connector instead, then records
it with record_kickoff_link.
"""
from __future__ import annotations

import httpx

from .config import settings

TRANSPORT: httpx.BaseTransport | None = None


class SuperOpsError(Exception):
    pass


def configured() -> bool:
    return bool(settings.superops_api_token and settings.superops_subdomain)


def _gql(query: str, variables: dict) -> dict:
    headers = {"Authorization": f"Bearer {settings.superops_api_token}",
               "CustomerSubDomain": settings.superops_subdomain, "Content-Type": "application/json"}
    with httpx.Client(timeout=30.0, transport=TRANSPORT) as http:
        r = http.post(settings.superops_api_url, json={"query": query, "variables": variables}, headers=headers)
    if r.status_code in (401, 403):
        raise SuperOpsError("SuperOps rejected the API token")
    if r.status_code != 200:
        raise SuperOpsError(f"SuperOps HTTP {r.status_code}")
    body = r.json()
    if body.get("errors"):
        raise SuperOpsError("SuperOps: " + "; ".join(e.get("message", "error") for e in body["errors"])[:400])
    return body.get("data") or {}


CLIENTS = """query getClientList($input: ListInfoInput!) {
  getClientList(input: $input) { clients { accountId name } }
}"""

CREATE = """mutation createTicket($input: CreateTicketInput!) {
  createTicket(input: $input) { ticketId displayId subject status }
}"""


def find_client(name: str) -> dict:
    data = _gql(CLIENTS, {"input": {"page": 1, "pageSize": 10,
                                    "condition": {"attribute": "name", "operator": "contains", "value": name}}})
    rows = (data.get("getClientList") or {}).get("clients") or []
    exact = [c for c in rows if (c.get("name") or "").lower() == name.lower()]
    if len(exact) == 1:
        return exact[0]
    if len(rows) == 1:
        return rows[0]
    if not rows:
        raise SuperOpsError(f"No SuperOps client matches '{name}'. Add the client in SuperOps, then retry")
    raise SuperOpsError(f"'{name}' matches {len(rows)} SuperOps clients: "
                        + ", ".join(c["name"] for c in rows[:6]))


def ensure_ticket(refs: dict, *, client: str, subject: str, description: str, practice: str,
                  requester: str = "", priority: str = "High") -> dict:
    if refs.get("superops_ticket_id"):
        return refs
    acct = find_client(client)
    inp = {"subject": subject[:250], "client": {"accountId": acct["accountId"]}, "description": description,
           "ticketType": "Service Request" if practice == "proserv" else "Incident",
           "priority": priority,
           "techGroup": {"name": settings.superops_tech_group_ir if practice == "ir"
                         else settings.superops_tech_group_proserv}}
    if requester:
        inp["requester"] = {"email": requester}
    t = (_gql(CREATE, {"input": inp}).get("createTicket") or {})
    if not t.get("ticketId"):
        raise SuperOpsError("SuperOps did not return a ticket")
    refs.update(superops_ticket_id=str(t["ticketId"]), superops_ticket=str(t.get("displayId") or t["ticketId"]),
                superops_client=acct["name"])
    return refs
