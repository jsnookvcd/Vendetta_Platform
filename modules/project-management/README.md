# Project Management

Delivery project management for the Incident Response and Professional Services
practices, built so PMs can run it from Claude. Staff-only; no client portal.

- **Boards.** One Kanban board per practice, where each card is an engagement and the
  columns are its lifecycle phases. Every engagement also gets its own task board
  (Backlog, To Do, In Progress, Blocked, In Review, Done). Columns can be added,
  renamed, reordered, WIP-limited and removed on either kind of board.
- **Tasks.** Add, edit, assign, date, label, checklist, comment, move, archive,
  restore and delete. Every change lands in the card's history. IR tasks can carry
  the five platform workstreams as labels.
- **Meeting notes.** Saved here, then written to SharePoint as a Word document in the
  engagement's case site (when it has one) or in `<default site>/<folder>/<code>/Meeting
  Notes`. Action items become tasks. A failed copy is kept, flagged, and retried.
- **Time.** Written to Harvest as the PM (matched by email) against the engagement's
  linked Harvest project. Analysts touch only their own entries; admins can log or
  fix anyone's. Every write is logged locally.
- **Claude.** `/mcp` is a remote MCP server. A PM adds it as a custom connector and
  signs in once with Microsoft 365. Claude then acts as that PM with that PM's role.

## Connecting Claude

The module's **Connect Claude** page has the URL and steps. In short:

1. Claude, Settings, Connectors, add custom connector, URL `https://pm.<domain>/mcp`.
   Leave the OAuth client fields blank; Claude registers itself.
2. Connect, sign in with Microsoft 365, approve.
3. Ask in plain words: "what's on my plate", "open an IR engagement for IFB, 80 hour
   budget", "move the IFB card to Forensics", "add tasks for imaging DC01 and pulling
   UAL, assign me", "write up this call and add the action items", "log 2.5 hours to
   IFB forensic analysis yesterday", "how much of the Rize budget is left".

For Claude Code, either connect with the URL and sign in through the browser, or
create a personal access token on the same page:

```bash
claude mcp add --transport http vendetta-pm https://pm.<domain>/mcp \
  --header "Authorization: Bearer vpm_pat_..."
```

### Tools

Read: `whoami`, `my_work`, `list_engagements`, `get_engagement`, `get_board`,
`list_tasks`, `get_task`, `list_meeting_notes`, `get_meeting_note`,
`list_harvest_projects`, `list_harvest_tasks`, `list_time_entries`, `engagement_burn`.

Write (hidden from viewers): `create_engagement`, `update_engagement`,
`move_engagement`, `create_task`, `create_tasks`, `update_task`, `move_task`,
`comment_on_task`, `remove_task`, `restore_task`, `manage_board_column`,
`log_meeting_notes`, `update_meeting_note`, `retry_sharepoint_mirror`, `log_time`,
`update_time_entry`, `delete_time_entry`.

### How the connector is secured

- OAuth 2.1 authorization server in the module: protected resource metadata
  (RFC 9728), authorization server metadata (RFC 8414), dynamic client registration
  (RFC 7591), authorization code with mandatory PKCE S256, refresh tokens that rotate.
- Registration accepts only redirect URIs on `MCP_REDIRECT_ALLOWLIST` (Claude's hosted
  callback and loopback for Claude Code).
- The authorize step is the module's own staff sign-in plus a consent screen.
- Only a SHA-256 of each token is stored. Access tokens last an hour, refresh tokens
  thirty days; personal access tokens expire when the PM chooses.
- Every call re-reads the person's role from the staff roster mirror. Viewers see only
  read tools. Deactivating someone on the platform stops their connector on the next
  call. PMs revoke their own connections on the Connect Claude page.
- Write tool calls are recorded in the audit log with their arguments.

## Setup

1. Deploy with the platform (`infra/terraform` adds it as `project-management`, port
   8900, host `pm.`). The ALB must be on so Claude can reach `/mcp`; PUBLIC_URL is set
   by the deployment.
2. Grant the module to people on the control plane's Staff page (the **Project
   manager** and **Incident responder** profiles include it).
3. Integrations page, as an admin: Harvest account ID and an administrator's personal
   access token; the default SharePoint site and folder. Graph credentials default to
   the SSO app registration, which then needs Sites.Selected (write on the delivery
   site and each IR case site) or Sites.ReadWrite.All.
4. On each engagement, link the Harvest project and, for IR, the case site URL.

Run alone: `docker network create vendetta` once, copy `.env.example` to `.env`, then
`docker compose up`. Tests: create role and database `pmtool`/`pmtool_test` in a local
Postgres and run `pytest` here. Harvest and Graph are replaced by in-memory fakes.

## Toward the platform

The service layer (`app/service.py`) holds every operation; the web console, the JSON
API and the MCP tools all call it. When the platform's engagement hub takes over the
engagement record, the boards, cards and notes move with it and the MCP tool layer
keeps working unchanged. `POST /api/engagements` is idempotent on code so the IR hub
and the Office of Special Projects can open the delivery engagement automatically.
