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
- **Templates.** Each engagement type (BEC, ransomware, malware analysis, general IR,
  tabletop, vCISO onboarding, pentest, Pre-Ransomware Assessment, plus your own) carries
  its standard tasks with owner by role and due offset, client milestones, budget,
  target days per phase and closeout list. Open an engagement from one, apply one
  later, or save a finished engagement's board as a new one.
- **Client milestones.** Client-visible milestones publish to the IR hub case (IR) or
  the Office of Special Projects engagement (ProServ) named by the platform reference.
  The client sees them in that portal, and a newly reached one is written to the signed
  timeline or chain once.
- **Change control.** The sold baseline is kept. Change requests add hours or days with
  a reason and the client's agreement, and a second person approves. Approval moves the
  working budget and end date.
- **Capacity.** Per person, per week: remaining task estimates against bookable hours,
  overdue work in the current week, unscheduled and unestimated work called out, and
  this week's Harvest hours. Ask whether the team can take an engagement of a given size.
- **Metrics.** Time to contain, time to report, cycle time, on-time close, days per
  phase against template targets, hours against sold, scope growth, task and milestone
  on-time rates, by practice and engagement type.
- **Alerts.** Overdue and blocked tasks, WIP limits, budget burn at 80 and 100 percent,
  hours past the sold baseline with no change request, engagements near or past their
  end, phases past target, overdue milestones, change requests waiting on a decision,
  failed SharePoint and portal publishes. Rechecked every 15 minutes, posted to Teams
  when high, emailed as a morning digest, and queued by SABINE.
- **Closeout and invoicing.** A closeout checklist that gates closing, and a draft
  invoice created in Harvest from uninvoiced time (or a fixed fee). Drafts only.
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

Delivery method: `list_templates`, `get_template`, `team_capacity`, `portfolio_metrics`,
`list_changes`, `list_alerts`, `closeout` (view for everyone), `uninvoiced_time`; and for
analysts `save_template`, `apply_template`, `manage_milestone`, `request_change`,
`decide_change`, `acknowledge_alert`, `draft_invoice`, `set_capacity` (admin).

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
4. On each engagement, link the Harvest project and, for IR, the case site URL. Set the
   platform reference (IR case number or OSP engagement id) so milestones reach the
   client.
5. Optional alert delivery: `ALERT_TEAMS_WEBHOOK_URL` for the delivery channel, and
   `ALERT_MAIL_FROM` (a mailbox the app may send as, needing Graph Mail.Send) for the
   7am digest. Thresholds are `ALERT_*` settings in `app/config.py`.
6. Set each person's bookable hours on Capacity, or keep their Harvest weekly capacity.

Run alone: `docker network create vendetta` once, copy `.env.example` to `.env`, then
`docker compose up`. Tests: create role and database `pmtool`/`pmtool_test` in a local
Postgres and run `pytest` here. Harvest and Graph are replaced by in-memory fakes.

## Engagement kickoff

One request opens an IR case or a ProServ engagement in every system it lives in and
links them together. From Claude: "kick off a BEC case for IFB, Dan leads, Craig on
forensics, Hugo is the client contact, CrowdStrike sensor in the toolset". The
`new-engagement` Claude skill walks the intake and calls `kickoff_engagement`.

| Step | What it makes | Needs |
|---|---|---|
| platform_record | IR hub case with the firm-wide case number, or OSP engagement | `PLATFORM_HUB_URL` / `OSP_URL` |
| engagement | practice card, task board, template tasks, milestones, closeout | always |
| harvest | Harvest project under the case code, practice tasks, team assigned | Harvest on Integrations |
| superops | SuperOps ticket on the client's account, practice tech group | `SUPEROPS_API_TOKEN`, or Claude's SuperOps connector |
| m365_workspace | private Microsoft 365 group (engagement mailbox `ir-781@` / `ps-012@`), Team, threads-layout channels, private admin channel, tags, SharePoint folder tree | Graph application permissions below |
| mailbox | external senders allowed, no inbox copies, Send As for the team | the mailbox worker |
| client_uploads | Client Uploads shared to named client contacts, sign-in required | client contacts |
| client_tools | selected tools copied from the tools library into Client Uploads | `KICKOFF_TOOLS_*` |
| slack_channel | private Slack channel, staff invited, Slack Connect invite to the client | `SLACK_BOT_TOKEN`, `slack: channel` |
| announce | kickoff card in the delivery channel (Teams) and Slack | `ALERT_TEAMS_WEBHOOK_URL`, `SLACK_ANNOUNCE_CHANNEL` |

The engagement code comes back immediately; the Microsoft 365 steps finish in the
background (`kickoff_status`). A run stores every external id it creates, so
`retry_kickoff` finishes failed or skipped steps without creating anything twice. A
step whose integration is not configured is recorded as skipped and listed in
`follow_ups_for_claude`, which the skill finishes through Claude's own connectors and
records with `record_kickoff_link`. IR engagements will not open here if the IR hub is
configured but unreachable, so case numbers never fork from the firm-wide sequence.

MCP tools: `kickoff_options`, `kickoff_engagement`, `kickoff_status`, `retry_kickoff`,
`record_kickoff_link`. Service API: `POST /api/kickoff`, `GET /api/kickoff/{id or code}`,
`POST /api/kickoff/{id or code}/retry`.

### Microsoft Graph application permissions

Group.ReadWrite.All, User.Read.All, Team.Create, TeamMember.ReadWrite.All,
Channel.Create, ChannelMember.ReadWrite.All, TeamworkTag.ReadWrite.All,
Sites.ReadWrite.All (or Files.ReadWrite.All with Sites.Selected on the tools library).
External sharing must allow existing or new guests on group sites for Client Uploads.

### Mailbox worker

Graph cannot set Exchange group options, so `worker/Invoke-MailboxJobs.ps1` does them
with Exchange Online app-only certificate auth (an app registration with
Exchange.ManageAsApp and the Exchange Administrator role). On the platform host:

```
# /etc/systemd/system/vendetta-mailbox-worker.service
[Service]
Type=oneshot
EnvironmentFile=/etc/vendetta/mailbox-worker.env   # PM_API_URL, PM_API_TOKEN, EXO_*
ExecStart=/usr/bin/pwsh -NoProfile -File /opt/vendetta/modules/project-management/worker/Invoke-MailboxJobs.ps1 -Once

# /etc/systemd/system/vendetta-mailbox-worker.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
```

### Slack app

Bot scopes: chat:write, channels:manage, groups:write, users:read, users:read.email,
conversations.connect:write. Invite the bot to the announce channel.

## Toward the platform

The service layer (`app/service.py`) holds every operation; the web console, the JSON
API and the MCP tools all call it. When the platform's engagement hub takes over the
engagement record, the boards, cards and notes move with it and the MCP tool layer
keeps working unchanged. `POST /api/engagements` is idempotent on code so the IR hub
and the Office of Special Projects can open the delivery engagement automatically.
