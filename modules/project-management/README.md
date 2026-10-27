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
- **Kickoff.** One form (or one sentence to Claude) stands a new engagement up across
  every tool. See [Project kickoff](#project-kickoff).
- **Claude.** `/mcp` is a remote MCP server. A PM adds it as a custom connector and
  signs in once with Microsoft 365. Claude then acts as that PM with that PM's role.

## Project kickoff

`/kickoff` takes the practice, client, engagement name, template, PM, lead, team,
budget and billing, and then:

1. Opens the engagement here: practice board card, task board, tasks and milestones
   from the template.
2. Links the platform record. IR: opens an IR hub case (or links the case number
   given) and publishes the client milestones to it. ProServ: links the OSP engagement
   id when one is given.
3. Harvest: finds or creates the client, creates the project (code = engagement code,
   budget in hours with an alert at `KICKOFF_HARVEST_BUDGET_ALERT_PCT`, hourly at a
   project rate or each person's rate, or fixed fee), assigns the practice's tasks
   (`KICKOFF_HARVEST_TASKS_IR` / `_PROSERV`, non-billable ones flagged) and the team,
   with the PM as project manager. An existing project id can be linked instead.
4. Microsoft 365: each practice has one parent team, `KICKOFF_IR_TEAM_ID` ("Vendetta
   Incident Response") and `KICKOFF_PROSERV_TEAM_ID` ("Vendetta Professional
   Services"). The kickoff adds the engagement team to the practice team, then opens a
   private channel in it named `<code> <codename or client>` (50 characters at most),
   in the threads layout, with the PM and `KICKOFF_CHANNEL_OWNERS` as owners and the
   team (plus `KICKOFF_IR_ALWAYS_MEMBERS` or `_PROSERV_ALWAYS_MEMBERS`) as members.
   Only those people see the channel.
5. Lays out the folder tree (`KICKOFF_FOLDERS_IR` / `_PROSERV`) in the channel's files
   folder. A private channel has its own SharePoint site, so each engagement's files
   stay separate. This engagement's meeting notes save to its `Meeting Notes` folder.
6. Engagement email: a plus address on the practice's shared mailbox
   (`KICKOFF_IR_MAILBOX`, `KICKOFF_PROSERV_MAILBOX`), for example
   `ir+vcd-ir-2026-014@vendettacd.io`. A folder named for the engagement and an inbox
   rule file everything sent or copied to that address. Mail stays in the shared
   mailbox and is never copied into Teams or anyone's inbox.
7. Adds two tabs to the engagement channel: this engagement's board and Vendetta Time.
8. Makes sure the practice team has its `Time Entry` channel (`KICKOFF_TIME_CHANNEL_NAME`)
   with a Log Time tab that is not locked to any engagement. Created once, then left alone.
9. Vendetta Time: adds the Projects row (code, practice, client, PM, billing type,
   Harvest project id) and the TabContexts row (`channel|<teamId>|<channelId>`), so the
   Vendetta Time tab in the engagement channel opens locked to the engagement.
10. Ticket: no ticketing system is wired while the replacement for Jira Service
    Management is chosen. A ticket reference typed in is recorded. `app/ticketing.py`
    is where the chosen system plugs in.
11. Drafts the client kickoff email in the PM's Drafts, CC the engagement address.
    Never sends.
12. Posts the kickoff with every link to the delivery channel (`ALERT_TEAMS_WEBHOOK_URL`).

Each step records what it did and is safe to run again, so a failed step is retried
from the kickoff page without repeating the work that succeeded. A new private
channel's site takes a few minutes to appear; that step waits and a background loop
retries it every `KICKOFF_RETRY_SECONDS`.

### Time entry

Time is logged in one of two places, and both go through the same approval.

- **The engagement channel's Vendetta Time tab.** Locked to that engagement through the
  TabContexts row, so the project is already filled in.
- **The practice team's Time Entry channel.** One Log Time tab for the whole practice,
  for logging a day across several engagements. It has no TabContexts row, so Vendetta
  Time asks which engagement the hours are for.

Either way the entry goes to the engagement manager as an approval card in Teams, and
only approved entries post to Harvest. The Time Entry channel is a standard channel,
so everyone in the practice team can open it; what each person can log against is
whatever Vendetta Time allows them.

### Practice team capacity

A team holds 1,000 channels in total, standard, private and shared, and a deleted
channel keeps counting for 30 days. The kickoff warns once the practice team holds
`KICKOFF_CHANNEL_WARN_AT` channels (900 by default). Before it fills, create the next
practice team, move the Time Entry channel over, and set the new team id; engagements
already open stay where they are.

### One-time setup

1. Create the two practice teams (private), put the core staff in them, and set
   members' permission to create private channels off. Put each team's group id in
   `KICKOFF_IR_TEAM_ID` and `KICKOFF_PROSERV_TEAM_ID`.
2. Confirm the tenant has finished Microsoft's private channel migration (the old cap
   of 30 private channels per team no longer applies once it has).
3. Create the shared mailboxes for `KICKOFF_IR_MAILBOX` and `KICKOFF_PROSERV_MAILBOX`
   and give the practice staff Full Access and Send As. Shared mailboxes take mail from
   outside senders by default, and Exchange Online accepts plus addresses by default.
4. Restrict the app's mail permissions to those two mailboxes and the PMs with an
   Exchange application access policy.

From Claude: "kick off an IR engagement for Atlantic Credit Union, ransomware template,
Dan as lead, 120 hours at 350, CIO is cio@atlanticcu.example". The tools are
`kickoff_engagement`, `get_kickoff` and `retry_kickoff`. The JSON API is
`POST /api/kickoffs` (same fields as the form) and `GET /api/kickoffs/{id}`.

Graph application permissions the kickoff needs, with admin consent: User.Read.All,
GroupMember.ReadWrite.All (adds people to the practice team), Channel.Create,
Channel.ReadBasic.All, ChannelMember.ReadWrite.All, ChannelSettings.ReadWrite.All
(threads layout), Files.ReadWrite.All (case folders), Sites.ReadWrite.All (Vendetta Time
lists and meeting notes in new channel sites, which cannot be granted Sites.Selected
before they exist), TeamsTab.Create, TeamsAppInstallation.ReadWriteForTeam.All
(Vendetta Time tab), and Mail.ReadWrite plus MailboxSettings.ReadWrite (engagement mail
folder and rule, client email draft). Group.ReadWrite.All and Team.Create are no longer
needed. Harvest needs the administrator token already used for time.

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

Kickoff: `kickoff_engagement`, `get_kickoff`, `retry_kickoff`.

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

## Toward the platform

The service layer (`app/service.py`) holds every operation; the web console, the JSON
API and the MCP tools all call it. When the platform's engagement hub takes over the
engagement record, the boards, cards and notes move with it and the MCP tool layer
keeps working unchanged. `POST /api/engagements` is idempotent on code so the IR hub
and the Office of Special Projects can open the delivery engagement automatically.
