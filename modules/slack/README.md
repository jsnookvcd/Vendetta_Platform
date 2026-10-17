# Slack Responder

Lean, tactical incident response from Slack. Responders declare, coordinate and record an incident in the channel they are already in, and every action lands in the IR hub on the case's signed chain under their own name. SABINE is the voice in Slack.

The responder keeps no case data. Cases, notes, status, cards and pages live in the IR hub; proposals live with SABINE. This module stores only which Slack channel belongs to which case, which announcements it already made, and its own audit log.

## What responders can do

Anywhere in Slack:

- `/ir declare` opens a form (client, severity, what is happening). The IR hub opens the case and pages on-call; the responder creates a private war room `#ir-<case number>`, invites the declarer, the case lead and anyone in `WARROOM_INVITE`, sets the topic, pins the case card and posts the command help.
- `/ir declare critical Riverbend: ransom note on FS01` does the same in one line from a phone.
- `/ir cases` lists active cases. `/ir sitrep VCD-IR-2026-781` shows the case card, open cards and the latest timeline entries. `/ir room VCD-IR-2026-781` opens a war room for a case that came in another way.
- `/ir ask <question>`, or a mention of the bot, asks SABINE. A request she can act on follows her autonomy policy; anything pending shows Approve and Reject.
- The global shortcut *Declare an incident* opens the same form.

In a war room the case comes from the channel:

- `/ir note <text>` and `/ir note forensics: <text>` log an internal timeline entry, optionally to a workstream.
- `/ir status contained` (or just `/ir contained`), `/ir sev critical`, `/ir lead @dan`.
- `/ir task forensics: image FS01 @dan` adds a card; `/ir tasks` lists open cards with Start, Blocked and Done.
- `/ir page <message>` pages on-call through the IR hub's SNS and Teams path with the case and war room attached.
- React with :memo: on any message, or use the message shortcut *Log to IR case*, to put that message on the timeline with its author, time, attachments' names and Slack permalink. The message gets a check mark. Logging the same message twice is refused.
- `/ir link VCD-IR-2026-781` binds an existing channel to a case; `/ir unlink` releases it.

Feeds:

- `SLACK_IR_CHANNEL` hears every new case once, from any origin (escalations from MDR or managed services, the client portal, the console, Slack), with buttons to open its war room.
- A war room hears when its case changes outside Slack (status, severity, lead), and its topic and pinned card follow.
- `SLACK_SABINE_CHANNEL` gets each proposal waiting on a person once, with Approve and Reject. When the proposal is decided anywhere, the message updates to say who decided it.

## Access

The platform staff roster decides everything. The Slack user's profile email must be on an internal domain and listed on the roster:

- incident-response grant: viewer can read cases (cases, sitrep, tasks); analyst or admin can change them.
- sabine grant (analyst or admin): ask SABINE, decide her proposals.

Anyone else in the workspace is refused, and the refusal is audited. The roster is asked live with a one-minute cache; when the control plane changes a person it calls `POST /api/provision/sync` here and the cache is dropped, so a deactivation applies on the next command. If the control plane is down the last roster seen is used; if none has ever been seen, everyone is refused.

Each call to the IR hub or SABINE carries the module's own token, `X-Vendetta-Actor: slack`, and `X-Vendetta-On-Behalf-Of: <email>`. The IR hub records `dan@vendettacd.io via slack` on the timeline and in its audit log; SABINE records the same on her ledger. The header means nothing without the token.

## What stays out of Slack

- Host actions (isolate, kill, disable) stay in managed services under the two-person rule.
- High-risk SABINE proposals show a link to her console; the API refuses a high-risk decision from any bridge.
- Notes from Slack are internal only. Client-visible updates are written in the IR console.
- Nothing in a war room is logged unless a person asks for it (a command, :memo:, or the shortcut). Privileged conversation stays in Slack unless someone puts it on the record.

## Setup

1. Create the Slack app from `slack-app-manifest.yaml` (api.slack.com/apps, *From an app manifest*). Install it to the workspace.
2. Generate an app-level token with `connections:write` (Basic Information, App-Level Tokens). Socket Mode needs it.
3. Put the secrets in SSM and redeploy:
   - `/vendetta/slack/SLACK_BOT_TOKEN` (SecureString, the `xoxb-` token)
   - `/vendetta/slack/SLACK_APP_TOKEN` (SecureString, the `xapp-` token)
   - `/vendetta/slack/SLACK_SIGNING_SECRET` (SecureString; needed for HTTP mode, harmless otherwise)
   - `/vendetta/slack/SLACK_IR_CHANNEL` and `/vendetta/slack/SLACK_SABINE_CHANNEL` (channel ids, `C0...`); invite the bot to both
   - optional `/vendetta/slack/WARROOM_INVITE` (Slack user ids or work emails, comma separated)
4. Check the console at the module host (break-glass admin) or the platform's go-live screen. The banner names anything missing.

Terraform wires the rest: the module's own secrets, `MODULE_DIRECTORY` with the IR hub, SABINE and the control plane, and `PLATFORM_TOKEN`.

## Settings

See `app/config.py`. The ones worth knowing: `SLACK_COMMAND` (default `/ir`), `WARROOM_PREFIX` (`ir`), `WARROOM_PRIVATE` (`true`), `MEMO_REACTION` (`memo`), `POLL_INTERVAL_SECONDS` (`30`), `SLACK_TEAM_ID` (pin to one workspace), `INTERNAL_EMAIL_DOMAINS` (`vendettacd.io`).

## Tests

`pytest -q` against a disposable Postgres (`SLACK_TEST_DATABASE_URL`, default `postgresql+psycopg://slack:slack@localhost:5432/slack_test`). Slack, the control plane, the IR hub and SABINE are faked behind one httpx MockTransport.
