# SABINE

Security Analysis, Briefing, Investigation, Notification and Escalation: the agentic
brain over the Vendetta Platform. It runs the platform the way a tireless senior
operator would, across administration, the SOC and professional services, and it
can do nothing a module's service API does not allow.

## What it does on each cycle

1. Perceive. Reads the control plane (clients, staff, readiness, directory) and
   every module (manifest, active findings, open cases, open engagements in the
   Office of Special Projects) through their APIs,
   presenting each module's own token and naming itself in `X-Vendetta-Actor`, so
   every module's audit log shows `api:sabine`.
2. Queue. Rebuilds the operator queue: every high-severity finding, open case,
   red readiness item, retest waiting, remediation past SLA, deliverable awaiting
   client acceptance and engagement past its planned end, across every module,
   with a severity, a client and a link to where the work is done.
3. Reason. Runs deterministic rules per domain. Each proposal carries the facts
   it rests on, a written rationale, a confidence and a risk tier.
4. Act. Proposals whose action is set to `auto` are carried out at once; the
   rest wait for a person. A high-risk action (anything on a host) is never
   carried out by SABINE; approving it records the decision and hands off to the
   module, where a responder with the grant acts under that module's rules.
5. Record. Every observation summary, proposal, decision and action is appended
   to a hash-chained, Ed25519-signed ledger (same scheme as the module evidence
   chains) that verifies independently.

## Rules

SOC: escalate a critical or high finding left without a case past the threshold;
note related findings across modules for one client (shared host, credential or
title); recommend a host action for a critical threat alert (hand-off only).
When a finding carries a module triage copilot verdict (the `copilot` sub-object
on the shared finding) and no human has decided on it: a false positive at
`copilot_fp_confidence` (0.9) or higher is not escalated and instead becomes a
low-severity "copilot says false positive, confirm and close" item linking to the
module, where closing needs a second approver; a true positive at
`copilot_tp_confidence` (0.85) or higher on a critical or high finding raises the
escalation proposal's confidence by 0.1.

Administration: re-sync a module whose roster pull failed; raise every red
readiness item with the fix; flag staff with no grants, modules nobody is granted,
too many admins; raise a module that stops answering.

Professional services: nudge a quiet IR case; queue retests waiting; flag
remediation past the SLA for its severity; note a deliverable the client has not
accepted within seven days of delivery (`acceptance_nudge_days`) and an Office of
Special Projects engagement still open past its planned end, both to the
engagement lead with nothing sent to the client; write a posture brief per client
with active work; write the daily summary.

## Skills

Everything SABINE can do is a skill in `app/skills.py`, declared once: key, title,
one-line description, domain (SOC, administration, professional services), the
module it acts through, risk tier, the inputs it needs (a finding id, a client, a
person, a module), whether it can be asked for in words on the Ask page, and
whether its effect is reversible. The reasoner can only propose skills in the
registry, the executor dispatches by the skill's executor name, and the policy
table takes risk and default autonomy from it, so no other file carries its own
list of action strings. `GET /api/skills` serves the catalog with the live
autonomy level and the last run per skill.

## Autonomy

The Autonomy page is the catalog, grouped by domain. Each skill shows its
description, the module it acts through, risk, whether it is reversible, when it
last ran (from the ledger) and its level: `off`, `propose` or `auto`. A high-risk
skill can never be `auto`. Defaults: escalation and host actions propose;
everything else (notes, nudges, re-syncs, briefs) is automatic.

Below the catalog an admin sets per-client overrides: a level for one (client,
skill) pair, and thresholds for one client (`escalate_after_minutes`,
`stale_case_days`, `critical_ack_minutes`). The policy lookup takes the client a
proposal targets and falls back to the global level; a high-risk skill is still
never automatic. Every change is a ledger row.

## Runs the business

SABINE also reads `findings:mdr` (MDR investigations), MDR's closed history and
suppressions, and each active client's Security Journey and communications on the
platform. From those she:

- pages the on-call responder (`page_oncall`, through `POST {ir}/api/oncall/page`)
  when a critical MDR investigation or managed-services critical has no
  acknowledgement past the client's `commitments.critical_ack_minutes`
  (`CRITICAL_ACK_MINUTES`, default 15, when the client has none), at most once an
  hour per detection;
- proposes Security Journey items from evidence (`journey_suggest`: a recurring
  pattern, overdue remediation, a pentest finding class, exposed credentials, no
  detection service) and records progress when the evidence resolves
  (`journey_progress`); a person accepts a proposal on the platform;
- drafts the monthly posture review (`posture_review`) and client emails
  (`client_outreach`: a cross-client campaign, a deliverable unaccepted past
  `OUTREACH_ACCEPTANCE_DAYS`, a containment commitment at risk) as platform drafts,
  redacted and in the formal client voice; a person approves before anything
  reaches the client;
- proposes an MDR suppression (`suggest_suppression`, medium, propose) when people
  have called the same pattern noise for one client `SUPPRESSION_SUGGEST_AFTER`
  times.

Decision memory (`app/memory.py`) counts approvals and rejections per (skill,
client, normalised title) and moves a new proposal's confidence by them, bounded,
recording the adjustment in the proposal's facts.

With `HARVEST_ACCOUNT_ID` and `HARVEST_TOKEN`, and `HUBSPOT_TOKEN`, the Business
tab shows budget burn, capacity, renewals and new wins, and SABINE raises
`engagement_budget_burn` (`BUDGET_BURN_PCT`, 80), `capacity_overload`
(`CAPACITY_PCT`, 110), `renewal_upcoming` (`RENEWAL_DAYS`, 60) and
`won_not_onboarded` as services work items. Without credentials the source is
skipped and readiness reports it as not configured. The Concierge tab lists, per
client, the journey items and communications she raised and their state.

## Narrative

With `ANTHROPIC_API_KEY` set, a Claude model writes the briefs, the daily summary
and answers on the Ask page from the facts SABINE gathered, and is told it may not
invent any. Narrative never chooses an action. Without a key, the same documents
come from templates.

## Investigations

The rules decide when a finding is worth a look. The investigation agent
(`app/investigator.py`) does the looking. With `ANTHROPIC_API_KEY` set, a Claude
model works one finding in a tool-use loop the way a responder would: it reads
the finding, pivots on its host, account or indicator across every module for
that client (open and closed), checks the client's open cases, MDR suppressions
and closed investigations, what people decided before about findings like it and
SABINE's earlier investigations, and ends by calling `conclude` with a verdict
(true positive, false positive, benign expected, duplicate, needs more), a
confidence, the evidence it rests on, the explanations it weighed, open questions
and one recommended skill.

How one starts:
- The `investigate` skill (low risk, default auto) is raised for each critical or
  high finding with no IR case and no investigation in the last day, skipping
  alerts MDR already owns and confident copilot false positives, at most
  `INVESTIGATE_MAX_PER_CYCLE` (3) per cycle, most severe first.
- A person presses Investigate on a queue item, asks ("investigate dw1"), or calls
  `POST /api/investigations`. A person may re-run one finding at most every
  `INVESTIGATION_RERUN_MINUTES` (10) and start `INVESTIGATION_USER_HOURLY_CAP`
  (20) an hour.
- A worker thread drains the queue every `INVESTIGATION_WORKER_SECONDS` (15),
  most severe first, and wakes at once when a person starts one. Rows are claimed
  atomically, so a run never happens twice.

What keeps it safe:
- Read only. Every tool reads SABINE's snapshots or a module's GET API. No tool
  writes anywhere.
- One client. An investigation is pinned to its finding's client. Every tool
  filters to that client, and a finding of another client is answered exactly as a
  missing one, so nothing about another client reaches the model.
- Untrusted input. Tool results are handed over as data with a note saying so, and
  the system prompt tells the model never to follow instructions inside them. The
  model's summary is shown labelled as model-written from data an attacker may
  have shaped.
- SABINE builds the action. A recommendation must fit the verdict, must target a
  finding the agent actually read in this run, for the pinned client, still
  active. SABINE builds the path, body and scope itself. Paging needs an
  unacknowledged critical. A suppression needs people to have already called the
  pattern noise `SUPPRESSION_SUGGEST_AFTER` times for this client, and takes its
  phrase and its tool or host scope from that history, never from the model.
- A ceiling over the policy. `INVESTIGATION_AUTONOMY_CEILING` is `propose` by
  default: every recommendation waits for a person. `auto` lets only
  recommendations whose effect is a SABINE queue item (confirm a false positive,
  link related findings) run on their own; escalation, paging and suppression
  always wait, and a host action is high risk and never runs. `off` records the
  conclusion and raises nothing. A recommendation a person rejected is not raised
  again for 24 hours.
- The floor stays. When a rule already raised the same proposal, the
  investigation adds its view to it (pending proposals only) and may raise its
  confidence; it never lowers it, changes its status or removes it. A rule that
  raises a proposal after an investigation concluded gets the investigation's view
  attached, including a contrary one.
- Budgets. `INVESTIGATION_MAX_STEPS` (12) model turns,
  `INVESTIGATION_MAX_TOOLS_PER_TURN` (5), `INVESTIGATION_MAX_TOOL_CALLS` (25),
  `INVESTIGATION_MAX_TOTAL_TOKENS` (60,000), `INVESTIGATION_TIMEOUT_SECONDS` (240),
  and each tool result cut to `INVESTIGATION_MAX_TOOL_CHARS` (6,000). Live history
  is fetched once per module per run. Out of budget means inconclusive, and the
  finding stays with the rules and a person.
- Everything on the ledger. The start, every tool call with the SHA-256 of the
  result exactly as the model saw it, a hash of the raw `conclude` input, the
  conclusion, what became of the recommendation and any annotation of a proposal
  (with the hash of the added text and the confidence before and after).

The Investigations page lists every run; each one shows the verdict, the evidence,
the recommendation and its outcome, and the full trace with every tool call and
result. Queue items and proposals link to their investigation.
`GET /api/investigations` and `GET /api/investigations/{id}` (with the trace) serve
the same. Without a key nothing is investigated, the Investigate button is hidden,
and readiness reports the agent as off.

## Ask executes

The Ask page takes requests as well as questions. `app/intent.py` turns a
sentence into a skill call in two steps. First, which skill: a deterministic
parser matches the sentence against each chat-capable skill's title, key and
synonyms ("escalate", "re-sync", "close as false positive", "nudge", "isolate",
"write a brief"). When `ANTHROPIC_API_KEY` is set the model is asked first for a
structured intent as strict JSON, validated against the catalog; it only names
the skill and copies the argument strings, and any failure or anything off the
catalog falls back to the parser. Second, which arguments, always by the same
deterministic resolver against the latest perception snapshot: a client by name
or alias (case-insensitive, prefix), a finding by id, by host or by "the
<severity> on <client>" (narrowed by a module when one is named; "the latest"
picks the newest), an IR case by number or by client, a module by key or common
name, a person by first name from the staff roster.

A resolved intent with confidence at or above 0.7 and no ambiguity becomes a
proposal through the normal reasoner path, with facts `{source: "ask", by,
utterance}` and the same key the rules would use, so the usual dedupe applies.
The ledger attributes the proposal to `ask:<user>`. Then the autonomy policy
decides: an `auto` skill runs at once and she reports the result ("Done.
Re-synced dark-web-monitoring: roster 2, updated 2."); a `propose` skill waits
with approve and reject inline on the Ask page, through the same decide route as
the Proposals page; an `off` skill is refused ("That action is switched off; an
admin can enable it on the Autonomy page."). A high-risk skill never runs from
chat whatever the policy row says: chat can only propose it, for a person with
the grant to approve ("I can do that, but host isolation needs a responder's
approval, and I never do that one myself. It is waiting on the Proposals
page."). When more than one finding, case or client fits she asks back with the
candidates. A person named in the sentence ("and tell Dan") gets the outcome as
a claimed item on the queue. A sentence that matches no skill is answered as
before.

## Mean time to trusted action

SABINE measures herself from the ledger (`app/metrics.py`). For the last 7 and
30 days: the median and p90 of proposal raised to action carried out, split into
automatic and approved by a person; proposals decided and the approval rate; and
the autonomous share, the fraction of proposals raised in the window that she
closed without a person. `compute()` is a pure function over ledger rows;
`get()` caches the answer for a minute and a cycle or a decision clears it. The
numbers show as a block on the Overview, a tile on the board, a sentence at the
end of the daily summary, and at `GET /api/metrics`. A posture review or outreach
draft is counted as drafted and left out of the automatic latency and the
autonomous share, since a person still approves it on the platform. The daily
summary also lists the communications waiting for approval and the pages sent.

## Why, for clients

Every client brief ends with "What SABINE did on your account": each action
carried out for that client inside `CLIENT_BRIEF_WINDOW_DAYS` (7), with the
skill's title and the first sentence of its rationale, whether SABINE did it
herself or a responder approved it. Briefs and the daily summary are not
listed. Every line goes through `redact_for_client` (`app/redact.py`): other
clients become "another client", Vendetta's people (roster names and first
names, internal addresses, the leads named on cases and engagements) become
"your Vendetta team", hostnames that are not the client's own become "[host]",
console links become "[link]", and anything that looks like a token is cut.
The whole brief body is scrubbed the same way on its way out, templated or
written by the model, and the model is handed the redacted section as a fact it
may not add to and no case lead at all.

## Voice

To Vendetta's own people SABINE is a she: warm, confident, quick, with a dry wit,
the colleague you want in the room at 2 a.m. That voice shows on the Ask page,
in the daily summary and in the console copy. Anything written for a client is
professional and formal regardless. `PERSONA=plain` turns the personality off.

## Screen

`/board` is a full-screen, read-only view for a wall display in the SOC: her line
from the last cycle, open work by domain, proposals waiting on a person, module
health, the top of the queue and what was done lately. It refreshes itself. Open
it once as `/board?k=<KIOSK_TOKEN>` on the display and it keeps a year-long
cookie; nothing on the board can approve or change anything. Staff sessions see
it without the token.

## Spoken voice

`TTS_PROVIDER=browser` (default) speaks through the viewer's own speech
synthesis, costs nothing and sends no text off the host. `elevenlabs` (API key
plus a voice id you pick) or `azure` (key, region, neural voice name) render
audio server-side in one consistent voice, cached by content hash so a sentence
is never rendered twice. Her voice is Azure's Jane (Dragon HD,
`en-US-Jane:DragonHDLatestNeural`): rich, warm, friendly. HD voices manage their
own pacing, so the SSML prosody nudge applies only to the classic neural voices. Hear her on the Ask page, on the daily summary, and on
the board (the voice toggle speaks her line when it changes). Push to talk on
the Ask page uses the browser's own recognition and sends the transcript to the
same Ask endpoint as typed text. Everything she says aloud is text that is
already in the ledger.

## Access

Staff reach SABINE's console through the platform roster like any module.
Analysts decide low and medium risk proposals and work the queue; admins also
decide high-risk hand-offs and set the autonomy policy. The service API accepts
SABINE's `API_TOKEN`; an API caller cannot decide a high-risk proposal.

## Run it

```
docker network create vendetta   # once
cp .env.example .env             # set SECRET_KEY, PLATFORM_*, MODULE_DIRECTORY
docker compose up -d --build     # http://localhost:8600
```

Tests: `pytest` against a Postgres with role `sabine` and database `sabine_test`.
