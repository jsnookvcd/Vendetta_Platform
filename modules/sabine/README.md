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

## Narrative

With `ANTHROPIC_API_KEY` set, a Claude model writes the briefs, the daily summary
and answers on the Ask page from the facts SABINE gathered, and is told it may not
invent any. It never chooses an action. Without a key, the same documents come
from templates.

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
