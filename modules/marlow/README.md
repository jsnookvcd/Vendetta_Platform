# MARLOW

Monitoring, Analysis, Response, Lifecycle and Operations Workflow: the agentic
brain over the Vendetta Platform. It runs the platform the way a tireless senior
operator would, across administration, the SOC and professional services, and it
can do nothing a module's service API does not allow.

## What it does on each cycle

1. Perceive. Reads the control plane (clients, staff, readiness, directory) and
   every module (manifest, active findings, open cases) through their APIs,
   presenting each module's own token and naming itself in `X-Vendetta-Actor`, so
   every module's audit log shows `api:marlow`.
2. Queue. Rebuilds the operator queue: every high-severity finding, open case,
   red readiness item, retest waiting and remediation past SLA, across every
   module, with a severity, a client and a link to where the work is done.
3. Reason. Runs deterministic rules per domain. Each proposal carries the facts
   it rests on, a written rationale, a confidence and a risk tier.
4. Act. Proposals whose action is set to `auto` are carried out at once; the
   rest wait for a person. A high-risk action (anything on a host) is never
   carried out by MARLOW; approving it records the decision and hands off to the
   module, where a responder with the grant acts under that module's rules.
5. Record. Every observation summary, proposal, decision and action is appended
   to a hash-chained, Ed25519-signed ledger (same scheme as the module evidence
   chains) that verifies independently.

## Rules

SOC: escalate a critical or high finding left without a case past the threshold;
note related findings across modules for one client (shared host, credential or
title); recommend a host action for a critical threat alert (hand-off only).

Administration: re-sync a module whose roster pull failed; raise every red
readiness item with the fix; flag staff with no grants, modules nobody is granted,
too many admins; raise a module that stops answering.

Professional services: nudge a quiet IR case; queue retests waiting; flag
remediation past the SLA for its severity; write a posture brief per client with
active work; write the daily summary.

## Autonomy

The Autonomy page sets each action to `off`, `propose` or `auto`. A high-risk
action can never be `auto`. Defaults: escalation and host actions propose;
everything else (notes, nudges, re-syncs, briefs) is automatic.

## Narrative

With `ANTHROPIC_API_KEY` set, a Claude model writes the briefs, the daily summary
and answers on the Ask page from the facts MARLOW gathered, and is told it may not
invent any. It never chooses an action. Without a key, the same documents come
from templates.

## Voice

To Vendetta's own people MARLOW is a she: warm, confident, quick, with a dry wit,
the colleague you want in the room at 2 a.m. That voice shows on the Ask page,
in the daily summary and in the console copy. Anything written for a client is
professional and formal regardless. `PERSONA=plain` turns the personality off.

## Access

Staff reach MARLOW's console through the platform roster like any module.
Analysts decide low and medium risk proposals and work the queue; admins also
decide high-risk hand-offs and set the autonomy policy. The service API accepts
MARLOW's `API_TOKEN`; an API caller cannot decide a high-risk proposal.

## Run it

```
docker network create vendetta   # once
cp .env.example .env             # set SECRET_KEY, PLATFORM_*, MODULE_DIRECTORY
docker compose up -d --build     # http://localhost:8600
```

Tests: `pytest` against a Postgres with role `marlow` and database `marlow_test`.
