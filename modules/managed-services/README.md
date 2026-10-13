# Managed Services

The NOC/SOC console that puts every tool a managed client has deployed in one
place, plus a client portal where the client sees alerts and the actions taken and
can message the SOC, NOC or helpdesk. It is a module of the Vendetta Platform: it
runs as its own container stack, exposes its alerts as platform findings, and
escalates into IR cases in the engagement hub.

Tools it links to today: SuperOps (PSA/RMM), SentinelOne and CrowdStrike Falcon
(EDR), Huntress (MDR), and Acronis Cyber Protect Cloud (backup).

## What it does

One record shape over every tool
- Sync pulls each client's slice of each deployed tool into two normalized tables:
  devices (agent, workload, endpoint) and alerts (threat, detection, incident
  report, backup failure, RMM alert). Everything downstream, the console, the
  portal and the platform findings feed, reads that shape and never cares which
  vendor a record came from.
- Each record keeps a deep link back to the vendor console, and the module keeps
  its own triage state separate from the vendor's own state, which is shown
  alongside it.
- Sync is read-then-reconcile: a vendor-side resolution closes the alert here, but
  a run never un-resolves or un-publishes anything, so triage and portal
  publications survive. One dead tool is recorded as a failed sync and never stops
  the others.

The tech console
- A dashboard of open alerts worst-first, device health, tool connection state and
  conversations waiting on a reply.
- A page per client with every deployed tool as a card (device counts, open
  alerts, last sync, one-click into the vendor console), the client's devices with
  inline isolate/contain actions, open alerts, the message desks and the action
  history.
- An alert page that runs the vendor's own response actions without leaving the
  console, routed to the right tool:
  - SentinelOne: kill, quarantine, remediate, resolve as true/false positive,
    isolate or reconnect the host.
  - CrowdStrike: mark in progress or close the detection, network-contain or lift
    containment on the host.
  - Huntress: approve or reject the remediation plan, resolve the report, isolate
    or release the host.
  - Acronis: run the backup again now, dismiss the alert.
  - SuperOps: resolve the alert, raise a ticket.
  Every action is logged with its result. A tool failure comes back as a readable
  message, never a stack trace, and the log row says failed. Destructive actions
  refuse to run against an empty target, so a bad filter can never hit a whole
  tenancy.
- Triage separate from the tools: acknowledge, resolve on this console only,
  reopen, and escalate to an IR case in the engagement hub.

The client portal
- Enabled per client with allowed email domains; client users sign in with
  Microsoft 365 and are confined to the portal.
- They see the alerts a tech has published, each with a plain-language note, the
  actions their team has taken (in friendly wording, not vendor codes), recently
  resolved items, and their device reporting count. Internal detail, raw vendor
  payloads and unpublished alerts never appear.
- Three message desks, SOC, NOC and helpdesk. A helpdesk conversation opens a
  SuperOps ticket on the client's first message and mirrors every later message,
  from either side, into that ticket as a conversation. SOC and NOC stay in the
  console. A SuperOps outage never blocks a message; the ticket is retried on the
  next one.

Platform integration
- GET /api/findings exposes every alert in the platform finding model, so the
  engagement hub reads this module the same way it reads dark web monitoring.
- Escalation posts the shared contract to POST {PLATFORM_HUB_URL}/api/ir-cases with
  Bearer PLATFORM_HUB_TOKEN. A threat, detection or incident lands on Scoping and
  Containment; a backup failure on Recovery and Restoration. The alert records the
  returned case number.
- MODULE_ENABLED=false shows a disabled notice, idles the worker, and /api/module
  reports enabled false.

## How a client's tools are connected

Credentials are tenant-level and live in the environment (SSM in production): one
SuperOps token and subdomain, one SentinelOne service-user token, one CrowdStrike
MSSP (Flight Control) parent client, one Huntress user key, one Acronis partner
client. Which slice of each tool belongs to a client is mapped on the client's
page in the console:

- SuperOps: the client's accountId.
- SentinelOne: the site IDs (comma separated); one MSP-scoped token covers them.
- CrowdStrike: the child CID; the module takes a token locked to that CID per call.
- Huntress: the organization id.
- Acronis: the customer tenant UUID.

A tool counts as deployed for a client once its mapping is set, and only then does
sync touch it.

## Platform roster and preflight

When PLATFORM_URL is set, this module pulls its client roster and per-client tool mapping from the control plane (clients are activated there, pulled here with "Pull from platform" or on the worker's interval). Without it, clients are managed in this console directly.

Before a live run, Settings has a "Test connections" button (and `python -m app.preflight`) that makes the lightest real read against each configured tool and reports what came back, so dropping in real credentials and confirming them is one action.

## Run it

```bash
cp .env.example .env          # set SECRET_KEY, ADMIN_PASSWORD_HASH and the tool creds you have
docker compose up -d --build  # console on 127.0.0.1:8200, plus the sync worker
```

Generate the admin hash with modules/dark-web-monitoring/scripts/make_password_hash.py.
The web container binds to loopback; reach it over SSM port forwarding, or set
WEB_BIND=0.0.0.0 behind the ALB. The worker syncs every SYNC_INTERVAL_SECONDS.

Co-host on the platform instance as a third compose project (ports: dark web 8000,
IR hub 8100, managed services 8200), each with its own Postgres volume. Dedicated
Terraform for this module is not written yet.

## Tests

```bash
createdb msp_test   # owned by a role msp/msp, or set MSP_TEST_DATABASE_URL
python -m pytest tests -q
```

Connector tests pin each vendor's request shapes and normalization against canned
responses (httpx.MockTransport), with no network. App tests run against Postgres
with fake connectors injected, covering sync upserts and vendor-resolution
following, the alert actions and their logging, publish-and-portal scoping, the
actions feed wording, desk messaging with the SuperOps ticket binding, escalation
to the hub contract, the findings API and the module switch.

## Connector notes and limits

- The connector contracts are built from each vendor's official API docs and
  SDKs. A few fine points (SuperOps UI deep-link patterns, the exact Huntress
  resolve-status value, Acronis console URLs) were not documented and are handled
  defensively; set the *_BASE_URL / console settings per tenant to get exact deep
  links. Live credentials have not been exercised yet.
- SuperOps has no webhook payload documented publicly, so sync is poll-based on an
  interval. CrowdStrike and SentinelOne actions are capped and refuse empty
  targets by design.
- Read the connector docstrings in app/connectors for the per-tool specifics.

## Not built yet

- Webhook receivers (where a vendor supports them) to cut sync latency.
- Per-tech RBAC beyond admin/analyst/client.
- Bulk actions across many alerts or devices at once.
- Its own Terraform stack.
- Live-credential shakeout against each vendor.
