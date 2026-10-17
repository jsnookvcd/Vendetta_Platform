# Incident Response and Case Management

The engagement hub of the Vendetta Platform. It is the system of record for IR clients, retainers and cases, and it is where the other modules escalate findings. A dark web credential exposure, an actively exploited vulnerability, a pentest-discovered compromise or an MDR detection all land here as an IR case on the five-workstream template, attached to the right workstream.

Runs as its own container stack, like every platform module. Shared contracts: /docs/ARCHITECTURE.md. Module descriptor: module.yaml.

## What it does

Cases
- Case numbers are a firm-wide running sequence, VCD-IR-2026-780, 781, 782 and on. The client name and incident type are never part of the number. The sequence is a locked counter row, so two cases opened at the same moment never collide. Prefix, year and starting number are set with CASE_PREFIX, CASE_YEAR and CASE_SEQ_START.
- Every case opens with the five workstreams: Scoping and Containment, Forensics and Analysis, Recovery and Restoration, Notification and Legal, Resilience and Hardening. Scoping and Containment starts in progress; the rest start not started. Each workstream has a status (not started, in progress, blocked, done), an owner, and a one-line milestone the client sees.
- Case status runs open, contained, eradicated, recovered, closed. Closing stamps the close time.
- The timeline records notes, findings, status changes and system events against a workstream. Each entry is internal-only or client-visible. Escalated findings arrive internal-only with their full payload attached.
- Counsel-directed cases are flagged privileged with breach counsel named. A privileged case shows the client the workstream milestones only, with no timeline detail, and deliverables issue under the Incident Response line.

Case board
- Every case has a Kanban board. Columns are To do, In progress, Blocked or waiting, and Done. Each workstream is a lane, so the board reads as the five-workstream template with its work laid out. Cards carry an owner, a due date (red when overdue), a client-visible flag, and the latest timeline entry logged against them.
- A case opens with the default playbook: 21 cards across the five workstreams, defined in app/playbook.py. The first Scoping and Containment card starts in progress. Analysts add, edit and remove cards per case.
- Cards move by drag and drop, or with the buttons on each card when scripting is off.
- The board and the timeline map to each other automatically:
  - Moving a card writes a timeline entry on its workstream (Started, Blocked or waiting, Completed, Resumed, Reopened). Reordering within a column is not logged.
  - A timeline entry attached to a card links to it. A card in To do moves to In progress on its first entry, and the same entry can move it to Blocked or Done. An entry on a workstream can also become a new card.
  - An escalated finding adds a review card to its workstream's lane, linked to the finding entry.
  - A workstream's status follows its cards: all done is done, any work in progress is in progress, otherwise blocked if a card is blocked, otherwise not started. Each change goes on the client timeline, so portal milestones move without anyone touching them. A workstream with no cards keeps the status set by hand.
- Client-visible cards show on the portal as steps under each workstream with a progress bar. When an internal entry completes a client-visible card, the client sees "Completed" with the card title and never the internal note. Privileged cases show step counts only.

Declare incident
- One button opens a numbered case, assigns the first named responder on the client's retainer as lead, and pages on-call through SNS (email, SMS) and a Teams adaptive card. The page carries the case number, client, severity, origin and lead, plus an Open case link when PUBLIC_URL is set.
- Available to staff from the console, to retainer clients from their portal, and to other systems at POST /api/ir-cases/declare. A client without an active retainer cannot self-declare; they call.

Retainers
- GetZero tier, hours purchased and used, response SLA in minutes, named responders (the first is the default lead), renewal date.
- Readiness checklist per client, seeded with the standard items (IR plan reviewed, contact tree, EDR coverage, offline backups tested, tabletop, carrier and panel counsel on file). Items can be added per client. The count shows on the client's portal.

Client portal
- Enabled per client with allowed email domains. Client users sign in with Microsoft 365 and land on /portal, scoped to their own company. They see their retainer (tier, hours remaining, SLA, readiness), their cases with workstream progress, and client-visible updates. Internal-only entries never render there, and privileged cases show milestones only.
- Client users are confined to /portal by middleware; every other route redirects them back.

Engagement hub API
- POST /api/ir-cases is the escalation contract every module calls. Bearer token from the settings page.
- The hub resolves the client by hub id, then by case-insensitive name, then creates it. Modules keep their own databases, so a module's client id is not the hub's; name matching is what joins them, and an unknown client is created rather than dropped.
- Link or open: if the payload carries case_ref naming an open case, the finding attaches to it. Otherwise a new case opens with origin escalated, the retainer lead assigned, and on-call paged. Either way a review card for the finding lands on the board.
- An escalation can raise a case's severity but never lower it.
- GET /api/ir-cases lists cases with workstream state, card counts per workstream and column, and a board summary. GET /api/module returns the module manifest, including enabled. OpenAPI docs at /api/docs.

Escalation payload
```json
{
  "source_module": "dark-web-monitoring",
  "client_id": "<module's client id>",
  "case_ref": "VCD-IR-2026-781 or empty",
  "severity": "low | medium | high | critical",
  "summary": "one line",
  "workstream": "Forensics and Analysis",
  "finding": { "...platform finding model, with subject.client naming the client..." }
}
```
Response: `{"case_id": "VCD-IR-2026-784", "id": "<uuid>", "linked": false}`.

Chain of custody and evidence export
- Every timeline entry is hash-chained and Ed25519-signed per case as it is written. Staff verify the chain at /cases/{id}/chain/verify and download the proof at /cases/{id}/proof.json; the client sees the verification result on the portal and downloads their own proof, with internal-only entries sealed.
- Download sealed evidence package, on the case page and the portal case page, builds a self-verifying zip from the shared evidence-export library (vendored into app/evidence_export with verify_evidence.py beside it): a signed manifest, the chain as proof.json, the public key, the standalone verifier and a plain-language README. The client's package seals internal-only entries and still verifies. Set TSA_URL to anchor each package to an RFC 3161 time authority; blank still seals the package, without the third-party time anchor. EVIDENCE_SIGNING_KEY is the dedicated chain key; blank derives one from SECRET_KEY with a warning.

Sign-in and roles
- Microsoft 365 / Entra ID single sign-on, same setup as the dark web module (see its README for the app registration). Users from INTERNAL_EMAIL_DOMAINS are staff; ADMIN_EMAILS are admins; users from a client's portal domains are client users scoped to that client. The local admin account is the break-glass path.
- Security headers, a strict CSP, login throttling and secure cookies under TLS, as in the dark web module.

Module switch
- MODULE_ENABLED=false shows a disabled notice on every page, /api/module reports enabled false, and /healthz stays up for the load balancer.

## Platform roster

When PLATFORM_URL is set, the hub pulls its client roster from the control plane ("Pull from platform" on the Clients page); clients are activated there. The pull sets only the platform-owned fields (name, industry, portal domains) and never touches retainers or cases. Escalations that carry a platform_client_id resolve the case's client by that shared id first, so a client lines up across every module.

## Connect the dark web module

1. Open Settings in the IR hub and copy the bearer token.
2. In the dark web module's environment (SSM), set PLATFORM_HUB_URL to the hub's URL and PLATFORM_HUB_TOKEN to that token. Restart its web container.
3. Escalate any hit from its console (the Escalate button) or with POST /api/findings/{id}/escalate. The hit records the hub case number in its alert refs and moves to reviewing.
4. To route a client's later findings into an existing case, enter the hub case number in "Set case ref" on that client's page in the dark web module. Findings link to it while the case is open; once it closes, the next escalation opens a new case.

Tested against a running hub: the dark web module's own escalate code opened a hub case, matched the client by name, and a second finding with case_ref linked to the same case and raised it to critical.

## Run it

```bash
cp .env.example .env          # set SECRET_KEY and ADMIN_PASSWORD_HASH at minimum
docker compose up -d --build  # console on 127.0.0.1:8100
```

Generate the admin hash with modules/dark-web-monitoring/scripts/make_password_hash.py. The web container binds to loopback; reach it over SSM port forwarding, or set WEB_BIND=0.0.0.0 behind the ALB.

The hub is small enough to co-host on the dark web module's t4g.small as a second compose project on port 8100, with its own Postgres volume. Dedicated Terraform for this module is not written yet; until it is, deploy it on the existing instance.

## Tests

```bash
createdb irhub_test   # owned by a role irhub/irhub, or set IRHUB_TEST_DATABASE_URL
python -m pytest tests -q
```

The suite runs against real Postgres because the hub depends on row locks and JSON columns. It covers numbering, the workstream template, the escalation contract with the dark web payload, link-or-open and severity rules, retainer lead assignment, portal scoping, the privileged and internal-only filters, the module switch, and the board: playbook seeding, moves and their timeline entries, update-to-card linking, escalation cards, derived workstream status, reordering, and what the portal shows. A browser drag was also checked against a running hub.

## Not built yet

- Separate client executive and client technical portal views. Today every client user sees the same milestone and update view.
- Breach counsel and carrier panel roles.
- Case-site provisioning (SharePoint or Teams) on declare.
- Hour tracking against the retainer from timeline entries; hours used is entered by hand.
- Report and deliverable generation from the case.
- Playbooks per incident type. Every case opens with the one default playbook today.
- Its own Terraform stack.
