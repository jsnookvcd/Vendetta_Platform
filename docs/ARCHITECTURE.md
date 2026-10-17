# Vendetta Platform architecture

This describes the contracts every module shares. The goal is that the engagement hub, the client-facing views and the reporting all work the same way regardless of which module produced the data. Dark Web Monitoring is the reference implementation.

## Modules

A module is a self-contained service for one service line. It owns its runtime, data store, infrastructure and deployment, and it is reached by the hub over HTTP. Modules do not share a database or a binary; they share contracts.

Every module:

- lives under modules/<name>/ and declares itself in module.yaml;
- serves its manifest at GET /api/module, including `enabled`, its roles, and its finding types;
- honors a MODULE_ENABLED flag. When off, the UI shows a disabled notice, background work idles, and /api/module reports enabled:false so the hub can read status;
- exposes its findings in the shared finding model below at GET /api/findings, filterable by `status` (`active`, the default, with `open` as a synonym; `all`; or a literal module status), by `platform_client_id` and by `client` (name substring);
- can escalate a finding into an IR case in the hub, both from its UI and over its service API at POST /api/findings/{id}/escalate;
- pulls its client roster from the control plane on a schedule and on demand (POST /api/provision/sync), and serves GET /clients/platform/{platform_client_id} as the deep-link target the control plane sends people to;
- refuses to start on a placeholder SECRET_KEY, and authenticates its service API with a deployment-set API_TOKEN.

The shapes are pinned as JSON Schemas in docs/contracts and every module's test suite validates what it emits against them.

## The finding model

Modules produce different raw records (a dark web hit, a vulnerability, a pentest issue, an MDR detection), but each is exposed to the hub as a finding with this shape:

```
id            string, unique within the module
module        the module name, e.g. "dark-web-monitoring"
platform      "Vendetta Platform"
subject       { client_id, platform_client_id, client, case_ref }   the account it belongs to
type          module-specific record kind (e.g. victim, vulnerability, detection)
severity      low | medium | high | critical
status        new | reviewing | confirmed | false_positive | closed
title         short human description
evidence      [ { id, sha256, captured_at, storage_uri } ]   may be empty
created_at    ISO 8601
workstream    the IR workstream a finding attaches to when escalated
```

`subject.platform_client_id` is the control plane's id for the client and is the key every module shares; `subject.client_id` is the producing module's own database key and is informational only. Severity `info` is collapsed to `low` before a finding leaves a module. The full schema is docs/contracts/finding.schema.json.

The hub reads findings at GET /api/findings on each module and the manifest at GET /api/module. A module keeps its own richer native shape too (the dark web module also serves /api/hits); the finding model is the common denominator the hub and client views rely on.

## The control plane

The control plane (modules/platform) is the front door and the system of record for three things the modules used to each own separately: the canonical client directory, which modules are turned on per client, and how each client maps into the tools. It holds no vendor secrets; those stay with the module that uses them. It reaches each module over HTTP with a per-module bearer token.

Three integration points:

- Provisioning (modules read from it): a module calls GET {platform}/api/platform/clients?module=<key> with the platform's bearer token and gets the active clients that have it enabled. For managed-services each client also carries its tool tenancy mapping. The module upserts its own client rows keyed by the platform client id (adopting any it already had by name). Every client module consumes it: incident-response, dark-web-monitoring, managed-services, vulnerability-management, penetration-testing and professional-services. A module's pull is authoritative only for the platform-owned fields (name, portal domains, the executive-email list, and for managed-services the tool mapping); each module's own data (IR retainers and cases, dark web watch terms and the IAB profile, managed-services sync history, a module's own portal on/off toggle) is never touched. Pulls run on a schedule in each module (PROVISION_INTERVAL_SECONDS, five minutes by default; managed-services pulls from its sync worker), and each module records its last pull result in its readiness report.
- Roster push (it writes to modules): whenever a client changes on the control plane (added, edited, a module toggled, a tool mapped), the control plane calls POST {module}/api/provision/sync on the modules concerned, which pull immediately. An activation lands in the module within seconds; the scheduled pull is the safety net.
- Overview (it reads from modules): the control plane calls each module's /api/module for health, readiness and live counts, cached briefly and degrading gracefully.

The control plane learns where each module is from MODULE_DIRECTORY, which the deployment renders (service URL on the shared docker network, that module's API token, and its public URL). It is applied at startup to any module that is not yet wired and can be re-applied from the Connections page, so a fresh host needs no hand entry. Each module row also carries a public URL, and the client page links straight into each active module's view of that client (`{public_url}/clients/platform/{id}`); modules link back with PLATFORM_PUBLIC_URL.

### Tiers, the Security Journey, communications and Client 360

The control plane also owns what the client relationship is made of, so every module and SABINE read one answer:

- Service tier and commitments. Each client has a tier (core, advanced, premier), an account lead, and two response commitments: critical acknowledged within 15, 10 or 5 minutes and contained within 240, 120 or 60 by tier, each overridable per client. They travel on the roster as `tier`, `account_lead`, `commitments` and `services`, the client sees them on the portal, and SABINE pages against them.
- Security Journey. A per-client plan of items, each with an area (identity, endpoint, cloud, email, network, data, vulnerability, response, governance, awareness), a status (proposed, planned, in_progress, done, declined) and its source. Staff add items as planned; SABINE adds them as proposed at `POST /api/platform/clients/{pid}/journey`, idempotent on a stable source_ref, and only a person accepts or declines a proposal. SABINE may move an accepted item to in_progress or done at `.../journey/{item}/progress` when its evidence resolves; it is refused on a proposed or declined item. The client portal shows planned, in-progress and done items only.
- Communications. Posture reviews and proactive outreach are drafts at `POST /api/platform/clients/{pid}/communications` (idempotent on source_ref). The client's account lead or a platform admin edits and approves; approval publishes to the client portal and emails the executive list through the SMTP notifier when configured, and a mail failure never blocks it. A viewer cannot approve. This is the single human approval point for anything said to a client.
- Client 360. `/clients/{cid}` and `GET /api/platform/clients/{pid}/360` read every module live with the per-module tokens, in parallel, cached briefly: active findings by module and severity (including MDR investigations), open IR cases, open engagements with deliverables waiting, the journey and the communications. A module that is down shows unreachable; every row is checked against the client's platform id before it is shown.

### The client portal front door

The control plane serves a client portal at `/portal`, signed in with the same Entra flow the modules use and mapped to one client by email domain (a domain matching two clients is refused). It shows the tier and commitments, a tile per enabled service line linking into that module's own portal, the accepted Security Journey and approved communications. Client sessions are confined to `/portal*` by the access gate and again at every route, with a cross-tenant test suite, exactly as in the modules.

The canonical client id lives here, and every built module stores it on its own client rows. Escalations carry it too: a module sends its platform_client_id, and the engagement hub resolves the case's client by that shared id first, falling back to name.

## The engagement hub

The hub is the spine for findings and cases, and a system of record for IR cases and retainers. (Client identity and module entitlement belong to the control plane above; the hub owns the case lifecycle.) Modules feed it; it does not reach into their databases. Two integration points:

- Findings: the hub pulls findings from each enabled module to present a single view per client and to drive client-facing surfaces.
- Escalation: a module can open or link an IR case for a finding by POSTing to the hub, attaching it to a workstream. IR cases use a fixed five-workstream template: Scoping and Containment, Forensics and Analysis, Recovery and Restoration, Notification and Legal, Resilience and Hardening.

The hub is the incident-response module (modules/incident-response). Escalation is live: POST {PLATFORM_HUB_URL}/api/ir-cases with Bearer PLATFORM_HUB_TOKEN (the hub's API_TOKEN, which the deployment hands every finding module). The payload is docs/contracts/escalation.schema.json: source_module, platform_client_id, client (name), case_ref, severity, summary (and title, the same text), workstream and the finding. The hub resolves the module's client by the shared platform_client_id when the escalation carries one, then by name, and never by the source module's own client_id; it links to the open case named in case_ref or opens a new one, raises but never lowers severity, and records the finding internal-only on the requested workstream. The reply is docs/contracts/escalation-result.schema.json (case_id, id, linked). Every finding module stores the returned case number on the finding, so escalating the same finding again attaches to that case instead of opening another, and exposes the same escalation over its own service API at POST /api/findings/{id}/escalate, answering `{escalated, case, linked}` or `{escalated: false, reason}` with HTTP 502.

The findings pull is live: the hub reads GET /api/findings?status=active from each finding-serving module, caches the results briefly, and degrades gracefully so a module that is down shows as unreachable and simply contributes nothing. The sources come from one of two places: the hub's own FINDINGS_SOURCES config (a JSON list of name, base_url and token), or, when that is unset, the control plane's module directory at GET /api/platform/modules?module=incident-response, which returns the enabled, connected, finding-serving modules with their base URL and bearer token. The directory is scoped to its caller (registry.DIRECTORY_CONSUMERS): the hub names itself and receives the finding modules it reads from and nothing else, any other caller is refused, and SABINE never uses it because its reach is its own MODULE_DIRECTORY. That directory is driven by the Connections page, so in a normal deployment an operator wires each module once on the control plane and the hub discovers its finding sources from there rather than keeping a second copy of the list. dark-web-monitoring, managed-services, vulnerability-management, penetration-testing and mdr all serve the finding model and are offered as sources. Each finding is mapped to a hub client by the shared platform_client_id first, then by name, the same resolution escalation uses, so the finding model carries subject.platform_client_id. The consolidated view is at /findings, optionally scoped to one client, and the same pull is served at /api/findings-pull for programmatic use.

A module whose PLATFORM_HUB_URL is blank runs standalone; escalation is a no-op.

The Office of Special Projects (modules/professional-services) is a client module that does not serve the finding model. Its records are engagements and deliverables, served at GET /api/engagements (open by default, with the same `platform_client_id` and `client` filters), and it escalates a live risk from an engagement into the hub on the Resilience and Hardening workstream with the same hub token the finding modules hold. The deployment gives it PLATFORM_HUB_URL and PLATFORM_HUB_TOKEN for that reason even though the hub never pulls from it.

## Roles

The platform has these role families. A module enforces the ones relevant to it.

- admin: internal, full control.
- analyst: internal, full operational access.
- viewer: internal, read only. Opens every staff page and reads every API; every state-changing request (POST, PUT, DELETE, forms, actions, settings) answers 403. Each module enforces it once, by HTTP method, in its auth layer (auth.require_write), so no route needs its own check.
- client: read-only, scoped to a single client, sees only confirmed findings and that client's reports. Enabled per client. A client user has a portal on the control plane (the front door) and on each module they use.
- breach_counsel: privileged access to findings tied to a counsel-directed IR case.
- partner_carrier: scoped access for a reseller or insurance carrier; no access by default.

Internal identity comes from Entra ID SSO, and who gets in at what level is decided by the control plane's staff roster. A person is onboarded once on the platform's Staff page (email, name, title, an access profile), which records a platform role (viewer, analyst or admin) and a grant per module (none, viewer, analyst or admin, plus for managed services whether they may run response actions and approve destructive ones; a viewer never acts or approves). Profiles (Administrator, Incident responder, SOC analyst, Offensive security, vCISO / advisory, Leadership) are starting points; any single grant can be adjusted afterwards. Leadership is viewer on the platform and in every module, and analyst in SABINE so they can read briefs, work the queue and decide low and medium risk proposals. Every module pulls the roster at GET /api/platform/staff?module=<key> alongside its client roster, mirrors it into its users table, and at SSO sign-in asks the control plane live (cached a minute, falling back to the mirror if the control plane is down): once anyone is onboarded, an internal account not granted that module is denied, however its email domain reads. Deactivating a person on the platform is pushed to every module and ends their sessions on the next request. Until the first person is onboarded, the older rules stand: an email in the internal domains, allowlist or group is an analyst, and admin_emails are admins; admin_emails also remain the bootstrap path into the control plane so an empty or broken roster can never lock everyone out. Client identity is mapped from the signing-in user's email domain to the one client that has the portal enabled for that domain. SSO is wired in-app, not only through the environment: each module (and the control plane) has a Settings > SSO page where an admin enters the tenant, client ID and secret, and Save and verify stores it (secret encrypted at rest) and checks it against Microsoft right then by fetching the tenant's OIDC discovery document and performing a client-credentials token request. Stored config overrides the environment, so SSO can be pre-seeded through SSM and still changed in the UI, and a change takes effect with no redeploy because the OAuth client is built per request from the resolved config. A portal domain belongs to a single client: the control plane refuses assigning a domain already used by another active client, and at sign-in a domain that somehow matches more than one client is refused rather than guessed, so a user is never mapped into the wrong tenant.

## Portal views: executive and technical

A client's own people do not all want the same portal. A CISO or an analyst wants the detail; a CEO or board member wants the posture. The platform splits the client portal into two views off one sign-in, with no extra role or account.

- The control plane holds an executive-email list per client (set on the client edit page, pushed in the provisioning roster). A signed-in client user whose email is on that list gets the **executive view**; everyone else at the client gets the **technical view**. This is computed once at `resolve_identity` and exposed as `Identity.is_executive`; it never widens tenant scope, only narrows what a client user sees within their own tenant.
- Executive view is summary-only. Managed services shows a security-posture panel (severity counts, how many items the team is handling) instead of the per-alert table, and the per-alert drill-down is redirected back to the portal home. The IR hub shows workstream milestones only, not the step-by-step timeline. Dark web shows the exposure counts and trend, not the finding-by-finding table, and the detailed exposure report download is withheld.
- Technical view is the full detail: the alert table with drill-down, the IR case timeline, the dark web findings list and the downloadable report.
- The split is presentation within a tenant, not a second security boundary: both views are already confined to the one client by the tenant isolation below. An executive is never shown another tenant's data, and the view is driven entirely by the platform-owned email list, so a client cannot elevate their own view.

## Tenant isolation

The platform is a multi-tenant MSSP system, and the tenant boundary is a security boundary enforced the same way in every module.

- Operators (admin, analyst) work across every client. A client user is bound to one client_id at login and may only reach the portal.
- The boundary is enforced at two layers. The access-gate middleware confines a client session to the portal. Independently, every staff route and the service API require an internal role at the route itself (current_user and api_user refuse a client session), so a client can never reach another tenant's data even if the gate is bypassed or a new route is added.
- Every client-facing record carries client_id, and every portal query filters on it. Portal detail routes go through one helper, require_owned, which returns 404 unless the record exists, belongs to the signed-in client, and meets any extra condition (such as being published), so a client cannot even probe which ids belong to another tenant.
- This is logical multi-tenancy on a shared database per module, with client_id as the tenant key. It is proven, not assumed: each portal-bearing module ships a cross-tenant test suite (two clients, one signed in, asserting no read, probe or action crosses the boundary, plus a direct test of the route-level backstop).
- Tool tenancy is per client: one MSSP-level credential per vendor, narrowed to each client's slice (SentinelOne site IDs, CrowdStrike child CID via Flight Control, Huntress org, Acronis tenant, SuperOps account). Reads and actions are always scoped to the client's mapping.

Wiring a tool in is done in-app on the managed-services Integrations page, not by editing the environment and redeploying. An operator enters the vendor credentials, and they are stored encrypted (Fernet, same scheme as the control-plane token encryption) and tested against the live API on save, so connecting a tool is one screen and takes effect immediately. A stored credential overrides the environment default for that field, a blank secret on a re-save keeps the stored secret, and disconnecting removes the stored credential and falls back to the environment. The connectors resolve each field as stored-over-environment, so a tool can be pre-seeded through SSM and still overridden in the UI. The field set per tool, which fields are secret, and the environment fallback for each live in one place (creds.py), which the Integrations page and the connectors both read.

### When a client requires physical separation

Logical multi-tenancy is the default and is the right fit for nearly every client. Some clients, though — a defense contractor, a bank under a specific regulator, a client whose contract says it outright — require their data to live in a database no other tenant touches. For those we do not reach for an in-app per-tenant database router. That router (resolving a different database connection per request from the tenant) is a large, failure-prone change — connection-pool-per-tenant, migrations fanned out across N databases, every query path newly dependent on getting the routing right — and it buys a weaker separation than the honest answer: a dedicated deployment.

A dedicated tenant is the same code, run as its own stack:

- Stand up a separate instance of each module that client uses, each pointed at its own database (its own `DATABASE_URL`), with its own tool credentials. This is the ordinary per-module deployment, run once for this client instead of shared.
- Provision it from the control plane exactly as a shared stack is: the dedicated modules pull `GET /api/platform/clients?module=<key>` filtered to that one client. A client that must also have a dedicated control plane runs its own platform instance; most do not need to.
- Route the client's portal domain to their stack at the load balancer. Nothing in the application changes, so there is no dedicated-only code path to keep correct, and the separation is physical at the database and the host, not a predicate the app has to evaluate on every request.

The trade is real and we name it: a dedicated stack costs more to run and to patch (N stacks to upgrade, not one), and that cost is the point — it is what physical isolation means. The platform supports both models with the same binaries; which one a client gets is a deployment decision recorded against the client, not a fork of the code. The shared model stays the default because its boundary is tested and its operational cost is flat; the dedicated model exists for the clients whose requirements genuinely demand it.

## Evidence chains and the sealed export

Every evidence-bearing module keeps a per-subject hash chain of Ed25519-signed records through one vendored `app/evidence.py` (the case timeline in incident-response, the response-action log in managed-services, deliverable sign-off in professional-services). The evidence-export shared library (modules/evidence-export) turns any of those chains into one package shape: a zip with a signed manifest over every file, the chain as proof.json, the public key, an embedded standalone verifier and a README, with an optional RFC 3161 timestamp when TSA_URL is set. Each adopting module vendors the package into `app/evidence_export/` and wires a one-click route: professional-services and managed-services export per client at `/clients/{id}/evidence/export.zip` and `/portal/evidence/export.zip`; incident-response exports per case at `/cases/{id}/evidence/export.zip` and `/portal/cases/{id}/evidence/export.zip`, sealing internal-only entries in the client's copy so their content is withheld while the chain still verifies. A client, auditor or opposing expert runs `python verify_evidence.py <package>` with no platform access and learns one verification step for every module.

## The triage copilot

The ai-triage shared library (modules/ai-triage) is an evidence-grounded triage assistant for the finding-bearing modules. Given one finding it proposes a verdict (true positive, false positive, needs investigation, duplicate, benign) with a calibrated confidence and a written rationale, from a deterministic rules backend that always runs; an LLM backend is optional, grounded against the rules and replaced by them on any failure or disagreement. The copilot never acts. managed-services is the reference wiring: the library is vendored into `app/triage/`, a proposal is computed when sync first sees an alert (or on demand at `POST /api/alerts/{id}/copilot`), stored on the alert, and signed into the per-client action chain as a `triage_proposed` row attributed to `copilot:<model>`. A tech accepts, overrides or rejects it on the alert page; the decision is signed as `triage_decided` naming the approver, and a closing verdict resolves the alert only under the module's existing two-person rule. The proposal travels on the shared finding as an optional `copilot` sub-object, so SABINE reads it: a confident false positive is queued for confirmation instead of escalated, and a confident true positive raises the escalation proposal's confidence.

## Managed detection and response

MDR (modules/mdr) is the detection layer over managed services. It reads managed-services alerts as signals at `GET /api/findings?status=all` with the managed-services token, on a schedule (DETECT_INTERVAL_SECONDS) and on demand, and runs them through a pure detection engine: rules plus per-client overrides plus suppressions in, investigation opens and attachments out.

- Rules are data. Each has match conditions (tools, alert types, title substrings, minimum severity), a correlation (group by host, client or title, a window and a threshold), MITRE ATT&CK technique ids and a response recommendation (none, isolate host, disable account, block indicator). An admin edits them in the console; every edit is versioned and attributed. Per client, a rule can be switched off or given a different severity. `/api/coverage` maps the rule set onto ATT&CK tactics.
- Suppressions belong to one client, match on tool, title text or host, carry a reason and expire (1 to 90 days). "This was noise" on an investigation closes it as a false positive and creates one. Expired suppressions stop applying and are listed for monthly review.
- An investigation is one per rule, client and group key while open; new signals attach. It carries a number (MDR-YYYY-NNNN), severity, status (new, investigating, contained, closed), verdict (pending, true positive, false positive, benign), the signals, a signed timeline in the shared evidence chain scheme, acknowledgement, containment and close times, and the escalated case. It is served as a finding of type `investigation` with extra fields SABINE and the control plane read: native_status, verdict, mitre, opened_at, acknowledged_at, contained_at, response (action, host, and alert_ref, the managed-services alert to act on), rule, signals and signal_title.
- MDR never acts on a host. Preparing containment records the recommendation and links the responder to the managed-services alert page, where the module's action permissions and two-person rule apply. Escalation uses the standard contract onto Scoping and Containment and stores the case number.
- `/api/metrics` publishes MTTD (first signal to investigation), MTTA (opened to acknowledged) and MTTR (opened to contained, or closed when never contained), median and p90, overall and per client. The client portal shows the client their own numbers alongside their published investigations.

## SABINE, the agentic brain

SABINE (modules/sabine) sits on top of the contracts rather than inside any module. It perceives through the same service APIs an operator uses, presenting each module's token and naming itself in `X-Vendetta-Actor` so module audit logs read `api:sabine`; it keeps one operator queue across administration, the SOC and professional services (including the Office of Special Projects, whose open engagements it reads at /api/engagements to queue a deliverable the client has not accepted within seven days and an engagement still open past its planned end); it raises proposals from deterministic rules, each with the facts it rests on, a rationale, a confidence and a risk tier, and only for a skill in its catalog (`app/skills.py`, one declaration per action with domain, module, risk, inputs and reversibility, served at `/api/skills` and shown as the Autonomy page); it carries out the ones whose action is set to `auto` and waits for a person on the rest; and it appends every observation summary, proposal, decision and action to a hash-chained Ed25519-signed ledger. The Ask page accepts requests as well as questions: a deterministic parser (with the model, when configured, used only to extract a structured intent validated against the catalog) resolves a skill and its arguments from the perception snapshot, raises a proposal attributed to `ask:<user>`, and the same autonomy policy decides whether it runs now, waits for a person, or is refused; a high-risk skill never runs from chat. She measures herself from the same ledger: mean time to trusted action (proposal raised to action carried out, median and p90, automatic and human-approved) with the approval rate and the share of proposals closed with no person, over 7 and 30 days, on the Overview, the board, the daily summary and `/api/metrics`. Each client brief closes with what SABINE did on that account in the last week, every line redacted for the client (no other client, no Vendetta person, no host that is not theirs, no console link, no token), and the whole brief body is scrubbed the same way. She also runs the client relationship and the business side. She reads MDR investigations and suppressions, each client's Security Journey and communications on the control plane, and, when credentials are set, Harvest (project budget and spend, people's capacity and hours) and HubSpot (renewals and closed-won deals). From those, skills in the same catalog: `page_oncall` pages through the IR hub's `POST /api/oncall/page` when a critical MDR investigation or managed-services alert sits unacknowledged past the client's commitment (once per detection per hour, and never for an alert an open investigation already owns); `journey_suggest` and `journey_progress` keep each client's journey current from evidence; `posture_review` drafts the monthly review and `client_outreach` drafts a note when a campaign touched the client, a deliverable waits or a commitment is at risk, both posted as drafts for the account lead to approve, in the formal client voice and through the client redaction; `suggest_suppression` proposes an MDR suppression (medium risk, a person decides) when people have dismissed the same pattern for one client repeatedly; and `engagement_budget_burn`, `capacity_overload`, `renewal_upcoming` and `won_not_onboarded` raise work items from the business sources. An admin can set autonomy per client and skill and thresholds per client on the Autonomy page, each change in the ledger, and a high-risk skill is still never automatic for any client. Decision memory adjusts each new proposal's confidence from the people's earlier approvals and rejections of the same skill, client and pattern, and records the adjustment in the proposal's facts. A draft a person still has to approve is not counted as a closed loop in mean time to trusted action.

Three limits no setting changes: a high-risk action is never automatic, SABINE never touches a client host (it hands off to the module where a responder acts under that module's approval rules), and the language model, when configured, only writes from facts the rules produced and never chooses an action. Its reach is the deployment-rendered MODULE_DIRECTORY, its console access is the platform staff roster, and the platform's readiness screen reports its reach and last cycle.

## Deployment wiring

One host runs every module as its own compose project, and every web container joins one external docker network ("vendetta") under its module key, so modules reach each other as `http://<module-key>:8000` from inside any container. The deployment (infra/terraform) generates every secret a module needs, including a dedicated API_TOKEN per module, hands each client module the platform's token and each finding module the hub's token, and renders the control plane's MODULE_DIRECTORY, so the whole mesh is wired at first boot. Configuration is rendered from SSM into each module's .env on every deploy (infra/host/vendetta-env), so a parameter added later reaches the containers on the next `infra/redeploy.sh`. Modules fail closed: a placeholder SECRET_KEY stops the container, and managed-services starts with ACTIONS_READONLY=true until an operator turns actions on.

## Enablement

Two switches:

- Module on/off: MODULE_ENABLED turns a whole capability on or off. The hub flips it.
- Per-client capability: a module may gate a feature per client (the dark web module's client portal is enabled per client with an allowed-domains list).

## Starting a new module

1. Copy the shape of modules/vulnerability-management (the smallest complete module): module.yaml, a /api/module manifest with `enabled` and a readiness block, the finding model at /api/findings with the shared filters, MODULE_ENABLED handling, provision.py with the scheduled pull and POST /api/provision/sync, the /clients/platform/{pid} deep link, boot.py, and role-gated views.
2. Register it in modules/registry.yaml with its status and enablement flag, and in the control plane's registry.py (DEFAULT_MODULES, FINDING_MODULES, PROBE).
3. Map the module's native records to the finding model and add tests/test_contracts.py validating against docs/contracts.
4. Wire escalation to the hub behind PLATFORM_HUB_URL, both from the UI and at POST /api/findings/{id}/escalate, storing the returned case number.
5. Add a Dockerfile and docker-compose.yml that joins the shared network under the module key, and add the module to infra/terraform/variables.tf (modules, module_hosts, listener_priorities) and, if it signs evidence, to local.signing_modules.
