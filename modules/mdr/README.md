# Managed Detection and Response

Status: built and tested (service name `mdr` on the shared docker network, host `mdr.`, port 8800). Shared contracts: /docs/ARCHITECTURE.md.

## Scope

MDR is the detection and investigation pipeline over the managed-services signals. Managed services normalizes alerts from every client tool (SentinelOne, CrowdStrike, Huntress, Acronis, SuperOps, Entra ID, AWS); MDR pulls them, runs them through a rule set mapped to MITRE ATT&CK, and opens investigations that the SOC carries to a verdict. Clients see the investigations, the verdict on each and what Vendetta did. The raw alert stream stays with the analysts.

## How detection works

- Signals: MDR reads `GET {MANAGED_SERVICES_URL}/api/findings?status=all` with `MANAGED_SERVICES_TOKEN` every `DETECT_INTERVAL_SECONDS` (default 120) and on `POST /api/detect/run`. Each finding is stored as a signal keyed by its managed-services alert id, so an investigation's evidence survives the alert being resolved upstream. A signal for a client this module has not been provisioned with is kept and never opens anything.
- Rules are data. Each has a match (tools, signal types, title substrings, minimum severity), a correlation (group by host, client or title; a window; a threshold), ATT&CK technique ids and a recommended response. Fifteen starter rules ship seeded: ransomware behavior (T1486), credential dumping (T1003), suspicious PowerShell (T1059.001), risky sign-in (T1078), MFA fatigue (T1621), failed sign-in burst (T1110), mailbox forwarding (T1114.003), cloud credential misuse (T1552.005), scheduled task persistence (T1053.005), lateral movement (T1021), backup tampering and repeated backup failures (T1490), security tool tampering (T1562.001), remote access tools (T1219), and a burst-of-signals-on-one-host correlation rule. An admin edits them on the Rules page; every edit is a new version with who and why. A per-client override disables a rule or changes its severity for one client.
- Suppressions belong to one client and match on any of tool, title fragment and host. They expire (1 to 90 days); expired ones stay on the Suppressions page for the monthly tuning review.
- The engine (`app/engine.py`) is a pure function from signals, rules, overrides, suppressions and the open investigations to a plan: which investigations to open and which signals to attach. One investigation stays open per rule, client and group key, and new matching signals attach to it.

## Investigations

Numbered `MDR-YYYY-NNNN`, each with a severity, status (new, investigating, contained, closed), verdict (pending, true positive, false positive, benign), the rule and its ATT&CK techniques, the host, the signals and a signed, hash-chained timeline (`app/evidence.py`, exportable as a sealed package with a standalone verifier). Analysts acknowledge, set a verdict, add notes, publish a client summary, prepare containment, mark contained, close, reopen and escalate. "This was noise" closes the investigation as a false positive and creates a suppression for that client (30 days by default, reason required). Prepare containment records the recommended action and links the responder to `{MANAGED_SERVICES_PUBLIC_URL}/alerts/{alert_ref}`; MDR never acts on a host. Escalation posts the contract payload to the IR hub on the Scoping and Containment workstream and stores the case number, so a second escalation attaches to the same case.

## Console

Overview (open by severity, unacknowledged criticals, MTTD, MTTA and MTTR), Investigations, Rules (edit with versions, per-client overrides), Suppressions (active, expiring, expired for review), Coverage (rules over the ATT&CK tactics), Clients, Settings and SSO.

## Roles

Admins edit rules and overrides. Analysts work investigations and suppressions. Viewers read every page and API and change nothing. A client with the portal enabled sees their published investigations, the verdicts, what Vendetta did and their own MTTD, MTTA and MTTR; executive contacts (per `executive_emails`) see the counts and the response times only. Tenant isolation runs through `auth.require_owned` with a cross-tenant test suite.

## Platform link

The module pulls its client roster and the staff roster from the control plane (`PLATFORM_URL`, `PLATFORM_TOKEN`) every `PROVISION_INTERVAL_SECONDS` and whenever the control plane pushes `POST /api/provision/sync`, and serves `/clients/platform/{platform_client_id}` as the deep link. It refuses to start on a placeholder `SECRET_KEY` unless `ALLOW_INSECURE_DEFAULTS=true`, authenticates its service API with `API_TOKEN` (a caller may name itself with `X-Vendetta-Actor`, recorded as `api:<name>`), and signs timelines with `EVIDENCE_SIGNING_KEY`.

## Run it

`docker compose up -d --build` from this directory with a `.env` built from `.env.example`. The web container binds 127.0.0.1:8800 by default (`WEB_BIND=0.0.0.0` behind the load balancer) and joins the external `vendetta` network as `mdr`, so other modules reach it at `http://mdr:8000`.

## Endpoints

- `GET /api/module`: manifest with `enabled`, counts and the readiness block (including the signal source).
- `GET /api/findings`: investigations in the shared finding model, type `investigation`; `status` is `active` (default) or `open`, `all`, or a native status; `platform_client_id` and `client` filters. Each carries `native_status`, `verdict`, `mitre`, `opened_at`, `acknowledged_at`, `contained_at`, `response {action, host, alert_ref}`, `rule` and `signals`.
- `POST /api/findings/{id}/escalate`: `{escalated, case, linked}`, or `{escalated: false, reason}` with HTTP 502.
- `POST /api/suppressions`: body `{platform_client_id, tool?, title_contains?, host?, reason, days, created_by}`, answers `{id, expires_at}`; 404 for an unknown client, 400 for days outside 1 to 90, no reason, or no match field.
- `GET /api/suppressions?platform_client_id=`: the suppressions with `active` and `hits`.
- `GET /api/metrics?days=30&platform_client_id=`: MTTD (earliest signal to opened), MTTA (opened to acknowledged) and MTTR (opened to contained, or closed when never contained) as median and p90 minutes, overall and `by_client`.
- `GET /api/coverage`: the rules mapped onto the ATT&CK tactics with counts.
- `GET /api/rules`, `POST /api/detect/run`, `POST /api/provision/sync`, `GET /api/investigations/{id}/evidence/verify`.

## Tests

`MDR_TEST_DATABASE_URL` points at a disposable Postgres (default `mdr:mdr@localhost:5432/mdr_test`); `pytest -q` from the module directory.
