# Vendetta Platform

The Vendetta Platform is the hosted system of record for Vendetta Cyber Defense delivery. It is built as a set of modules around a shared engagement hub, each covering one service line and each able to be turned on or off per deployment. Dark Web Monitoring is the first module in production and is the reference implementation that the others follow. Incident Response is the engagement hub the other modules escalate into.

## Modules

- platform: the control plane and front door. System of record for the client directory, which modules are on per client, how each client maps into the tools, each client's service tier, response commitments and account lead, the Security Journey and client communications, and the staff roster with each person's access level per module. A Client 360 per client reads every module live; the client portal home at /portal gives the client one front door into every service line they have. Live cross-module overview and the go-live readiness screen. Every module consumes it. See modules/platform.
- dark-web-monitoring: leak-site, forum, credential and certificate monitoring with evidence preservation and a client portal. In production. See modules/dark-web-monitoring.
- vulnerability-management: scan ingest (POST /api/scans), findings deduped across scans, a client portal with an exposure trend over time and click-through remediation steps, and escalation to the hub. Built, tested and deployed. See modules/vulnerability-management.
- penetration-testing: engagements and findings with a retest loop, the report rendered from findings at close, a client portal with a cross-engagement trend and click-through remediation, and escalation to the hub. Built, tested and deployed. See modules/penetration-testing.
- incident-response: IR cases and retainers; the engagement hub spine, with the five-workstream case template, one-button incident declaration, a client portal and the escalation API. Built; first deploy pending.
- professional-services (Office of Special Projects): vCISO retainers, implementation projects, tabletop exercises, assessments and advisory, run as engagements with deliverables the client accepts (signs off) on the portal, every delivery and sign-off bound into a signed, hash-chained chain of custody with a downloadable proof, and escalation to the hub for live risk. Built, tested, containerized and deployed (host osp., port 8700). See modules/professional-services.
- evidence-export: shared library that turns any module's signed chain of custody into a court-admissible, self-verifying export package (sealed manifest, embedded standalone verifier, optional RFC 3161 trusted timestamp), with an independent verifier that confirms a package offline with no access to the platform. professional-services is the reference wiring; incident-response (per case) and managed-services (per client) are wired too. Built and tested. See modules/evidence-export.
- ai-triage: shared evidence-grounded triage copilot for the finding-bearing modules. Proposes a verdict with a calibrated confidence and a written rationale, with a deterministic rules fallback that always runs and grounds any LLM output; a human accepts or rejects, a second approver is required for high-stakes or low-confidence verdicts, and both the proposal and the decision are written to the signed evidence chain. managed-services is the reference wiring, and SABINE reads the verdict from the shared finding. Built and tested. See modules/ai-triage.
- managed-services: a console over every tool a managed client has deployed (SuperOps, SentinelOne, CrowdStrike, Huntress, Acronis), with a client portal for alerts, actions taken and messaging the SOC, NOC and helpdesk. Built; live credentials pending. See modules/managed-services.
- sabine: SABINE, the agentic brain. One operator queue across every module, proposals with rationale at a per-action autonomy level (per client where an admin sets it), action only through module APIs as itself, a signed ledger of everything it did, briefs and a daily summary. She also runs the client relationship and the business: pages on-call when a critical sits past the client's commitment, maintains each client's Security Journey, drafts monthly posture reviews and proactive outreach for a person to approve, learns from every human decision, proposes MDR suppressions for repeated noise, and watches Harvest burn and capacity and HubSpot renewals and new wins. Built and tested. See modules/sabine.
- mdr: managed detection and response. Detection rules over managed-services signals (EDR, identity, cloud, backup), readable and editable by the operator and mapped to MITRE ATT&CK, with per-client overrides and expiring suppressions. Investigations with verdicts, a signed timeline, escalation to the IR hub and a containment hand-off to managed services; MTTD, MTTA and MTTR published per client; client portal. Built and tested (port 8800). See modules/mdr.
- project-management: delivery PM for the IR and ProServ practices. One Kanban board per practice (columns are engagement phases), a task board per engagement, meeting notes stored here and mirrored to the engagement's SharePoint folder, and time written to Harvest as the PM. Staff-only. PMs work it from the web board or from Claude: the module is a remote MCP server at /mcp that a PM adds as a Claude connector and signs into with their own account (OAuth 2.1 with PKCE), so every change is made as that person with their access level. Built and tested (port 8900, host pm.). See modules/project-management.
- network-operations: managed network and infrastructure operations: device and service health, change and maintenance tracking. Planned.

modules/registry.yaml lists them with status and the environment flag that enables each.

## How a module is built

Every module is a self-contained service under modules/<name>/ that:

- declares itself in module.yaml and serves that manifest at /api/module, including an `enabled` flag;
- honors a MODULE_ENABLED switch so the platform can turn the capability on or off;
- contributes to the shared finding model (see docs/ARCHITECTURE.md), so the engagement hub reads every module's output the same way;
- can escalate a finding into an IR case in the hub, attached to the right workstream, from its UI and at POST /api/findings/{id}/escalate;
- pulls its client roster from the control plane on a schedule and when the control plane pushes a change, and serves /clients/platform/{id} so the control plane can link straight to a client;
- emits the shapes pinned in docs/contracts and validates them in its own tests;
- honors the platform role families: internal staff (admin, analyst, viewer, granted per module on the control plane's Staff page and enforced at SSO sign-in), the client read-only role scoped to one client, and, where relevant, breach counsel and scoped partner or carrier access.

Dark Web Monitoring implements all of this today; treat its module.yaml, its /api/module manifest, its finding model mapping and its role-gated client portal as the pattern to copy.

## Architecture

infra/terraform stands the whole platform up on one AWS host behind a single load balancer that routes to each module by hostname, with every module on one docker network so they reach each other by name and every secret and cross-module token generated by the deployment; see infra/terraform/README.md. Each module can also run alone (create the shared network once with `docker network create vendetta`, then `docker compose up` in the module directory). GO_LIVE.md is the sequenced runbook from deploy to one real client, and infra/verify.sh checks a running stack.

docs/ARCHITECTURE.md describes the shared finding model, the engagement hub contract, module enablement, the role families, the tenant isolation standard, the executive and technical portal views, and how a module plugs in. Read it before starting a new module.

## Evidence integrity

The incident-response case timeline and the managed-services response-action log are each bound into a signed, tamper-evident chain of custody. Every record is hash-chained to the one before it and signed with an Ed25519 key as it is written, so altering, reordering, inserting or deleting any record is detectable. Verification needs only the records and the public key, so staff, clients and opposing counsel can check it independently; each module exposes a verify endpoint and a downloadable proof. See the chain-of-custody sections in docs/ARCHITECTURE.md.

## Tests and CI

Each built module has its own test suite that runs against a real Postgres, including cross-tenant isolation suites, the evidence-chain suites, and a contract suite that validates what the module emits against docs/contracts. GitHub Actions (.github/workflows/ci.yml) stands up Postgres, creates each module's test role and database, runs every suite, builds every module image and confirms it refuses a placeholder secret, validates the Terraform and shellchecks the host scripts, on push and pull request. To run one locally, start Postgres, create the module's test database (for example platform_test owned by role platform), and run pytest in the module directory.

## Repository layout

```
modules/
  platform/              control plane and front door (built)
  dark-web-monitoring/   reference module (in production)
  incident-response/     engagement hub (built)
  managed-services/      console over the client's deployed tools (built)
  vulnerability-management/
  penetration-testing/
  professional-services/ Office of Special Projects (built, deployed)
  evidence-export/       shared court-admissible export + standalone verifier (built and tested)
  ai-triage/             shared evidence-grounded triage copilot (built and tested)
  mdr/                   detection and investigation over managed-services signals (built)
  project-management/    IR and ProServ boards, tasks, meeting notes, Harvest time; MCP server for Claude (built)
  network-operations/
  registry.yaml          module catalog with status and enablement
infra/
  terraform/             platform-wide deploy: one host, one ALB, all modules
  host/                  scripts the host runs: .env renderer, nightly backup
docs/
  ARCHITECTURE.md        shared contracts
  contracts/             JSON Schemas for the finding, escalation and result shapes
```

Each module owns its own runtime and Dockerfiles. The control plane is the system of record for clients and per-client module enablement; the engagement hub owns the case lifecycle. infra/terraform runs every module on one host, and a module can also run alone.
