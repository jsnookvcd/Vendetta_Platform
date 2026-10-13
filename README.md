# Vendetta Platform

The Vendetta Platform is the hosted system of record for Vendetta Cyber Defense delivery. It is built as a set of modules around a shared engagement hub, each covering one service line and each able to be turned on or off per deployment. Dark Web Monitoring is the first module in production and is the reference implementation that the others follow. Incident Response is the engagement hub the other modules escalate into.

## Modules

- platform: the control plane and front door. System of record for the client directory, which modules are on per client, and how each client maps into the tools, with a live cross-module overview. Built; managed-services consumes it. See modules/platform.
- dark-web-monitoring: leak-site, forum, credential and certificate monitoring with evidence preservation and a client portal. In production. See modules/dark-web-monitoring.
- vulnerability-management: scan ingest, enrichment and risk scoring, with findings and client-owned remediation status. Wraps the existing Go scanner service. Planned.
- penetration-testing: engagement findings as records (severity, asset, evidence, remediation, retest), with the report rendered from them at close. Planned.
- incident-response: IR cases and retainers; the engagement hub spine, with the five-workstream case template, one-button incident declaration, a client portal and the escalation API. Built; first deploy pending.
- managed-services: a console over every tool a managed client has deployed (SuperOps, SentinelOne, CrowdStrike, Huntress, Acronis), with a client portal for alerts, actions taken and messaging the SOC, NOC and helpdesk. Built; live credentials pending. See modules/managed-services.
- mdr: managed detection and response: investigations with verdicts and analyst actions rather than raw alerts, convertible to an IR case. Planned.
- network-operations: managed network and infrastructure operations: device and service health, change and maintenance tracking. Planned.

modules/registry.yaml lists them with status and the environment flag that enables each.

## How a module is built

Every module is a self-contained service under modules/<name>/ that:

- declares itself in module.yaml and serves that manifest at /api/module, including an `enabled` flag;
- honors a MODULE_ENABLED switch so the platform can turn the capability on or off;
- contributes to the shared finding model (see docs/ARCHITECTURE.md), so the engagement hub reads every module's output the same way;
- can escalate a finding into an IR case in the hub, attached to the right workstream;
- honors the platform role families: internal staff (admin, analyst), the client read-only role scoped to one client, and, where relevant, breach counsel and scoped partner or carrier access.

Dark Web Monitoring implements all of this today; treat its module.yaml, its /api/module manifest, its finding model mapping and its role-gated client portal as the pattern to copy.

## Architecture

infra/terraform stands the whole platform up on one AWS host behind a single load balancer that routes to each module by hostname; see infra/terraform/README.md. Each module can also run alone. GO_LIVE.md is the sequenced runbook from deploy to one real client, and infra/verify.sh checks a running stack.

docs/ARCHITECTURE.md describes the shared finding model, the engagement hub contract, module enablement, the role families, and how a module plugs in. Read it before starting a new module.

## Repository layout

```
modules/
  platform/              control plane and front door (built)
  dark-web-monitoring/   reference module (in production)
  incident-response/     engagement hub (built)
  managed-services/      console over the client's deployed tools (built)
  vulnerability-management/
  penetration-testing/
  mdr/
  network-operations/
  registry.yaml          module catalog with status and enablement
infra/
  terraform/             platform-wide deploy: one host, one ALB, all modules
docs/
  ARCHITECTURE.md        shared contracts
```

Each module owns its own runtime and Dockerfiles. The control plane is the system of record for clients and per-client module enablement; the engagement hub owns the case lifecycle. infra/terraform runs every module on one host, and a module can also run alone.
