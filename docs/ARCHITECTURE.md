# Vendetta Platform architecture

This describes the contracts every module shares. The goal is that the engagement hub, the client-facing views and the reporting all work the same way regardless of which module produced the data. Dark Web Monitoring is the reference implementation.

## Modules

A module is a self-contained service for one service line. It owns its runtime, data store, infrastructure and deployment, and it is reached by the hub over HTTP. Modules do not share a database or a binary; they share contracts.

Every module:

- lives under modules/<name>/ and declares itself in module.yaml;
- serves its manifest at GET /api/module, including `enabled`, its roles, and its finding types;
- honors a MODULE_ENABLED flag. When off, the UI shows a disabled notice, background work idles, and /api/module reports enabled:false so the hub can read status;
- exposes its findings in the shared finding model below;
- can escalate a finding into an IR case in the hub.

## The finding model

Modules produce different raw records (a dark web hit, a vulnerability, a pentest issue, an MDR detection), but each is exposed to the hub as a finding with this shape:

```
id            string, unique within the module
module        the module name, e.g. "dark-web-monitoring"
platform      "Vendetta Platform"
subject       { client_id, client, case_ref }   the account it belongs to
type          module-specific record kind (e.g. victim, vulnerability, detection)
severity      low | medium | high | critical
status        new | reviewing | confirmed | false_positive | closed
title         short human description
evidence      [ { id, sha256, captured_at, storage_uri } ]   may be empty
created_at    ISO 8601
workstream    the IR workstream a finding attaches to when escalated
```

The hub reads findings at GET /api/findings on each module and the manifest at GET /api/module. A module keeps its own richer native shape too (the dark web module also serves /api/hits); the finding model is the common denominator the hub and client views rely on.

## The control plane

The control plane (modules/platform) is the front door and the system of record for three things the modules used to each own separately: the canonical client directory, which modules are turned on per client, and how each client maps into the tools. It holds no vendor secrets; those stay with the module that uses them. It reaches each module over HTTP with a per-module bearer token.

Two integration points, opposite directions:

- Provisioning (modules read from it): a module calls GET {platform}/api/platform/clients?module=<key> with a bearer token and gets the active clients that have it enabled. For managed-services each client also carries its tool tenancy mapping. The module upserts its own client rows keyed by the platform client id (adopting any it already had by name). managed-services, incident-response and dark-web-monitoring all consume it. A module's pull is authoritative only for the platform-owned fields (name, portal domains, the executive-email list, and for managed-services the tool mapping); each module's own data (IR retainers and cases, dark web watch terms and the IAB profile, managed-services sync history) is never touched.
- Overview (it reads from modules): the control plane calls each module's /api/module for health and its items endpoint for live counts, cached briefly and degrading gracefully.

The canonical client id lives here, and every built module stores it on its own client rows. Escalations carry it too: a module sends its platform_client_id, and the engagement hub resolves the case's client by that shared id first, falling back to name.

## The engagement hub

The hub is the spine for findings and cases, and a system of record for IR cases and retainers. (Client identity and module entitlement belong to the control plane above; the hub owns the case lifecycle.) Modules feed it; it does not reach into their databases. Two integration points:

- Findings: the hub pulls findings from each enabled module to present a single view per client and to drive client-facing surfaces.
- Escalation: a module can open or link an IR case for a finding by POSTing to the hub, attaching it to a workstream. IR cases use a fixed five-workstream template: Scoping and Containment, Forensics and Analysis, Recovery and Restoration, Notification and Legal, Resilience and Hardening.

The hub is the incident-response module (modules/incident-response). Escalation is live: POST {PLATFORM_HUB_URL}/api/ir-cases with Bearer PLATFORM_HUB_TOKEN, the token shown on the hub's settings page. The hub resolves the module's client by the shared platform_client_id when the escalation carries one, then by name, links to the open case named in case_ref or opens a new one, raises but never lowers severity, and records the finding internal-only on the requested workstream. The payload and response are documented in modules/incident-response/README.md.

The findings pull is live: the hub reads GET /api/findings from each module listed in its FINDINGS_SOURCES config (a JSON list of name, base_url and token), caches the results briefly, and degrades gracefully so a module that is down shows as unreachable and simply contributes nothing. Each finding is mapped to a hub client by the shared platform_client_id first, then by name, the same resolution escalation uses, so the finding model carries subject.platform_client_id. The consolidated view is at /findings, optionally scoped to one client, and the same pull is served at /api/findings-pull for programmatic use.

A module whose PLATFORM_HUB_URL is blank runs standalone; escalation is a no-op.

## Roles

The platform has these role families. A module enforces the ones relevant to it.

- admin: internal, full control.
- analyst: internal, full operational access.
- client: read-only, scoped to a single client, sees only confirmed findings and that client's reports. Enabled per client.
- breach_counsel: privileged access to findings tied to a counsel-directed IR case.
- partner_carrier: scoped access for a reseller or insurance carrier; no access by default.

Internal identity comes from Entra ID SSO (by email domain, allowlist or group); client identity is mapped from the signing-in user's email domain to the one client that has the portal enabled for that domain. A portal domain belongs to a single client: the control plane refuses assigning a domain already used by another active client, and at sign-in a domain that somehow matches more than one client is refused rather than guessed, so a user is never mapped into the wrong tenant.

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

## Enablement

Two switches:

- Module on/off: MODULE_ENABLED turns a whole capability on or off. The hub flips it.
- Per-client capability: a module may gate a feature per client (the dark web module's client portal is enabled per client with an allowed-domains list).

## Starting a new module

1. Copy the shape of modules/dark-web-monitoring: a module.yaml, a /api/module manifest with an `enabled` flag, the finding model at /api/findings, MODULE_ENABLED handling, and role-gated views.
2. Register it in modules/registry.yaml with its status and enablement flag.
3. Map the module's native records to the finding model.
4. Wire escalation to the hub behind PLATFORM_HUB_URL.
5. Keep the deployment self-contained under the module directory.
