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

## The engagement hub

The hub is the spine of the platform and the system of record for clients and IR cases. Modules feed it; it does not reach into their databases. Two integration points:

- Findings: the hub pulls findings from each enabled module to present a single view per client and to drive client-facing surfaces.
- Escalation: a module can open or link an IR case for a finding by POSTing to the hub, attaching it to a workstream. IR cases use a fixed five-workstream template: Scoping and Containment, Forensics and Analysis, Recovery and Restoration, Notification and Legal, Resilience and Hardening.

The hub is the incident-response module (modules/incident-response). Escalation is live: POST {PLATFORM_HUB_URL}/api/ir-cases with Bearer PLATFORM_HUB_TOKEN, the token shown on the hub's settings page. The hub resolves the module's client by name, links to the open case named in case_ref or opens a new one, raises but never lowers severity, and records the finding internal-only on the requested workstream. The payload and response are documented in modules/incident-response/README.md. The findings pull is not built yet.

A module whose PLATFORM_HUB_URL is blank runs standalone; escalation is a no-op.

## Roles

The platform has these role families. A module enforces the ones relevant to it.

- admin — internal, full control.
- analyst — internal, full operational access.
- client — read-only, scoped to a single client, sees only confirmed findings and that client's reports. Enabled per client.
- breach_counsel — privileged access to findings tied to a counsel-directed IR case.
- partner_carrier — scoped access for a reseller or insurance carrier; no access by default.

Internal identity comes from Entra ID SSO (by email domain, allowlist or group); client identity is mapped from the signing-in user's email domain to a client that has the portal enabled.

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
