# Office of Special Projects

Status: built and tested. Reference implementation: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

Vendetta's professional-services delivery arm. It runs vCISO retainers, implementation projects, tabletop exercises, assessments and advisory as structured engagements rather than a pile of documents. Each engagement holds deliverables (documents, reports, playbooks, policies, sessions, milestones, assessments) that move planned → in progress → in review → delivered, and that the client accepts — signs off — on their portal. Every material step is bound into a per-client, signed, tamper-evident chain of custody, so a deliverable sign-off is provable after the fact.

## What it contributes

Engagements and deliverables, not detections — so it does not feed the shared finding model. Its system of record is the engagement and its signed sign-off chain, with a downloadable proof (`/clients/{id}/evidence/proof.json`) that verifies independently against Vendetta's public key. When a vCISO or tabletop surfaces live risk, the engagement escalates into an IR case on the hub's "Resilience and Hardening" workstream.

## Roles

Admins and analysts (the delivery team) run engagements and deliverables; they cannot accept a deliverable on the client's behalf, and cannot delete one the client has already accepted. A client with the portal enabled sees only their published engagements and deliverables, accepts delivered items, and downloads the sign-off proof. Executive contacts (per `executive_emails`) additionally see the engagement's executive summary. No carrier access by default.

## Enablement

MODULE_ENABLED for the module; the client view is per client. Microsoft 365 SSO is configured in-app at /settings/sso.

## Endpoints

- `GET /api/module` — manifest with `enabled`, engagement types and deliverable statuses.
- `GET /api/clients/{id}/evidence/verify` — verify the client's sign-off chain.
- `GET /clients/{id}/evidence/proof.json` — downloadable, independently verifiable sign-off proof.

## Tests

`PSVC_TEST_DATABASE_URL` points at a disposable Postgres (default `psvc:psvc@localhost:5432/psvc_test`); `pytest -q` from the module directory. CI runs the suite on the `professional-services` matrix entry.
