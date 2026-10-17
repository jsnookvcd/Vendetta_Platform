# Office of Special Projects

Status: built, tested, containerized and deployed (host `osp.`, port 8700, service name `professional-services` on the shared docker network). Reference implementation: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

Vendetta's professional-services delivery arm. It runs vCISO retainers, implementation projects, tabletop exercises, assessments and advisory as structured engagements rather than a pile of documents. Each engagement holds deliverables (documents, reports, playbooks, policies, sessions, milestones, assessments) that move planned → in progress → in review → delivered, and that the client accepts (signs off) on their portal. Every material step is bound into a per-client, signed, tamper-evident chain of custody, so a deliverable sign-off is provable after the fact.

## What it contributes

Engagements and deliverables rather than detections, so it does not feed the shared finding model. Its system of record is the engagement and its signed sign-off chain, with a downloadable proof (`/clients/{id}/evidence/proof.json`) that verifies independently against Vendetta's public key. When a vCISO or tabletop surfaces live risk, the engagement escalates into an IR case on the hub's "Resilience and Hardening" workstream. The control plane and SABINE read its open engagements at `GET /api/engagements`; SABINE queues a deliverable the client has not accepted within seven days of delivery and an engagement still open past its planned end date.

## Roles

Admins and analysts (the delivery team) run engagements and deliverables; they cannot accept a deliverable on the client's behalf, and cannot delete one the client has already accepted. A client with the portal enabled sees only their published engagements and deliverables, accepts delivered items, and downloads the sign-off proof. Executive contacts (per `executive_emails`) additionally see the engagement's executive summary. No carrier access by default.

## Enablement

MODULE_ENABLED for the module; the client view is per client. Microsoft 365 SSO is configured in-app at /settings/sso.

## Platform link

The module pulls its client roster and the staff roster from the control plane (`PLATFORM_URL`, `PLATFORM_TOKEN`) every `PROVISION_INTERVAL_SECONDS` and whenever the control plane pushes `POST /api/provision/sync`. SSO sign-in for an internal account asks the staff roster live (cached a minute, mirrored users table as the offline fallback); once anyone is onboarded, a person not granted this module is denied. The control plane's client page links to `/clients/platform/{platform_client_id}`. The module refuses to start on a placeholder `SECRET_KEY` unless `ALLOW_INSECURE_DEFAULTS=true`, authenticates its service API with the deployment-set `API_TOKEN`, and signs the sign-off chain with `EVIDENCE_SIGNING_KEY`. Escalation needs `PLATFORM_HUB_URL` and `PLATFORM_HUB_TOKEN`, which the deployment sets.

## Run it

`docker compose up -d --build` from this directory with a `.env` built from `.env.example`. The web container binds 127.0.0.1:8700 by default (`WEB_BIND=0.0.0.0` behind the load balancer) and joins the external `vendetta` network as `professional-services`, so other modules reach it at `http://professional-services:8000`.

## Endpoints

- `GET /api/module`: manifest with `enabled`, engagement types, deliverable statuses and the readiness block.
- `GET /api/engagements`: engagements with their deliverables; `status` is `open` (default), `all` or a state, filterable by `platform_client_id` and `client`.
- `POST /api/provision/sync`: pull the client and staff rosters now (the control plane calls this on a change).
- `GET /api/clients/{id}/evidence/verify`: verify the client's sign-off chain.
- `GET /clients/{id}/evidence/proof.json`: downloadable, independently verifiable sign-off proof.
- `GET /clients/platform/{platform_client_id}`: deep link from the control plane into the client's page.

## Tests

`PSVC_TEST_DATABASE_URL` points at a disposable Postgres (default `psvc:psvc@localhost:5432/psvc_test`); `pytest -q` from the module directory. CI runs the suite on the `professional-services` matrix entry.
