# Cross-module contracts

These JSON Schemas are the shapes modules exchange. Each module's test suite
validates what it emits against them (tests/test_contracts.py), so a module
cannot drift from the hub without its own CI going red.

- finding.schema.json: the shared finding every module serves at `GET /api/findings`
  and embeds in an escalation. Query parameters every module accepts:
  `status` (`active`, the default, with `open` as a synonym; `all`; or a literal
  module status), `platform_client_id` (the control plane's id) and `client`
  (name substring).
- escalation.schema.json: what a module POSTs to the hub at `POST /api/ir-cases`.
  Every finding module also exposes `POST /api/findings/{id}/escalate` so the
  control plane or another module can drive an escalation over the service API.
- escalation-result.schema.json: what the hub answers, and what a module's
  escalate endpoint relays as `{escalated: true, case, linked}`. A failure is
  `{escalated: false, reason}` with HTTP 502.

Client identity across modules is the `platform_client_id` the control plane
assigns. A module's own `client_id` is its database key and is informational
only; name is the fallback match when the platform id is absent.

Authentication is `Authorization: Bearer <that module's API_TOKEN>`. The control
plane hands the hub each finding module's token through `GET /api/platform/modules`.

Staff: `GET /api/platform/staff?module=<key>` returns `{governs, staff: [{email,
name, title, role, config}]}`. `role` is `admin` or `analyst` for that module;
`config` carries module capabilities (managed services: `can_act`,
`can_approve`). `governs` is true once anyone has been onboarded, after which a
module admits internal sign-ins only from the list.
