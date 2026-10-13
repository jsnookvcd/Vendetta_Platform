# Platform control plane

The front door and the system of record for the Vendetta Platform. It holds the
canonical client directory, which modules are turned on per client, and how each
client maps into the tools. The main screen is a launcher and a live cross-module
overview; behind it, this is the backend that ties the modules together.

It is deliberately thin: it holds no vendor secrets. The actual tool credentials
live with the module that uses them (managed-services). The control plane owns the
client roster, the per-client enablement, and the per-client tool tenancy mapping,
and it reaches each module over HTTP with a per-module bearer token.

## What it does

The directory and entitlements
- Client is the canonical record, one row per client, platform-wide, with a stable
  id. Modules key their own records to that id, so one client lines up everywhere.
- ClientModule is the per-client on/off for each module.
- ClientTool is how a client maps into each tool (the tenancy value: SentinelOne
  site ids, CrowdStrike child CID, Huntress org, Acronis tenant, SuperOps account).

The main screen
- A platform-wide rollup: active clients, modules live, critical/high open and
  total open items across every module, tools connected.
- A module strip: each module with its status, a health dot, and its live open-item
  count read from the running module.
- The client table: each client with its active modules and how many tools are
  mapped.

Per-client activation (the backend you asked for, made visible)
- Turn each module on or off for a client. Planned modules show but cannot be
  activated until they exist.
- Map the client's tenancy in each tool, which is pushed to managed-services.
- Set the client's portal email domains once, here, to flow to each module's
  portal; and see the canonical platform id the modules key to.

Connections
- Each module's base URL and bearer token (how the platform reaches it), with a
  live health check.
- Each tool's connection state, refreshed from what managed-services reports.

## How the modules tie in

The control plane is the source of truth; modules pull from it.

```
GET /api/platform/clients?module=<key>
Authorization: Bearer <platform token>
```

returns the active clients that have that module enabled. For managed-services each
client also carries its tool mapping:

```json
{"module": "managed-services", "clients": [
  {"id": "d2c9...", "name": "Riverbend Credit Union", "slug": "riverbend-credit-union",
   "industry": "credit union", "portal_domains": "riverbendcu.org",
   "modules": ["dark-web-monitoring", "incident-response", "managed-services"],
   "tools": {"superops": "acc-rb", "sentinelone": "111,112", "crowdstrike": "aabbccdd",
             "huntress": "42", "acronis": "ten-rb"}}]}
```

managed-services consumes this today: it pulls the roster, upserts its own clients
keyed by the platform id (adopting any it already had by name), and fills in the
tool mapping. Activate a client and map its tools here, and managed-services picks
it up on its next pull or when a tech clicks "Pull from platform." The same
contract is how incident-response and dark-web-monitoring adopt the shared roster
next; each is a small change in that module (read the endpoint, upsert by platform
id), not a rewrite.

The overview reads the other direction: the platform calls each module's
`/api/module` for health and its items endpoint (`/api/findings`, `/api/ir-cases`)
for live counts. Every probe degrades gracefully and is cached briefly, so a module
that is down shows as unreachable and never breaks the screen.

## Run it

```bash
cp .env.example .env          # set SECRET_KEY and ADMIN_PASSWORD_HASH
docker compose up -d --build  # control plane on 127.0.0.1:8300
```

Then open Connections and give each running module its base URL and bearer token
(each module's token is on its own settings page). The control plane binds to
loopback; reach it over SSM port forwarding, or set WEB_BIND=0.0.0.0 behind the
ALB. Co-host on the platform instance as a fourth compose project (dark web 8000,
IR hub 8100, managed services 8200, control plane 8300).

The control plane is staff-only; clients never sign in here, they use each module's
own portal.

## Tests

```bash
createdb platform_test   # owned by a role platform/platform, or set PLATFORM_TEST_DATABASE_URL
python -m pytest tests -q
```

Covers registry seeding, the client directory and slugging, per-client module and
tool activation, the provisioning API contract (scoping by module, tool map only
for managed-services), the overview probe (live counts and graceful failure), tool
health refresh, and the module switch. The managed-services side of the loop is
tested in that module (tests/test_provision.py): pull, idempotency, adoption by
name, deactivation of dropped clients, and typed errors.

Verified end to end against running modules: the platform probed managed-services
and showed all five tools connected and live IR and managed-services counts on the
overview; all three built modules then pulled the roster and bound their clients to
their platform ids (managed-services with the tool mappings synced).

## Not built yet

- Push provisioning (the platform notifying a module to pull now) rather than the
  module pulling on its interval.
- Promoting the platform client id to the shared id in every module's own tables
  (managed-services stores it now; the others match by name as the IR hub does).
- Centralizing tool secrets here rather than in managed-services, if that is ever
  wanted (today secrets stay with the module, only the mapping is central).
- Per-tech RBAC beyond admin/analyst, and its own Terraform stack.
