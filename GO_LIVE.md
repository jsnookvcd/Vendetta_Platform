# Go live: one real slice

This is the exact path from the current state (built and tested) to one real
client flowing through one real tool, safely. It is sequenced so nothing touches a
client machine until you decide it should.

Two things only you can provide: an AWS account to deploy into, and one real tool
credential. Everything else is generated and wired by the deployment.

## The idea

Bring the first client in with tool actions turned off, prove the data pipe end to
end, then turn actions on. Managed Services starts read-only: with
`ACTIONS_READONLY=true` (the deployed default), every write to a tool (isolate,
contain, quarantine, run backup, resolve at source) is refused and logged. You can
sync a real client's devices and alerts and watch them render with zero chance of
touching a host.

Start with a low-risk tool. SuperOps (RMM alerts and tickets) or Acronis (backup
status) prove the whole pipe without any destructive action in play. Add the EDRs
(SentinelOne, CrowdStrike) after the pipe is proven, still in read-only mode, then
turn actions on last.

## 1. Deploy the stack

```bash
cd infra/terraform
terraform init
terraform plan           # read it once against the real account before the first apply
terraform apply          # one host, every built module; ALB off, reach over SSM
```

Put the read-only deploy key in SSM before apply (the host clones the private repo
with it on first boot):

```bash
aws ssm put-parameter --type SecureString --name /vendetta/DEPLOY_KEY \
  --value "$(cat deploy_key_ed25519)"
```

That is the only parameter you set by hand before boot. Terraform generates, per
module, the session secret, the Postgres password, a dedicated service bearer
token (`API_TOKEN`), the at-rest encryption key, the evidence signing key where the
module signs a chain, and a break-glass admin password, and it wires the modules to
each other: every client module gets the control plane's URL and token, every
finding module gets the IR hub's URL and token, and the control plane gets a
directory of every module's address, token and public URL. The modules reach each
other by name on a shared docker network, never over localhost.

Back up the generated keys before any real data lands. The evidence signing key is
what proves a case timeline or an action log was signed by Vendetta; the
encryption key is what decrypts the stored tool credentials and SSO secrets.
Rotating either needs a plan (keep prior public keys to verify old proofs; re-encrypt
stored secrets under the new key), so treat them as permanent:

```bash
for m in platform incident-response managed-services dark-web-monitoring vulnerability-management penetration-testing; do
  for k in ENCRYPTION_KEY EVIDENCE_SIGNING_KEY; do
    aws ssm get-parameter --with-decryption --name /vendetta/$m/$k --query Parameter.Value --output text 2>/dev/null \
      | sed "s|^|$m $k |"
  done
done
```

Give the host a few minutes to clone, build and start. First boot fails loudly (the
instance's system log shows which module did not come up) rather than leaving an
empty host.

## 2. Sign in and verify the deployment

Each module's local admin password is in SSM. Read the control plane's once:

```bash
aws ssm get-parameter --with-decryption --query Parameter.Value --output text \
  --name /vendetta/platform/ADMIN_PASSWORD
```

Port-forward the control plane and run the checker:

```bash
INSTANCE=$(terraform output -raw instance_id)
aws ssm start-session --target "$INSTANCE" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8300"],"localPortNumber":["8300"]}' &
# forward 8100 (IR), 8200 (managed services), 8000 (dark web), 8400 (vuln), 8500 (pentest), 8600 (MARLOW) the same way, then:
PLATFORM_TOKEN=$(aws ssm get-parameter --with-decryption --query Parameter.Value --output text --name /vendetta/platform/API_TOKEN)
PLATFORM_TOKEN=$PLATFORM_TOKEN bash infra/verify.sh
```

It checks each module's health and then reads the control plane's readiness report,
which rolls up every module's self-reported state into one screen (also at
`/readiness` in the control plane, Go-live in the sidebar, and as JSON at
`/api/platform/readiness` for a CI gate):

- blocking items (red) stop a production go-live: a module unreachable or disabled,
  a placeholder secret, nobody able to sign in, or a module whose roster pull from
  the control plane is failing;
- hardening items (amber) work today but should be set before onboarding a client:
  SSO saved but not verified, escalation to the hub not wired, secure cookies off
  behind https, tool actions live.

On a fresh deployment the only amber items should be SSO, the empty staff roster (step 3) and the public URL (step 9).
Every module should show its roster pulling within five minutes of boot; the
control plane also pushes a sync to the modules the moment a client changes there.

## Updating a running host

The host clones the repo at boot and does not pull on its own, so new code on main
goes live when you redeploy. From a machine with the same AWS/SSM access used above:

```bash
# all modules
infra/redeploy.sh
# or just the ones that changed
infra/redeploy.sh managed-services platform
```

It pulls main on the instance over SSM (no SSH, no open ports), re-renders each
module's `.env` from SSM, and rebuilds the named module stacks. Any parameter you
added or changed in SSM since the last deploy reaches the containers on this step;
a reboot does not re-render. Each module runs its own schema migration at container
start, so new tables and columns apply on restart. Pass INSTANCE=i-... and
REGION=... to target a specific host, or GIT_REF=... to deploy a branch or tag.

## 3. Onboard your people

Control plane, Staff: onboard yourself first with the Administrator profile, then
everyone else with the profile that fits (Incident responder, SOC analyst,
Offensive security, Leadership). Each person signs in to every console with their
Microsoft 365 account and gets exactly the level set here; nothing is configured
per module. From the first onboarding onward, an internal account that is not on
the roster for a module cannot sign in there, and deactivating someone on the
Staff page locks them out everywhere within seconds. The admin emails configured
for SSO stay admitted to the control plane as the break-glass path.

## 4. Confirm the modules are wired

MARLOW is on the Connections page too (`http://marlow:8000`, host `marlow.`). Open
its console: the overview shows what it can see and the queue. Run a cycle. On the
Autonomy page, every default is safe for a first deployment (escalation and host
actions propose; notes, nudges, re-syncs and briefs are automatic). Leave it
there until you have watched a few days of proposals; then widen what it may do.



Open Connections on the control plane (`localhost:8300`). Every built module should
already show a base URL (`http://<module>:8000`), a token, and a last roster push.
Nothing to type here; if a row is blank, click **Apply deployment directory**.

This directory is also how the IR hub discovers its finding sources: the hub pulls
findings from every connected finding module into its per-client view and /findings
page automatically, with no second list to maintain. Leave the hub's
FINDINGS_SOURCES unset to use this discovery; set it only to override.

## 5. Wire the first tool (low risk)

Pick SuperOps or Acronis first. On managed services, open **Integrations**, find the
tool, paste its credentials, and click **Connect and test**. The credentials are
saved encrypted in the database and the tool is tested against its live API right
then, reporting what came back ("N clients visible") or a precise error. Fix and
re-save until it shows CONNECTED. This is the live shakeout for that tool, it takes
effect with no redeploy, and it touches nothing on a client machine.

Every integration works this way: one screen, enter the credential, Connect, done.
Stored credentials override anything set in the environment, and a blank secret
field on a re-save keeps the stored secret. Disconnect removes the stored credential
and falls back to the environment if one is set there.

Credentials in the environment still work as a fallback, so you can pre-seed a tool
through SSM instead (`/vendetta/managed-services/SENTINELONE_API_TOKEN` and so on,
then `infra/redeploy.sh managed-services`); the Integrations page then shows it as
connected from source "env" and lets you override it in place.

## 6. Bring one client through

1. Control plane, Clients: add the real client, set its portal email domains.
2. On that client, activate Managed Services and enter its tenancy for the tool you
   wired (the SuperOps accountId, or the Acronis tenant UUID). Each change pushes a
   sync to the module right away.
3. On the client page, click **open in Managed Services**. The client is already
   there with its mapping (if not, the module's Clients page has **Pull from
   platform**).
4. On that client, **Sync all now**. Real devices and alerts come in.
5. Confirm they render: the client page shows the tool's devices and open alerts, and
   the alert pages show the real payloads.

Nothing has touched a client machine. Read-only mode is still on.

## 7. Add an EDR, still read-only

Wire SentinelOne or CrowdStrike the same way on the Integrations page (paste
credentials, Connect and test), map the client's site IDs or child CID, sync.
Confirm threats and host state render. Still no action can fire.

## 8. Turn actions on

When you are satisfied the data is right:

```bash
aws ssm put-parameter --overwrite --type String \
  --name /vendetta/managed-services/ACTIONS_READONLY --value false
infra/redeploy.sh managed-services
```

Response actions are now live, and the readiness screen says so in amber so nobody
forgets. Destructive ones (isolate, contain, quarantine, kill) still require a
confirmation click and the two-person rule where it is turned on, and every action
is logged into the signed action chain with who ran it and the result.

## 9. Turn on the public front (when ready)

Once DNS and the hostnames exist:

```bash
cd infra/terraform
terraform apply -var enable_alb=true -var base_domain=vendettacyber.com \
  -var hosted_zone_id=<zone> -var 'alert_emails=["soc@vendettacd.io"]'
infra/redeploy.sh
```

This brings every module up under the domain (platform., ir., msp., darkweb.,
vuln. and pentest.) and, on the redeploy, switches each module to bind for the
load balancer, turns on secure cookies, and sets each module's public URL so the
control plane's client page links straight into the right client in each module
and each module links back.

Wire Microsoft 365 SSO in-app: on each console (and the control plane) open
Settings > SSO, enter the Entra tenant, application client ID and secret, set the
redirect URL to that host's `/auth/callback`, and click Save and verify. It stores
the config (secret encrypted) and checks it against Microsoft right then, so you
confirm sign-in works without a redeploy. The same values can be pre-seeded through
SSM instead; the SSO page then shows source "env" and lets you override in place.

## Rollback

- A bad tool integration: disconnect it on the Integrations page (or clear its SSM
  params and redeploy); the client's other tools and all local data are untouched.
- A bad action: it is logged; the vendor console is the source of truth for undoing
  it (reconnect, lift containment, un-quarantine are all buttons in the module too).
- The whole host: daily EBS snapshots (7 kept) and the nightly Postgres dump of every
  module to the backups bucket (`terraform output backups_bucket`, 35 days kept).
  Restore a module by piping its dump into its compose `db` service.

## What still needs doing for full production

- Live Entra SSO and the dark web Tor path have not been exercised against the real
  services yet; test them on the deployed host.
- Access levels are admin and analyst per module (plus action and approval rights
  in managed services); a read-only internal role would need every write route
  gated in every module.
- MDR and network operations are still scaffolds (every other module is built,
  containerized and deployed).
- The scanner-to-API path exposes POST /api/scans with a reference adapter
  (modules/vulnerability-management/scripts), but has not run against the live Go
  scanner service yet; the first real scan is its shakeout.
- The first `terraform plan` against the real account is the shakeout for the
  Terraform itself; CI validates it but has never applied it.
