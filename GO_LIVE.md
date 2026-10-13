# Go live: one real slice

This is the exact path from the current state (built and tested, never run against a
real tool or in AWS) to one real client flowing through one real tool, safely. It is
sequenced so nothing touches a client machine until you decide it should.

Two things only you can provide: an AWS account to deploy into, and one real tool
credential. Everything else is ready.

## The idea

Bring the first client in with tool actions turned off, prove the data pipe end to
end, then turn actions on. Managed Services has a read-only switch for exactly this:
with `ACTIONS_READONLY=true`, every write to a tool (isolate, contain, quarantine,
run backup, resolve at source) is refused and logged. You can sync a real client's
devices and alerts and watch them render with zero chance of touching a host.

Start with a low-risk tool. SuperOps (RMM alerts and tickets) or Acronis (backup
status) prove the whole pipe without any destructive action in play. Add the EDRs
(SentinelOne, CrowdStrike) after the pipe is proven, still in read-only mode, then
turn actions on last.

## 1. Deploy the stack

```bash
cd infra/terraform
terraform init
terraform apply          # one host, all four modules; ALB off, reach over SSM
```

Put the read-only deploy key and a starting safety flag in SSM before or right after
apply:

```bash
aws ssm put-parameter --type SecureString --name /vendetta/DEPLOY_KEY \
  --value "$(cat deploy_key_ed25519)"
# Start managed services in read-only so no action can fire during validation.
aws ssm put-parameter --type String --name /vendetta/managed-services/ACTIONS_READONLY \
  --value true
```

### Signing and encryption keys

Generate these once, before any real data lands, and store them where you keep your
most sensitive secrets. If a key is absent the module derives a working key from its
`SECRET_KEY` and logs a warning, which is fine for a demo but means the key cannot be
backed up or rotated on its own. Set a dedicated key for each so it can be.

```bash
# Chain-of-custody signing key for the IR hub and managed services (32 bytes hex).
# A separate value per module is fine; each signs its own chain.
aws ssm put-parameter --type SecureString --name /vendetta/incident-response/EVIDENCE_SIGNING_KEY \
  --value "$(openssl rand -hex 32)"
aws ssm put-parameter --type SecureString --name /vendetta/managed-services/EVIDENCE_SIGNING_KEY \
  --value "$(openssl rand -hex 32)"

# At-rest encryption key for the control plane (Fernet: urlsafe base64 of 32 bytes).
# The parameter basename is rendered into the module's .env verbatim, so it must be
# ENCRYPTION_KEY to match the setting the control plane reads.
aws ssm put-parameter --type SecureString --name /vendetta/platform/ENCRYPTION_KEY \
  --value "$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

Treat all three as permanent. The evidence key is what proves a case timeline or an
action log was signed by Vendetta, so changing it makes every record signed under the
old key fail verification unless you keep the old public key to verify historical
proofs. The encryption key is what decrypts the stored module tokens, so losing it
means re-entering those tokens and changing it without a re-encryption pass makes the
existing ones unreadable. Back them up before go-live, and rotate only with a plan to
retain prior evidence public keys and re-encrypt under a new encryption key.

Reboot the instance (or re-run the deploy) so it picks up the keys and renders each
`.env`. Give it a few minutes to clone, build and start.

## 2. Verify the deployment

Port-forward the control plane and run the checker:

```bash
INSTANCE=$(terraform output -raw instance_id)
aws ssm start-session --target "$INSTANCE" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8300"],"localPortNumber":["8300"]}' &
# in another shell, forward 8100/8200/8000 the same way, then:
PLATFORM=http://localhost:8300 IR=http://localhost:8100 MS=http://localhost:8200 \
DW=http://localhost:8000 PLATFORM_TOKEN=<control-plane bearer> \
bash infra/verify.sh
```

The control-plane bearer is on its Settings page. Green across the board means the
four modules are up and the provisioning loop works.

Once the modules are wired (step 3), the control plane also serves a live go-live
checklist at `Platform.vendettacyber.com/readiness` (Go-live in the sidebar). It
rolls up every module's self-reported readiness together with the control plane's
own posture into one screen:

- blocking items (red) stop a production go-live: a module that is unreachable or
  disabled, or a control plane still running the default `SECRET_KEY`;
- hardening items (amber) work today but should be set before onboarding a client:
  Microsoft 365 SSO saved but not verified, or signing/encryption keys still derived
  from `secret_key` rather than set to dedicated values (step 1).

SSO counts as verified only after its test passes, not merely when it is saved, so
the screen reflects a configuration Microsoft has actually accepted. Re-check after
any change; the probe results are cached briefly. The same report is available as
JSON at `/api/platform/readiness` for a CI gate.

## 3. Wire the module endpoints and tokens

On the control plane (`localhost:8300`), open Connections and for each module paste
its base URL (`http://localhost:8100`, `:8200`, `:8000`, and the vulnerability and
pentest modules on their own ports) and its bearer token (each module's own Settings
page). The overview should then show live health and counts. This directory is also
how the IR hub discovers its finding sources: once the finding-serving modules
(dark web, managed services, vulnerability management, penetration testing) are
connected here, the hub pulls their findings into its per-client view and /findings
page automatically, with no second list to maintain. Leave the hub's FINDINGS_SOURCES
unset to use this discovery; set it only to override.

Set each module's token to reach the control plane:

```bash
aws ssm put-parameter --type SecureString --name /vendetta/managed-services/PLATFORM_TOKEN \
  --value "<control-plane bearer>"
# same for incident-response and dark-web-monitoring when you want them pulling too
```

## 4. Wire the first tool (low risk)

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
through SSM instead if you prefer; the Integrations page then shows it as connected
from source "env" and lets you override it in place.

## 5. Bring one client through

1. Control plane, Clients: add the real client, set its portal email domains.
2. On that client, activate Managed Services and enter its tenancy for the tool you
   wired (the SuperOps accountId, or the Acronis tenant UUID).
3. Managed services, Clients: **Pull from platform**. The client appears with its
   mapping.
4. On that client, **Sync all now**. Real devices and alerts come in.
5. Confirm they render: the client page shows the tool's devices and open alerts, and
   the alert pages show the real payloads.

Nothing has touched a client machine. Read-only mode is still on.

## 6. Add an EDR, still read-only

Wire SentinelOne or CrowdStrike the same way on the Integrations page (paste
credentials, Connect and test), map the client's site IDs or child CID, sync.
Confirm threats and host state render. Still no action can fire.

## 7. Turn actions on

When you are satisfied the data is right:

```bash
aws ssm put-parameter --overwrite --type String \
  --name /vendetta/managed-services/ACTIONS_READONLY --value false
```

Redeploy managed services. Response actions are now live. Destructive ones (isolate,
contain, quarantine, kill) still require a confirmation click, and every action is
logged with who ran it and the result.

## 8. Turn on the public front (when ready)

Once DNS and the hostnames exist:

```bash
cd infra/terraform
terraform apply -var enable_alb=true -var base_domain=vendettacyber.com \
  -var hosted_zone_id=<zone> -var 'alert_emails=["soc@vendettacd.io"]'
```

This brings the control plane up at platform.vendettacyber.com (and ir., msp.,
darkweb. under the same domain). Point each module's portal domains at these hosts
and set `COOKIE_SECURE=true`.

Wire Microsoft 365 SSO in-app: on each console (and the control plane) open
Settings > SSO, enter the Entra tenant, application client ID and secret, set the
redirect URL to that host's `/auth/callback`, and click Save and verify. It stores
the config (secret encrypted) and checks it against Microsoft right then, so you
confirm sign-in works without a redeploy. The same values can be pre-seeded through
SSM instead; the SSO page then shows source "env" and lets you override in place.

## Rollback

- A bad tool integration: clear that tool's SSM params and redeploy; the client's
  other tools and all local data are untouched.
- A bad action: it is logged; the vendor console is the source of truth for undoing
  it (reconnect, lift containment, un-quarantine are all buttons in the module too).
- The whole host: daily EBS snapshots (7 kept) and the nightly Postgres dump to S3.

## What still needs doing for full production

- Live Entra SSO and the dark web Tor path have not been exercised against the real
  services yet; test them on the deployed host.
- Per-tech RBAC beyond admin/analyst/client.
- A real `terraform plan` against the target account before the first apply.
- MDR and network operations are still scaffolds (vulnerability management and
  penetration testing are now built).
- The scanner-to-API path exposes POST /api/scans with a reference adapter
  (modules/vulnerability-management/scripts), but has not run against the live Go
  scanner service yet; the first real scan is its shakeout.
