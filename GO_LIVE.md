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
for m in platform incident-response managed-services dark-web-monitoring vulnerability-management penetration-testing sabine professional-services mdr project-management; do
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
# forward 8100 (IR), 8200 (managed services), 8000 (dark web), 8400 (vuln), 8500 (pentest), 8600 (SABINE), 8700 (OSP), 8800 (MDR) the same way, then:
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
Offensive security, vCISO / advisory, Leadership). Each person signs in to every console with their
Microsoft 365 account and gets exactly the level set here; nothing is configured
per module. Levels per module are none, viewer, analyst and admin. A viewer reads
every page and API and cannot change anything; Leadership is viewer everywhere and
analyst in SABINE. From the first onboarding onward, an internal account that is not on
the roster for a module cannot sign in there, and deactivating someone on the
Staff page locks them out everywhere within seconds. The admin emails configured
for SSO stay admitted to the control plane as the break-glass path.

Each onboarding sends the person a welcome note from SABINE with the console links
they were granted. To deliver it, add `<prefix>/platform/SMTP_HOST`, `SMTP_PORT`,
`SMTP_USER`, `SMTP_PASSWORD` (SecureString) and `SMTP_FROM` to SSM and redeploy;
until then the note is written to the control plane's log and onboarding proceeds.
The attempt is recorded as staff.invite in the platform audit log either way.

## 4. Confirm the modules are wired

SABINE is on the Connections page too (`http://sabine:8000`, host `sabine.`). Open
its console: the overview shows what it can see and the queue. Run a cycle. On the
Autonomy page, every default is safe for a first deployment (escalation and host
actions propose; notes, nudges, re-syncs and briefs are automatic). Leave it
there until you have watched a few days of proposals; then widen what it may do.

For the SOC wall display, read `/vendetta/sabine/KIOSK_TOKEN` from SSM and open
`https://sabine.<domain>/board?k=<token>` once on that screen; it keeps a cookie
and refreshes itself, and nothing on it can approve anything.

SABINE's voice is Azure's Jane (Dragon HD), set by Terraform as
`TTS_PROVIDER=azure` and `AZURE_SPEECH_VOICE=en-US-Jane:DragonHDLatestNeural`.
To turn it on: create an Azure AI Speech resource in East US (Dragon HD voices
are served from a short list of regions; East US is one), then put its key at
`/vendetta/sabine/AZURE_SPEECH_KEY` (SecureString) and `eastus` at
`/vendetta/sabine/AZURE_SPEECH_REGION`, and run `infra/redeploy.sh sabine`.
Until the key is there she speaks through the browser. ElevenLabs stays
available by setting `TTS_PROVIDER=elevenlabs` with its key and voice id.



Open Connections on the control plane (`localhost:8300`). Every built module should
already show a base URL (`http://<module>:8000`), a token, and a last roster push.
Nothing to type here; if a row is blank, click **Apply deployment directory**.

The Office of Special Projects (`http://professional-services:8000`, host `osp.`,
port 8700) is on the list as a client module: it pulls the client and staff
rosters, takes the roster push, and the client page links into it. It serves
engagements rather than findings, so the hub does not list it as a finding source;
it escalates into the hub from an engagement instead, and SABINE reads its open
engagements to queue deliverables awaiting client acceptance and engagements past
their planned end.

Managed Detection and Response (`http://mdr:8000`, host `mdr.`, port 8800) is a
finding module. Terraform hands it the managed-services URL and token, so it reads
managed-services alerts as signals on its own schedule; open its Overview and click
**Run detection** to see it work once managed services has alerts. Its Rules page
holds the seeded detections, each mapped to MITRE ATT&CK; read them before the first
client, switch off any that do not fit, and set per-client overrides there. It never
acts on a host: a containment hand-off links the responder to the managed-services
alert page, where the two-person rule still applies.

Project Management (`http://project-management:8000`, host `pm.`, port 8900) is
the PM tool for the IR and ProServ practices: the two practice Kanban boards, each
engagement's task board, meeting notes mirrored to SharePoint, and Harvest time. It
pulls the whole client directory (not only clients with the module switched on) and
its own staff roster, so grant it on the Staff page to the PMs and responders who
should use it. Three things to finish before the first PM uses it:

1. Integrations page (`pm.<domain>/settings/integrations`): the Harvest account ID
   and an administrator's personal access token, then **Save and test**.
2. On the same page, the default SharePoint delivery site. The Entra app needs the
   Microsoft Graph application permission Sites.Selected, granted write on that
   site and on each IR case site the provisioning flow creates (or
   Sites.ReadWrite.All). A note whose copy fails is kept and retried every ten
   minutes.
3. The ALB must be on, because the Claude connector reaches `https://pm.<domain>/mcp`
   and its OAuth metadata is built from PUBLIC_URL. Each PM then follows the
   **Connect Claude** page. If `alb_allowed_cidrs` is restricted to office ranges,
   the pm. host must also accept Claude's outbound addresses, or the connector
   cannot reach it.
4. Optional alert delivery, added by hand under `/vendetta/project-management/`:
   `ALERT_TEAMS_WEBHOOK_URL` (new high-severity alerts) and `ALERT_MAIL_FROM` (the
   morning digest; the Entra app then needs the Mail.Send application permission,
   ideally limited to that mailbox with an application access policy). SABINE queues
   the alerts either way.

Terraform also gives Project Management the hub URL and token and the Office of
Special Projects URL and token, so milestones on an engagement whose platform reference
names an IR case or an OSP engagement show in that client portal.

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

6. Back on the control plane client page, set the **service tier** (core, advanced,
   premier) and the **account lead**. The tier sets the response commitments the
   client sees on their portal (critical acknowledged in 15, 10 or 5 minutes) and
   that SABINE pages against; override either number per client if the contract says
   otherwise. The account lead is the person who approves what SABINE drafts for this
   client.
7. Turn on MDR for the client and run detection once. The Client 360 panel on the
   client page now shows everything the platform knows about them: findings by
   module, MDR investigations, open IR cases, open engagements, the Security Journey
   and any communications waiting.

Nothing has touched a client machine. Read-only mode is still on.

### What SABINE drafts for the client, and who sends it

SABINE never sends anything to a client. Monthly posture reviews and proactive
outreach (a campaign that touched them, a deliverable waiting, a commitment at risk)
arrive as drafts on the control plane under **Communications**. The account lead or
a platform admin reads, edits and approves; approval publishes it to the client
portal and emails it to the client's executive list when SMTP is configured. Items
SABINE suggests for the client's Security Journey arrive as proposed; a person
accepts or declines each one, and only accepted items appear on the portal.

### The client portal front door

The control plane now has a client portal at `https://platform.<domain>/portal`:
the client signs in with their own Microsoft 365 account, mapped to their client by
email domain, and sees their tier and commitments, a tile into every service line
they have, their Security Journey and the communications you approved. Sign-in runs
against Vendetta's own Entra tenant, the same as every module portal, so a client
user signs in as a B2B guest in that tenant: invite each client user (Entra >
Users > Invite external user) before they first open a portal. A self-service
multi-tenant sign-in would need the authority switched to `organizations` with
issuer validation per client tenant, which is not built yet.

### Business sources for SABINE (optional)

With Harvest and HubSpot connected, SABINE also watches engagement budget burn,
people over capacity, renewals coming up and closed-won deals not yet onboarded.
Put `/vendetta/sabine/HARVEST_ACCOUNT_ID`, `/vendetta/sabine/HARVEST_TOKEN` and
`/vendetta/sabine/HUBSPOT_TOKEN` in SSM (SecureString) and run
`infra/redeploy.sh sabine`. Without them the Business tab says not configured and
nothing else changes.

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
vuln., pentest., sabine., osp., mdr. and pm.) and, on the redeploy, switches each module to bind for the
load balancer, turns on secure cookies, and sets each module's public URL so the
control plane's client page links straight into the right client in each module
and each module links back.

Wire Microsoft 365 SSO in-app: on each console (and the control plane) open
Settings > SSO, enter the Entra tenant, application client ID and secret, set the
redirect URL to that host's `/auth/callback`, and click Save and verify. It stores
the config (secret encrypted) and checks it against Microsoft right then, so you
confirm sign-in works without a redeploy. The same values can be pre-seeded through
SSM instead; the SSO page then shows source "env" and lets you override in place.

## Live verification

Two paths have never been exercised against the real services: Microsoft 365 sign-in
and the dark web module's Tor path. These checks follow what the code does
(modules/*/app/sso.py and oidc.py, modules/dark-web-monitoring/app/fetch.py and
worker.py); each says what to look at and what success looks like.

### Entra SSO

One Entra app registration serves every console; each module host is one more
redirect URI on it.

1. App registration (Entra admin center > App registrations). Record three values:
   the Directory (tenant) ID, the Application (client) ID, and a client secret
   value (Certificates and secrets; copy the value, not the secret ID). Under API
   permissions grant Microsoft Graph delegated `openid`, `profile` and `email`. The
   platform type is Web, with the confidential code flow; no implicit grant. If you
   will restrict sign-in to a security group, add a groups claim under Token
   configuration so group object IDs appear in the id_token.
2. Redirect URIs (Authentication > Web). Add `https://<host>/auth/callback` for
   every module host, one per line, exactly:
   `platform.<domain>`, `ir.<domain>`, `msp.<domain>`, `darkweb.<domain>`,
   `vuln.<domain>`, `pentest.<domain>`, `sabine.<domain>`, `osp.<domain>`, `mdr.<domain>` and `pm.<domain>`. Each
   module sends its own Redirect URL setting when set, and otherwise the URL it
   computes for its `/auth/callback` route from the request host; behind the ALB
   that is the public hostname, so leaving the setting blank works once the public
   URL is on. A mismatch is the most common first-run failure and Microsoft reports
   it on its own page as `AADSTS50011`.
3. Enter the values on each console. Open Settings > SSO on the control plane and
   on every module. Fill Tenant ID, Application (client) ID and Client secret, set
   Redirect URL to that host's `/auth/callback` (or leave it blank behind the ALB),
   fill Internal email domains (`vendettacd.io`) and Admin emails (the first admin,
   as the bootstrap path into the control plane), tick SSO enabled, and click
   **Save and verify**. The same values can be pre-seeded as
   `<prefix>/<module>/ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` and `ENTRA_CLIENT_SECRET`
   in SSM; the page then shows source "env" and still lets you override in place.
4. What the verify button does. Save and verify (and Verify again) does two live
   calls from the container: it fetches
   `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration`
   and then posts a client-credentials token request to the token endpoint that
   document names, with scope `https://graph.microsoft.com/.default`. Success is the
   page banner "Microsoft 365 SSO verified. tenant reachable and client credentials
   valid" and the pills ENABLED and VERIFIED, with the last test time. The result is
   stored and the readiness screen's "SSO verified" check turns green only on a
   passed test; a saved but untested config stays amber. Failures name the step:
   "tenant discovery failed (http 400); check the tenant ID", "client credentials
   rejected: AADSTS7000215 ..." (the secret is wrong or expired), or "unreachable:
   ConnectError" (the host cannot reach login.microsoftonline.com; check egress).
   The client-credentials request needs no Graph application permission; the token
   it gets is discarded.
5. The browser round trip. Open the console's `/login`; with SSO enabled it shows a
   "Sign in with Microsoft 365" button. Click it: `/auth/login` redirects to
   Microsoft, you sign in, Microsoft returns to `/auth/callback`, and you land on
   the console's home page. Two outcomes short of that are explained by the
   login page: `/login?sso=failed` means the code exchange with Microsoft failed
   (check the redirect URI and the secret), and `/login?sso=denied` means Microsoft
   signed you in but the console refused the account. The denial rule is in
   oidc.py: once anyone is on the platform staff roster, the roster decides per
   module (a person not granted that module is denied, however their domain
   reads); before that, the account must be in Internal email domains, Extra
   allowed emails or the allowed group. On the control plane an address in Admin
   emails is admitted either way. A successful sign-in writes a `login.sso` row in
   that module's audit_log table with the role granted:

   ```bash
   cd /opt/vendetta_platform/modules/platform
   docker compose -p vcd-platform exec db psql -U platform -c \
     "select at, actor, detail from audit_log where action='login.sso' order by at desc limit 5"
   ```

6. Do it on every host. Repeat step 5 on each module console; the roster pull
   means the same person gets the level set on the Staff page everywhere, and the
   control plane's readiness screen shows "SSO verified" per module.

### Dark web module: the Tor path

The dark web stack runs its own Tor client container (service `tor`, built from
modules/dark-web-monitoring/infra/tor, SOCKS on 9050, client only, no relay). The
web and worker containers reach it as `TOR_PROXY=socks5://tor:9050`. Anything
ending in `.onion` goes through Tor; clearnet goes direct unless "Route clearnet
through Tor" is ticked. The readiness screen does not test Tor; it reports the
dark web module's collection sources count under integrations. Tor is verified
on the host and in the module as follows.

1. The Tor container is healthy. Its healthcheck is a TCP connect to 9050 with a
   90 second start period:

   ```bash
   cd /opt/vendetta_platform/modules/dark-web-monitoring
   docker compose -p vcd-dark-web-monitoring ps        # tor should read "healthy"
   docker compose -p vcd-dark-web-monitoring logs tor | grep -i "bootstrapped"
   ```

   Success is a `Bootstrapped 100% (done): Done` line. The worker container
   depends on `tor` being healthy and will not start before it.
2. The worker saw Tor. At start the worker polls the exit check up to twenty times,
   fifteen seconds apart, before scheduling any crawl:

   ```bash
   docker compose -p vcd-dark-web-monitoring logs worker | grep -i "tor"
   ```

   Success is `tor ok, exit ip <address>`; repeated `waiting for tor: {...}` lines
   with an error mean the proxy is up but circuits are not built yet, or egress to
   the Tor network is blocked.
3. The exit check from the console. Signed in to the dark web console, open
   `/research/torcheck` (linked from the Research page). It fetches
   `https://check.torproject.org/api/ip` through the proxy and returns Tor's own
   answer. Success is `{"IsTor": true, "IP": "<exit address>"}`. `{"IsTor": false,
   "error": "..."}` means the fetch through the proxy failed (the error names why);
   `IsTor: false` with an IP means the request did not go through Tor, which
   should not happen with the proxy set.
4. A .onion fetch. On the Research page paste a known onion URL (one of the seeded
   ransomware leak-site sources on the Sources page has one) and click Fetch. The
   page is read only: it fetches and renders visible text, nothing is posted. The
   result panel shows Status, Final URL and Bytes. Success is Status `200 OK` with
   a non-zero byte count and visible text below it. A failed fetch shows the status
   or `failed` with the exception text; `.onion` requests are given a 60 second
   connect and 90 second read window, so a slow site can take a minute to answer.
   Ticking Preserve writes the capture to the evidence store and shows its SHA-256
   with a download link; `/evidence/<id>/verify` confirms the stored bytes still
   match. Every fetch is a `research.fetch` row in the module's audit log.
5. The crawler fetches on its own. The onion crawl runs every
   ONION_CRAWL_INTERVAL minutes (120 by default) over the enabled onion sources.
   On the Sources page a source that fetched shows a "last ok" time and a fail
   count of 0; a failing one shows the fail count climbing and the last error text.
   The first crawl runs one interval after the worker starts, so either wait for it
   or confirm a single source by fetching its URL on the Research page as in step 4.

### Dark web module: optional connectors

The ransomware victim feed needs one key, and the module does nothing useful
without it. Get a free PRO key at my.ransomware.live, put it in SSM as
`/vendetta/dark-web-monitoring/RANSOMWARE_LIVE_API_KEY` (SecureString) and run
`infra/redeploy.sh dark-web-monitoring`. The feed then seeds the onion crawl list
from current group locations, ranks the priority groups, and queues a direct Tor
capture of the original leak post whenever a victim matches a client. On first
deploy after this change the 451 mirrors seeded from the archived ransomwatch list
are disabled automatically (kept, with the reason shown on Sources).

After the redeploy, check the module's Connectors page: Tor exiting through Tor,
a fresh worker heartbeat, and ransomware.live with a recent last success and
victims dated this week. `python -m app.diagnose` in the worker container prints
the same picture plus a probe of each upstream.

Each optional connector stays off until its settings exist, and the Connectors page
shows why. Put the values in SSM under `/vendetta/dark-web-monitoring/` and run
`infra/redeploy.sh dark-web-monitoring`:

- `HIBP_API_KEY` (SecureString) turns on Have I Been Pwned breach and stealer log
  queries; without it the page reads "needs HIBP_API_KEY".
- `TELEGRAM_API_ID`, `TELEGRAM_API_HASH` (SecureString) and `TELEGRAM_CHANNELS`
  enable Telegram; it also needs the one-time login in the module's DEPLOY.md
  ("Telegram login") to create the session file.
- `PASTES_ENABLED` stays `false` until psbdmp has been probed from the host with
  `python -m app.diagnose` in the worker (see the module README, "Optional
  connectors").
- `TOR_SEARCH_ENGINES` (String, optional) is a JSON list merged over the default
  live Tor search engines (Ahmia, OnionLand, Tor66) by key, for example
  `[{"key": "tor66", "enabled": false}]`. Leave it unset unless an engine is down or
  has moved; the module README ("Live Tor search engines") lists the fields.

Provisioned clients get starter watch terms from their name and portal domains,
and the readiness screen shows a "Watch terms" warning while any active dark web
client has no enabled terms.

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
  services yet; the Live verification section above is the runbook for the first
  time on the deployed host.
- Network operations is still a scaffold (every other module is built and
  containerized). MDR is built and wired but has only seen inserted test alerts; the
  first real SentinelOne, CrowdStrike, Entra and GuardDuty alerts through managed
  services are its shakeout, and the seeded rules will need tuning against them.
- Client portal sign-in relies on B2B guest invitations into Vendetta's tenant for
  every portal (control plane and modules); multi-tenant self-service sign-in is
  not built.
- Harvest and HubSpot connectors follow the published APIs and are tested against
  mocks only. Projects and companies match platform clients by name.
- The scanner-to-API path exposes POST /api/scans with a reference adapter
  (modules/vulnerability-management/scripts), but has not run against the live Go
  scanner service yet; the first real scan is its shakeout.
- The first `terraform plan` against the real account is the shakeout for the
  Terraform itself; CI validates it but has never applied it.
  infra/terraform/PLAN.md says how to run it and what a clean plan shows.
