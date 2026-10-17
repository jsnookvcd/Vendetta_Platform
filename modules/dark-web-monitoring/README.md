# Vendetta Dark Web Monitoring

Self-hosted dark web monitoring and research for managed services clients and active IR matters. One small Graviton instance in AWS, Tor for onion access, Postgres for search, S3 Object Lock for evidence, and alerts into email, Teams and the JSM IR desk.

This is the Dark Web Monitoring module of the Vendetta Platform. It runs as its own container stack and plugs into the platform's engagement hub: every hit is exposed as a platform finding with a severity, a status and evidence, and any finding can be escalated into an IR case. It also runs standalone until the hub is live. See module.yaml for the module descriptor and DEPLOY.md for the first-deploy runbook.

Internal tool. Client deliverables attribute findings to the Vendetta Platform; this repo name and the console branding do not appear in client-facing material.

## What it does

Collection
- Ransomware leak sites: the ransomware.live PRO victim feed, plus a direct Tor crawl of each tracked group's leak-site mirrors. The feed needs the free PRO key from my.ransomware.live in RANSOMWARE_LIVE_API_KEY; without it the connector reports "not configured" and never calls the public v2 tier. Onion sources are seeded daily from ransomware.live PRO group locations, which carry availability. A source is disabled, with the reason recorded, when its group has had no feed activity for 180 days or after 10 failed crawls in a row, and a person can re-enable it on the Sources page. The crawl visits priority groups first on every run and the rest by recent group activity, and stops at ONION_CRAWL_BUDGET_MINUTES (45) of wall-clock time as well as at its count cap. Without a profile a mirror is diffed at the index level and a new victim name is matched as a change. With a profile the crawler reads each victim entry and follows the victim's own post over Tor. ransomwatch stopped updating in mid-2025: it is never scheduled, its source is marked archived, and an admin can import its roughly 16,000 historical victims once with Backfill on the Connectors page, which is what makes client backfill useful on day one.
- Forums and markets: a forum source crawls board sections, thread lists and messages using a profile of kind forum. For boards your team already has an account on, store a session cookie on the source and it is sent read-only with every request. Nothing logs in, posts, replies, registers or purchases. This is read-only collection.
- Initial access brokers: brokers sell network access without naming the victim, advertising a profile instead (sector, country, revenue, host count, access type). The tool matches each client's business profile against forum and leak-site text and raises an IAB candidate for an analyst to confirm. Industry must match and at least one of country, state, revenue band or size band must corroborate, and the post must carry an access-for-sale signal, so sector chatter alone does not fire.
- Have I Been Pwned: breached accounts by domain (Core plan), infostealer logs by email domain and infostealer logs showing logins to the client's own sites (Pro plan). Requires a verified domain per client.
- Certificate Transparency: new certificates for client domains and subdomains, plus a lookalike sweep (homoglyphs, prefixes like secure- and login-, TLD swaps, inserted hyphens) for phishing infrastructure.
- Paste sites: psbdmp index of Pastebin dumps searched per watch term.
- Telegram: public channels, optional, via Telethon.
- Research console: fetch any URL (onion or clearnet) through the collector's Tor circuit and preserve the response.

Matching
- Watch terms per client: domain, email domain, brand, keyword, person, IP CIDR, regex. Severity per term.
- Victim and post items naming a client, and infostealer hits, are forced to at least high.
- A domain or email-domain term matching inside credential-bearing content is flagged as a credential exposure rather than a plain mention.
- Client business profile (industry, country, state, revenue band, employee/host band) drives IAB matching.
- Backfill button re-matches a new client's terms and profile against everything already collected. On a new IR engagement this answers "were they listed last month, and was access to them ever advertised" in seconds.

Alerting
- SNS topic (email, SMS) for everything at or above the threshold.
- Teams incoming webhook with an Adaptive Card.
- Jira Service Management is off by default and only activates if JIRA_BASE_URL is set. The code is in place for when the IR desk goes live; leave it blank until then.
- Alerts name the reason: a watch-term hit, a credential exposure, or an IAB candidate.

Credential handling
- Item kinds that carry secrets (paste, stealer, credential, forum message) are redacted at ingest. The database stores the affected email, username, domain, source and date, with passwords, hashes and keys masked. You can tell a client which accounts and which sites are exposed without the tool becoming a store of working credentials.
- When a specific matter needs the full record, the research console or the Preserve action re-fetches the source and writes the raw bytes to the Object Lock bucket with a hash and manifest, access-controlled and audit-logged.

Evidence
- Aggregator hit, then direct capture. The aggregator tells us where to look; the direct capture is the record. A hit on a victim, page or paste item queues a capture instead of fetching inline, so a feed job never waits on Tor. The worker drains the queue every CAPTURE_INTERVAL minutes (5) over Tor. The target is the original leak post when the feed gives one (post_url or claim_url), otherwise the group's current onion index from its enabled sources, best known first. A post URL is also tried on the group's other mirrors and then on its index pages. A capture is retried up to 4 times over 24 hours (waits of 1, 5 and 18 hours) and then marked unavailable. A captured page is preserved through the evidence path (raw bytes, SHA-256, timestamp, headers and a JSON manifest to S3) for the hit's client and item. An index page captured without the victim's name in its text is recorded as captured_index_no_match. The hit page shows the capture status, links the evidence and has a Capture now button for admins and analysts; the Connectors page shows queue depth and the 7 day success rate.
- Bucket has versioning and Object Lock with a default retention, so captures cannot be modified or deleted during the retention window. Governance mode by default; switch to Compliance for production.
- Verify endpoint re-hashes stored bytes against the recorded hash.
- Audit log of every analyst action.

Client deliverable
- Per-client exposure report, the thing you hand a client or counsel. Branded PDF with the Vendetta emblem on the cover, an executive summary with the severity breakdown, findings grouped by credential exposure, initial access broker activity, leak-site activity, mentions and infrastructure, recommended actions driven by what was found, and an evidence appendix with SHA-256 hashes. Issued under the Office of Special Projects line, prepared-by Jordan Snook, Founder and CEO. Download at /clients/{id}/report.pdf?days=30, preview the HTML at /clients/{id}/report. Rendered server-side with WeasyPrint, which needs the pango/cairo libraries already in the Dockerfile.

API
- GET /api/hits, GET /api/victims, GET /api/findings, GET /api/module, POST /api/clients/{id}/terms. Bearer token on the settings page. Built so the Vendetta Platform or a Jira automation can pull from it.

Sign-in
- Microsoft 365 / Entra ID single sign-on (OIDC). When configured, the team signs in with their 365 accounts, access is restricted to your tenant and optionally a security group or email allowlist, and each session and audit entry is tied to the real user. A users table records who has signed in, with a role field for later RBAC. The local admin account stays as a break-glass path behind an "Admin sign in" disclosure on the login page. SSO is off until ENTRA_CLIENT_ID and ENTRA_TENANT_ID are set, in which case the console runs on the shared admin login only.
- Entra app registration: register a Web app, set the redirect URI to https://<host>/auth/callback, create a client secret, grant Microsoft Graph delegated openid, profile and email, and if you want ENTRA_ALLOWED_GROUP, add a groups claim to the token configuration. Put ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET and ENTRA_REDIRECT_URL in SSM. SSO needs the console on a real HTTPS hostname for the redirect, so set COOKIE_SECURE true at the same time.

Hardening
- Security headers on every response (CSP, X-Frame-Options DENY, nosniff, no-referrer). In-memory login throttle per IP. Session cookie carries the secure flag when COOKIE_SECURE is set for TLS. Access is still expected to be behind SSM port forwarding or a VPN; these are layers, not the only control.

## Platform roster

When PLATFORM_URL is set, the module pulls its client roster from the Vendetta Platform control plane ("Pull from platform" on the Clients page); clients are activated there. The pull sets only the platform-owned fields (name, portal domains) and never touches watch terms, the IAB business profile or case_ref, so onboarding and tuning survive. Escalations carry the shared platform_client_id so the IR hub lines the client up across modules.

## Monthly cost, us-east-1, on-demand

EC2 t4g.small: about 12.26
EBS 30 GB gp3: about 2.40
S3 evidence and backups, first year, typical: under 1.00
SNS email: nil at this volume
CloudWatch logs, few hundred MB: under 1.00
Data transfer: under 1.00
Total: roughly 17 per month

A one-year Compute Savings Plan on the instance brings it to about 11 per month. t4g.micro drops the instance to about 6 per month and works for a small client count if Postgres shared_buffers is lowered to 64MB in docker-compose.yml.

HIBP is the only paid data source. The ransomware.live PRO key, the ransomwatch archive, crt.sh and psbdmp are free.

## Victim-source resilience

Live victim data comes from one aggregator, ransomware.live, so its outage, a key revocation or a schema change stops new victim items. The Connectors page flags the feed stale after 7 days without a newly published victim, and the direct crawl of priority groups keeps producing page and post items while it is down. A second victim source is worth adding for resilience, for example a commercial ransomware victim feed or profiled direct crawls of the most active groups written from the Priority Groups page. This plan does not build one.

HIBP tiers as of October 2026, paid annually:
Core 1, one verified domain: 4.39 per month
Core 2, three domains: 21.59 per month
Core 3, five domains: 36.99 per month
Core 4, ten domains: 159 per month
Pro 1, fifty domains plus infostealer logs: 379 per month

Core tiers return breached accounts by domain only. Infostealer logs by domain require Pro 1 or higher. The collector detects a 401 or 403 on the stealer endpoints and skips them, so a Core plan works fine for breach data while the Pro decision waits on client count. At roughly 20 monitored domains, Pro 1 is 7.58 per client per month and is the single most valuable feed in this stack for a managed services client, since a stealer log on a corporate email is usually a live session on an infected endpoint.

## Deploy

The full runbook is in DEPLOY.md. In short: create a read-only deploy key for the private repo and store it in SSM, `terraform apply` from `infra/terraform` (repo and subdirectory default to this module), put the remaining secrets in SSM, then open the console over an SSM port-forward. The instance clones the repo on boot and runs the stack from this module directory; `/opt/darkweb` on the instance is a symlink to it. No ports are exposed; everyone on the delivery team connects through their own SSM session, so IAM is the access control. To redeploy after a change, `sudo bash /opt/darkweb/scripts/deploy.sh` on the instance.

## Onboarding a client

Managed services: add the client, kind managed, contract ref. Add the primary domain (kind domain, high), email domain, brand name, and the names of the CEO, CFO and controller (kind person, medium). For a bank or credit union add routing-number-adjacent terms sparingly; they generate noise.

Fill in the business profile (industry, country, state, revenue band, employee or host band). This is what IAB matching uses. For a credit union, industry "credit union" plus state and a revenue band is enough to catch most broker ads that would describe it.

IR matter: add the client with kind ir and the case number. Add the same terms and the profile, then click Backfill. The hits page shows any prior leak-site listing, breach record, infostealer log or access-for-sale ad in the last year. Preserve evidence on anything relevant before the group's mirror goes down.

Priority groups: the Priority Groups page (/priority-groups) ranks the groups that get direct, profiled crawls. The computed list is the top 25 groups by ransomware.live victims published in the last 90 days, with victims whose sector matches an active client's industry counting double and those matching a client's country counting half again. The worker refreshes it daily. Admins can pin a group (always priority) or exclude one (never priority), and pins survive every refresh. Each group shows its profile state: none, draft (saved, not yet used successfully), working (the last crawl extracted entries) or broken (it extracted entries before and extracts none now). A broken profile is raised on the Connectors page and the dashboard.

Writing a leak-site profile: open the group's Profile from the Priority Groups page. The editor previews CSS selectors against the newest stored index page for the group (the crawl keeps the raw HTML of each changed index page) and lists the victims they would extract, with no network request. Save stores the profile in the database and points the group's onion sources at it. Selectors are plain CSS and multiple comma-separated selectors are tried in order, so a profile tolerates small layout changes. YAML profiles in app/profiles still load as a fallback when no database profile has the source's profile name; forum profiles are YAML only. A source with no profile still works; the profile only adds per-post structure.

Verify the client's domain in HIBP (DNS TXT record or email) so the breached-domain and stealer-log queries return data.

## Operations

Logs: `docker compose logs -f worker` on the instance, or CloudWatch group /darkweb/containers.
Collector health: Connectors page (/connectors). It lists every connector the worker schedules with whether it is configured (and the reason when it is not), its last run, last success, items collected in the last 24 hours and 7 days, the newest published date of its items and its last error. A live feed whose newest published item is older than 7 days is flagged stale. The worker heartbeat age and the latest Tor check sit at the top. Admins and analysts can press Run now, which queues the connector for the worker; the worker polls the queue every minute and the web container never runs a collector itself. The dashboard shows a red banner when the worker heartbeat is older than 5 minutes or Tor is not exiting through Tor, and an amber banner when a configured connector failed its last run or is stale. The same health is reported to the control plane readiness screen.
Diagnose: inside the worker container, `python -m app.diagnose` prints the heartbeat, the Tor status, the Connectors table and a live probe of each upstream (HTTP status and byte count only; keys and cookies are never printed). Add `--no-probe` to read the database only. It exits 1 when the worker or Tor is down or a configured connector failed.
Run history: every collector run is a row in collector_runs (job, start, finish, ok, new items, new hits, error) kept for 30 days. The worker also writes worker_state (heartbeat every minute, Tor check every 10 minutes).
Source health: Sources page. Leak sites go down constantly; a mirror with ten failures and a last OK of three weeks ago is normal and will be retried.
Backups: nightly pg_dump to the evidence bucket under backups/, plus daily EBS snapshots with seven retained.
Updates: `git pull` then `scripts/deploy.sh`.
Tor exit check: the Connectors page shows the worker's latest check; /research/torcheck runs one from the web container.

## Operational security

- All onion traffic leaves through Tor. Clearnet collection (feeds, HIBP, crt.sh) leaves from the instance's AWS IP. If you do not want a leak site operator to see an AWS address during research, tick "route clearnet through Tor".
- The crawler reads index pages only. It does not download leaked archives. Pulling victim data from a leak site is a decision for the case lead and counsel, not an automated process, and should be done from an isolated analysis VM.
- Nothing is posted, registered, or interacted with. Read only.
- Telegram requires a real account. Use a dedicated number and device, not a personal one.
- Treat the instance as holding client PII once HIBP data flows in. IAM access to it and to the bucket should match the IR desk's access list.

## Project layout

```
app/
  main.py          console and API
  worker.py        scheduler, built from the connector registry; heartbeat, Tor check, Run now queue
  connectors.py    connector registry: every collector, its interval, configured() check and status
  health.py        worker heartbeat, Tor status and run retention
  work_requests.py worker-polled request tables (run_requests now, reusable for later queues)
  diagnose.py      python -m app.diagnose
  collectors/      leak_feeds, onion_crawl, forum_crawl, hibp, ct_logs, pastes, telegram
  profiles/        per-site YAML selector profiles (leak and forum), with examples
  matcher.py       watch term matching
  iab.py           initial access broker matching against client profiles
  redact.py        credential masking at ingest
  report.py        per-client exposure report aggregation
  profiles.py      profile loader
  alerts.py        SNS, Teams, Jira (Jira off unless configured)
  evidence.py      S3 captures with hashes
  pipeline.py      ingest -> redact -> dedupe -> match + IAB -> alert -> queue capture
  ransomware_live.py  PRO API client (verified paths, auth header, fair use) with fixtures in tests/fixtures
  onion_sources.py seeding from PRO group locations, disable rules, crawl order, ransomwatch migration
  captures.py      direct capture queue drained by the worker over Tor
  priority.py      priority group ranking, pins and exclusions
  profile_store.py database parser profiles, preview extraction, broken-profile detection
  db.py            models
infra/terraform/   EC2, S3 Object Lock, SNS, IAM, SSM, DLM
scripts/           deploy, render_env, backup, password hash, telegram login
tests/
```

## Local development

```
cp .env.example .env   # set ADMIN_PASSWORD_HASH and SECRET_KEY
docker compose up --build
```
Console at http://localhost:8000. With RANSOMWARE_LIVE_API_KEY set, the worker seeds onion sources from ransomware.live PRO group locations on first start and runs the victim feed immediately; the first Tor sweep starts after ONION_CRAWL_INTERVAL. At start it also runs a one-time migration that disables onion mirrors seeded from the ransomwatch archive (meta.seeded_from "ransomwatch"), recording the reason and never deleting a row.

## Roadmap

- Entra ID OIDC login when the console moves behind an ALB.
- Screenshot capture (headless Chromium over Tor) alongside text captures.
- Per-client weekly PDF exposure summary for managed services reporting.
- Forum and market sources beyond leak sites, each added as an onion source with a parser.
- Platform integration: hits as a module in the Vendetta Platform, evidence manifests linked to case records.
