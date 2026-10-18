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
- Paste sites: a paste index searched per watch term. Off by default (PASTES_ENABLED=false) because psbdmp.ws, the only free index wired in, could not be verified as working; see "Optional connectors" below.
- Telegram: public channels, optional, via Telethon (in requirements.txt). Needs TELEGRAM_* settings and a one-time login; see DEPLOY.md.
- Research console: fetch any URL (onion or clearnet) through the collector's Tor circuit and preserve the response.
- Live Tor search (/search/live): an analyst types a query, picks engines and the worker sends it to each onion search engine over Tor. The page polls the request every few seconds; searches usually take 20 to 90 seconds. Results are merged and de-duplicated by onion host and path and show which engines returned each. Every result is plain text: no HTML from a result page is rendered or executed, and only http(s) URLs are kept. "Open in research console" prefills /research with the URL and marks it so it is fetched over Tor even when it is clearnet, and the analyst can preserve it as evidence through the existing path. "Add as source" (admin and analyst) registers an onion result as a Source to profile later. Starting a search queues Tor work, so viewers cannot start one (403) and cannot add sources. A search is shown only to the user who requested it and to admins; saved search runs are client work and are visible to all staff from the client page. Every search is written to the audit log with who searched what. Search collected data (/search) remains the full text search over the module's own database.
- Saved Tor searches: on a client page an admin or analyst saves a query with an interval (6 hours to a week). The tor_search connector checks for due saved searches every SAVED_SEARCH_INTERVAL minutes (15), runs them through the same search_requests path and ingests new results as kind search items through pipeline.ingest, so watch-term matching, alerting and capture apply. A result already collected (same onion host and path) is never stored or alerted twice.

Matching
- Watch terms per client: domain, email domain, brand, keyword, person, IP CIDR, regex. Severity per term.
- Victim and post items naming a client, and infostealer hits, are forced to at least high.
- A domain or email-domain term matching inside credential-bearing content is flagged as a credential exposure rather than a plain mention.
- Client business profile (industry, country, state, revenue band, employee/host band) drives IAB matching.
- Starter watch terms: a client provisioned from the control plane gets its portal domains as domain and email_domain terms and its name as a brand term, plus a variant with legal suffixes stripped. These are marked auto on the client page.
- Backfill re-matches a client's terms against items collected in the last 365 days. It is queued automatically whenever terms are added (by provisioning, on the client page or through the terms API) and runs in the worker within a minute; the Backfill button queues a full pass including the business profile. The client page shows the last result. On a new IR engagement this answers "were they listed last month, and was access to them ever advertised" without manual setup.

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

When PLATFORM_URL is set, the module pulls its client roster from the Vendetta Platform control plane ("Pull from platform" on the Clients page); clients are activated there. The pull sets the platform-owned fields (name, portal domains) and leaves the IAB business profile and case_ref alone, so onboarding and tuning survive.

Each pull also adds starter watch terms for every client it creates or updates, when missing (app/watchterms.py):

- each portal domain as a domain term and an email_domain term;
- the client name as a brand term, and a second brand term with common legal suffixes stripped (Inc, LLC, L.L.C., Corp, Corporation, Co, Ltd, Credit Union, Federal Credit Union, FCU, Bank, N.A.), so "Riverbend Credit Union" also yields "Riverbend".

A brand term shorter than 4 characters or made only of generic words (First, National, Community, Bank, Credit, Union, Group and similar; the list is STOPWORDS in app/watchterms.py) is skipped because it would match unrelated victims. Starter terms are marked auto in the Source column of the client's watch terms. The pull never deletes a term and never alters one that already exists with the same text and kind, whoever added it. When an analyst removes an auto term the removal is recorded (auto_term_tombstones) and later pulls do not add it back; the client page lists those removals. New starter terms queue a 365 day backfill for that client. Escalations carry the shared platform_client_id so the IR hub lines the client up across modules.

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

HIBP is the only paid data source. ransomware.live, ransomwatch and crt.sh are free. psbdmp is off by default (see Optional connectors).

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

Managed services: a client provisioned from the control plane arrives with starter terms (domains and brand, marked auto). Review them, remove any that are too broad, and add the names of the CEO, CFO and controller (kind person, medium) and any other brands. A client added by hand on this console has no starter terms: add the primary domain (kind domain, high), email domain and brand name yourself. Readiness warns while any active client has no enabled watch terms. For a bank or credit union add routing-number-adjacent terms sparingly; they generate noise.

Fill in the business profile (industry, country, state, revenue band, employee or host band). This is what IAB matching uses. For a credit union, industry "credit union" plus state and a revenue band is enough to catch most broker ads that would describe it.

IR matter: add the client with kind ir and the case number. Add the same terms and the profile; adding terms queues a backfill automatically, and Backfill queues a full pass that also matches the business profile. The hits page shows any prior leak-site listing, breach record, infostealer log or access-for-sale ad in the last year. Preserve evidence on anything relevant before the group's mirror goes down.

Priority groups: the Priority Groups page (/priority-groups) ranks the groups that get direct, profiled crawls. The computed list is the top 25 groups by ransomware.live victims published in the last 90 days, with victims whose sector matches an active client's industry counting double and those matching a client's country counting half again. The worker refreshes it daily. Admins can pin a group (always priority) or exclude one (never priority), and pins survive every refresh. Each group shows its profile state: none, draft (saved, not yet used successfully), working (the last crawl extracted entries) or broken (it extracted entries before and extracts none now). A broken profile is raised on the Connectors page and the dashboard.

Writing a leak-site profile: open the group's Profile from the Priority Groups page. The editor previews CSS selectors against the newest stored index page for the group (the crawl keeps the raw HTML of each changed index page) and lists the victims they would extract, with no network request. Save stores the profile in the database and points the group's onion sources at it. Selectors are plain CSS and multiple comma-separated selectors are tried in order, so a profile tolerates small layout changes. YAML profiles in app/profiles still load as a fallback when no database profile has the source's profile name; forum profiles are YAML only. A source with no profile still works; the profile only adds per-post structure. Saving a profile is open to analysts as well as admins, by design: profiles only shape how the crawl parses a group's own leak site, every save is audited, and the selectors are bounded (at most 200 characters and 10 comma-separated parts each, with preview and crawl extraction stopped after 5 seconds in a separate process). Viewers can open the editor read only.

Verify the client's domain in HIBP (DNS TXT record or email) so the breached-domain and stealer-log queries return data.

## Optional connectors

Each optional connector stays off until it has what it needs, and the Connectors page, readiness and `python -m app.diagnose` show the reason.

- HIBP: "needs HIBP_API_KEY" until the key is set in SSM (/darkweb/HIBP_API_KEY). It also needs at least one domain or email_domain watch term.
- Telegram: "needs TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_CHANNELS" while any is unset, then "missing Telegram session file at <path>" until scripts/telegram_login.py has been run once. The session path is TELEGRAM_SESSION_PATH (default /data/telegram.session on the shared volume). DEPLOY.md has the login steps.
- Pastes: "PASTES_ENABLED is false" by default. On Oct 17, 2026 psbdmp.ws could not be reached from the build environment and no current documentation for its v3 API was found; the latest public reference describes it at psbdmp.cc with registration required. Probe it from the host with `python -m app.diagnose` and set PASTES_ENABLED=true only when the psbdmp search returns HTTP 200 with JSON. A replacement index is a class implementing PasteSource (search and fetch) in app/collectors/pastes.py, registered in SOURCES and selected with PASTE_SOURCE.
- Forums: "no forum profiles configured" until a profile of kind forum exists in app/profiles and an enabled forum Source references it. No live forum profiles ship in code.

## Live Tor search engines

Engines are declared in app/tor_search.py and overridden with TOR_SEARCH_ENGINES, a JSON list of engine objects merged by key. An object naming an existing key changes only the fields it sets, so a dead engine is switched off or moved without a release:

```
TOR_SEARCH_ENGINES=[{"key": "tor66", "enabled": false}, {"key": "ahmia", "base_url": "http://<new address>.onion"}]
```

Fields: key, name, parser (ahmia, onionland or tor66), enabled, base_url, search_path, query_param, params (fixed query parameters), token_path and token_form (the page and form to copy hidden inputs from before searching). Invalid JSON or an unknown parser turns the connector off with the reason on the Connectors page.

Default engines and what was verified on Oct 17 to 18, 2026. The build environment could not reach Tor or ahmia.fi, so none was fetched live; confirm each on the host with a live search and `python -m app.diagnose`, which probes every enabled engine over Tor.

- Ahmia (juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion). Verified from Ahmia's own source (github.com/ahmia/ahmia-site, commit db1a091, Sep 25, 2026). The search form carries a hidden input whose name and value rotate every minute; /search/ without it redirects home. The adapter fetches the homepage, copies every hidden input of form#searchForm and then searches. Queries are capped at 100 characters, Ahmia's own limit.
- OnionLand (3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion). Address listed identically by three maintained onion search tools (robin, Oct 2026; Sicry, May 2026; OnionSearch, 2023). Markup from OnionSearch's parser.
- Tor66 (tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion). Address listed identically by the same three tools. Markup from OnionSearch's parser.

An engine that is down, refuses the request or changes its layout returns no results and records the error; the other engines still answer. The last search's per-engine state and the count of searches in the last 24 hours show on the tor_search row of the Connectors page, and a search where every engine failed marks that row failed. The tests under tests/test_tor_search.py run each adapter against fixtures in tests/fixtures/tor_search_*.html. When an engine changes its markup, save a fresh result page from the research console, update the fixture and the parser together.

## Forum profiles and authenticated cookies

Forum collection is read only. The crawler fetches board pages and threads and stores their text. It never logs in, registers, posts, replies, sends messages, votes or purchases, and a profile must not point it at a URL that does any of those things (logout, post, buy, vote or profile edit links).

Writing a forum profile:

1. Open a board page and a thread page through the research console (/research) so the fetch goes over Tor from the server, and copy the markup.
2. Copy app/profiles/_example_forum.yaml to a new file named for the board, for example app/profiles/xss_board.yaml. Files whose names start with an underscore are examples and are ignored.
3. Keep `kind: forum` and fill in the selectors: thread_selector for each thread row on a board page, thread_link_selector and thread_title_selector within a row, post_selector for each message on a thread page, and author_selector, body_selector and date_selector within a message. Comma-separated selectors are tried in order.
4. List the board sections to start from under `sections`, relative to the source URL. Set page_param and max_pages for pagination and keep max_threads_per_run modest (25 is the default) so a sweep stays polite.
5. Commit the file and redeploy; profiles load at start.
6. On the Sources page add a source of kind forum with the board's base URL and the profile's file name (without .yaml) in the Profile field. The Connectors page then shows the forum connector as configured.

Storing an authenticated cookie on a Source: for a board the delivery team already has an account on, sign in from a dedicated research browser (Tor Browser for onion boards), copy the Cookie request header for the board's domain from the browser's developer tools, and paste it into the Session cookie field when adding the source, or into the cookie form on an existing source. It is stored in the source's meta and sent with every request to that source. The Sources page shows only whether a cookie is set, and audit entries record set or cleared without the value. Use an account created for research, never a personal one. When the board expires the session the crawl starts returning login pages; paste a fresh cookie. Clearing the field removes it.

## Operations

Logs: `docker compose logs -f worker` on the instance, or CloudWatch group /darkweb/containers.
Collector health: Connectors page (/connectors). It lists every connector the worker schedules with whether it is configured (and the reason when it is not), its last run, last success, items collected in the last 24 hours and 7 days, the newest published date of its items and its last error. A live feed whose newest published item is older than 7 days is flagged stale. The worker heartbeat age and the latest Tor check sit at the top. Admins and analysts can press Run now, which queues the connector for the worker; the worker polls the queue every minute and the web container never runs a collector itself. The dashboard shows a red banner when the worker heartbeat is older than 5 minutes or Tor is not exiting through Tor, and an amber banner when a configured connector failed its last run or is stale. The same health is reported to the control plane readiness screen.
Diagnose: inside the worker container, `python -m app.diagnose` prints the heartbeat, the Tor status, the Connectors table and a live probe of each upstream (HTTP status and byte count only; keys and cookies are never printed). Add `--no-probe` to read the database only. It exits 1 when the worker or Tor is down or a configured connector failed.
Run history: every collector run is a row in collector_runs (job, start, finish, ok, new items, new hits, error) kept for 30 days. The worker also writes worker_state (heartbeat every minute, Tor check every 10 minutes).
Source health: Sources page. Leak sites go down constantly; a mirror with ten failures and a last OK of three weeks ago is normal and will be retried.
Backups: nightly pg_dump to the evidence bucket under backups/, plus daily EBS snapshots with seven retained.
Updates: `git pull` then `scripts/deploy.sh`.
Tor exit check: the Connectors page shows the worker's latest check; /research/torcheck runs one from the web container.
Live searches: each one is a row in search_requests (query, engines, requester, status, merged results and per-engine status, counts, errors and timings), drained by the worker every TOR_SEARCH_POLL_SECONDS (20) and kept for 90 days. Each live search is also a collector_runs row under tor_search with trigger manual.

## Operational security

- All onion traffic leaves through Tor. Clearnet collection (feeds, HIBP, crt.sh) leaves from the instance's AWS IP. If you do not want a leak site operator to see an AWS address during research, tick "route clearnet through Tor".
- The crawler reads index pages only. It does not download leaked archives. Pulling victim data from a leak site is a decision for the case lead and counsel, not an automated process, and should be done from an isolated analysis VM.
- Nothing is posted, registered, or interacted with. Read only. Live Tor search only issues GET requests to the search engines; it never follows a result, logs in, registers, posts, purchases or downloads, and it reduces every result page to text.
- Telegram requires a real account. Use a dedicated number and device, not a personal one.
- Treat the instance as holding client PII once HIBP data flows in. IAM access to it and to the bucket should match the IR desk's access list.

## Project layout

```
app/
  main.py          console and API
  worker.py        scheduler, built from the connector registry; heartbeat, Tor check, Run now queue
  connectors.py    connector registry: every collector, its interval, configured() check and status
  health.py        worker heartbeat, Tor status and run retention
  work_requests.py worker-polled request tables (run_requests, backfill_requests, search_requests)
  tor_search.py    live Tor search: engine adapters, merge, search requests and saved searches
  diagnose.py      python -m app.diagnose
  collectors/      leak_feeds, onion_crawl, forum_crawl, hibp, ct_logs, pastes, telegram
  profiles/        per-site YAML selector profiles (leak and forum), with examples
  matcher.py       watch term matching
  watchterms.py    starter watch terms for provisioned clients, auto term tombstones
  backfill.py      queued re-matching of collected items when terms are added
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
