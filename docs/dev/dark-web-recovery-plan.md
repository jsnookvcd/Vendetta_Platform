# Dark Web Monitoring recovery plan

Development strategy for making modules/dark-web-monitoring actually collect, match, search Tor and show its own health. Written Oct 17, 2026 against main 3758108. Feed this file to Claude Code; work the phases in order and do not skip Phase 0 or Phase 1.

## Symptoms reported

- The dark web module does not appear to work.
- The connectors do nothing visible.
- There is no way to search Tor.

## What "working" means (acceptance for the whole plan)

1. The console shows, for every connector, whether it is configured, when it last ran, when it last succeeded, how many items it produced and the last error, and the worker's heartbeat.
2. Tor status (SOCKS reachable, exiting through Tor, exit IP, last checked) is visible on the dashboard and in the readiness block the control plane reads.
3. Every scheduled job runs on its interval, including the leak feeds.
4. At least one live ransomware victim feed produces items dated within the last 7 days on the deployed host.
5. An analyst can type a query on a Live Tor Search page and get onion results fetched over Tor, open any result through the research console, and preserve it as evidence.
6. A client provisioned from the control plane gets starter watch terms from its name and domains, so a victim post naming that client produces a hit without manual setup.
7. Collectors, the fetch layer and the worker scheduler have tests that run in CI without network access.

## Confirmed findings (code review plus a local probe run)

Each item names the evidence. Fix them in the phase listed.

**F1. The leak feeds job never runs after boot.** `app/worker.py` adds the job with `next_run_time=None`. In APScheduler 3.x that adds the job paused. Verified locally: the job's `next_run_time` is None after `add_job`. The worker calls `leak_feeds.run` once at startup and never again. Phase 2.

**F2. ransomware.live is called on the free public tier, which fails.** With no `RANSOMWARE_LIVE_API_KEY` the code uses `https://api.ransomware.live/v2`. Per ransomware.live, v2 is limited to one request per minute per endpoint and is not intended for business use; the free PRO tier needs a key from my.ransomware.live. At boot `_seed()` calls `/groups` and then `leak_feeds.run` calls `/recentvictims` seconds later. The local probe got `403 Forbidden` on both (that may partly be the sandbox's egress, so confirm on the host in Phase 0). The endpoint paths and the auth header name (`X-API-KEY` in config) have not been verified against the PRO API's OpenAPI document. Phase 2.

**F3. ransomwatch is archived and its data is 16 months stale, yet it reports healthy.** The probe ingested 16,032 victims from ransomwatch `posts.json`, the newest published 2025-06-16, and the source was marked `last_ok` with no error. Anyone looking at Sources sees a green feed that will never produce a new victim. Phase 2.

**F4. The onion crawl list is seeded from that stale archive.** `seed_onion_sources` registered 451 onion mirrors from ransomwatch `groups.json` (marketo, lockbit2, suncrypt and similar long-dead sites). `onion_crawl.run` attempts up to 150 per run with 3-second pauses and 90-second Tor timeouts, so a run can spend hours timing out against dead mirrors. Backoff only begins after 5 failures per source. Phase 2.

**F5. Tor and collector health are invisible.** The worker waits up to five minutes for Tor and then starts anyway. Job exceptions go only to the container log (`_job` logs and swallows them). `readiness.integrations()` reports only a count of Source rows, so readiness is green with Tor down and every connector failing. The only Tor check is the raw JSON at `/research/torcheck`. Phase 1.

**F6. There is no Tor search.** `/search` runs a full-text query over items already in the local database. When collection is broken it returns nothing, and it never queries Tor. `/research` fetches one URL you already know. Searching onion space needs a new feature. Phase 3.

**F7. Provisioned clients have no watch terms, so nothing can ever hit.** `app/provision.py` creates platform clients with the comment that onboarding adds watch terms later. Matching (`app/matcher.py`) only produces hits against WatchTerm rows. A client added on the control plane therefore produces zero hits even when collection works. Phase 4.

**F8. Optional connectors are silently off.**
- Telegram: `telethon` is not in `requirements.txt`, so the collector logs "telethon not installed" and returns, and it also needs an interactive session file.
- HIBP returns early without `HIBP_API_KEY`.
- Pastes depend on psbdmp.ws, whose current availability is unverified.
- Forum crawl needs a profile per forum, and only `_example_*.yaml` profiles exist.

None of this is shown in the UI. Phase 1 surfaces it; Phase 4 fixes it.

**F9. No tests cover collection.** The suite covers the matcher, redaction, tenancy, SSO, provisioning and contracts. Nothing exercises `fetch.py`, any collector, `pipeline.ingest` end to end, or `worker.py`. That is how F1 to F5 shipped. Each phase adds tests.

### Checked and not a bug

`TOR_PROXY=socks5://tor:9050` with httpx 0.28 sends the hostname to the proxy (httpcore's SOCKS5 connect uses a domain address type), so `.onion` names resolve inside Tor. `socks5h://` is also accepted by httpx 0.28 if you prefer to be explicit. The Tor container's healthcheck exists, so the worker's `depends_on: service_healthy` is satisfiable.

## Phase 0. Live diagnosis on the host (do first, record results)

Run these over SSM on i-055dafb6ce920256d (stack at /opt/vendetta_platform/modules/dark-web-monitoring, compose project vcd-dark-web-monitoring). Send each block as its own SSM command because output caps at 24,000 characters. Paste the results into a new section at the bottom of this file titled "Phase 0 results" before writing code.

```bash
# 1. Containers and health
cd /opt/vendetta_platform/modules/dark-web-monitoring
docker compose -p vcd-dark-web-monitoring ps

# 2. Tor bootstrap and worker startup
docker compose -p vcd-dark-web-monitoring logs --tail 60 tor | grep -Ei "bootstrap|warn|err" | tail -20
docker compose -p vcd-dark-web-monitoring logs --tail 300 worker | grep -Ei "tor ok|waiting for tor|scheduler started|failed|error|seeded|new victims|onion crawl" | tail -40

# 3. Tor from inside the worker
docker compose -p vcd-dark-web-monitoring exec -T worker python -c "from app.fetch import tor_check; print(tor_check())"

# 4. Each upstream from inside the worker (clearnet direct)
docker compose -p vcd-dark-web-monitoring exec -T worker python - <<'PY'
import httpx
for u in ["https://api.ransomware.live/v2/recentvictims", "https://api-pro.ransomware.live/openapi.json",
          "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
          "https://psbdmp.ws/api/v3/search/example.com", "https://crt.sh/?q=example.com&output=json"]:
    try:
        r = httpx.get(u, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        print(r.status_code, len(r.content), u)
    except Exception as e:
        print("ERR", type(e).__name__, e, u)
PY

# 5. What the database says
docker compose -p vcd-dark-web-monitoring exec -T db psql -U darkweb -d darkweb -c "
select kind, count(*) sources, sum((fail_count>0)::int) failing, max(last_ok) last_ok from sources group by kind order by kind;" -c "
select kind, count(*) items, max(published_at) newest_published, max(collected_at) newest_collected from items group by kind order by kind;" -c "
select (select count(*) from clients) clients, (select count(*) from watch_terms) terms, (select count(*) from hits) hits;"

# 6. Environment the worker actually has (names only, no values)
docker compose -p vcd-dark-web-monitoring exec -T worker sh -c 'env | cut -d= -f1 | grep -E "TOR|RANSOMWARE|HIBP|TELEGRAM|MODULE_ENABLED|DATABASE" | sort'
```

Expected from the code review: the leak feed job ran once at boot only (F1); ransomware.live failing or rate limited (F2); ransomwatch items with newest published around 2025-06 (F3); hundreds of onion sources with many failing (F4); terms count near zero (F7). Anything different from that changes the plan; note it.

## Phase 1. Make health visible before fixing anything

Goal: the operator can see exactly which connector is broken and why, in the console and on the platform readiness screen.

1. **CollectorRun model.** One row per job execution: job id, started_at, finished_at, ok, items_new, hits_new, error (truncated), detail JSON. Wrap `_job` in `worker.py` to write it. Keep 30 days.
2. **Worker heartbeat.** The worker writes `last_heartbeat` (a small key/value table or a WorkerState row) every minute from a scheduler job, plus the Tor check result every 10 minutes: reachable, IsTor, exit IP, error, checked_at.
3. **Connector registry.** One module (`app/connectors.py`) that declares every connector: key, name, kind (feed, onion, forum, paste, ct, hibp, telegram, search), `configured()` with the reason when not (missing key, missing dependency, no profiles, no terms), interval, and the job id. The worker schedules from this registry so there is one list.
4. **Connectors page** (`/connectors`, staff, read only for viewers). Per connector: configured or the reason it is not, last run, last success, items in the last 24 hours and 7 days, newest published date of its items, last error. Flag "stale" when the newest published item is older than 7 days for a live feed. Show worker heartbeat age and Tor status at the top. Add a "Run now" button per connector (admin and analyst) that queues an immediate run through a `run_requests` table the worker polls each minute; the web container never runs collectors itself.
5. **Dashboard banner.** Red when the heartbeat is older than 5 minutes or Tor is not exiting through Tor; amber when any configured connector failed its last run or is stale.
6. **Readiness.** Extend `readiness.integrations()` with `tor` (ok, checked_at, error), `worker_heartbeat_age_seconds`, and per connector `{configured, last_ok, stale, error}`. The control plane readiness screen should then show dark web red when Tor or the worker is down. Check how modules/platform/app/readiness.py renders module integrations and add a check there if it only counts.
7. **Diagnose CLI.** `python -m app.diagnose` inside the worker container prints the same table as the Connectors page plus a live probe of each upstream (status code and byte count, no secrets). It replaces most of the Phase 0 commands for next time; document it in the module README and DEPLOY.md.

Tests: CollectorRun written on success and on exception; heartbeat and Tor status persisted (mock `tor_check`); Connectors page renders with no data, with failures and with stale data; viewer cannot press Run now; readiness block shape.

## Phase 2. Fix scheduling and the feeds

1. **F1.** Remove `next_run_time=None` from the leak feeds job. Add a regression test that builds the scheduler (factor job registration into a function that returns the configured `BlockingScheduler` without starting it) and asserts every job has a non-null `next_run_time`.
2. **F2, ransomware.live.**
   - Treat the PRO API as required for this feed. Without `RANSOMWARE_LIVE_API_KEY` the connector is "not configured: needs a free PRO key from my.ransomware.live" and does not call v2 at all.
   - Fetch `https://api-pro.ransomware.live/openapi.json` (or the docs page source) and confirm the recent victims path, the groups path, the group locations shape and the auth header name. Update the code and config defaults to match, with a unit test against a recorded fixture of the real response shape.
   - Respect fair use: one call per endpoint per run, a clear User-Agent, backoff on 429 honouring Retry-After.
   - Add the SSM parameter `/vendetta/dark-web-monitoring/RANSOMWARE_LIVE_API_KEY` to GO_LIVE and the module DEPLOY.md. Jordan gets the key at my.ransomware.live.
3. **F3, ransomwatch.** Stop treating it as a live feed. Keep it only as a one-time historical backfill behind an admin button, and mark the source `archived` so it never shows green as live.
4. **F4, onion sources.**
   - Seed from ransomware.live PRO group locations, which carry availability, instead of the ransomwatch archive.
   - Add `seeded_at` and `last_seen_in_feed` to Source meta.
   - Disable sources whose group has had no feed activity in 180 days and sources that failed 10 consecutive runs, recording why. A person can re-enable them on the Sources page.
   - Order crawling by group activity so live groups are crawled first.
   - Cap a run by wall-clock time (for example 45 minutes) as well as by count.
   - Provide a migration that disables the 451 stale mirrors already in production rather than deleting them.
5. **Aggregator hit, then direct capture.** The aggregator tells us where to look; the direct capture is the record.
   - When a feed item (kind `victim`) produces a hit for a client, queue a capture instead of fetching inline inside `ingest`. Today `pipeline.ingest` calls `evidence.preserve` synchronously, which blocks the feed job on Tor.
   - A `captures` table holds hit_id, target URL, status (pending, captured, unavailable), attempts, next_attempt_at, evidence_id and last error.
   - The target is the original leak post URL when the feed gives one (`post_url` or `claim_url`), otherwise the group's current onion index from its enabled Sources, best-known first.
   - The worker drains the queue every few minutes over Tor. It retries up to 4 times over 24 hours with backoff and tries the group's other mirrors before giving up.
   - It preserves the page through the existing evidence path with its SHA-256 and signed chain, linked to the hit and the client. If the index page is captured but the victim's name is not found in its text, record that as `captured_index_no_match`.
   - The hit page shows capture status, a link to the evidence and a "Capture now" button. The Connectors page shows queue depth and the success rate.
6. **Priority groups.** Rank which groups get direct, profiled crawls instead of index snapshots.
   - Compute the top 25 groups from the ransomware.live PRO data by victims in the last 90 days, weighted up for sectors and countries that match active clients' industries.
   - An admin can pin or exclude groups on a Priority Groups page, and the computed list refreshes daily.
   - Crawl priority groups first and every run; crawl the rest by activity within the time budget.
   - Parsers need live HTML, which only the host can fetch over Tor, so ship the tooling rather than guessed selectors. The Priority Groups page lists each group with its profile state (none, draft, working, broken).
   - A profile editor previews selectors against the most recent captured index page of that group (a stored `page` item), showing the victims they would extract before the profile is saved.
   - A profile that extracted entries before and now extracts none is marked broken and raised on the Connectors page.
7. **Freshness rule.** A feed whose newest published item is older than 7 days is "stale" on the Connectors page and in readiness, even when its last HTTP call succeeded.
8. **Victim alternatives.** Note in the module README that a second victim source is worth adding for resilience (for example a commercial feed or direct profiled crawls of the most active groups). Do not build it in this plan.

Tests: scheduler regression; ransomware.live client against fixtures for success, 401/403, 429 with Retry-After and schema drift; ransomwatch never scheduled; seeding from group fixtures; disable rules; wall-clock cap (monkeypatch time); capture queue lifecycle (pending to captured, retries across mirrors, unavailable after the last attempt, index captured without the victim name); ingest no longer fetches inline; priority ranking with industry weighting, pins and exclusions; profile preview against a stored page; broken-profile detection.

## Phase 3. Live Tor search

Goal: an analyst searches onion space from the console, with every request leaving through Tor from the server, never from the analyst's workstation.

1. **Search engine adapters** in `app/tor_search.py`, each with `search(query, limit) -> [Result(title, url, snippet, engine)]`, all requests through `fetch()` over Tor.
   - Start with Ahmia's onion service. Fetch Ahmia's homepage first and parse any hidden form token its search form requires; Ahmia has used one to deter scraping.
   - Add one or two more onion engines behind the same interface.
   - Verify each engine's current onion address and form fields live before coding against them, and keep the addresses in config (`TOR_SEARCH_ENGINES`) so a dead engine can be swapped without a release.
   - Fail per engine, never the whole search.
2. **Page** `/search/live`: query box and engine checkboxes. Results are merged and de-duplicated by onion host and path, each showing which engines returned it. Each result has "Open in research console" (prefills `/research` with the URL) and "Add as source" (creates an onion Source a person can later profile).
3. **Async execution.** Tor searches take 20 to 90 seconds. Run them in the worker through a `search_requests` table (query, engines, requested_by, status, results JSON). The page polls every few seconds. The web container never blocks on Tor.
4. **Audit and evidence.** Every live search is written to the audit log with who searched what. Preserving a result uses the existing evidence path with its SHA-256 and signed chain.
5. **Saved searches.** Optionally, a saved query per client re-runs on a schedule and ingests new results as `search` items through `pipeline.ingest`, so watch-term matching and alerting apply.
6. **Rename the existing `/search`** in the UI to "Search collected data" so the two are not confused.

Tests: each adapter against recorded HTML fixtures, including token extraction and a changed layout (returns an empty list with an error, no exception); merge and de-duplication; request lifecycle through the worker with `fetch` mocked; audit entry written; viewer can search but cannot add a source.

Guardrails: read only. No logging in, registering, posting, purchasing or downloading files from result pages. HTML is fetched and reduced to text; nothing from a result page is executed or rendered as HTML in the console.

## Phase 4. Coverage that produces hits

1. **F7, starter watch terms.** When provisioning creates or updates a client, add terms if missing:
   - each portal domain as `domain` and `email_domain`;
   - the client name as `brand`, with common suffixes such as Inc, LLC and Credit Union stripped into a second variant.

   Mark them `source=auto` so an analyst can see and remove them. Never delete a term an analyst added. Readiness warns on any active client with zero enabled terms.
2. **Backfill on new terms.** When terms are added, run the existing backfill (`/clients/{cid}/backfill`) automatically over the last 365 days of collected items so historical victim posts produce hits immediately.
3. **Telegram.** Add `telethon` to requirements, keep the collector off until `TELEGRAM_*` and a session file exist, and show those reasons on the Connectors page. Document `scripts/telegram_login.py` in DEPLOY.md.
4. **HIBP.** Show "needs HIBP_API_KEY" on the Connectors page. Add the SSM parameter to GO_LIVE.
5. **Pastes.** Probe psbdmp.ws from the host (Phase 0, block 4). If it is dead or unreliable, disable the connector with that reason and leave a stub for a replacement source.
6. **Forums.** Ship no live forum profiles in code. Add a short guide in the README for writing a forum profile and storing an authenticated cookie on a Source, and make the Connectors page say "no forum profiles configured" until one exists.

Tests: auto terms on provision (create, update, no deletion of analyst terms); backfill triggered; each optional connector reports the right not-configured reason.

## Phase 5. Verify on the host and close out

1. Merge, run `infra/redeploy.sh dark-web-monitoring`, then `python -m app.diagnose` in the worker.
2. Walk the acceptance list at the top of this file on the live console and record each result with a timestamp in a "Verification" section at the bottom of this file.
3. Confirm the platform readiness screen shows the dark web Tor and connector checks.
4. Update modules/dark-web-monitoring/README.md, DEPLOY.md, GO_LIVE.md (new SSM parameters: RANSOMWARE_LIVE_API_KEY, HIBP_API_KEY, optional TELEGRAM_*, TOR_SEARCH_ENGINES) and docs/ARCHITECTURE.md where the module's behaviour changed.

## Working rules for Claude Code

- Work on a branch per phase (for example `dw/phase-1-observability`), with small commits and the repository's commit trailer.
- Run the module suite against Postgres before each commit: database `darkweb_test`, role `darkweb`, timezone UTC; see `tests/conftest.py`. Keep CI green.
- Tests never touch the network. Use httpx `MockTransport` or recorded fixtures under `tests/fixtures/`.
- Never put tokens, API keys or cookie values in logs, audit entries, the Connectors page or diagnose output. Show only whether one is set.
- The web container never makes Tor requests on a request thread except the existing single-URL research fetch. Long work goes through worker-polled request tables.
- Keep the module's contracts unchanged: `/api/findings`, `/api/module`, escalation and provisioning shapes are pinned by `docs/contracts` and `tests/test_contracts.py`.
- Writing style for UI copy, docs and commit messages: no em or en dashes, no "not X but Y" constructions, no one-line punchy fragments, direct declarative prose.

## Prompt to start Claude Code

> Read docs/dev/dark-web-recovery-plan.md in full. Start with Phase 0: I will paste the host diagnostic results; until I do, begin Phase 1 on a branch named dw/phase-1-observability. Follow the plan's working rules. After each phase, stop, summarise what changed, show the test count, and list anything that contradicts the plan's findings before moving to the next phase.
