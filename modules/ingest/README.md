# Telemetry Ingest

Telemetry Ingest is the SOC's front door for data. It reads each client's own security tools, normalizes every record once to the Open Cybersecurity Schema Framework (OCSF), stamps it with the client's platform id, and seals it into a signed chain of evidence that belongs to that client. Sigma rules run over the normalized stream, and every detection is served to MDR in the shared finding model.

## What makes it different

Every SIEM and MDR stores telemetry. This module proves it.

- Each delivery is parsed strictly (duplicate keys, NaN and Infinity are refused, because two parsers could read such a record differently), and each vendor record is hashed in its RFC 8785 canonical form before it is normalized. The normalized event is hashed the same way. Both hashes form one leaf.
- Each client's events are sealed on a schedule into an RFC 6962 Merkle tree. The batch header carries the root and the hash of the client's previous header, and it is signed with Ed25519, so each client has one append-only signed chain.
- Every chain head is anchored daily to an Object Lock bucket in the evidence account, which Vendetta cannot rewrite. Each client also gets its own signed anchor statement, which names only its own chain head and the digest of the global anchor.
- Any single event can be proven with a proof file of a few hundred bytes and the open verifier, `app/receipts.py`, without revealing any other event. The verifier requires the public key Vendetta published (`--key`); without it, it reports UNPINNED, because a file can carry any key.
- Normalization is deterministic and carries no processing time, so anyone can re-run the open mapper over the archived raw record and reproduce the exact event hash the receipt commits to.
- A client can export its own chain from the portal, with its latest anchor statement, and verify both: a chain cut short before the anchor, or rewritten under it, fails.

That is what lets an investigation, an IR report, a regulatory filing, an insurance claim or an expert report cite telemetry that is provably what the vendor sent.

## Doors

| Door | How | Sources |
| --- | --- | --- |
| Pull | Scheduled API polling with a cursor per connector | CrowdStrike alerts, SentinelOne threats, Microsoft Defender alerts, Huntress incidents, Entra sign-ins and audit, Okta System Log, Microsoft 365 audit, Google Workspace |
| Push | `POST /api/ingest/{connector_id}` with `Authorization: Bearer <secret>` or `X-Vendetta-Timestamp` plus `X-Vendetta-Signature: sha256=<HMAC of "<ts>.<body>">` | Any mapper; Event Hubs relays, Okta event hooks, EventBridge (GuardDuty), CloudTrail files |
| Bucket | SQS notifications for allowlisted buckets, routed by bucket and prefix | CloudTrail, CrowdStrike Falcon Data Replicator, GuardDuty exports |
| Syslog | Vector (`deploy/vector.toml`) relays TLS syslog to the push door | CEF from firewalls and appliances |

The tenant always comes from the connector. A record cannot claim another client.

## Running locally

```
docker network create vendetta   # once
cp .env.example .env              # or set SECRET_KEY and ALLOW_INSECURE_DEFAULTS=true
docker compose up --build
```

The console is on http://127.0.0.1:9000. Tests run against Postgres:

```
createuser ingest && createdb -O ingest ingest_test
pytest -q
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `EVIDENCE_SIGNING_KEY` | required | Ed25519 seed (hex) that signs every batch and anchor. The module refuses to start without it. Back it up, and publish its public key. |
| `API_READ_TOKEN` | derived | Read-only bearer for GET routes. MDR, SABINE and the control plane read with it; it can never seal, pull, escalate or sync. |
| `SEAL_INTERVAL_SECONDS` | 60 | Seal schedule. |
| `SEAL_MAX_EVENTS` | 20000 | Largest batch. |
| `CONNECTOR_INTERVAL_SECONDS` | 300 | Default polling interval. |
| `STREAM_INTERVAL_SECONDS` | 30 | Detection pass interval. |
| `HOT_RETENTION_DAYS` | 30 | Hot store retention. Batch headers and leaf hashes are kept for life. |
| `WORKER_ROLES` | all | Which background loops run here: connectors, stream, seal, bucket. |
| `KINESIS_STREAM` | | Publish events and batch headers to Kinesis (Firehose archives them, the lake reads them). |
| `OPENSEARCH_URL` | | Bulk index events per tenant and month (SigV4 with the task role). |
| `ANCHOR_BUCKET` | | Evidence account bucket for daily anchors. |
| `BUCKET_FEED_QUEUE_URL`, `BUCKET_ALLOWLIST` | | Turn on the bucket door. |
| `MAX_PUSH_BYTES`, `MAX_PUSH_RECORDS`, `MAX_RECORD_BYTES` | 5 MB, 5000, 256 KB | Push limits. An oversized record is rejected whole, never truncated. |

## Known limits

- Vendor API details marked "unsure" in the connector code need confirming against live tenants (Huntress field names, CrowdStrike paging, Okta privilege fields).
- Managed services still pulls alerts from the same EDR consoles. Until its alerts carry the vendor id, MDR can see the same alert from both modules. Turn off the managed-services alert sync for a tool once its ingest connector is live for that client.
- Sigma support covers the rule format, all common modifiers and count thresholds. Sigma v2 correlation documents, `base64offset` and placeholders are not implemented.
- Rules match on the first 16,384 characters of any value, and wildcards use a backtracking-free matcher. A `|re` modifier still runs Python's regular expression engine, so an admin can write a slow one; the dry run stops after 10 seconds and says so, and the seeded rules use no regular expressions on attacker-controlled fields.
- Integers in canonical JSON are written exactly; floats follow ECMAScript. A verifier in a language whose JSON parser turns large integers into doubles must keep them as integers.
