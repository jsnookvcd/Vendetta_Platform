# Disaster recovery: us-east-2 pilot light

us-east-1 runs everything. us-east-2 holds copies of the data that cannot be
rebuilt and nothing else, so it costs storage and little compute until a
recovery. The org SCP already allows both regions.

## What is replicated today

| Data | Mechanism | Stack | Notes |
|---|---|---|---|
| Evidence ledger anchors | S3 cross-region replication into a COMPLIANCE-locked bucket, replica KMS key in us-east-2 | evidence | Delete markers are not replicated; the ledger is append-only on both sides |
| RDS PostgreSQL (all module databases) | Automated backup replication, 14 days, KMS key in us-east-2 | soc-apps (`dr.tf`) | Point-in-time restore in us-east-2 within the replicated window |
| Container images | ECR registry replication for `vcd-soc/*` | soc-apps (`dr.tf`) | Same tags, so a DR apply uses the same `default_image_tag` |
| Security Lake | A second data lake in us-east-2 collecting that region's sources | lake | It holds us-east-2 activity. It is a separate lake, so us-east-1 OCSF data is not copied there |
| Security Lake KMS key | Multi-region key with a replica in us-east-2 | lake | |
| Organization CloudTrail | Multi-region trail | org | Records both regions; the archive bucket itself lives in us-east-1 |

## What is not replicated yet

These are the gaps to close in a later `infra/aws/dr` stack:

- **Raw event archive** (`vcd-soc-raw-<account>`). Add a COMPLIANCE or
  GOVERNANCE-locked replica bucket in us-east-2 with a replica KMS key and an
  S3 replication rule, the same shape as the evidence stack.
- **Log archive** (`vcd-soc-log-archive-<account>`). Same pattern.
- **Terraform state bucket** (`vcd-platform-tfstate-715841340804`). Enable
  replication to us-east-2 so a recovery can run Terraform when us-east-1 S3
  is impaired.
- **OpenSearch.** Treated as rebuildable: indexes are reloaded from the lake
  and RDS. Add a manual snapshot repository in an S3 bucket replicated to
  us-east-2 if reindex time becomes too long.
- **Valkey.** Cache and short-lived queues only; it starts empty.
- **Secrets.** SSM parameters under `/vendetta/` are regional. Re-run
  `scripts/copy-ssm-params.sh` against us-east-2 (set `AWS_REGION`) as part of
  the quarterly DR test, or replicate them with a scheduled job.
- **Ingest.** Kinesis and Firehose are regional and rebuilt by applying the
  ingest stack in us-east-2; events in flight during the outage are lost
  unless connectors replay from the vendor APIs, which most support for 7 days.

## Recovery runbook

1. Declare the event and freeze changes to us-east-1 stacks.
2. Network: apply the network stack with `region = "us-east-2"` under a new
   backend key, then attach the spokes as in the main README.
3. Data stores: restore RDS in us-east-2 from the replicated automated backups
   to the latest restorable time. Import the restored instance into a soc-apps
   state for us-east-2 or reference it as an existing endpoint.
4. Secrets: confirm `/vendetta/<module>/*` exists in us-east-2 and rewrite each
   `DATABASE_URL` to the restored endpoint.
5. Applications: apply soc-apps with `region = "us-east-2"`,
   `enable_dr_replication = false`, the same `default_image_tag`, and a
   us-east-2 ACM certificate. Apply ingest the same way, and point it at the
   raw archive replica once that exists.
6. DNS: move every module hostname to the us-east-2 ALB.
7. Evidence: verify a sample of ledger anchors in the replica bucket against
   the signing key's public key before custodians resume work there.

## Targets

These are the targets the design supports once the gaps above are closed,
and the numbers to test against in the quarterly drill: RPO of about 5
minutes for module databases (automated backup replication lag) and 15 minutes
for replicated buckets (S3 replication without RTC); RTO of 4 hours, most of it
the RDS restore and DNS propagation.
