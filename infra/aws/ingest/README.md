# ingest

Runs in the ingest account. Every event lands on the Kinesis stream
`vcd-soc-events`. Firehose copies the stream to the raw archive in the lake
account as `tenant=<id>/source=<family>/yyyy/MM/dd/`, gzip. `ingest-stream`
reads the same stream for streaming Sigma detection. `ingest-worker` pulls
from vendor APIs, reads the bucket-feed queue, and writes OCSF into Security
Lake through the custom source provider roles.

Ways in:

- Webhooks: API Gateway HTTP API, `ANY /api/ingest/{proxy+}`, through a VPC link
  to an internal ALB with WAF, to `ingest-web`.
- Syslog: internet-facing NLB, TLS on 6514 with `syslog_certificate_arn`, to
  Vector on TCP. Only `syslog_allowed_cidrs` may connect.
- Bucket feeds: S3 or SNS notifications from `bucket_feed_source_arns` into
  `vcd-soc-ingest-bucket-feed`, with a DLQ after five receives.

Every record must carry top-level `tenant_id` and `source` fields; Firehose
partitions on them with JQ and sends records without them to `errors/`.

Client access: each client creates a role named `VendettaSOCReader*` that
trusts `worker_task_role_arn` with `sts:ExternalId` set to the tenant id. The
worker policy refuses AssumeRole calls without an ExternalId. Tenant connector
secrets live in Secrets Manager under `vcd/ingest/tenants/`.

The firehose and worker role names are fixed (`vcd-soc-ingest-firehose`,
`vcd-soc-ingest-worker-task`) because the lake stack's bucket and key policies
name them before they exist.
