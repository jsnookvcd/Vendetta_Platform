# Vendetta SOC on AWS

Infrastructure as code for the Vendetta SOC: a multi-account AWS Organization,
a central egress network, a security data lake, an ingest pipeline, the
platform modules on ECS Fargate, and a retention-locked evidence account.

The single-host stack in `infra/terraform` keeps running unchanged until the
cutover at the end of this document. Nothing here reads or modifies its state.

## Layout

```
infra/aws/
  org/         AWS Organizations, OUs, accounts, SCPs, delegated admins, org CloudTrail, Identity Center
  network/     Transit Gateway, egress VPC, Network Firewall, Tor segment isolation
  lake/        Security Lake, raw archive, per-tenant KMS keys, Lake Formation filters, Athena, Glue
  ingest/      Kinesis, Firehose, SQS, webhook API, syslog NLB, ingest ECS services
  soc-apps/    Platform modules on ECS, RDS, Valkey, OpenSearch, ALB, WAF, ECR (prod and staging)
  evidence/    COMPLIANCE-locked ledger bucket, replica, split-duty KMS keys, signing key
  modules/
    vpc/           three-AZ VPC, app and data subnets, TGW attachment, flow logs, endpoints
    ecs-service/   Fargate ARM64 service with Service Connect, autoscaling, optional ALB rule
    secure-bucket/ hardened S3 bucket (SSE-KMS, versioning, optional Object Lock, TLS-only policy)
    waf-acl/       regional web ACL with the AWS managed baseline
  scripts/copy-ssm-params.sh   one-time copy of /vendetta/<module>/* into a soc-apps account
  DR.md        us-east-2 pilot light
  (CI)            the infra-aws job in .github/workflows/ci.yml runs fmt and validate on every stack
```

Each stack directory has its own README.md with its inputs, outputs and apply
notes. Conventions across all of them: default tags
`Project = "vendetta-soc"`, `ManagedBy = "terraform"`, `Stack = "<name>"`;
resource names start with `vcd-soc-`; `for_each` everywhere a resource is
optional; no secret has a default value.

## Accounts and network plan

| Account key | OU | Runs |
|---|---|---|
| (management) | root | org stack, state bucket, today's single host |
| log-archive | Security | org CloudTrail and VPC flow log archive |
| security-tooling | Security | delegated admin for GuardDuty, Security Hub, Inspector, Config, Access Analyzer |
| data-lake | Security | lake stack, Security Lake delegated admin |
| evidence | Security | evidence stack |
| ingest | Infrastructure | ingest stack |
| network (optional) | Infrastructure | network stack; until it exists, run network in ingest |
| soc-apps-prod | Workloads | soc-apps with environment = prod |
| soc-apps-staging | Workloads | soc-apps with environment = staging |

Sandbox is created empty for experiments.

| CIDR | Use | TGW segment |
|---|---|---|
| 10.10.0.0/16 | ingest VPC | spoke |
| 10.20.0.0/16 | soc-apps prod VPC | spoke (tor_peer) |
| 10.21.0.0/16 | soc-apps staging VPC | spoke |
| 10.30.0.0/16 | data-lake (reserved) | protected |
| 10.40.0.0/16 | evidence (reserved) | protected |
| 10.60.0.0/20, 10.61.0.0/20 | Tor VPCs, prod and staging | tor |
| 10.255.0.0/22 | egress VPC | egress |

## Apply order

```
org -> network -> lake -> evidence -> ingest -> soc-apps (staging, then prod)
```

Two stacks need a second pass:

1. **org.** The log-archive provider alias assumes a role in an account that
   does not exist yet. Apply the accounts first, then everything:
   `tofu apply -target=aws_organizations_account.member` and then `tofu apply`.
2. **network.** Spoke stacks create their TGW attachments (auto-accepted). Put
   each attachment id from their outputs into `spoke_attachments` and apply
   network again so it associates and propagates them.

Outputs feed the next stack through variables: `org` gives account ids, the
organization id and ARN, and the log-archive bucket ARN; `network` gives the
Transit Gateway id; `lake` gives the raw bucket, its key, the tenant keys and
the custom source roles to `ingest`; `evidence` gives the ledger bucket and key
to `soc-apps`. Passing values explicitly keeps each stack valid on its own and
keeps one stack's state out of another's reach.

Initialize every stack with its backend file:

```bash
cd infra/aws/<stack>
cp backend.hcl.example backend.hcl      # git-ignored
tofu init -backend-config=backend.hcl   # or terraform init
tofu apply -var-file=<env>.tfvars       # tfvars are git-ignored too
```

The examples use the existing state bucket `vcd-platform-tfstate-715841340804`
with a key per stack and `use_lockfile = true` (S3 native locking, Terraform
1.10+ or OpenTofu 1.10+).

## Provider and assume-role pattern

Every stack runs with management-account credentials (an Identity Center
SOCAdmin session in the management account, or the CI role there). The default
provider of each member-account stack assumes
`arn:aws:iam::<account id>:role/OrganizationAccountAccessRole`, the role
Organizations creates in each new account. Stacks that touch a second region
(lake, evidence, soc-apps) add an alias for that region assuming the same role.
The org stack itself runs in the management account and uses an alias only for
the log-archive bucket and its key.

The SCPs exempt `OrganizationAccountAccessRole` and the BreakGlass permission
set. Only management-account administrators can assume that role, and they can
detach SCPs anyway, so the exemption adds no reach. Restrict who holds SOCAdmin
in the management account accordingly.

## What each stack builds

**org.** Organization with all features, the four OUs, member accounts named
`vcd-soc-<key>` (`close_on_deletion = false`, `prevent_destroy`), and SCPs:
`vcd-soc-baseline` at the root (deny leaving the org; deny stopping or
deleting CloudTrail, GuardDuty, Config, Security Hub, Access Analyzer and
Security Lake; deny Object Lock, versioning, bucket policy deletion and
DeleteBucket on retention-locked buckets), `vcd-soc-region-guard` at the root
(deny regional services outside `allowed_regions`, with the AWS standard global
service exemptions), and `vcd-soc-imdsv2` on each OU. Delegated administrators,
the organization CloudTrail (multi-region, log file validation, KMS) into a
retention-locked bucket in log-archive, and the four Identity Center permission
sets with group assignments from variables.

**network.** Egress VPC with TGW, firewall and public subnets per AZ, NAT
gateways, and Network Firewall in strict order: Tor isolation rules first, then
the TLS SNI and HTTP Host domain allowlist, then drop. The Transit Gateway has
no default route table; four route tables (spoke, protected, tor, egress) make
every path explicit, and the TGW is shared with the organization through RAM.

**lake.** Security Lake in us-east-1 and us-east-2 with a multi-region KMS key,
GLACIER_IR at 90 days, the eight native AWS sources, and one custom source per
Vendetta connector family with the ingest account as provider. The raw archive
bucket `vcd-soc-raw-<account>` (Object Lock GOVERNANCE, seven years, GLACIER_IR
at 90 days, DEEP_ARCHIVE at 395 days) accepts writes only from the ingest
pipeline roles. One KMS key per tenant (`alias/vcd-tenant-<id>`). Lake Formation
admins and per-tenant data cells filters. The `vcd-soc` Athena workgroup with
enforced KMS result encryption and a scan cutoff, and a Glue table over the raw
archive with partition projection.

**ingest.** Kinesis stream `vcd-soc-events` (on-demand, KMS), Firehose to the
raw archive with dynamic partitioning by tenant and source, the bucket-feed SQS
queue and DLQ, the webhook HTTP API through a VPC link to an internal ALB, the
syslog NLB (TLS 6514) to Vector, and the four ECS services with least-privilege
task roles.

How the Telemetry Ingest module splits across the two accounts: its console and
client portal run in soc-apps (host `ingest.`, the module's own Postgres database
on the shared RDS), and so does low-volume push for webhook vendors. The ingest
account carries the high-volume side: the connector worker, the streaming
detection service, Vector for syslog, and the API Gateway webhook path, all with
`WORKER_ROLES` set per service (`connectors,seal,bucket` on the worker, `stream`
on the detection service, empty on the web tasks). Those services reach the same
ingest database over the Transit Gateway. Decision still open: whether to keep one
database for both accounts (simplest, current design) or give the ingest account its
own RDS and publish events to soc-apps only through Kinesis.

**soc-apps.** ECS cluster with Container Insights and the `vendetta.internal`
Service Connect namespace, one service per module (plus worker services for
dark web and managed services), ECR repositories, RDS PostgreSQL 16 Multi-AZ,
Valkey with TLS and an auth token, OpenSearch with fine-grained access control,
the public ALB with the same hostnames and listener priorities as
`infra/terraform/alb.tf`, WAF, optional CloudFront, optional Tor egress VPC, and
the DR copies in DR.md.

**evidence.** Ledger anchor bucket with Object Lock COMPLIANCE (seven years),
replicated to a COMPLIANCE-locked bucket in us-east-2, ledger keys whose
administration and use sit with different roles, and an asymmetric signing key.

## Security notes and known limits

- **Tor isolation.** The tor TGW route table has blackhole routes for the
  data-lake and evidence CIDRs, and the protected table has blackholes for the
  Tor CIDRs. Without the blackholes, a Tor packet for a protected CIDR would
  follow 0.0.0.0/0 to the egress VPC and come back through the egress route
  table, which propagates every attachment. The firewall drops the same traffic
  as a second layer. The tor table propagates only spokes marked `tor_peer`.
- **WAF on the webhook path.** AWS WAF cannot be associated with an API Gateway
  HTTP API, only with REST API stages. The web ACL sits on the internal ALB
  behind the VPC link, so every webhook still passes it.
- **Retention-locked bucket SCP.** S3 has historically not evaluated
  `aws:ResourceTag` for bucket-level actions. The SCP keeps the tag statement as
  asked and adds a name-pattern statement (`locked_bucket_arn_patterns`) that
  holds either way.
- **Two-person control on evidence keys.** KMS has no native two-person rule.
  The evidence stack separates key administration (key-admin role) from key use
  (custodian role) and requires an `approver` session tag and MFA to assume the
  custodian role. The tag is supplied by the caller, so it records a claimed
  approver and does not prove a second person acted. True two-person approval
  needs a broker (for example a Step Functions approval flow that assumes the
  custodian role on the approver's confirmation). Identity Center sessions may
  not carry `aws:MultiFactorAuthPresent`; if custodians cannot assume the role
  with `require_mfa = true`, enforce MFA in Entra conditional access for the
  EvidenceCustodian group and set `require_mfa = false`.
- **Ed25519.** The chain-of-custody signing stays in the application with the
  Ed25519 seed in SSM. The KMS signing key defaults to ECC_NIST_P256. Whether
  AWS KMS offers an Ed25519 key spec in this account's regions was not
  confirmed while writing this; check the KMS key spec list for us-east-1
  before relying on it, and set `signing_key_spec` if it does.
- **Object Lock writers.** PutObject into a bucket with default Object Lock
  retention needs an integrity checksum (Content-MD5 or an x-amz-checksum
  header). Confirm in staging that Firehose deliveries to the raw archive and
  VPC flow log deliveries to the log archive succeed. If either is rejected,
  move that writer to an unlocked staging prefix or bucket and copy into the
  locked bucket with S3 Batch Operations.
- **Tenant keys and Firehose.** A Firehose stream encrypts with one key, the
  raw-archive key. Tenant keys serve the pipeline's per-tenant envelope
  encryption (payload fields, exports, evidence packages) and carry an
  encryption context condition `tenant_id = <id>`.
- **Lake Formation filters.** The normalizer writes a top-level `tenant_id`
  column on every custom source record (and keeps it in `unmapped.tenant_id`).
  Filters only bind once the Glue tables exist and `IAMAllowedPrincipals` no
  longer has access to them; set `enable_tenant_cell_filters = true` after the
  first crawler run. Native AWS sources have no tenant column; they hold
  Vendetta's own accounts only.
- **Valkey auth token.** Generated with `random_password` (the pattern
  `infra/terraform` uses) and stored in Secrets Manager for the tasks. It is also
  in state, which lives in the encrypted, versioned state bucket.

## Still manual

- **Account emails.** Each root email in `account_emails` receives a
  verification mail from AWS. Confirm each one, then set a root password and
  MFA through the root recovery flow and lock the credentials away.
- **Identity Center and Entra.** Enable Identity Center once in the management
  account, connect Entra ID as the external identity provider, and turn on SCIM
  provisioning from the Entra enterprise application. Terraform only references
  the synced group ids in `permission_set_assignments`.
- **Security Lake delegated admin.** If Security Lake does not recognize the
  data-lake account after the org apply, run
  `aws securitylake register-data-lake-delegated-administrator --account-id <data-lake id>`
  from the management account.
- **Security Lake subscriber for OpenSearch.** OpenSearch direct query over the
  lake needs a Security Lake query subscriber and an OpenSearch data source
  connection; set both up once the lake has data.
- **OpenSearch role mapping.** Map each module task role (soc-apps output
  `task_role_arns`) to an OpenSearch backend role through the security plugin
  API as the master role.
- **Per-module databases.** Created by the bootstrap below, never by Terraform.
- **Security Hub, GuardDuty, Inspector, Config organization settings.** The
  org stack registers the delegated admin; turning on auto-enable and standards
  happens in the security-tooling account.
- **Client cross-account roles.** Each client creates `VendettaSOCReader<name>`
  trusting the ingest worker role (`worker_task_role_arn`) with
  `sts:ExternalId` equal to the tenant id.

### Database bootstrap

Run once per environment from a one-off ECS task in the app subnets with the
`db_bootstrap_security_group_id` group and the RDS master secret
(`rds_master_secret_arn`) injected. For each entry in the `module_databases`
output, with the module's existing `POSTGRES_PASSWORD` from SSM:

```sql
CREATE ROLE <db> LOGIN PASSWORD '<POSTGRES_PASSWORD>';
GRANT <db> TO vcdadmin;
CREATE DATABASE <db> OWNER <db>;
```

Then write the URL the module reads, as a SecureString, from an operator
session (the value never enters Terraform):

```
/vendetta/<module>/DATABASE_URL =
  postgresql+psycopg://<db>:<POSTGRES_PASSWORD>@<rds_endpoint>:5432/<db>?sslmode=require
```

The parameter group forces SSL, so `sslmode=require` is mandatory.

## Migration from the single host

### Resource mapping

| infra/terraform today | New home |
|---|---|
| `aws_instance.host` (i-055dafb6ce920256d), user_data, compose stacks | soc-apps ECS services, one per module, plus `<module>-worker` for dark web and managed services |
| Per-module Postgres containers and `pgdata` volumes | soc-apps RDS PostgreSQL 16, one database per module |
| `aws_s3_bucket.backups`, `vendetta-backup` nightly dumps, DLM snapshots | RDS automated backups (35 days PITR) and the DR copy in us-east-2 |
| `aws_s3_bucket.evidence` (GOVERNANCE) | evidence stack ledger bucket (COMPLIANCE), set as `EVIDENCE_BUCKET` for dark web, IR and evidence export |
| `aws_lb.this`, target groups, listener rules, `listener_priorities`, `module_hosts` | soc-apps `alb.tf` with the same hostnames and priorities |
| `aws_acm_certificate.alb` | a certificate in the soc-apps account (`acm_certificate_arn`) |
| `aws_route53_record.host` | repointed to the soc-apps ALB at cutover |
| `aws_sns_topic.alerts` | soc-apps `aws_sns_topic.alerts` (subscribers confirm again) |
| `aws_ssm_parameter.*` under `/vendetta/<module>/` | copied by `scripts/copy-ssm-params.sh`; ECS reads them as secrets |
| `_defaults` JSON | rendered as plain ECS environment in `soc-apps/services.tf` |
| Shared docker network, `http://<module>:8000` | Service Connect namespace `vendetta.internal`, same URLs |
| Tor container beside dark web | optional Tor VPC and `tor` service on the TGW tor segment |
| Instance role, profile, auto-recover alarm, DLM role | retired with the host |
| Default VPC and public subnet | soc-apps VPC, private app and data subnets |

### Cutover

1. Apply the stacks in order through soc-apps staging. Push images to ECR from
   CI (`vcd-soc/<module>:<git sha>`) and set `default_image_tag`.
2. Request the ACM certificate in soc-apps-prod for every module host and add
   its DNS validation records to the existing zone.
3. Run `scripts/copy-ssm-params.sh` with the host account as source and
   soc-apps-prod as destination, then the database bootstrap above.
4. Apply soc-apps prod with `desired_count = 0` and `min = 0` for every
   module, so no module runs migrations against an empty database before the
   restore.
5. Lower the TTL on every module record to 60 seconds a day ahead. At the
   window, stop the web and worker containers on the host
   (`docker compose -p <module> stop web worker`) so nothing writes.
6. Dump each module database from its container on the host:
   `docker compose -p <module> exec -T db pg_dump -U <db> -Fc <db> > <module>.dump`,
   upload the dumps to the backups bucket, grant the soc-apps bootstrap task
   read access to that prefix, and `pg_restore --no-owner --role=<db> -d <db>`
   each one from a one-off ECS task. Check row counts per table against the
   host.
7. Copy the existing evidence objects into the ledger bucket with S3 Batch
   Operations and record the source version ids and original retention dates in
   the manifest. The copies get the new bucket's default retention. The old
   bucket stays until its own retention expires.
8. Set the normal `min` and `desired_count` values and apply; raising the
   autoscaling minimum starts the tasks. Check each module through the new ALB
   before DNS moves:
   `curl --resolve <host>:443:<alb ip> https://<host>/healthz`.
9. In `infra/terraform`, run `terraform state rm 'aws_route53_record.host'` so
   the old stack stops managing the records, then point each record at the
   soc-apps ALB (`alb_dns_name`, `alb_zone_id`), or move the zone and set
   `hosted_zone_id` in soc-apps.
10. Watch errors, queue depth and login flows for a week with the host stopped
    but intact as the rollback path. Rolling back is pointing DNS back and
    starting the host containers.
11. Retire `i-055dafb6ce920256d` last: take a final EBS snapshot, then remove
    the instance from `infra/terraform` (`terraform destroy -target=aws_instance.host`
    or `deploy = false` on every module). Keep the old evidence bucket, the
    backups bucket and the SSM parameters until their retention ends.

Two application changes ride along with the move. Dark web writes captures to
`/data` on a local volume today; on Fargate that storage is ephemeral, so the
module must write captures to `EVIDENCE_BUCKET`. Modules must accept
`DATABASE_URL` with `sslmode=require` and `REDIS_URL` with `rediss://`.

## Validation

All six stacks pass `tofu init -backend=false`, `tofu validate` and
`tofu fmt -check -recursive` with OpenTofu 1.8.5 and the AWS provider 5.100.0.
They were also exercised with OpenTofu 1.10 mock-provider tests (apply against
mocked AWS) to evaluate every expression and `for_each`; the tests are not part
of the repository. No plan has run against real
accounts; run `plan` per stack against the target account before the first
apply.
