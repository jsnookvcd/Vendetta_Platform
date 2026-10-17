# First `terraform plan` against the real account

CI runs `terraform fmt -check` and `terraform validate` with no backend and no
credentials. Nothing here has been planned against AWS yet. This is how to do
that first plan, what it needs, and what it should show. It does not run apply.

## 1. Credentials and tools

- Terraform >= 1.6 (CI pins 1.9.8; use the same).
- An AWS profile for the target account with the permissions in section 4:
  `export AWS_PROFILE=vendetta` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
  / `AWS_SESSION_TOKEN` in the environment. Confirm with
  `aws sts get-caller-identity`; the account id it prints is the one every bucket
  name and ARN in the plan will carry.

## 2. Backend

`main.tf` carries a commented `backend "s3" {}` block. State will hold every
generated secret (session keys, API tokens, admin passwords), so it belongs in a
private bucket, never on a laptop.

Before the first init, in the same account:

1. Create the state bucket (versioning on, default encryption on, public access
   blocked) and a DynamoDB table with a string partition key `LockID`.
2. Copy `backend.hcl.example` to `backend.hcl` (git-ignored) and fill in the
   bucket, key, region and table.
3. Uncomment `backend "s3" {}` in `main.tf`.

Then:

```bash
cd infra/terraform
terraform init -backend-config=backend.hcl
```

A plan with the backend left commented out still works and writes
`terraform.tfstate` locally; that is acceptable for a plan and never for an apply.

## 3. Variables

Everything has a default, so a first plan needs no variables. Set the ones below
on purpose rather than by accident:

- `region` (default `us-east-1`): must match the backend region and the region
  the deploy key parameter lives in.
- `base_domain` (default `vendettacyber.com`): the zone the module hosts sit in.
  Only used when `enable_alb` is on.
- `enable_alb` (default `false`): leave it off for the first plan and the first
  apply. See the note on the certificate below.
- `modules`: the deployed set. The default deploys all eight (platform,
  incident-response, managed-services, dark-web-monitoring,
  vulnerability-management, penetration-testing, sabine, professional-services).
  To hold one back, override the map with `deploy = false` on that key.
- `alert_emails` (default empty): each address becomes an SNS subscription the
  recipient must confirm.
- `repo_url` and `git_ref`: what the host clones on first boot. The deploy key is
  read from SSM at `<ssm_prefix>/DEPLOY_KEY`; it is not a Terraform input and must
  be in SSM before the first apply, not before the plan.

Put overrides in `terraform.tfvars` (git-ignored) or pass `-var`:

```bash
terraform plan -out=first.tfplan
terraform plan -out=first.tfplan -var region=us-east-2 -var 'alert_emails=["soc@vendettacd.io"]'
```

Do not pass `-var enable_alb=true` on the first plan. With the ALB on and a
`hosted_zone_id`, the certificate validation records are built from
`aws_acm_certificate.alb[0].domain_validation_options`, which Terraform cannot
know until the certificate exists, and the plan stops on that `for_each`. Apply
the host first, then enable the ALB as a second apply, as the README describes.

## 4. IAM permissions the runner needs

A plan with no existing state makes only read calls. Apply needs the write
permissions for every resource type in the stack. The simplest honest answer for
the person running the first apply is `AdministratorAccess` on a dedicated
deployment role; for a least-privilege role, the actions are:

Plan (read only):

- `sts:GetCallerIdentity`
- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeImages`
- `s3:ListBucket`, `s3:GetObject`, `s3:PutObject` on the state bucket and
  `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` on the lock table
  (the lock is taken even for a plan)

Apply (in addition, scoped to the account and region where possible):

- EC2: security groups and rules, instances, volumes, instance metadata
  options, key-less launch (`ec2:RunInstances`, `ec2:CreateSecurityGroup`,
  `ec2:AuthorizeSecurityGroup*`, `ec2:RevokeSecurityGroup*`, `ec2:CreateTags`,
  `ec2:Describe*`, `ec2:TerminateInstances`, `ec2:ModifyInstance*`)
- IAM: roles, inline and attached policies, instance profiles
  (`iam:CreateRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`,
  `iam:CreateInstanceProfile`, `iam:AddRoleToInstanceProfile`, `iam:PassRole`,
  `iam:Get*`, `iam:List*`, and the matching delete and detach actions)
- S3: both buckets with versioning, object lock, encryption, public access
  block and lifecycle (`s3:CreateBucket`, `s3:PutBucketVersioning`,
  `s3:PutBucketObjectLockConfiguration`, `s3:PutEncryptionConfiguration`,
  `s3:PutBucketPublicAccessBlock`, `s3:PutLifecycleConfiguration`,
  `s3:GetBucket*`, `s3:GetEncryptionConfiguration`, `s3:GetLifecycleConfiguration`,
  `s3:PutBucketTagging`, `s3:DeleteBucket`)
- SSM: `ssm:PutParameter`, `ssm:GetParameter`, `ssm:GetParameters`,
  `ssm:DeleteParameter`, `ssm:AddTagsToResource`, `ssm:ListTagsForResource`
  on `arn:aws:ssm:<region>:<account>:parameter/vendetta/*`
- SNS: `sns:CreateTopic`, `sns:Subscribe`, `sns:Unsubscribe`, `sns:GetTopicAttributes`,
  `sns:SetTopicAttributes`, `sns:ListTagsForResource`, `sns:TagResource`, `sns:DeleteTopic`
- CloudWatch: `cloudwatch:PutMetricAlarm`, `cloudwatch:DescribeAlarms`,
  `cloudwatch:DeleteAlarms`, `cloudwatch:ListTagsForResource`
- DLM: `dlm:CreateLifecyclePolicy`, `dlm:GetLifecyclePolicy`,
  `dlm:UpdateLifecyclePolicy`, `dlm:DeleteLifecyclePolicy`, plus `iam:PassRole`
  on the DLM role
- With the ALB on: `elasticloadbalancing:*` on the load balancer, target groups,
  listeners and rules; `acm:RequestCertificate`, `acm:DescribeCertificate`,
  `acm:DeleteCertificate`, `acm:AddTagsToCertificate`; and
  `route53:ChangeResourceRecordSets`, `route53:GetChange`, `route53:ListResourceRecordSets`
  on the hosted zone

The instance itself gets its own role from the stack (SSM core, the two buckets,
the alert topic, the `/vendetta/*` parameters and the container log group); the
runner role is separate and is only used by Terraform.

## 5. What a clean first plan shows

With the defaults (eight modules deployed, `enable_alb = false`, no alert
emails) a first plan against an empty account ends with:

```
Plan: 146 to add, 0 to change, 0 to destroy.
```

Counted by type:

- `random_password`: 33 (SECRET_KEY, POSTGRES_PASSWORD, API_TOKEN and
  ADMIN_PASSWORD for each of 8 modules, plus SABINE's kiosk token)
- `random_bytes`: 14 (ENCRYPTION_KEY for 8 modules, EVIDENCE_SIGNING_KEY for the
  6 signing modules)
- `aws_ssm_parameter`: 77 (per module: SECRET_KEY, POSTGRES_PASSWORD, API_TOKEN,
  ENCRYPTION_KEY, ADMIN_PASSWORD, ADMIN_PASSWORD_HASH and `_defaults` = 48;
  EVIDENCE_SIGNING_KEY 6; PLATFORM_TOKEN in the 7 client modules; PLATFORM_HUB_TOKEN
  in the 4 finding modules and the Office of Special Projects = 5; the platform's
  MODULE_DIRECTORY; SABINE's MODULE_DIRECTORY and KIOSK_TOKEN)
- `aws_s3_bucket` 2, with `aws_s3_bucket_versioning` 2,
  `aws_s3_bucket_server_side_encryption_configuration` 2,
  `aws_s3_bucket_public_access_block` 2, `aws_s3_bucket_lifecycle_configuration` 2
  and `aws_s3_bucket_object_lock_configuration` 1 (evidence only) = 11
- `aws_iam_role` 2, `aws_iam_role_policy_attachment` 2, `aws_iam_role_policy` 1,
  `aws_iam_instance_profile` 1 = 6
- `aws_security_group` 1 (the instance; no ingress rules while the ALB is off)
- `aws_sns_topic` 1 (`aws_sns_topic_subscription` adds one per alert email)
- `aws_instance` 1, `aws_cloudwatch_metric_alarm` 1, `aws_dlm_lifecycle_policy` 1

Every `aws_ssm_parameter` value shows as `(sensitive value)`. The
`ADMIN_PASSWORD_HASH` parameters carry `ignore_changes = [value]`, so they are
written once and later plans never try to rewrite them. Four data sources are
read and do not count: the caller identity, the default VPC and its subnets, and
the latest AL2023 arm64 AMI.

Anything other than `0 to change, 0 to destroy` on a first plan means the account
is not empty (a bucket or parameter with the same name already exists) and must be
looked at before apply.

Turning the ALB on afterwards (`-var enable_alb=true -var hosted_zone_id=...`,
with the host already applied) adds 54: 8 `aws_security_group_rule`, 1 ALB
security group, 1 `aws_lb`, 8 target groups, 8 attachments, 2 listeners, 8
listener rules, 1 certificate, 8 validation records, 1 validation and 8 alias
records; and changes 10 in place: the 8 `_defaults` parameters (bind address,
secure cookies, public URL) and the two MODULE_DIRECTORY parameters (public URLs).
Bringing your own certificate (`acm_certificate_arn`) drops the certificate, its
validation and the 8 validation records from that count.

## 6. After the plan

Keep `first.tfplan` only long enough to apply it; it contains the generated
secrets in plaintext. Do not commit it. `terraform apply first.tfplan` is the
first step of GO_LIVE.md section 1.
