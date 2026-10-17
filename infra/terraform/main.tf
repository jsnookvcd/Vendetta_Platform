terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state. State holds every generated secret (SSM values, admin
  # passwords), so it belongs in a private, versioned, encrypted bucket with a
  # lock table, never on a laptop. Uncomment, then pass the bucket details at
  # init time from a copy of backend.hcl.example:
  #   terraform init -backend-config=backend.hcl
  # CI keeps running validate with -backend=false, which ignores this block.
  # backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "vendetta-platform"
      Owner     = "Vendetta Cloud Team"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "me" {}

locals {
  deployed = { for k, m in var.modules : k => m if m.deploy }
}

# ------------------------------------------------------------------ network
# Default VPC, public subnet. The instance has no inbound rules except, when the
# ALB is on, the module ports from the ALB security group. Otherwise access is
# only through SSM Session Manager port forwarding.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "instance" {
  name        = "${var.name_prefix}-instance"
  description = "Vendetta Platform host: egress only, plus module ports from the ALB when enabled"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Each deployed module's port is reachable only from the ALB security group.
resource "aws_security_group_rule" "from_alb" {
  for_each                 = var.enable_alb ? local.deployed : {}
  type                     = "ingress"
  security_group_id        = aws_security_group.instance.id
  from_port                = each.value.port
  to_port                  = each.value.port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb[0].id
  description              = "ALB to ${each.key}"
}

# ------------------------------------------------------------------ shared evidence bucket
resource "aws_s3_bucket" "evidence" {
  bucket              = "${var.name_prefix}-evidence-${data.aws_caller_identity.me.account_id}"
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.evidence_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "tier-down"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }
    noncurrent_version_expiration {
      noncurrent_days = var.evidence_retention_days
    }
  }
}

# ------------------------------------------------------------------ alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ------------------------------------------------------------------ IAM
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name_prefix}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid     = "EvidenceWrite"
    actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:GetObjectRetention"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*",
    aws_s3_bucket.backups.arn, "${aws_s3_bucket.backups.arn}/*"]
  }
  statement {
    sid       = "Alerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "Config"
    actions   = ["ssm:GetParametersByPath", "ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.me.account_id}:parameter${var.ssm_prefix}/*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.me.account_id}:log-group:/vendetta/*"]
  }
}

resource "aws_iam_role_policy" "instance" {
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-instance"
  role = aws_iam_role.instance.name
}

# ------------------------------------------------------------------ config in SSM
# Every secret a module needs is generated here and stored as a SecureString, so a
# fresh host boots fully wired: session secret, Postgres password, a dedicated
# service bearer token, the at-rest encryption key, the evidence signing key where
# the module signs a chain, and a break-glass admin password. Nothing is derived
# from SECRET_KEY on the host and nothing has to be typed in after first boot.
resource "random_password" "secret_key" {
  for_each = local.deployed
  length   = 64
  special  = false
}

resource "random_password" "pg" {
  for_each = local.deployed
  length   = 32
  special  = false
}

# Service-to-service bearer token per module (the value other modules present).
resource "random_password" "api_token" {
  for_each = local.deployed
  length   = 48
  special  = false
}

# Fernet key: urlsafe base64 of 32 random bytes.
resource "random_bytes" "encryption_key" {
  for_each = local.deployed
  length   = 32
}

# Ed25519 seed for the chain-of-custody signer, hex, in the modules that sign one.
resource "random_bytes" "evidence_signing_key" {
  for_each = { for k, m in local.deployed : k => m if contains(local.signing_modules, k) }
  length   = 32
}

# Break-glass local admin. The plaintext is kept in SSM for the operator to read
# once (aws ssm get-parameter --with-decryption --name <prefix>/<module>/ADMIN_PASSWORD);
# the host only ever renders the bcrypt hash into .env.
resource "random_password" "admin" {
  for_each = local.deployed
  length   = 24
  special  = false
}

locals {
  signing_modules = ["incident-response", "managed-services", "vulnerability-management", "penetration-testing", "sabine", "professional-services", "mdr"]
  finding_modules = ["dark-web-monitoring", "managed-services", "vulnerability-management", "penetration-testing", "mdr"]
  # Modules that escalate into the IR hub: the finding modules, plus the Office of
  # Special Projects, which opens a case from an engagement without serving findings.
  hub_modules    = concat(local.finding_modules, ["professional-services"])
  client_modules = [for k in keys(local.deployed) : k if k != "platform"]
  # Modules that serve findings or clients, as the control plane's directory lists
  # them (SABINE is an agent over the platform, not a module the platform pushes to).
  directory_modules = [for k in local.client_modules : k if k != "sabine"]

  # Service addresses on the shared docker network ("vendetta"): each module's web
  # container is reachable by its module key on port 8000 from any other container.
  service_url = { for k, m in local.deployed : k => "http://${k}:8000" }
  public_url  = { for k, m in local.deployed : k => (var.enable_alb && var.base_domain != "" ? "https://${lookup(var.module_hosts, k, k)}.${var.base_domain}" : "") }

  # What the control plane needs to wire every module without hand entry.
  module_directory = {
    for k in local.directory_modules : k => {
      base_url   = local.service_url[k]
      token      = random_password.api_token[k].result
      public_url = local.public_url[k]
    }
  }
}

resource "aws_ssm_parameter" "secret_key" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/SECRET_KEY"
  type     = "SecureString"
  value    = random_password.secret_key[each.key].result
}

resource "aws_ssm_parameter" "pg" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/POSTGRES_PASSWORD"
  type     = "SecureString"
  value    = random_password.pg[each.key].result
}

resource "aws_ssm_parameter" "api_token" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/API_TOKEN"
  type     = "SecureString"
  value    = random_password.api_token[each.key].result
}

# The encryption key and the evidence signing key are written once and never
# rotated by Terraform. Replacing the encryption key makes every stored secret
# unreadable; replacing the signing key breaks verification of every chain already
# signed. A key that already exists in SSM (set by hand before Terraform managed it)
# is imported and kept as it is.
resource "aws_ssm_parameter" "encryption_key" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/ENCRYPTION_KEY"
  type     = "SecureString"
  value    = replace(replace(random_bytes.encryption_key[each.key].base64, "+", "-"), "/", "_")
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "evidence_signing_key" {
  for_each = random_bytes.evidence_signing_key
  name     = "${var.ssm_prefix}/${each.key}/EVIDENCE_SIGNING_KEY"
  type     = "SecureString"
  value    = each.value.hex
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "admin_password" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/ADMIN_PASSWORD"
  type     = "SecureString"
  value    = random_password.admin[each.key].result
}

# bcrypt() salts freshly on every plan, so the hash is written once and then left
# alone; the password it hashes never changes unless the random resource is tainted.
resource "aws_ssm_parameter" "admin_password_hash" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/ADMIN_PASSWORD_HASH"
  type     = "SecureString"
  value    = bcrypt(random_password.admin[each.key].result, 12)
  lifecycle {
    ignore_changes = [value]
  }
}

# Each client module authenticates to the control plane with the platform's token,
# and modules that escalate authenticate to the hub with the hub's token.
resource "aws_ssm_parameter" "platform_token" {
  for_each = toset(local.client_modules)
  name     = "${var.ssm_prefix}/${each.key}/PLATFORM_TOKEN"
  type     = "SecureString"
  value    = random_password.api_token["platform"].result
}

resource "aws_ssm_parameter" "hub_token" {
  for_each = toset([for k in local.hub_modules : k if contains(keys(local.deployed), k) && contains(keys(local.deployed), "incident-response")])
  name     = "${var.ssm_prefix}/${each.key}/PLATFORM_HUB_TOKEN"
  type     = "SecureString"
  value    = random_password.api_token["incident-response"].result
}

# The control plane's module directory: service URL, token and public URL per
# module, applied at startup to any module row that is still blank.
resource "aws_ssm_parameter" "module_directory" {
  count = contains(keys(local.deployed), "platform") ? 1 : 0
  name  = "${var.ssm_prefix}/platform/MODULE_DIRECTORY"
  type  = "SecureString"
  tier  = "Advanced"
  value = jsonencode(local.module_directory)
}

# MDR pulls signals from managed services with the managed-services API token.
resource "aws_ssm_parameter" "mdr_signal_token" {
  count = contains(keys(local.deployed), "mdr") && contains(keys(local.deployed), "managed-services") ? 1 : 0
  name  = "${var.ssm_prefix}/mdr/MANAGED_SERVICES_TOKEN"
  type  = "SecureString"
  value = random_password.api_token["managed-services"].result
}

# SABINE's board: the wall-display token (open <sabine host>/board?k=<token> once on
# the display; it keeps a cookie from then on).
resource "random_password" "kiosk" {
  count   = contains(keys(local.deployed), "sabine") ? 1 : 0
  length  = 40
  special = false
}

resource "aws_ssm_parameter" "kiosk_token" {
  count = contains(keys(local.deployed), "sabine") ? 1 : 0
  name  = "${var.ssm_prefix}/sabine/KIOSK_TOKEN"
  type  = "SecureString"
  value = random_password.kiosk[0].result
}

# SABINE's reach: every deployed module including the control plane and the hub,
# each with its own token, so the brain acts through each module's API as itself.
resource "aws_ssm_parameter" "sabine_directory" {
  count = contains(keys(local.deployed), "sabine") ? 1 : 0
  name  = "${var.ssm_prefix}/sabine/MODULE_DIRECTORY"
  type  = "SecureString"
  tier  = "Advanced"
  value = jsonencode({
    for k in keys(local.deployed) : k => {
      base_url   = local.service_url[k]
      token      = random_password.api_token[k].result
      public_url = local.public_url[k]
    } if k != "sabine"
  })
}

# Non-secret defaults per module. Rendered into .env at first boot and again on
# every redeploy (infra/redeploy.sh), so a change here reaches the containers on
# the next deploy.
resource "aws_ssm_parameter" "common" {
  for_each = local.deployed
  name     = "${var.ssm_prefix}/${each.key}/_defaults"
  type     = "String"
  tier     = "Advanced"
  value = jsonencode(merge(
    {
      MODULE_ENABLED = "true"
      ADMIN_USER     = "admin"
      WEB_BIND       = var.enable_alb ? "0.0.0.0" : "127.0.0.1"
      COOKIE_SECURE  = var.enable_alb ? "true" : "false"
      AWS_REGION     = var.region
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      BACKUP_BUCKET  = aws_s3_bucket.backups.id
    },
    local.public_url[each.key] != "" ? { PUBLIC_URL = local.public_url[each.key] } : {},
    contains(["dark-web-monitoring", "incident-response"], each.key) ? {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
    } : {},
    # Every client module pulls its roster from the control plane by service name
    # and links people back to the control plane's public URL.
    each.key != "platform" && contains(keys(local.deployed), "platform") ? merge(
      { PLATFORM_URL = local.service_url["platform"] },
      local.public_url["platform"] != "" ? { PLATFORM_PUBLIC_URL = local.public_url["platform"] } : {}
    ) : {},
    # Finding modules and the Office of Special Projects escalate into the hub by service name.
    contains(local.hub_modules, each.key) && contains(keys(local.deployed), "incident-response") ? {
      PLATFORM_HUB_URL = local.service_url["incident-response"]
    } : {},
    # Managed services starts read-only: no tool action can fire until an operator
    # sets <prefix>/managed-services/ACTIONS_READONLY=false and redeploys.
    each.key == "managed-services" ? { ACTIONS_READONLY = "true" } : {},
    # MDR reads its signals from managed services by service name and links a
    # responder to the managed-services alert page for any containment hand-off.
    each.key == "mdr" && contains(keys(local.deployed), "managed-services") ? merge(
      { MANAGED_SERVICES_URL = local.service_url["managed-services"] },
      local.public_url["managed-services"] != "" ? { MANAGED_SERVICES_PUBLIC_URL = local.public_url["managed-services"] } : {}
    ) : {},
    # SABINE speaks in Azure's Jane (Dragon HD) once an operator adds
    # <prefix>/sabine/AZURE_SPEECH_KEY (SecureString) and AZURE_SPEECH_REGION and
    # redeploys; until then she falls back to the browser's own voice.
    each.key == "sabine" ? {
      TTS_PROVIDER       = "azure"
      AZURE_SPEECH_VOICE = "en-US-Jane:DragonHDLatestNeural"
    } : {}
  ))
}

# ------------------------------------------------------------------ backups
# Nightly Postgres dumps from every module stack (infra/host/vendetta-backup).
resource "aws_s3_bucket" "backups" {
  bucket        = "${var.name_prefix}-backups-${data.aws_caller_identity.me.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.backup_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# ------------------------------------------------------------------ instance
data "aws_ami" "al2023_arm" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-arm64"]
  }
}

resource "aws_instance" "host" {
  ami                         = data.aws_ami.al2023_arm.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
    tags                  = { Name = "${var.name_prefix}-host" }
  }

  metadata_options {
    http_tokens = "required"
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    repo_url    = var.repo_url
    git_ref     = var.git_ref
    ssm_prefix  = var.ssm_prefix
    region      = var.region
    modules_csv = join(",", [for k, m in local.deployed : "${k}:${m.subdir}:${m.port}"])
  })

  tags = { Name = "${var.name_prefix}-host" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_cloudwatch_metric_alarm" "recover" {
  alarm_name          = "${var.name_prefix}-auto-recover"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { InstanceId = aws_instance.host.id }
  alarm_actions       = ["arn:aws:automate:${var.region}:ec2:recover"]
}

resource "aws_dlm_lifecycle_policy" "daily" {
  description        = "vendetta platform daily snapshot"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { Name = "${var.name_prefix}-host" }
    schedule {
      name = "daily"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["06:00"]
      }
      retain_rule {
        count = 7
      }
      copy_tags = true
    }
  }
}

resource "aws_iam_role" "dlm" {
  name = "${var.name_prefix}-dlm"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "dlm.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}
