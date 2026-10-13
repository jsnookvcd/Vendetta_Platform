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
    sid       = "EvidenceWrite"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:GetObjectRetention"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
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
# Per-module secret key and Postgres password, generated here and stored as
# SecureString so they never land in plaintext anywhere but SSM.
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

# Non-secret defaults per module: bind to the host port behind the ALB, the shared
# bucket and SNS, and the on-host cross-module URLs. The modules reach each other
# over localhost on one box. The bearer tokens that authenticate those calls are
# set after first boot (platform -> modules on the Connections page; modules ->
# platform via <ssm_prefix>/<module>/PLATFORM_TOKEN), since each is derived from a
# module's own SECRET_KEY.
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
    },
    contains(["dark-web-monitoring", "incident-response"], each.key) ? {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
    } : {},
    # Modules that read the platform roster point at the on-host control plane.
    contains(["dark-web-monitoring", "incident-response", "managed-services"], each.key) ? {
      PLATFORM_URL = "http://localhost:8300"
    } : {},
    # Modules that escalate point at the on-host IR hub.
    contains(["dark-web-monitoring", "managed-services"], each.key) ? {
      PLATFORM_HUB_URL = "http://localhost:8100"
    } : {},
    each.key == "platform" && var.enable_alb && var.base_domain != "" ? {
      PUBLIC_URL = "https://${var.module_hosts["platform"]}.${var.base_domain}"
    } : {}
  ))
  lifecycle {
    ignore_changes = [value]
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
