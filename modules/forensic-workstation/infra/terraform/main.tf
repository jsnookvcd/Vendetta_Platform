terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "forensic-workstation"
      Owner     = "Vendetta Cloud Team"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "me" {}
data "aws_partition" "p" {}

locals {
  account = data.aws_caller_identity.me.account_id
  name    = var.name_prefix
}

# ------------------------------------------------------------------ network
# No inbound rules at all. Analysts reach the box through SSM Session Manager
# (shell and port forwarding), so nothing listens on the internet. Egress is open
# for package installs, Bedrock, and the Microsoft symbol server that Volatility
# uses for PDBs. Supply subnet_id to place it in a private subnet with a NAT.
data "aws_vpc" "default" {
  count   = var.subnet_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == "" ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

data "aws_subnet" "chosen" {
  id = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.default[0].ids[0]
}

resource "aws_security_group" "ws" {
  name        = "${local.name}-ws"
  description = "Forensic workstation: egress only, access through SSM"
  vpc_id      = data.aws_subnet.chosen.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------------ encryption
resource "aws_kms_key" "fw" {
  description             = "Forensic workstation: case volume, evidence bucket, logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.p.partition}:iam::${local.account}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "fw" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.fw.key_id
}

# ------------------------------------------------------------------ evidence bucket
# intake/<case>/...   analysts upload acquisitions here from their laptops
# cases/<case>/...    workstation exports work product, reports and the custody log
# Object Lock keeps every version for evidence_retention_days. GOVERNANCE mode lets
# a principal with s3:BypassGovernanceRetention clean up a mistaken upload;
# switch to COMPLIANCE once the process is settled.
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name}-evidence-${local.account}"
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.fw.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "tier-down"
    status = "Enabled"
    filter {}
    transition {
      days          = 60
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }
  }
}

# ------------------------------------------------------------------ logging
# Every Session Manager session (keystrokes and output) lands here, and the MCP
# server's hash-chained audit log is shipped alongside it.
resource "aws_cloudwatch_log_group" "sessions" {
  name              = "/forensic-workstation/sessions"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.fw.arn
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/forensic-workstation/audit"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.fw.arn
}

# Custom session document: lands the analyst as the "analyst" Linux user and
# records the whole session. Kept separate from the account default document so
# the platform's other SSM usage is untouched.
resource "aws_ssm_document" "shell" {
  name            = "${local.name}-AnalystShell"
  document_type   = "Session"
  document_format = "JSON"
  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Forensic workstation analyst shell"
    sessionType   = "Standard_Stream"
    inputs = {
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.sessions.name
      cloudWatchEncryptionEnabled = true
      cloudWatchStreamingEnabled  = true
      kmsKeyId                    = aws_kms_key.fw.key_id
      runAsEnabled                = true
      runAsDefaultUser            = "analyst"
      idleSessionTimeout          = "60"
      shellProfile = {
        linux = "cd /cases && exec bash -l"
      }
    }
  })
}

# ------------------------------------------------------------------ instance role
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ws" {
  name               = "${local.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ws.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "ws" {
  # Claude through Amazon Bedrock, so evidence content stays inside this AWS
  # account and region boundary. Cross-region inference profiles route to the
  # foundation model in other US regions, hence the wildcard region.
  dynamic "statement" {
    for_each = var.claude_backend == "bedrock" ? [1] : []
    content {
      sid = "ClaudeOnBedrock"
      actions = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:GetInferenceProfile",
      ]
      resources = [
        "arn:${data.aws_partition.p.partition}:bedrock:*::foundation-model/anthropic.*",
        "arn:${data.aws_partition.p.partition}:bedrock:*:${local.account}:inference-profile/*",
        "arn:${data.aws_partition.p.partition}:bedrock:*:${local.account}:application-inference-profile/*",
      ]
    }
  }

  # Bedrock list calls are not resource scoped.
  dynamic "statement" {
    for_each = var.claude_backend == "bedrock" ? [1] : []
    content {
      sid       = "BedrockList"
      actions   = ["bedrock:ListInferenceProfiles", "bedrock:ListFoundationModels"]
      resources = ["*"]
    }
  }

  statement {
    sid       = "EvidenceRead"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectRetention"]
    resources = ["${aws_s3_bucket.evidence.arn}/intake/*", "${aws_s3_bucket.evidence.arn}/cases/*"]
  }

  # Write only under cases/. The workstation can never overwrite intake.
  statement {
    sid       = "WorkProductWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/cases/*"]
  }

  statement {
    sid       = "EvidenceList"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid       = "Kms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.fw.arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"]
    resources = ["${aws_cloudwatch_log_group.sessions.arn}:*", "${aws_cloudwatch_log_group.audit.arn}:*", aws_cloudwatch_log_group.sessions.arn, aws_cloudwatch_log_group.audit.arn]
  }

  statement {
    sid       = "Config"
    actions   = ["ssm:GetParameter", "ssm:GetParametersByPath"]
    resources = ["arn:${data.aws_partition.p.partition}:ssm:${var.region}:${local.account}:parameter${var.ssm_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "ws" {
  role   = aws_iam_role.ws.id
  policy = data.aws_iam_policy_document.ws.json
}

resource "aws_iam_instance_profile" "ws" {
  name = "${local.name}-instance"
  role = aws_iam_role.ws.name
}

# ------------------------------------------------------------------ analyst access policy
# Attach this to the analysts' IAM group or SSO permission set. It allows a shell
# and port forwarding to this instance only, and uploads into intake/.
data "aws_iam_policy_document" "analyst" {
  statement {
    sid     = "StartSession"
    actions = ["ssm:StartSession"]
    resources = [
      aws_instance.ws.arn,
      aws_ssm_document.shell.arn,
      "arn:${data.aws_partition.p.partition}:ssm:${var.region}::document/AWS-StartPortForwardingSession",
    ]
  }
  statement {
    sid       = "ManageOwnSessions"
    actions   = ["ssm:TerminateSession", "ssm:ResumeSession"]
    resources = ["arn:${data.aws_partition.p.partition}:ssm:*:*:session/$${aws:userid}-*"]
  }
  statement {
    sid       = "StartStop"
    actions   = ["ec2:StartInstances", "ec2:StopInstances"]
    resources = [aws_instance.ws.arn]
  }
  statement {
    sid       = "Describe"
    actions   = ["ec2:DescribeInstances", "ssm:DescribeInstanceInformation", "ssm:GetConnectionStatus"]
    resources = ["*"]
  }
  statement {
    sid       = "IntakeUpload"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = ["${aws_s3_bucket.evidence.arn}/intake/*"]
  }
  statement {
    sid       = "ReadCases"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.evidence.arn}/cases/*", "${aws_s3_bucket.evidence.arn}/intake/*"]
  }
  statement {
    sid       = "ListBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }
  statement {
    sid       = "Kms"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.fw.arn]
  }
}

resource "aws_iam_policy" "analyst" {
  name        = "${local.name}-analyst"
  description = "Analyst access to the forensic workstation through SSM and evidence intake"
  policy      = data.aws_iam_policy_document.analyst.json
}

# ------------------------------------------------------------------ config in SSM
resource "aws_ssm_parameter" "config" {
  for_each = {
    EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
    AUDIT_LOG_GROUP = aws_cloudwatch_log_group.audit.name
    CLAUDE_BACKEND  = var.claude_backend
    CLAUDE_MODEL    = var.claude_model
    BEDROCK_REGION  = var.bedrock_region
  }
  name  = "${var.ssm_prefix}/${each.key}"
  type  = "String"
  value = each.value == "" ? "default" : each.value
}

# ANTHROPIC_API_KEY is only used when claude_backend = "anthropic". Add it out of
# band so it never lands in Terraform state:
#   aws ssm put-parameter --type SecureString --name <ssm_prefix>/ANTHROPIC_API_KEY --value sk-ant-...

# ------------------------------------------------------------------ instance
# Ubuntu 24.04 x86_64. Most free DFIR tooling targets Ubuntu, and several
# prebuilt binaries (EZ Tools on .NET, hayabusa, capa, floss) ship x86_64 first.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_instance" "ws" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnet.chosen.id
  vpc_security_group_ids      = [aws_security_group.ws.id]
  iam_instance_profile        = aws_iam_instance_profile.ws.name
  associate_public_ip_address = var.subnet_id == "" # default VPC needs a public IP for egress; no inbound exists

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    kms_key_id            = aws_kms_key.fw.arn
    delete_on_termination = true
    tags                  = { Name = "${local.name}-root" }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    repo_url       = var.repo_url
    git_ref        = var.git_ref
    module_subdir  = var.module_subdir
    ssm_prefix     = var.ssm_prefix
    region         = var.region
    enable_desktop = var.enable_desktop
  })

  tags = { Name = "${local.name}" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# Case data lives on its own volume so the OS can be rebuilt without touching
# cases, and so the volume can be snapshotted per case for preservation.
resource "aws_ebs_volume" "cases" {
  availability_zone = data.aws_subnet.chosen.availability_zone
  size              = var.cases_volume_gb
  type              = "gp3"
  throughput        = var.cases_volume_throughput
  iops              = var.cases_volume_iops
  encrypted         = true
  kms_key_id        = aws_kms_key.fw.arn
  tags              = { Name = "${local.name}-cases", Snapshot = "daily" }
}

resource "aws_volume_attachment" "cases" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.cases.id
  instance_id = aws_instance.ws.id
}

# ------------------------------------------------------------------ cost control
# Stop the instance after idle_stop_hours of low CPU. The case volume and its
# data persist across stop/start. Set idle_stop_hours = 0 to disable.
resource "aws_cloudwatch_metric_alarm" "idle_stop" {
  count               = var.idle_stop_hours > 0 ? 1 : 0
  alarm_name          = "${local.name}-idle-stop"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Maximum"
  period              = 3600
  evaluation_periods  = var.idle_stop_hours
  threshold           = 5
  comparison_operator = "LessThanThreshold"
  dimensions          = { InstanceId = aws_instance.ws.id }
  alarm_actions       = ["arn:${data.aws_partition.p.partition}:automate:${var.region}:ec2:stop"]
}

resource "aws_cloudwatch_metric_alarm" "recover" {
  alarm_name          = "${local.name}-auto-recover"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { InstanceId = aws_instance.ws.id }
  alarm_actions       = ["arn:${data.aws_partition.p.partition}:automate:${var.region}:ec2:recover"]
}

# Daily snapshot of the case volume, 14 kept.
resource "aws_dlm_lifecycle_policy" "cases" {
  description        = "forensic workstation case volume daily snapshot"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { Snapshot = "daily" }
    schedule {
      name = "daily"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["07:00"]
      }
      retain_rule {
        count = var.snapshot_retain_count
      }
      copy_tags = true
    }
  }
}

resource "aws_iam_role" "dlm" {
  name = "${local.name}-dlm"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "dlm.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

# DLM needs the CMK to snapshot an encrypted volume.
resource "aws_iam_role_policy" "dlm_kms" {
  role = aws_iam_role.dlm.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncrypt*"]
      Resource = aws_kms_key.fw.arn
    }]
  })
}
