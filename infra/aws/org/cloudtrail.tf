# Organization CloudTrail from the management account, delivered to a
# retention-locked bucket in the log-archive account. The same bucket receives
# VPC flow logs from every member account (modules/vpc).

data "aws_caller_identity" "management" {}

locals {
  management_id    = data.aws_caller_identity.management.account_id
  org_id           = aws_organizations_organization.this.id
  trail_name       = "vcd-soc-org-trail"
  trail_arn        = "arn:aws:cloudtrail:${var.region}:${local.management_id}:trail/${local.trail_name}"
  log_archive_id   = local.account_ids["log-archive"]
  log_archive_name = "vcd-soc-log-archive-${local.log_archive_id}"
  log_archive_arn  = "arn:aws:s3:::${local.log_archive_name}"
  all_account_ids  = concat([local.management_id], values(local.account_ids))
  log_reader_accts = [local.account_ids["security-tooling"], local.account_ids["data-lake"]]
}

# ------------------------------------------------------------------ KMS
data "aws_iam_policy_document" "cloudtrail_key" {
  statement {
    sid       = "LogArchiveAccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.log_archive_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.management_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailDescribe"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "FlowLogDelivery"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = local.all_account_ids
    }
  }

  statement {
    sid       = "SecurityReaders"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [for a in local.log_reader_accts : "arn:aws:iam::${a}:root"]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  provider                = aws.log_archive
  description             = "vcd-soc organization CloudTrail and flow log archive"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.cloudtrail_key.json
}

resource "aws_kms_alias" "cloudtrail" {
  provider      = aws.log_archive
  name          = "alias/vcd-soc-log-archive"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# ------------------------------------------------------------------ bucket
data "aws_iam_policy_document" "log_archive_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.log_archive_arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "CloudTrailWrite"
    actions = ["s3:PutObject"]
    resources = [
      "${local.log_archive_arn}/AWSLogs/${local.management_id}/*",
      "${local.log_archive_arn}/AWSLogs/${local.org_id}/*",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "FlowLogAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [local.log_archive_arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = local.all_account_ids
    }
  }

  statement {
    sid       = "FlowLogWrite"
    actions   = ["s3:PutObject"]
    resources = ["${local.log_archive_arn}/AWSLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = local.all_account_ids
    }
  }

  statement {
    sid       = "SecurityReaders"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [local.log_archive_arn, "${local.log_archive_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [for a in local.log_reader_accts : "arn:aws:iam::${a}:root"]
    }
  }
}

module "log_archive_bucket" {
  source    = "../modules/secure-bucket"
  providers = { aws = aws.log_archive }

  name                       = local.log_archive_name
  kms_key_arn                = aws_kms_key.cloudtrail.arn
  object_lock_mode           = var.log_archive_object_lock_mode
  object_lock_retention_days = var.log_archive_retention_days
  noncurrent_expiration_days = var.log_archive_retention_days
  lifecycle_transitions = [
    { days = 90, storage_class = "GLACIER_IR" },
    { days = 395, storage_class = "DEEP_ARCHIVE" },
  ]
  policy_json = data.aws_iam_policy_document.log_archive_bucket.json
}

# ------------------------------------------------------------------ trail
resource "aws_cloudtrail" "org" {
  name                          = local.trail_name
  s3_bucket_name                = module.log_archive_bucket.id
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  depends_on = [module.log_archive_bucket, aws_organizations_organization.this]
}
