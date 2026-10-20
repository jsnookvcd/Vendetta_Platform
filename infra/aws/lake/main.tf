# Amazon Security Lake in the data-lake account (the delegated administrator
# registered by the org stack). Normalized OCSF data lands in the
# aws-security-data-lake-<region>-<id> buckets Security Lake creates.

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "meta_store_manager" {
  name               = "vcd-soc-securitylake-metastore"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "meta_store_manager" {
  role       = aws_iam_role.meta_store_manager.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeMetastoreManager"
}

# aws_securitylake_data_lake takes one configuration block, for the region of
# its provider, so each region is its own resource: the primary here and the
# secondary through the aws.secondary provider.
locals {
  lake_regions = var.enable_secondary_region ? [var.region, var.secondary_region] : [var.region]
}

resource "aws_securitylake_data_lake" "this" {
  meta_store_manager_role_arn = aws_iam_role.meta_store_manager.arn

  configuration {
    region = var.region

    encryption_configuration {
      kms_key_id = aws_kms_key.lake.arn
    }

    lifecycle_configuration {
      transition {
        days          = var.security_lake_transition_days
        storage_class = "GLACIER_IR"
      }
      expiration {
        days = var.security_lake_expiration_days
      }
    }
  }

  depends_on = [aws_iam_role_policy_attachment.meta_store_manager]
}

resource "aws_securitylake_data_lake" "secondary" {
  for_each                    = var.enable_secondary_region ? toset(["this"]) : toset([])
  provider                    = aws.secondary
  meta_store_manager_role_arn = aws_iam_role.meta_store_manager.arn

  configuration {
    region = var.secondary_region

    encryption_configuration {
      kms_key_id = aws_kms_replica_key.lake_secondary.arn
    }

    lifecycle_configuration {
      transition {
        days          = var.security_lake_transition_days
        storage_class = "GLACIER_IR"
      }
      expiration {
        days = var.security_lake_expiration_days
      }
    }
  }

  depends_on = [aws_iam_role_policy_attachment.meta_store_manager, aws_securitylake_data_lake.this]
}

# Creating several log sources at once can return ConflictException from the
# Security Lake API; if it does, re-run apply (or apply with -parallelism=1).
resource "aws_securitylake_aws_log_source" "this" {
  for_each = var.aws_log_sources

  source {
    accounts       = var.log_source_accounts
    regions        = local.lake_regions
    source_name    = each.key
    source_version = each.value
  }

  depends_on = [aws_securitylake_data_lake.this, aws_securitylake_data_lake.secondary]
}

# ------------------------------------------------------------------ custom sources
data "aws_iam_policy_document" "glue_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "crawler" {
  name               = "vcd-soc-securitylake-crawler"
  assume_role_policy = data.aws_iam_policy_document.glue_trust.json
}

resource "aws_iam_role_policy_attachment" "crawler_glue" {
  role       = aws_iam_role.crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

data "aws_iam_policy_document" "crawler" {
  statement {
    sid       = "ReadLakeBuckets"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::aws-security-data-lake-*", "arn:aws:s3:::aws-security-data-lake-*/*"]
  }
  statement {
    sid       = "LakeKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.lake.arn, aws_kms_replica_key.lake_secondary.arn]
  }
}

resource "aws_iam_role_policy" "crawler" {
  name   = "lake-buckets"
  role   = aws_iam_role.crawler.id
  policy = data.aws_iam_policy_document.crawler.json
}

resource "aws_securitylake_custom_log_source" "this" {
  for_each       = var.custom_sources
  source_name    = each.key
  source_version = "1.0"
  event_classes  = each.value

  configuration {
    crawler_configuration {
      role_arn = aws_iam_role.crawler.arn
    }
    provider_identity {
      external_id = var.custom_source_external_id
      principal   = var.ingest_account_id
    }
  }

  depends_on = [aws_securitylake_data_lake.this, aws_iam_role_policy.crawler]
}
