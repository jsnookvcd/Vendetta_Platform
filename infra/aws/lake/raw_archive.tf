# Raw archive: every event exactly as the connector received it, before
# normalization, partitioned by Firehose as
#   tenant=<id>/source=<family>/yyyy/MM/dd/
# Object Lock keeps it immutable for raw_retention_days. Only the ingest
# pipeline roles can write; everyone else is denied PutObject.

locals {
  raw_bucket_name = "vcd-soc-raw-${local.account_id}"
  raw_bucket_arn  = "arn:aws:s3:::${local.raw_bucket_name}"
}

data "aws_iam_policy_document" "raw_bucket" {
  statement {
    sid       = "PipelineWrite"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${local.raw_bucket_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.ingest_account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.pipeline_arns
    }
  }

  statement {
    sid       = "PipelineBucketRead"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [local.raw_bucket_arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.ingest_account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.pipeline_arns
    }
  }

  statement {
    sid       = "DenyWritesFromAnyoneElse"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.raw_bucket_arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.pipeline_arns
    }
  }
}

module "raw_bucket" {
  source = "../modules/secure-bucket"

  name                       = local.raw_bucket_name
  kms_key_arn                = aws_kms_key.raw.arn
  object_lock_mode           = var.raw_object_lock_mode
  object_lock_retention_days = var.raw_retention_days
  noncurrent_expiration_days = var.raw_retention_days
  lifecycle_transitions = [
    { days = 90, storage_class = "GLACIER_IR" },
    { days = 395, storage_class = "DEEP_ARCHIVE" },
  ]
  policy_json = data.aws_iam_policy_document.raw_bucket.json
}
