# Hardened S3 bucket used by every stack that keeps records: owner-enforced
# ownership, public access blocked, versioning on, SSE-KMS with a bucket key,
# optional Object Lock, optional lifecycle tiers, and a bucket policy that denies
# any request without TLS 1.2 or later. Callers append their own statements
# through var.policy_json.

locals {
  object_lock = var.object_lock_mode != null
  lifecycle   = length(var.lifecycle_transitions) > 0 || var.expiration_days != null || var.noncurrent_expiration_days != null
}

resource "aws_s3_bucket" "this" {
  bucket              = var.name
  object_lock_enabled = local.object_lock
  force_destroy       = false
  tags = merge(var.tags, local.object_lock ? {
    "vendetta:retention" = "locked"
  } : {})
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  for_each = local.object_lock ? toset(["this"]) : toset([])
  bucket   = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each = local.lifecycle ? toset(["this"]) : toset([])
  bucket   = aws_s3_bucket.this.id

  rule {
    id     = "tiering"
    status = "Enabled"
    filter {}

    dynamic "transition" {
      for_each = var.lifecycle_transitions
      content {
        days          = transition.value.days
        storage_class = transition.value.storage_class
      }
    }

    dynamic "expiration" {
      for_each = var.expiration_days == null ? [] : [var.expiration_days]
      content {
        days = expiration.value
      }
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.noncurrent_expiration_days == null ? [] : [var.noncurrent_expiration_days]
      content {
        noncurrent_days = noncurrent_version_expiration.value
      }
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

data "aws_iam_policy_document" "combined" {
  source_policy_documents = compact([data.aws_iam_policy_document.tls.json, var.policy_json])
}

resource "aws_s3_bucket_policy" "this" {
  bucket     = aws_s3_bucket.this.id
  policy     = data.aws_iam_policy_document.combined.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
