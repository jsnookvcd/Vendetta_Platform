data "aws_caller_identity" "current" {}

data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  pipeline_arns  = [for r in var.ingest_pipeline_role_names : "arn:aws:iam::${var.ingest_account_id}:role/${r}"]
  reader_pattern = concat(var.analyst_principal_patterns, var.evidence_principal_patterns)
}

# ------------------------------------------------------------------ Security Lake key
data "aws_iam_policy_document" "lake_key" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "S3AndGlueInAccount"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.*.amazonaws.com", "glue.*.amazonaws.com"]
    }
  }

  # Custom source writes arrive through the provider role Security Lake creates
  # in this account, so they are covered by the in-account statement above.

  statement {
    sid       = "OrgReaders"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.reader_pattern
    }
  }
}

resource "aws_kms_key" "lake" {
  description             = "vcd-soc Security Lake"
  enable_key_rotation     = true
  multi_region            = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.lake_key.json
}

resource "aws_kms_alias" "lake" {
  name          = "alias/vcd-soc-security-lake"
  target_key_id = aws_kms_key.lake.key_id
}

resource "aws_kms_replica_key" "lake_secondary" {
  provider                = aws.secondary
  description             = "vcd-soc Security Lake (replica)"
  primary_key_arn         = aws_kms_key.lake.arn
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.lake_key.json
}

resource "aws_kms_alias" "lake_secondary" {
  provider      = aws.secondary
  name          = "alias/vcd-soc-security-lake"
  target_key_id = aws_kms_replica_key.lake_secondary.key_id
}

# ------------------------------------------------------------------ raw archive key
data "aws_iam_policy_document" "raw_key" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "PipelineEncrypt"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
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

  # Multipart uploads read the data key back, so the pipeline also needs Decrypt
  # scoped to S3 in this region.
  statement {
    sid       = "PipelineMultipart"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.ingest_account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.pipeline_arns
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "Readers"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = local.reader_pattern
    }
  }
}

resource "aws_kms_key" "raw" {
  description             = "vcd-soc raw event archive"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.raw_key.json
}

resource "aws_kms_alias" "raw" {
  name          = "alias/vcd-soc-raw-archive"
  target_key_id = aws_kms_key.raw.key_id
}
