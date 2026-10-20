# Ledger anchor bucket (COMPLIANCE Object Lock) replicated to a second region,
# where the replica bucket is locked the same way.

locals {
  ledger_name  = "vcd-soc-ledger-${local.account_id}"
  ledger_arn   = "arn:aws:s3:::${local.ledger_name}"
  replica_name = "vcd-soc-ledger-replica-${local.account_id}"
}

data "aws_iam_policy_document" "ledger_bucket" {
  # Append-only: no principal deletes an object or a version, even after
  # retention expires. Retiring old anchors is a deliberate policy change.
  statement {
    sid       = "AppendOnly"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${local.ledger_arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  dynamic "statement" {
    for_each = length(var.ledger_writer_principal_arns) > 0 ? [1] : []
    content {
      sid       = "LedgerWriters"
      actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:ListBucket"]
      resources = [local.ledger_arn, "${local.ledger_arn}/*"]
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
        values   = var.ledger_writer_principal_arns
      }
    }
  }
}

module "ledger" {
  source = "../modules/secure-bucket"

  name                       = local.ledger_name
  kms_key_arn                = aws_kms_key.ledger.arn
  object_lock_mode           = var.object_lock_mode
  object_lock_retention_days = var.retention_days
  policy_json                = data.aws_iam_policy_document.ledger_bucket.json
}

module "replica" {
  source    = "../modules/secure-bucket"
  providers = { aws = aws.replica }

  name                       = local.replica_name
  kms_key_arn                = aws_kms_key.replica.arn
  object_lock_mode           = var.object_lock_mode
  object_lock_retention_days = var.retention_days
}

resource "aws_s3_bucket_replication_configuration" "ledger" {
  bucket = module.ledger.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"
    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = module.replica.arn
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica.arn
      }
    }
  }

  depends_on = [module.ledger, module.replica, aws_iam_role_policy.replication]
}
