# Two roles split key administration from key use.
#
#   vcd-soc-evidence-key-admin  : administers the keys (policy, rotation,
#                                 deletion schedule); cannot encrypt, decrypt or sign.
#   vcd-soc-evidence-custodian  : uses the keys; assumable only with MFA and an
#                                 "approver" session tag.
#
# KMS has no native two-person rule. This split plus the approver tag is a
# control and an audit trail; README.md states what it does and does not stop.

data "aws_caller_identity" "current" {}

data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  terraform_role = data.aws_iam_session_context.current.issuer_arn
}

data "aws_iam_policy_document" "key_admin_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.key_admin_principal_patterns
    }
  }
}

resource "aws_iam_role" "key_admin" {
  name                 = "vcd-soc-evidence-key-admin"
  assume_role_policy   = data.aws_iam_policy_document.key_admin_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "custodian_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.custodian_principal_patterns
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/approver"
      values   = ["?*"]
    }
    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "custodian" {
  name                 = "vcd-soc-evidence-custodian"
  assume_role_policy   = data.aws_iam_policy_document.custodian_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "custodian" {
  statement {
    sid = "Ledger"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:ListBucket", "s3:ListBucketVersions",
      "s3:GetObjectRetention", "s3:GetObjectLegalHold", "s3:PutObjectLegalHold",
    ]
    resources = [module.ledger.arn, "${module.ledger.arn}/*", module.replica.arn, "${module.replica.arn}/*"]
  }
  statement {
    sid       = "LedgerKeys"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.ledger.arn, aws_kms_key.replica.arn]
  }
  statement {
    sid       = "Sign"
    actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [aws_kms_key.signing.arn]
  }
}

resource "aws_iam_role_policy" "custodian" {
  name   = "evidence"
  role   = aws_iam_role.custodian.id
  policy = data.aws_iam_policy_document.custodian.json
}

# ------------------------------------------------------------------ replication
data "aws_iam_policy_document" "s3_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  name               = "vcd-soc-evidence-replication"
  assume_role_policy = data.aws_iam_policy_document.s3_trust.json
}

data "aws_iam_policy_document" "replication" {
  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [module.ledger.arn]
  }
  statement {
    actions = [
      "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention", "s3:GetObjectLegalHold",
    ]
    resources = ["${module.ledger.arn}/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"]
    resources = ["${module.replica.arn}/*"]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.ledger.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.replica.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.replica_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  name   = "replicate-ledger"
  role   = aws_iam_role.replication.id
  policy = data.aws_iam_policy_document.replication.json
}
