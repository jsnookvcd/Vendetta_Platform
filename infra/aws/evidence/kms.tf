# Ledger encryption keys (one per region) and the asymmetric anchor signing key.
#
# Key policies name principals directly instead of delegating to the account
# root, so IAM policies in this account cannot widen access. Terraform's own
# role stays in the admin statement because KMS refuses a policy that would lock
# out the caller.

locals {
  admin_principals = distinct([aws_iam_role.key_admin.arn, local.terraform_role])

  key_admin_actions = [
    "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:DeleteAlias", "kms:DescribeKey",
    "kms:DisableKey", "kms:DisableKeyRotation", "kms:EnableKey", "kms:EnableKeyRotation",
    "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetPublicKey", "kms:ListAliases",
    "kms:ListGrants", "kms:ListKeyPolicies", "kms:ListResourceTags", "kms:PutKeyPolicy",
    "kms:RevokeGrant", "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource",
    "kms:UpdateAlias", "kms:UpdateKeyDescription",
  ]
}

data "aws_iam_policy_document" "ledger_key" {
  for_each = toset(["primary", "replica"])

  statement {
    sid       = "KeyAdministration"
    actions   = local.key_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.admin_principals
    }
  }

  statement {
    sid       = "CustodianUse"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.custodian.arn]
    }
  }

  statement {
    sid       = "Replication"
    actions   = each.key == "primary" ? ["kms:Decrypt", "kms:DescribeKey"] : ["kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.replication.arn]
    }
  }

  dynamic "statement" {
    for_each = each.key == "primary" && length(var.ledger_writer_principal_arns) > 0 ? [1] : []
    content {
      sid       = "LedgerWritersViaS3"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
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
        values   = var.ledger_writer_principal_arns
      }
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${var.region}.amazonaws.com"]
      }
    }
  }
}

resource "aws_kms_key" "ledger" {
  description             = "vcd-soc evidence ledger"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.ledger_key["primary"].json
}

resource "aws_kms_alias" "ledger" {
  name          = "alias/vcd-soc-evidence-ledger"
  target_key_id = aws_kms_key.ledger.key_id
}

resource "aws_kms_key" "replica" {
  provider                = aws.replica
  description             = "vcd-soc evidence ledger replica"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.ledger_key["replica"].json
}

resource "aws_kms_alias" "replica" {
  provider      = aws.replica
  name          = "alias/vcd-soc-evidence-ledger"
  target_key_id = aws_kms_key.replica.key_id
}

# ------------------------------------------------------------------ signing key
# Countersigns ledger anchors so a verifier can check them against a key no
# module holds. The per-module Ed25519 chain-of-custody signing stays in the
# application (EVIDENCE_SIGNING_KEY in SSM): this stack does not assume AWS KMS
# offers an Ed25519 key spec in the account's region. If it does, set
# signing_key_spec to that spec after confirming it with
#   aws kms create-key --key-spec <spec> --key-usage SIGN_VERIFY --dry-run
# (or the KMS documentation for the region); see README.md.
data "aws_iam_policy_document" "signing_key" {
  statement {
    sid       = "KeyAdministration"
    actions   = local.key_admin_actions
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.admin_principals
    }
  }

  statement {
    sid       = "CustodianSign"
    actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.custodian.arn]
    }
  }

  dynamic "statement" {
    for_each = length(var.signer_principal_arns) > 0 ? [1] : []
    content {
      sid       = "ModuleSigners"
      actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
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
        values   = var.signer_principal_arns
      }
    }
  }

  statement {
    sid       = "OrgVerify"
    actions   = ["kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
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
  }
}

resource "aws_kms_key" "signing" {
  description              = "vcd-soc evidence anchor signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = var.signing_key_spec
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.signing_key.json
}

resource "aws_kms_alias" "signing" {
  name          = "alias/vcd-soc-evidence-signing"
  target_key_id = aws_kms_key.signing.key_id
}
