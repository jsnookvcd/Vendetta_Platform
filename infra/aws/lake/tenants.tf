# One KMS key per tenant (platform client). The ingest pipeline encrypts with
# it; analysts and evidence custodians decrypt. The data-lake account root can
# administer the key but cannot use it, so a principal in this account needs a
# key policy grant (below) to touch tenant data.
#
# Firehose writes the raw archive with the raw-archive key (a delivery stream
# has one key). Tenant keys are for the pipeline's per-tenant envelope
# encryption: payload fields, tenant exports and evidence packages.

data "aws_iam_policy_document" "tenant_key" {
  for_each = var.tenants

  statement {
    sid = "KeyAdministrationOnly"
    actions = [
      "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:CreateGrant", "kms:DeleteAlias",
      "kms:DescribeKey", "kms:DisableKey", "kms:DisableKeyRotation", "kms:EnableKey",
      "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
      "kms:ListAliases", "kms:ListGrants", "kms:ListKeyPolicies", "kms:ListResourceTags",
      "kms:PutKeyPolicy", "kms:RevokeGrant", "kms:ScheduleKeyDeletion", "kms:TagResource",
      "kms:UntagResource", "kms:UpdateAlias", "kms:UpdateKeyDescription",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "PipelineEncrypt"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"]
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
    dynamic "condition" {
      for_each = var.require_tenant_encryption_context ? [each.key] : []
      content {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:tenant_id"
        values   = [condition.value]
      }
    }
  }

  statement {
    sid       = "AnalystAndEvidenceDecrypt"
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
    dynamic "condition" {
      for_each = var.require_tenant_encryption_context ? [each.key] : []
      content {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:tenant_id"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_kms_key" "tenant" {
  for_each                = var.tenants
  description             = "vcd-soc tenant ${each.key} (${each.value.name})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.tenant_key[each.key].json
  tags = {
    "vendetta:tenant" = each.key
    "vendetta:tier"   = each.value.tier
  }
}

resource "aws_kms_alias" "tenant" {
  for_each      = var.tenants
  name          = "alias/vcd-tenant-${each.key}"
  target_key_id = aws_kms_key.tenant[each.key].key_id
}
