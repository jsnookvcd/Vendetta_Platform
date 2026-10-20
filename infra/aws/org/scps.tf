# Service control policies. SCPs never apply to the management account, so
# nothing here limits the account Terraform runs from.
#
# Attachment plan (an account or OU can carry at most five SCPs, FullAWSAccess
# included):
#   root : FullAWSAccess, vcd-soc-baseline, vcd-soc-region-guard
#   each OU : vcd-soc-imdsv2

locals {
  exempt = {
    test     = "ArnNotLike"
    variable = "aws:PrincipalArn"
    values   = var.scp_exempt_principal_arns
  }
}

# ------------------------------------------------------------------ baseline
data "aws_iam_policy_document" "baseline" {
  statement {
    sid       = "DenyLeaveOrganization"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }

  statement {
    sid    = "ProtectSecurityServices"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail",
      "cloudtrail:StopLogging",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:UpdateTrail",
      "guardduty:DeleteDetector",
      "guardduty:DeleteMembers",
      "guardduty:DisassociateFromAdministratorAccount",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:DisassociateMembers",
      "guardduty:StopMonitoringMembers",
      "config:DeleteConfigRule",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:DeleteRetentionConfiguration",
      "config:StopConfigurationRecorder",
      "securityhub:DeleteMembers",
      "securityhub:DisableSecurityHub",
      "securityhub:DisassociateFromAdministratorAccount",
      "securityhub:DisassociateFromMasterAccount",
      "securityhub:DisassociateMembers",
      "securityhub:DisableImportFindingsForProduct",
      "access-analyzer:DeleteAnalyzer",
      "securitylake:DeleteDataLake",
      "securitylake:DeleteAwsLogSource",
    ]
    resources = ["*"]
    condition {
      test     = local.exempt.test
      variable = local.exempt.variable
      values   = local.exempt.values
    }
  }

  # Retention-locked buckets: no changing Object Lock settings and no deleting
  # the bucket. Two statements: one by tag, one by name pattern, because S3 has
  # historically not evaluated aws:ResourceTag for bucket-level actions (see
  # README). The name pattern statement holds even where the tag is ignored.
  statement {
    sid    = "ProtectLockedBucketsByTag"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:DeleteBucket",
      "s3:PutBucketVersioning",
      "s3:DeleteBucketPolicy",
    ]
    resources = ["arn:aws:s3:::*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/vendetta:retention"
      values   = ["locked"]
    }
    condition {
      test     = local.exempt.test
      variable = local.exempt.variable
      values   = local.exempt.values
    }
  }

  statement {
    sid    = "ProtectLockedBucketsByName"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:DeleteBucket",
      "s3:PutBucketVersioning",
      "s3:DeleteBucketPolicy",
    ]
    resources = var.locked_bucket_arn_patterns
    condition {
      test     = local.exempt.test
      variable = local.exempt.variable
      values   = local.exempt.values
    }
  }
}

resource "aws_organizations_policy" "baseline" {
  name        = "vcd-soc-baseline"
  description = "Deny leaving the org, disabling security services, and altering retention-locked buckets"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.baseline.minified_json
}

resource "aws_organizations_policy_attachment" "baseline_root" {
  policy_id = aws_organizations_policy.baseline.id
  target_id = local.root_id
}

# ------------------------------------------------------------------ region guard
# NotAction list follows the AWS example SCP for region restriction, with
# Identity Center, account and billing services added.
data "aws_iam_policy_document" "region_guard" {
  statement {
    sid    = "DenyOutsideAllowedRegions"
    effect = "Deny"
    not_actions = [
      "a4b:*", "access-analyzer:*", "account:*", "acm:*", "aws-marketplace-management:*",
      "aws-marketplace:*", "aws-portal:*", "billing:*", "budgets:*", "ce:*", "chime:*",
      "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
      "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "freetier:*",
      "globalaccelerator:*", "health:*", "iam:*", "identitystore:*", "importexport:*",
      "invoicing:*", "kms:*", "mobileanalytics:*", "networkmanager:*", "organizations:*",
      "payments:*", "pricing:*", "route53:*", "route53domains:*", "route53-recovery-cluster:*",
      "route53-recovery-control-config:*", "route53-recovery-readiness:*",
      "s3:CreateMultiRegionAccessPoint", "s3:GetAccountPublic*", "s3:ListAllMyBuckets",
      "s3:ListMultiRegionAccessPoints", "s3:PutAccountPublic*", "shield:*", "sso:*",
      "sts:*", "support:*", "tax:*", "trustedadvisor:*", "waf-regional:*", "waf:*",
      "wafv2:*", "wellarchitected:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = local.exempt.test
      variable = local.exempt.variable
      values   = local.exempt.values
    }
  }
}

resource "aws_organizations_policy" "region_guard" {
  name        = "vcd-soc-region-guard"
  description = "Deny regional services outside ${join(", ", var.allowed_regions)}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.region_guard.minified_json
}

resource "aws_organizations_policy_attachment" "region_guard_root" {
  policy_id = aws_organizations_policy.region_guard.id
  target_id = local.root_id
}

# ------------------------------------------------------------------ IMDSv2
data "aws_iam_policy_document" "imdsv2" {
  statement {
    sid       = "RequireImdsV2OnLaunch"
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = ["arn:aws:ec2:*:*:instance/*"]
    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"
      values   = ["required"]
    }
  }

  statement {
    sid       = "LimitImdsHopCount"
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = ["arn:aws:ec2:*:*:instance/*"]
    condition {
      test     = "NumericGreaterThan"
      variable = "ec2:MetadataHttpPutResponseHopLimit"
      values   = ["2"]
    }
  }

  statement {
    sid       = "DenyImdsDowngrade"
    effect    = "Deny"
    actions   = ["ec2:ModifyInstanceMetadataOptions"]
    resources = ["*"]
    condition {
      test     = local.exempt.test
      variable = local.exempt.variable
      values   = local.exempt.values
    }
  }
}

resource "aws_organizations_policy" "imdsv2" {
  name        = "vcd-soc-imdsv2"
  description = "Require IMDSv2 on every EC2 launch"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.imdsv2.minified_json
}

resource "aws_organizations_policy_attachment" "imdsv2" {
  for_each  = aws_organizations_organizational_unit.this
  policy_id = aws_organizations_policy.imdsv2.id
  target_id = each.value.id
}
