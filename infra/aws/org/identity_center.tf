# IAM Identity Center permission sets and group assignments. Groups come from
# Entra ID through SCIM provisioning, configured once in the Identity Center
# console; Terraform only references their group ids.

data "aws_ssoadmin_instances" "this" {
  for_each = var.enable_identity_center ? toset(["this"]) : toset([])
}

locals {
  sso_instance_arn = var.enable_identity_center ? tolist(data.aws_ssoadmin_instances.this["this"].arns)[0] : null

  permission_sets = {
    SOCAdmin = {
      description = "Vendetta SOC administrators"
      session     = "PT4H"
      managed     = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
    SOCAnalyst = {
      description = "Read-only console plus Security Lake and Athena query"
      session     = "PT8H"
      managed     = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", "arn:aws:iam::aws:policy/SecurityAudit"]
    }
    EvidenceCustodian = {
      description = "Evidence ledger read and append, signing key verification, custodian role assumption"
      session     = "PT4H"
      managed     = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]
    }
    BreakGlass = {
      description = "Emergency administrator; exempt from protective SCPs. Every use is reviewed."
      session     = "PT1H"
      managed     = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
  }

  managed_attachments = var.enable_identity_center ? {
    for pair in flatten([
      for ps, cfg in local.permission_sets : [for arn in cfg.managed : { ps = ps, arn = arn }]
    ]) : "${pair.ps}|${pair.arn}" => pair
  } : {}

  account_lookup = merge(local.account_ids, { management = local.management_id })

  assignments = var.enable_identity_center ? {
    for a in flatten([
      for name, cfg in var.permission_set_assignments : [
        for acct in cfg.accounts : {
          key            = "${name}|${acct}"
          permission_set = cfg.permission_set
          group_id       = cfg.group_id
          account_id     = local.account_lookup[acct]
        }
      ]
    ]) : a.key => a
  } : {}
}

resource "aws_ssoadmin_permission_set" "this" {
  for_each         = var.enable_identity_center ? local.permission_sets : {}
  name             = each.key
  description      = each.value.description
  instance_arn     = local.sso_instance_arn
  session_duration = each.value.session
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each           = local.managed_attachments
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps].arn
  managed_policy_arn = each.value.arn
}

# ------------------------------------------------------------------ inline policies
data "aws_iam_policy_document" "analyst" {
  statement {
    sid = "AthenaInSocWorkgroup"
    actions = [
      "athena:BatchGetQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults",
      "athena:GetQueryResultsStream", "athena:GetWorkGroup", "athena:ListQueryExecutions",
      "athena:StartQueryExecution", "athena:StopQueryExecution",
    ]
    resources = ["arn:aws:athena:*:${local.data_lake_id}:workgroup/${var.lake_query_workgroup}"]
  }
  statement {
    sid = "CatalogRead"
    actions = [
      "glue:BatchGetPartition", "glue:GetDatabase", "glue:GetDatabases", "glue:GetPartition",
      "glue:GetPartitions", "glue:GetTable", "glue:GetTables",
    ]
    resources = ["arn:aws:glue:*:${local.data_lake_id}:*"]
  }
  statement {
    sid       = "LakeFormationDataAccess"
    actions   = ["lakeformation:GetDataAccess"]
    resources = ["*"]
  }
  statement {
    sid       = "AthenaResults"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:AbortMultipartUpload"]
    resources = ["arn:aws:s3:::vcd-soc-athena-results-${local.data_lake_id}", "arn:aws:s3:::vcd-soc-athena-results-${local.data_lake_id}/*"]
  }
  statement {
    sid       = "LakeKeys"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["arn:aws:kms:*:${local.data_lake_id}:key/*"]
  }
  statement {
    sid       = "SecurityLakeRead"
    actions   = ["securitylake:Get*", "securitylake:List*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "custodian" {
  statement {
    sid = "LedgerReadAppend"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:ListBucket", "s3:ListBucketVersions",
      "s3:GetObjectRetention", "s3:GetObjectLegalHold", "s3:PutObjectLegalHold",
    ]
    resources = ["arn:aws:s3:::vcd-soc-ledger-*", "arn:aws:s3:::vcd-soc-ledger-*/*"]
  }
  statement {
    sid       = "AssumeCustodianUsageRole"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = ["arn:aws:iam::${local.account_ids["evidence"]}:role/vcd-soc-evidence-custodian"]
  }
  statement {
    sid       = "VerifySignatures"
    actions   = ["kms:GetPublicKey", "kms:Verify", "kms:DescribeKey"]
    resources = ["arn:aws:kms:*:${local.account_ids["evidence"]}:key/*"]
  }
}

resource "aws_ssoadmin_permission_set_inline_policy" "analyst" {
  for_each           = var.enable_identity_center ? toset(["this"]) : toset([])
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this["SOCAnalyst"].arn
  inline_policy      = data.aws_iam_policy_document.analyst.json
}

resource "aws_ssoadmin_permission_set_inline_policy" "custodian" {
  for_each           = var.enable_identity_center ? toset(["this"]) : toset([])
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this["EvidenceCustodian"].arn
  inline_policy      = data.aws_iam_policy_document.custodian.json
}

# ------------------------------------------------------------------ assignments
resource "aws_ssoadmin_account_assignment" "this" {
  for_each           = local.assignments
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  principal_id       = each.value.group_id
  principal_type     = "GROUP"
  target_id          = each.value.account_id
  target_type        = "AWS_ACCOUNT"

  depends_on = [
    aws_ssoadmin_managed_policy_attachment.this,
    aws_ssoadmin_permission_set_inline_policy.analyst,
    aws_ssoadmin_permission_set_inline_policy.custodian,
  ]
}
