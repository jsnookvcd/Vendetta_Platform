# AWS Organization, OUs and member accounts.
#
# If the management account already belongs to an organization, import it first:
#   tofu import aws_organizations_organization.this <o-xxxxxxxxxx>

resource "aws_organizations_organization" "this" {
  feature_set = "ALL"

  aws_service_access_principals = [
    "access-analyzer.amazonaws.com",
    "account.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "guardduty.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
    "inspector2.amazonaws.com",
    "ram.amazonaws.com",
    "securityhub.amazonaws.com",
    "securitylake.amazonaws.com",
    "sso.amazonaws.com",
  ]

  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  root_id = aws_organizations_organization.this.roots[0].id
  ous     = toset(["Security", "Infrastructure", "Workloads", "Sandbox"])
}

resource "aws_organizations_organizational_unit" "this" {
  for_each  = local.ous
  name      = each.key
  parent_id = local.root_id
}

resource "aws_organizations_account" "member" {
  for_each          = var.account_emails
  name              = "vcd-soc-${each.key}"
  email             = each.value
  parent_id         = aws_organizations_organizational_unit.this[var.account_ou[each.key]].id
  role_name         = var.member_access_role_name
  close_on_deletion = false

  tags = {
    "vendetta:account" = each.key
  }

  lifecycle {
    prevent_destroy = true
    # role_name and iam_user_access_to_billing only apply at creation.
    ignore_changes = [role_name, iam_user_access_to_billing]
  }
}

locals {
  account_ids = { for k, a in aws_organizations_account.member : k => a.id }
}

# Lets the network stack share the Transit Gateway with the whole organization.
resource "aws_ram_sharing_with_organization" "this" {
  depends_on = [aws_organizations_organization.this]
}
