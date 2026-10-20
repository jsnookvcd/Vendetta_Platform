# Security services are administered from the security-tooling account; the
# Security Lake is administered from the data-lake account. Registration runs in
# the management account; the services themselves are configured from the
# delegated accounts (outside this stack for GuardDuty, Security Hub, Inspector,
# Config and Access Analyzer; in the lake stack for Security Lake).

locals {
  security_tooling_id = local.account_ids["security-tooling"]
  data_lake_id        = local.account_ids["data-lake"]

  delegated_via_organizations = {
    access-analyzer          = { principal = "access-analyzer.amazonaws.com", account = local.security_tooling_id }
    config                   = { principal = "config.amazonaws.com", account = local.security_tooling_id }
    config-multiaccountsetup = { principal = "config-multiaccountsetup.amazonaws.com", account = local.security_tooling_id }
    securitylake             = { principal = "securitylake.amazonaws.com", account = local.data_lake_id }
  }
}

resource "aws_guardduty_organization_admin_account" "this" {
  admin_account_id = local.security_tooling_id
  depends_on       = [aws_organizations_organization.this]
}

# Security Hub must be enabled in the management account before it can
# delegate administration.
resource "aws_securityhub_account" "management" {
  enable_default_standards = false
}

resource "aws_securityhub_organization_admin_account" "this" {
  admin_account_id = local.security_tooling_id
  depends_on       = [aws_organizations_organization.this, aws_securityhub_account.management]
}

resource "aws_inspector2_delegated_admin_account" "this" {
  account_id = local.security_tooling_id
  depends_on = [aws_organizations_organization.this]
}

# Security Lake: AWS documents RegisterDataLakeDelegatedAdministrator (securitylake
# API) as the supported path. The Organizations-level registration below is what
# that API performs; if Security Lake reports the data-lake account is not its
# delegated administrator, run once from the management account:
#   aws securitylake register-data-lake-delegated-administrator --account-id <data-lake id>
resource "aws_organizations_delegated_administrator" "this" {
  for_each          = local.delegated_via_organizations
  account_id        = each.value.account
  service_principal = each.value.principal
  depends_on        = [aws_organizations_organization.this]
}
