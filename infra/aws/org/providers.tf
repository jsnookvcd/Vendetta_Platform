# The default provider is the management (payer) account. Everything that lives
# in a member account goes through an alias that assumes the
# OrganizationAccountAccessRole Organizations creates in every new account.
#
# On the very first apply the member account ids are not known yet, so apply in
# two passes (see README.md):
#   tofu apply -target=aws_organizations_account.member
#   tofu apply

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "log_archive"
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids["log-archive"]}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-org"
  }
  default_tags {
    tags = local.tags
  }
}

locals {
  tags = {
    Project   = "vendetta-soc"
    ManagedBy = "terraform"
    Stack     = "org"
  }
}
