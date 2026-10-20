terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }

  backend "s3" {}
}

locals {
  tags = {
    Project   = "vendetta-soc"
    ManagedBy = "terraform"
    Stack     = "lake"
  }
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${var.data_lake_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-lake"
  }
  default_tags {
    tags = local.tags
  }
}

# Second region for the Security Lake KMS replica key.
provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
  assume_role {
    role_arn     = "arn:aws:iam::${var.data_lake_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-lake"
  }
  default_tags {
    tags = local.tags
  }
}
