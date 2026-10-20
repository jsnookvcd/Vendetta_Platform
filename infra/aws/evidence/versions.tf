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
    Stack     = "evidence"
  }
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${var.evidence_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-evidence"
  }
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "replica"
  region = var.replica_region
  assume_role {
    role_arn     = "arn:aws:iam::${var.evidence_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-evidence"
  }
  default_tags {
    tags = local.tags
  }
}
