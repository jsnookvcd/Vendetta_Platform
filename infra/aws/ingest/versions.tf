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
    Stack     = "ingest"
  }
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${var.ingest_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-ingest"
  }
  default_tags {
    tags = local.tags
  }
}
