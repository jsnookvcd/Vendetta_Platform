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

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${var.network_account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-network"
  }
  default_tags {
    tags = {
      Project   = "vendetta-soc"
      ManagedBy = "terraform"
      Stack     = "network"
    }
  }
}
