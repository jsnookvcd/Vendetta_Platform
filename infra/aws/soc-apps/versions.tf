terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # engine = "valkey" on ElastiCache needs a recent 5.x; the lock file pins
      # the exact version (validated against 5.100.0).
      version = "~> 5.70"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.region
  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-apps-${var.environment}"
  }
  default_tags {
    tags = {
      Project     = "vendetta-soc"
      ManagedBy   = "terraform"
      Stack       = "soc-apps"
      Environment = var.environment
    }
  }
}

# DR region for the pilot light copies (dr.tf).
provider "aws" {
  alias  = "dr"
  region = var.dr_region
  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/${var.member_access_role_name}"
    session_name = "vcd-soc-apps-${var.environment}"
  }
  default_tags {
    tags = {
      Project     = "vendetta-soc"
      ManagedBy   = "terraform"
      Stack       = "soc-apps"
      Environment = var.environment
    }
  }
}
