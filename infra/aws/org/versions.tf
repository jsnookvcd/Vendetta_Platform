terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }

  # Partial S3 backend; pass the rest with -backend-config=backend.hcl.
  # CI validates with -backend=false, which ignores this block.
  backend "s3" {}
}
