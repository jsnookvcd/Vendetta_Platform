# Vendetta SOC applications on ECS Fargate. One stack, two environments:
# prod in soc-apps-prod and staging in soc-apps-staging, selected by
# var.environment and a backend key per environment.

data "aws_caller_identity" "current" {}

locals {
  env        = var.environment
  name       = "vcd-soc-${local.env}"
  account_id = data.aws_caller_identity.current.account_id
  host_sfx   = local.env == "prod" ? "" : "-${local.env}"

  vpc_cidr = coalesce(var.vpc_cidr, local.env == "prod" ? "10.20.0.0/16" : "10.21.0.0/16")
  tor_cidr = coalesce(var.tor_vpc_cidr, local.env == "prod" ? "10.60.0.0/20" : "10.61.0.0/20")
  tor_on   = var.enable_tor_egress && var.tor_image != null && var.transit_gateway_id != null

  deployed = { for k, m in var.modules : k => m if m.deploy }
  public   = { for k, m in local.deployed : k => m if m.public }
  workers  = { for k, m in local.deployed : k => m if m.worker_command != null }

  hosts       = { for k, _ in local.public : k => "${lookup(var.module_hosts, k, k)}${local.host_sfx}.${var.base_domain}" }
  public_url  = { for k, h in local.hosts : k => "https://${h}" }
  service_url = { for k, _ in local.deployed : k => "http://${k}:8000" }

  # Same groupings as infra/terraform/main.tf, so each module gets the same
  # secrets and wiring it has on the host today.
  signing_modules = ["incident-response", "managed-services", "vulnerability-management", "penetration-testing", "sabine", "professional-services", "mdr"]
  finding_modules = ["dark-web-monitoring", "managed-services", "vulnerability-management", "penetration-testing", "mdr"]
  hub_modules     = concat(local.finding_modules, ["professional-services"])
  has             = { for k in ["platform", "incident-response", "managed-services", "sabine", "mdr", "dark-web-monitoring"] : k => contains(keys(local.deployed), k) }
}

# ------------------------------------------------------------------ network
module "vpc" {
  source = "../modules/vpc"

  name                  = local.name
  cidr                  = local.vpc_cidr
  create_public_subnets = true # internet-facing ALB only
  transit_gateway_id    = var.transit_gateway_id
  flow_log_bucket_arn   = var.flow_log_bucket_arn
}

# Tor gets its own VPC so its attachment can sit on the TGW tor segment, which
# has blackhole routes for the data-lake and evidence CIDRs. Only the dark web
# module reaches it, on 9050, through Service Connect.
module "tor_vpc" {
  source   = "../modules/vpc"
  for_each = local.tor_on ? toset(["tor"]) : toset([])

  name                = "${local.name}-tor"
  cidr                = local.tor_cidr
  transit_gateway_id  = var.transit_gateway_id
  flow_log_bucket_arn = var.flow_log_bucket_arn
  interface_endpoints = ["logs", "ecr.api", "ecr.dkr"]
  gateway_endpoints   = ["s3"]
}

# ------------------------------------------------------------------ cluster
resource "aws_service_discovery_http_namespace" "this" {
  name        = "vendetta.internal"
  description = "Service Connect namespace: module <key> answers at http://<key>:8000"
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  service_connect_defaults {
    namespace = aws_service_discovery_http_namespace.this.arn
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_kms_key" "apps" {
  description             = "${local.name} data stores, secrets and logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "apps" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.apps.key_id
}

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ------------------------------------------------------------------ ECR
resource "aws_ecr_repository" "module" {
  for_each             = merge(local.deployed, local.tor_on ? { tor = null } : {})
  name                 = "vcd-soc/${each.key}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.apps.arn
  }
}

data "aws_iam_policy_document" "ecr_org_pull" {
  statement {
    sid     = "OrgPull"
    actions = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_ecr_repository_policy" "module" {
  for_each   = aws_ecr_repository.module
  repository = each.value.name
  policy     = data.aws_iam_policy_document.ecr_org_pull.json
}

resource "aws_ecr_lifecycle_policy" "module" {
  for_each   = aws_ecr_repository.module
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the newest 100 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 100 }
      action       = { type = "expire" }
    }]
  })
}
