# OpenSearch Service in the private data subnets, three AZs, fine-grained
# access control with an IAM master role (no internal user database).
#
# The domain access policy trusts the account and leaves authorization to IAM
# plus fine-grained access control. Map each module task role to an OpenSearch
# backend role once after creation (README, manual steps); the master role does
# that through the security plugin API.

locals {
  os_domain_name  = local.name
  os_domain_arn   = "arn:aws:es:${var.region}:${local.account_id}:domain/${local.os_domain_name}"
  os_master_arn   = coalesce(var.opensearch_master_role_arn, try(aws_iam_role.opensearch_master["this"].arn, null))
  os_create_admin = var.opensearch_master_role_arn == null
}

resource "aws_iam_service_linked_role" "opensearch" {
  for_each         = var.create_opensearch_service_linked_role ? toset(["this"]) : toset([])
  aws_service_name = "opensearchservice.amazonaws.com"
}

data "aws_iam_policy_document" "opensearch_master_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SOCAdmin_*"]
    }
  }
}

resource "aws_iam_role" "opensearch_master" {
  for_each           = local.os_create_admin ? toset(["this"]) : toset([])
  name               = "${local.name}-opensearch-master"
  assume_role_policy = data.aws_iam_policy_document.opensearch_master_trust.json
}

data "aws_iam_policy_document" "opensearch_master" {
  statement {
    actions   = ["es:ESHttp*"]
    resources = ["${local.os_domain_arn}/*"]
  }
}

resource "aws_iam_role_policy" "opensearch_master" {
  for_each = aws_iam_role.opensearch_master
  name     = "opensearch-http"
  role     = each.value.id
  policy   = data.aws_iam_policy_document.opensearch_master.json
}

resource "aws_security_group" "opensearch" {
  name        = "${local.name}-opensearch"
  description = "OpenSearch HTTPS from module tasks"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "opensearch_from_apps" {
  for_each                     = toset(local.app_sg_keys)
  security_group_id            = aws_security_group.opensearch.id
  description                  = "https from ${each.key}"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = local.app_security_groups[each.key]
}

resource "aws_cloudwatch_log_group" "opensearch" {
  for_each          = toset(["audit", "application"])
  name              = "/vcd-soc/opensearch/${local.os_domain_name}/${each.key}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "opensearch_logs" {
  statement {
    actions   = ["logs:PutLogEvents", "logs:CreateLogStream"]
    resources = [for lg in aws_cloudwatch_log_group.opensearch : "${lg.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name     = "${local.name}-opensearch"
  policy_document = data.aws_iam_policy_document.opensearch_logs.json
}

data "aws_iam_policy_document" "opensearch_access" {
  statement {
    actions   = ["es:ESHttp*"]
    resources = ["${local.os_domain_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_opensearch_domain" "this" {
  domain_name     = local.os_domain_name
  engine_version  = var.opensearch_engine_version
  access_policies = data.aws_iam_policy_document.opensearch_access.json

  cluster_config {
    instance_type          = var.opensearch_instance_type
    instance_count         = var.opensearch_instance_count
    zone_awareness_enabled = true
    zone_awareness_config {
      availability_zone_count = 3
    }

    dedicated_master_enabled = var.opensearch_dedicated_master
    dedicated_master_type    = var.opensearch_dedicated_master ? var.opensearch_master_type : null
    dedicated_master_count   = var.opensearch_dedicated_master ? 3 : null

    warm_enabled = var.opensearch_ultrawarm
    warm_type    = var.opensearch_ultrawarm ? var.opensearch_warm_type : null
    warm_count   = var.opensearch_ultrawarm ? var.opensearch_warm_count : null
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.opensearch_volume_gb
  }

  vpc_options {
    subnet_ids         = module.vpc.data_subnet_ids
    security_group_ids = [aws_security_group.opensearch.id]
  }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = local.os_master_arn
    }
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.apps.arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch["audit"].arn
  }

  log_publishing_options {
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch["application"].arn
  }

  software_update_options {
    auto_software_update_enabled = true
  }

  lifecycle {
    precondition {
      condition     = !var.opensearch_ultrawarm || var.opensearch_dedicated_master
      error_message = "UltraWarm requires dedicated master nodes."
    }
  }

  depends_on = [aws_iam_service_linked_role.opensearch, aws_cloudwatch_log_resource_policy.opensearch]
}
