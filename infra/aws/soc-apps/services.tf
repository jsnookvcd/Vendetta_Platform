# Every module as an ECS service (plus a worker service where the module has
# one), wired the way infra/terraform wires the host: the same SSM parameters
# under <ssm_prefix>/<module>/ and the same service URLs (http://<module>:8000,
# now through Service Connect).
#
# Terraform only references parameter ARNs; it never reads or writes the secret
# values. The parameters are copied into this account by
# infra/aws/scripts/copy-ssm-params.sh, and DATABASE_URL is written by the
# database bootstrap (README.md). A task whose parameter is missing fails to
# start with ResourceInitializationError, which names the parameter.

locals {
  ssm_base = "arn:aws:ssm:${var.region}:${local.account_id}:parameter${var.ssm_prefix}"

  evidence_bucket_name = var.evidence_bucket_arn == null ? null : element(split(":::", var.evidence_bucket_arn), 1)
  evidence_modules     = ["dark-web-monitoring", "incident-response", "evidence-export"]
  bedrock_modules      = ["sabine", "ai-triage"]

  module_env = {
    for k, m in local.deployed : k => merge(
      {
        MODULE_ENABLED = "true"
        ADMIN_USER     = "admin"
        WEB_BIND       = "0.0.0.0"
        COOKIE_SECURE  = "true"
        AWS_REGION     = var.region
        SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
        OPENSEARCH_URL = "https://${aws_opensearch_domain.this.endpoint}"
      },
      m.public ? { PUBLIC_URL = local.public_url[k] } : {},
      k != "platform" && local.has["platform"] ? merge(
        { PLATFORM_URL = local.service_url["platform"] },
        contains(keys(local.public_url), "platform") ? { PLATFORM_PUBLIC_URL = local.public_url["platform"] } : {}
      ) : {},
      contains(local.hub_modules, k) && local.has["incident-response"] ? {
        PLATFORM_HUB_URL = local.service_url["incident-response"]
      } : {},
      contains(local.evidence_modules, k) && local.evidence_bucket_name != null ? {
        EVIDENCE_BUCKET = local.evidence_bucket_name
      } : {},
      k == "managed-services" ? { ACTIONS_READONLY = "true" } : {},
      k == "mdr" && local.has["managed-services"] ? merge(
        { MANAGED_SERVICES_URL = local.service_url["managed-services"] },
        contains(keys(local.public_url), "managed-services") ? { MANAGED_SERVICES_PUBLIC_URL = local.public_url["managed-services"] } : {}
      ) : {},
      k == "sabine" ? {
        TTS_PROVIDER       = "azure"
        AZURE_SPEECH_VOICE = "en-US-Jane:DragonHDLatestNeural"
      } : {},
      k == "dark-web-monitoring" && local.tor_on ? { TOR_PROXY = "socks5://tor:9050" } : {},
      lookup(var.module_environment, k, {}),
    )
  }

  module_secrets = {
    for k, m in local.deployed : k => merge(
      { for n in ["SECRET_KEY", "API_TOKEN", "ENCRYPTION_KEY", "ADMIN_PASSWORD_HASH", "DATABASE_URL"] : n => "${local.ssm_base}/${k}/${n}" },
      { REDIS_URL = "${aws_secretsmanager_secret.valkey.arn}:url::" },
      k != "platform" ? { PLATFORM_TOKEN = "${local.ssm_base}/${k}/PLATFORM_TOKEN" } : {},
      contains(local.hub_modules, k) && local.has["incident-response"] ? { PLATFORM_HUB_TOKEN = "${local.ssm_base}/${k}/PLATFORM_HUB_TOKEN" } : {},
      contains(local.signing_modules, k) ? { EVIDENCE_SIGNING_KEY = "${local.ssm_base}/${k}/EVIDENCE_SIGNING_KEY" } : {},
      contains(["platform", "sabine"], k) ? { MODULE_DIRECTORY = "${local.ssm_base}/${k}/MODULE_DIRECTORY" } : {},
      k == "sabine" ? { KIOSK_TOKEN = "${local.ssm_base}/sabine/KIOSK_TOKEN" } : {},
      k == "mdr" && local.has["managed-services"] ? { MANAGED_SERVICES_TOKEN = "${local.ssm_base}/mdr/MANAGED_SERVICES_TOKEN" } : {},
      { for n in lookup(var.extra_ssm_secrets, k, []) : n => "${local.ssm_base}/${k}/${n}" },
    )
  }

  priority = { for i, k in keys(local.deployed) : k => lookup(var.listener_priorities, k, 500 + i) }
  image    = { for k, _ in local.deployed : k => "${aws_ecr_repository.module[k].repository_url}:${lookup(var.image_tags, k, var.default_image_tag)}" }
}

# ------------------------------------------------------------------ task role policies
data "aws_iam_policy_document" "module" {
  for_each = local.deployed

  statement {
    sid       = "OwnConfig"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = ["${local.ssm_base}/${each.key}", "${local.ssm_base}/${each.key}/*"]
  }

  statement {
    sid       = "Alerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "Search"
    actions   = ["es:ESHttpDelete", "es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost", "es:ESHttpPut", "es:ESHttpPatch"]
    resources = ["${local.os_domain_arn}/*"]
  }

  dynamic "statement" {
    for_each = contains(local.evidence_modules, each.key) && var.evidence_bucket_arn != null ? [1] : []
    content {
      sid = "Evidence"
      actions = [
        "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket",
        "s3:GetObjectRetention", "s3:GetObjectLegalHold",
      ]
      resources = [var.evidence_bucket_arn, "${var.evidence_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = contains(local.evidence_modules, each.key) && var.evidence_kms_key_arn != null ? [1] : []
    content {
      sid       = "EvidenceKey"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = [var.evidence_kms_key_arn]
    }
  }

  dynamic "statement" {
    for_each = contains(local.bedrock_modules, each.key) ? [1] : []
    content {
      sid       = "Bedrock"
      actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      resources = var.bedrock_model_arns
    }
  }
}

# ------------------------------------------------------------------ services
module "service" {
  source   = "../modules/ecs-service"
  for_each = local.deployed

  name                          = each.key
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = local.vpc_cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = local.image[each.key]
  cpu                           = each.value.cpu
  memory                        = each.value.memory
  desired_count                 = each.value.desired_count
  min_capacity                  = each.value.min
  max_capacity                  = each.value.max
  container_port                = 8000
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  source_security_group_ids     = each.value.public ? [aws_security_group.alb.id] : []
  environment                   = local.module_env[each.key]
  secrets                       = local.module_secrets[each.key]
  task_role_policies            = { task = data.aws_iam_policy_document.module[each.key].json }
  log_kms_key_arn               = null
  log_retention_days            = var.log_retention_days
  enable_execute_command        = local.env == "staging"

  load_balancer = each.value.public ? {
    listener_arn = aws_lb_listener.https.arn
    priority     = local.priority[each.key]
    host_headers = [local.hosts[each.key]]
  } : null
}

module "worker" {
  source   = "../modules/ecs-service"
  for_each = local.workers

  name                          = "${each.key}-worker"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = local.vpc_cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = local.image[each.key]
  command                       = each.value.worker_command
  cpu                           = each.value.cpu
  memory                        = each.value.memory
  desired_count                 = 1
  min_capacity                  = 1
  max_capacity                  = each.value.max
  container_port                = null
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  environment                   = local.module_env[each.key]
  secrets                       = local.module_secrets[each.key]
  task_role_policies            = { task = data.aws_iam_policy_document.module[each.key].json }
  log_retention_days            = var.log_retention_days
}

# Tor SOCKS proxy in the tor VPC. Service Connect publishes it as tor:9050;
# only the soc-apps VPC CIDR may reach the port.
module "tor" {
  source   = "../modules/ecs-service"
  for_each = local.tor_on ? toset(["tor"]) : toset([])

  name                          = "tor"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.tor_vpc["tor"].vpc_id
  vpc_cidr                      = local.tor_cidr
  subnet_ids                    = module.tor_vpc["tor"].app_subnet_ids
  image                         = var.tor_image
  cpu                           = 256
  memory                        = 512
  desired_count                 = 1
  min_capacity                  = 1
  max_capacity                  = 2
  container_port                = 9050
  port_name                     = "socks"
  app_protocol                  = null
  service_connect_port          = 9050
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  ingress_cidrs                 = [local.vpc_cidr]
  log_retention_days            = var.log_retention_days
}
