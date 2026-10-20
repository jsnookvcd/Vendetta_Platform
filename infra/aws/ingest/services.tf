# ECS cluster and the four ingest services.

resource "aws_ecs_cluster" "this" {
  name = "vcd-soc-ingest"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  service_connect_defaults {
    namespace = aws_service_discovery_http_namespace.this.arn
  }
}

resource "aws_service_discovery_http_namespace" "this" {
  name        = "ingest.vendetta.internal"
  description = "Service Connect namespace for the ingest services"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  common_env = {
    AWS_REGION            = var.region
    KINESIS_STREAM        = aws_kinesis_stream.events.name
    TENANT_SECRET_PREFIX  = "vcd/ingest/tenants/"
    RAW_BUCKET            = element(split(":::", var.raw_bucket_arn), 1)
    BUCKET_FEED_QUEUE_URL = aws_sqs_queue.bucket_feed.url
  }
  tenant_secret_arn = "arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:vcd/ingest/tenants/*"
}

# ------------------------------------------------------------------ task policies
data "aws_iam_policy_document" "web" {
  statement {
    sid       = "PutEvents"
    actions   = ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"]
    resources = [aws_kinesis_stream.events.arn]
  }
  statement {
    sid       = "StreamKey"
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.ingest.arn]
  }
  statement {
    sid       = "WebhookSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.tenant_secret_arn]
  }
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid       = "TenantConnectorSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.tenant_secret_arn]
  }
  statement {
    sid       = "PutEvents"
    actions   = ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"]
    resources = [aws_kinesis_stream.events.arn]
  }
  statement {
    sid       = "StreamKey"
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.ingest.arn]
  }
  statement {
    sid       = "WriteRawArchive"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${var.raw_bucket_arn}/tenant=*"]
  }
  statement {
    sid       = "RawAndTenantKeys"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = concat([var.raw_kms_key_arn], values(var.tenant_kms_key_arns))
  }
  statement {
    sid       = "BucketFeedQueue"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.bucket_feed.arn]
  }
  # Client tenants grant read access by creating VendettaSOCReader* roles that
  # trust this task role and require an ExternalId (the tenant's id, stored in
  # its Secrets Manager entry). The worker always sends one; the Null condition
  # refuses any AssumeRole call that omits it.
  statement {
    sid       = "AssumeClientReaderRoles"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/${var.client_reader_role_prefix}*"]
    condition {
      test     = "Null"
      variable = "sts:ExternalId"
      values   = ["false"]
    }
  }
  dynamic "statement" {
    for_each = length(var.securitylake_provider_role_arns) > 0 ? [1] : []
    content {
      sid       = "AssumeSecurityLakeProviderRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.securitylake_provider_role_arns
    }
  }
}

data "aws_iam_policy_document" "stream" {
  statement {
    sid = "ReadEvents"
    actions = [
      "kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:DescribeStreamConsumer",
      "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards",
      "kinesis:RegisterStreamConsumer", "kinesis:SubscribeToShard", "kinesis:ListStreamConsumers",
    ]
    resources = [aws_kinesis_stream.events.arn, "${aws_kinesis_stream.events.arn}/consumer/*"]
  }
  statement {
    sid       = "StreamKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.ingest.arn]
  }
  statement {
    sid = "Checkpoints"
    actions = [
      "dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
      "dynamodb:DeleteItem", "dynamodb:Scan", "dynamodb:Query",
    ]
    resources = [aws_dynamodb_table.stream_checkpoints.arn]
  }
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = length(var.securitylake_provider_role_arns) > 0 ? [1] : []
    content {
      sid       = "AssumeSecurityLakeProviderRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.securitylake_provider_role_arns
    }
  }
}

data "aws_iam_policy_document" "vector" {
  statement {
    sid       = "PutEvents"
    actions   = ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"]
    resources = [aws_kinesis_stream.events.arn]
  }
  statement {
    sid       = "StreamKey"
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.ingest.arn]
  }
}

# ------------------------------------------------------------------ services
module "ingest_web" {
  source = "../modules/ecs-service"

  name                          = "ingest-web"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = module.vpc.cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = var.images["ingest-web"]
  cpu                           = var.service_sizing["ingest-web"].cpu
  memory                        = var.service_sizing["ingest-web"].memory
  desired_count                 = var.service_sizing["ingest-web"].desired_count
  min_capacity                  = var.service_sizing["ingest-web"].min
  max_capacity                  = var.service_sizing["ingest-web"].max
  container_port                = 8000
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  source_security_group_ids     = [aws_security_group.alb.id]
  environment                   = local.common_env
  task_role_policies            = { task = data.aws_iam_policy_document.web.json }
  log_retention_days            = var.log_retention_days

  load_balancer = {
    listener_arn  = aws_lb_listener.webhook.arn
    priority      = 100
    path_patterns = ["/api/ingest/*"]
  }
}

module "ingest_worker" {
  source = "../modules/ecs-service"

  name                          = "ingest-worker"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = module.vpc.cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = var.images["ingest-worker"]
  cpu                           = var.service_sizing["ingest-worker"].cpu
  memory                        = var.service_sizing["ingest-worker"].memory
  desired_count                 = var.service_sizing["ingest-worker"].desired_count
  min_capacity                  = var.service_sizing["ingest-worker"].min
  max_capacity                  = var.service_sizing["ingest-worker"].max
  container_port                = null
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  environment = merge(local.common_env, {
    CLIENT_ROLE_PREFIX = var.client_reader_role_prefix
  })
  task_role_policies = { task = data.aws_iam_policy_document.worker.json }
  log_retention_days = var.log_retention_days
}

module "ingest_stream" {
  source = "../modules/ecs-service"

  name                          = "ingest-stream"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = module.vpc.cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = var.images["ingest-stream"]
  cpu                           = var.service_sizing["ingest-stream"].cpu
  memory                        = var.service_sizing["ingest-stream"].memory
  desired_count                 = var.service_sizing["ingest-stream"].desired_count
  min_capacity                  = var.service_sizing["ingest-stream"].min
  max_capacity                  = var.service_sizing["ingest-stream"].max
  container_port                = null
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn
  environment = merge(local.common_env, {
    CHECKPOINT_TABLE = aws_dynamodb_table.stream_checkpoints.name
  })
  task_role_policies = { task = data.aws_iam_policy_document.stream.json }
  log_retention_days = var.log_retention_days
}

module "vector" {
  source = "../modules/ecs-service"

  name                          = "vector"
  name_prefix                   = "vcd-soc-ingest-"
  cluster_arn                   = aws_ecs_cluster.this.arn
  cluster_name                  = aws_ecs_cluster.this.name
  vpc_id                        = module.vpc.vpc_id
  vpc_cidr                      = module.vpc.cidr
  subnet_ids                    = module.vpc.app_subnet_ids
  image                         = var.images["vector"]
  cpu                           = var.service_sizing["vector"].cpu
  memory                        = var.service_sizing["vector"].memory
  desired_count                 = var.service_sizing["vector"].desired_count
  min_capacity                  = var.service_sizing["vector"].min
  max_capacity                  = var.service_sizing["vector"].max
  container_port                = 6514
  port_name                     = "syslog"
  app_protocol                  = null
  service_connect_namespace_arn = null
  external_target_group_arns    = [aws_lb_target_group.vector.arn]
  source_security_group_ids     = [aws_security_group.nlb.id]
  environment = {
    AWS_REGION     = var.region
    KINESIS_STREAM = aws_kinesis_stream.events.name
    SYSLOG_PORT    = "6514"
  }
  task_role_policies = { task = data.aws_iam_policy_document.vector.json }
  log_retention_days = var.log_retention_days
}
