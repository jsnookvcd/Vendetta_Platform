# RDS PostgreSQL (one database per module, created by the bootstrap step in
# README.md, never by Terraform), ElastiCache Valkey, and their security groups.
# Every module service and worker security group may reach both.

locals {
  app_security_groups = merge(
    { for k, m in module.service : k => m.security_group_id },
    { for k, m in module.worker : "${k}-worker" => m.security_group_id },
  )
  app_sg_keys = concat(keys(local.deployed), [for k in keys(local.workers) : "${k}-worker"])
}

# One-off ECS tasks (database bootstrap, pg_restore) run with this group.
resource "aws_security_group" "db_bootstrap" {
  name        = "${local.name}-db-bootstrap"
  description = "One-off database bootstrap and restore tasks"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "db_bootstrap" {
  security_group_id = aws_security_group.db_bootstrap.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ------------------------------------------------------------------ RDS
resource "aws_security_group" "rds" {
  name        = "${local.name}-rds"
  description = "PostgreSQL from module tasks"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_apps" {
  for_each                     = toset(local.app_sg_keys)
  security_group_id            = aws_security_group.rds.id
  description                  = "postgres from ${each.key}"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = local.app_security_groups[each.key]
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_bootstrap" {
  security_group_id            = aws_security_group.rds.id
  description                  = "postgres from bootstrap tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db_bootstrap.id
}

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = module.vpc.data_subnet_ids
}

resource "aws_db_parameter_group" "pg16" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements"
    apply_method = "pending-reboot"
  }
}

data "aws_iam_policy_document" "rds_monitoring_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${local.name}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_trust.json
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "postgres" {
  identifier     = "${local.name}-postgres"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.apps.arn

  username                      = "vcdadmin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.apps.arn

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.pg16.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  backup_retention_period   = 35
  backup_window             = "07:00-07:30"
  maintenance_window        = "sun:08:00-sun:09:00"
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name}-postgres-final"

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.apps.arn
  performance_insights_retention_period = 7
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]

  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  apply_immediately                   = false
}

# ------------------------------------------------------------------ Valkey
resource "aws_security_group" "valkey" {
  name        = "${local.name}-valkey"
  description = "Valkey from module tasks"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "valkey_from_apps" {
  for_each                     = toset(local.app_sg_keys)
  security_group_id            = aws_security_group.valkey.id
  description                  = "valkey from ${each.key}"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = local.app_security_groups[each.key]
}

resource "aws_elasticache_subnet_group" "this" {
  name       = local.name
  subnet_ids = module.vpc.data_subnet_ids
}

# The auth token follows infra/terraform's pattern: random_password, stored in
# Secrets Manager for the tasks. Like every generated secret there, it is also
# in state, which lives in the encrypted, versioned state bucket.
resource "random_password" "valkey" {
  length  = 64
  special = false
}

resource "aws_cloudwatch_log_group" "valkey_slow" {
  name              = "/vcd-soc/elasticache/${local.name}-valkey/slow-log"
  retention_in_days = var.log_retention_days
}

resource "aws_elasticache_replication_group" "valkey" {
  replication_group_id       = "${local.name}-valkey"
  description                = "${local.name} cache and queues"
  engine                     = "valkey"
  engine_version             = var.valkey_engine_version
  node_type                  = var.valkey_node_type
  num_cache_clusters         = 1 + var.valkey_replicas
  port                       = 6379
  automatic_failover_enabled = var.valkey_replicas > 0
  multi_az_enabled           = var.valkey_replicas > 0
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.valkey.id]
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.apps.arn
  transit_encryption_enabled = true
  auth_token                 = random_password.valkey.result
  snapshot_retention_limit   = 7
  apply_immediately          = false

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.valkey_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
}

resource "aws_secretsmanager_secret" "valkey" {
  name        = "vcd-soc/${local.env}/valkey"
  description = "Valkey auth token and connection URL for the module tasks"
  kms_key_id  = aws_kms_key.apps.arn
}

resource "aws_secretsmanager_secret_version" "valkey" {
  secret_id = aws_secretsmanager_secret.valkey.id
  secret_string = jsonencode({
    auth_token = random_password.valkey.result
    url        = "rediss://:${random_password.valkey.result}@${aws_elasticache_replication_group.valkey.primary_endpoint_address}:6379/0"
  })
}
