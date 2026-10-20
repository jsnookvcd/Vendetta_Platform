# Pilot light in the DR region (DR.md): container images and RDS automated
# backups are copied continuously, so a recovery needs only an apply of this
# stack with region = dr_region and a restore from the replicated backups.

resource "aws_kms_key" "dr" {
  for_each                = var.enable_dr_replication ? toset(["this"]) : toset([])
  provider                = aws.dr
  description             = "${local.name} replicated RDS backups"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "dr" {
  for_each      = aws_kms_key.dr
  provider      = aws.dr
  name          = "alias/${local.name}-dr"
  target_key_id = each.value.key_id
}

resource "aws_db_instance_automated_backups_replication" "postgres" {
  for_each               = aws_kms_key.dr
  provider               = aws.dr
  source_db_instance_arn = aws_db_instance.postgres.arn
  kms_key_id             = each.value.arn
  retention_period       = 14
}

resource "aws_ecr_replication_configuration" "this" {
  for_each = var.enable_dr_replication ? toset(["this"]) : toset([])

  replication_configuration {
    rule {
      destination {
        region      = var.dr_region
        registry_id = local.account_id
      }
      repository_filter {
        filter      = "vcd-soc/"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}
