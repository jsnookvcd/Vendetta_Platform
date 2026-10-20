output "vpc_attachment_id" {
  description = "Add to the network stack spoke_attachments as segment = spoke, tor_peer = true when Tor egress is on."
  value       = module.vpc.transit_gateway_attachment_id
}

output "tor_vpc_attachment_id" {
  description = "Add to the network stack spoke_attachments as segment = tor."
  value       = try(module.tor_vpc["tor"].transit_gateway_attachment_id, null)
}

output "alb_dns_name" {
  description = "Point every public module hostname here at cutover (or let hosted_zone_id manage it)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "module_hosts" {
  value = local.hosts
}

output "ecr_repositories" {
  value = { for k, r in aws_ecr_repository.module : k => r.repository_url }
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.address
}

output "rds_master_secret_arn" {
  description = "RDS-managed master credential, used only by the database bootstrap."
  value       = try(aws_db_instance.postgres.master_user_secret[0].secret_arn, null)
}

output "module_databases" {
  description = "module => database name for the bootstrap step (one database and one owner role per module)."
  value       = { for k, m in local.deployed : k => coalesce(m.db_name, replace(k, "-", "_")) }
}

output "db_bootstrap_security_group_id" {
  value = aws_security_group.db_bootstrap.id
}

output "app_subnet_ids" {
  value = module.vpc.app_subnet_ids
}

output "valkey_endpoint" {
  value = aws_elasticache_replication_group.valkey.primary_endpoint_address
}

output "opensearch_endpoint" {
  value = aws_opensearch_domain.this.endpoint
}

output "opensearch_master_role_arn" {
  value = local.os_master_arn
}

output "task_role_arns" {
  description = "Map each to an OpenSearch backend role after the domain is created."
  value = merge(
    { for k, m in module.service : k => m.task_role_arn },
    { for k, m in module.worker : "${k}-worker" => m.task_role_arn },
  )
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}
