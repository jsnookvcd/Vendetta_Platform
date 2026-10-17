output "instance_id" {
  description = "Reach the consoles over SSM: aws ssm start-session --target <id> --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"8300\"],\"localPortNumber\":[\"8300\"]}'"
  value       = aws_instance.host.id
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "alb_dns_name" {
  description = "Point each module host's DNS at this when bringing your own DNS."
  value       = var.enable_alb ? aws_lb.this[0].dns_name : "ALB disabled"
}

output "module_urls" {
  description = "Per-module URL once the ALB and DNS are up."
  value = var.enable_alb && var.base_domain != "" ? {
    for k, m in local.deployed : k => "https://${lookup(var.module_hosts, k, k)}.${var.base_domain}"
  } : { note = "ALB disabled; reach modules over SSM port forwarding (platform 8300, ir 8100, msp 8200, darkweb 8000, vuln 8400, pentest 8500, sabine 8600, osp 8700)" }
}

output "ssm_prefix" {
  description = "Put tool credentials and cross-module tokens here, e.g. <prefix>/managed-services/SENTINELONE_API_TOKEN."
  value       = var.ssm_prefix
}

output "backups_bucket" {
  value = aws_s3_bucket.backups.id
}

output "admin_password_hint" {
  description = "Each module's break-glass admin password is in SSM; read it once with the command shown."
  value       = "aws ssm get-parameter --with-decryption --query Parameter.Value --output text --name ${var.ssm_prefix}/platform/ADMIN_PASSWORD"
}
