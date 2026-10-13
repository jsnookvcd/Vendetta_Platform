output "instance_id" {
  value = aws_instance.monitor.id
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "connect" {
  description = "Open the console on http://localhost:8000 from your Mac"
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.monitor.id} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"8000\"],\"localPortNumber\":[\"8000\"]}'"
}

output "shell" {
  value = "aws ssm start-session --region ${var.region} --target ${aws_instance.monitor.id}"
}

output "console_url" {
  description = "Public URL when the ALB is enabled; otherwise use the SSM port-forward in `connect`."
  value       = var.enable_alb ? "https://${var.domain_name}" : "(ALB disabled; use the SSM port-forward)"
}

output "alb_dns_name" {
  description = "ALB DNS name to point domain_name at if you manage DNS yourself."
  value       = var.enable_alb ? aws_lb.console[0].dns_name : ""
}

output "entra_redirect_url" {
  description = "Set this as ENTRA_REDIRECT_URL in SSM and as the Entra app redirect URI."
  value       = var.enable_alb ? "https://${var.domain_name}/auth/callback" : ""
}
