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
