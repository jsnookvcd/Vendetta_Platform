output "arn" {
  value = aws_wafv2_web_acl.this.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
