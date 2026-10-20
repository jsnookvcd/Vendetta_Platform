output "service_name" {
  value = aws_ecs_service.this.name
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "task_role_name" {
  value = aws_iam_role.task.name
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "target_group_arn" {
  value = try(aws_lb_target_group.this["this"].arn, null)
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
