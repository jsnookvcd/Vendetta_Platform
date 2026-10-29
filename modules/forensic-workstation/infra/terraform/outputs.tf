output "instance_id" {
  value = aws_instance.ws.id
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "analyst_policy_arn" {
  description = "Attach to the analysts' IAM group or SSO permission set"
  value       = aws_iam_policy.analyst.arn
}

output "connect_shell" {
  description = "Analyst shell (lands as the analyst user in /cases, session recorded)"
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.ws.id} --document-name ${aws_ssm_document.shell.name}"
}

output "connect_desktop" {
  description = "Forward RDP to localhost:13389, then connect an RDP client to localhost:13389"
  value       = var.enable_desktop ? "aws ssm start-session --region ${var.region} --target ${aws_instance.ws.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=13389" : "desktop disabled"
}

output "intake_upload_example" {
  value = "aws s3 cp ./HOST01.E01 s3://${aws_s3_bucket.evidence.id}/intake/<CASE-ID>/HOST01.E01"
}
