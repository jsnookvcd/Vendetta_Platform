output "ledger_bucket_arn" {
  description = "Feed to soc-apps evidence_bucket_arn."
  value       = module.ledger.arn
}

output "replica_bucket_arn" {
  value = module.replica.arn
}

output "ledger_kms_key_arn" {
  description = "Feed to soc-apps evidence_kms_key_arn."
  value       = aws_kms_key.ledger.arn
}

output "signing_key_arn" {
  value = aws_kms_key.signing.arn
}

output "key_admin_role_arn" {
  value = aws_iam_role.key_admin.arn
}

output "custodian_role_arn" {
  value = aws_iam_role.custodian.arn
}
