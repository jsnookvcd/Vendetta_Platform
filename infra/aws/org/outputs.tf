output "organization_id" {
  value = aws_organizations_organization.this.id
}

output "organization_arn" {
  description = "Feed to the network stack (RAM principal for the Transit Gateway share)."
  value       = aws_organizations_organization.this.arn
}

output "root_id" {
  value = local.root_id
}

output "ou_ids" {
  value = { for k, ou in aws_organizations_organizational_unit.this : k => ou.id }
}

output "account_ids" {
  description = "Member account ids by key; every other stack takes its target account id from here."
  value       = local.account_ids
}

output "log_archive_bucket_arn" {
  description = "Feed to modules/vpc flow_log_bucket_arn in every spoke."
  value       = module.log_archive_bucket.arn
}

output "log_archive_kms_key_arn" {
  value = aws_kms_key.cloudtrail.arn
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.org.arn
}

output "permission_set_arns" {
  value = { for k, ps in aws_ssoadmin_permission_set.this : k => ps.arn }
}
