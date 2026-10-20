output "data_lake_arn" {
  value = aws_securitylake_data_lake.this.arn
}

output "raw_bucket_arn" {
  description = "Feed to the ingest stack raw_bucket_arn."
  value       = module.raw_bucket.arn
}

output "raw_bucket_name" {
  value = module.raw_bucket.id
}

output "raw_kms_key_arn" {
  description = "Feed to the ingest stack raw_kms_key_arn."
  value       = aws_kms_key.raw.arn
}

output "lake_kms_key_arn" {
  value = aws_kms_key.lake.arn
}

output "tenant_kms_key_arns" {
  description = "Feed to the ingest stack tenant_kms_key_arns."
  value       = { for k, key in aws_kms_key.tenant : k => key.arn }
}

output "custom_source_provider_roles" {
  description = "source => { role_arn, location }. The ingest stack's securitylake_provider_role_arns takes the role ARNs."
  value = {
    for k, src in aws_securitylake_custom_log_source.this : k => {
      role_arn = try(src.provider_details[0].role_arn, null)
      location = try(src.provider_details[0].location, null)
    }
  }
}

output "athena_workgroup" {
  value = aws_athena_workgroup.soc.name
}

output "raw_glue_table" {
  value = "${aws_glue_catalog_database.raw.name}.${aws_glue_catalog_table.raw_events.name}"
}
