# lake

Runs in the data-lake account. Builds Security Lake (us-east-1 and us-east-2),
the native AWS log sources, a custom source per Vendetta connector family, the
raw archive bucket, one KMS key per tenant, Lake Formation settings and
per-tenant row filters, the `vcd-soc` Athena workgroup, and the Glue table over
the raw archive.

Inputs: `data_lake_account_id`, `ingest_account_id`, `organization_id` from
org; `custom_source_external_id` (sensitive, set through
`TF_VAR_custom_source_external_id`); `tenants`; `custom_sources`.

Custom source names are capped at 20 characters by Security Lake, so they carry
the family name without the `vcd-soc-` prefix.

Tenant filters: leave `enable_tenant_cell_filters = false` for the first apply.
Once each custom source has data and its Glue table exists, revoke
`IAMAllowedPrincipals` on the Security Lake database, set the flag to true and
apply. Each filter is `<tenant_filter_column> = '<platform_client_id>'`.

Raw archive queries must name a tenant (`WHERE tenant = '1001'`); the tenant
partition is injected. Objects in DEEP_ARCHIVE (after 395 days) need a restore
before Athena can read them.

If Security Lake returns ConflictException while creating log sources, apply
again or use `-parallelism=1`.

Outputs for ingest: `raw_bucket_arn`, `raw_kms_key_arn`, `tenant_kms_key_arns`,
`custom_source_provider_roles`.
