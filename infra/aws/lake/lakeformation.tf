# Lake Formation administration and per-tenant row filters.
#
# Tenant isolation in the lake: the Vendetta normalizer writes a top-level
# tenant column (var.tenant_filter_column, default tenant_id; the same value is
# also kept in unmapped.tenant_id for OCSF consumers) on every record it sends
# to a custom source. Each tenant gets a data cells filter per custom source
# table with the row filter <column> = '<platform_client_id>'. Native AWS sources
# (CloudTrail, VPC flow and the rest) carry no tenant column; they are scoped by
# account, and Vendetta's own accounts are the only accounts in them.

resource "aws_lakeformation_data_lake_settings" "this" {
  # The settings resource replaces the admin list, so the Terraform role is kept
  # in it or the next apply could lock Terraform out.
  admins = distinct(concat(var.lake_admin_arns, [data.aws_iam_session_context.current.issuer_arn]))
}

locals {
  # Glue table ARN: arn:aws:glue:<region>:<account>:table/<database>/<table>
  custom_tables = {
    for k, src in aws_securitylake_custom_log_source.this : k => {
      database = split("/", src.attributes[0].table_arn)[1]
      table    = split("/", src.attributes[0].table_arn)[2]
    }
  }

  tenant_filters = var.enable_tenant_cell_filters ? {
    for pair in setproduct(keys(var.tenants), keys(var.custom_sources)) :
    "${pair[0]}|${pair[1]}" => { tenant = pair[0], source = pair[1] }
  } : {}

  tenant_grants = var.enable_tenant_cell_filters ? {
    for g in flatten([
      for tenant, principals in var.tenant_filter_grants : [
        for p in principals : [
          for src in keys(var.custom_sources) : { tenant = tenant, source = src, principal = p }
        ]
      ]
    ]) : "${g.tenant}|${g.source}|${g.principal}" => g
  } : {}
}

resource "aws_lakeformation_data_cells_filter" "tenant" {
  for_each = local.tenant_filters

  table_data {
    name             = "vcd-soc-${each.value.tenant}-${each.value.source}"
    table_catalog_id = local.account_id
    database_name    = local.custom_tables[each.value.source].database
    table_name       = local.custom_tables[each.value.source].table

    column_wildcard {}

    row_filter {
      filter_expression = "${var.tenant_filter_column} = '${each.value.tenant}'"
    }
  }

  depends_on = [aws_lakeformation_data_lake_settings.this]
}

resource "aws_lakeformation_permissions" "tenant_select" {
  for_each    = local.tenant_grants
  principal   = each.value.principal
  permissions = ["SELECT"]

  data_cells_filter {
    name             = "vcd-soc-${each.value.tenant}-${each.value.source}"
    table_catalog_id = local.account_id
    database_name    = local.custom_tables[each.value.source].database
    table_name       = local.custom_tables[each.value.source].table
  }

  depends_on = [aws_lakeformation_data_cells_filter.tenant]
}
