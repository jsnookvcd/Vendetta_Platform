# Athena workgroup for SOC queries and a Glue table over the raw archive.

module "athena_results" {
  source = "../modules/secure-bucket"

  name                       = "vcd-soc-athena-results-${local.account_id}"
  kms_key_arn                = aws_kms_key.lake.arn
  expiration_days            = var.athena_results_expiration_days
  noncurrent_expiration_days = 1
}

resource "aws_athena_workgroup" "soc" {
  name          = "vcd-soc"
  description   = "Vendetta SOC queries over Security Lake and the raw archive"
  force_destroy = false

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.athena_bytes_scanned_cutoff

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location       = "s3://${module.athena_results.id}/results/"
      expected_bucket_owner = local.account_id
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.lake.arn
      }
    }
  }
}

# ------------------------------------------------------------------ raw archive table
resource "aws_glue_catalog_database" "raw" {
  name        = "vcd_soc_raw"
  description = "Raw connector events as received, before OCSF normalization"
}

locals {
  raw_sources = distinct(concat(keys(var.custom_sources), var.extra_raw_sources))
}

# Partition projection: tenant is injected (every query must name a tenant,
# which keeps scans per client), source is an enum, dt is the Firehose date path.
# The columns describe the Vendetta ingest envelope; payload holds the vendor
# record as JSON text.
resource "aws_glue_catalog_table" "raw_events" {
  name          = "events"
  database_name = aws_glue_catalog_database.raw.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                      = "TRUE"
    classification                = "json"
    compressionType               = "gzip"
    "projection.enabled"          = "true"
    "projection.tenant.type"      = "injected"
    "projection.source.type"      = "enum"
    "projection.source.values"    = join(",", local.raw_sources)
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy/MM/dd"
    "projection.dt.range"         = "2026/01/01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${module.raw_bucket.id}/tenant=$${tenant}/source=$${source}/$${dt}/"
  }

  partition_keys {
    name = "tenant"
    type = "string"
  }
  partition_keys {
    name = "source"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${module.raw_bucket.id}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "tenant_id"
      type = "string"
    }
    columns {
      name = "source"
      type = "string"
    }
    columns {
      name = "connector"
      type = "string"
    }
    columns {
      name = "event_id"
      type = "string"
    }
    columns {
      name = "event_time"
      type = "string"
    }
    columns {
      name = "received_at"
      type = "string"
    }
    columns {
      name = "payload"
      type = "string"
    }
  }
}
