variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ingest_account_id" {
  description = "org output account_ids[\"ingest\"]."
  type        = string
}

variable "member_access_role_name" {
  type    = string
  default = "OrganizationAccountAccessRole"
}

# ------------------------------------------------------------------ network
variable "vpc_cidr" {
  type    = string
  default = "10.10.0.0/16"
}

variable "transit_gateway_id" {
  description = "network output transit_gateway_id. Null keeps the VPC without internet egress (endpoints only)."
  type        = string
  default     = null
}

variable "flow_log_bucket_arn" {
  description = "org output log_archive_bucket_arn."
  type        = string
  default     = null
}

# ------------------------------------------------------------------ lake wiring
variable "raw_bucket_arn" {
  description = "lake output raw_bucket_arn."
  type        = string
}

variable "raw_kms_key_arn" {
  description = "lake output raw_kms_key_arn."
  type        = string
}

variable "tenant_kms_key_arns" {
  description = "lake output tenant_kms_key_arns."
  type        = map(string)
  default     = {}
}

variable "securitylake_provider_role_arns" {
  description = "Role ARNs from the lake output custom_source_provider_roles; the worker and stream tasks assume them to write OCSF Parquet into Security Lake."
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------ pipeline
variable "kinesis_retention_hours" {
  type    = number
  default = 168
}

variable "firehose_buffer_mb" {
  description = "Firehose buffer size; dynamic partitioning requires at least 64."
  type        = number
  default     = 128
}

variable "firehose_buffer_seconds" {
  type    = number
  default = 60
}

variable "bucket_feed_source_arns" {
  description = "S3 buckets or SNS topics (vendor or client) allowed to send object notifications to the bucket-feed queue."
  type        = list(string)
  default     = []
}

variable "client_reader_role_prefix" {
  description = "Client accounts create a role named <prefix>* that trusts the ingest worker role with an ExternalId condition."
  type        = string
  default     = "VendettaSOCReader"
}

# ------------------------------------------------------------------ edges
variable "syslog_certificate_arn" {
  description = "ACM certificate for the syslog TLS listener (e.g. syslog.vendettacyber.io)."
  type        = string
}

variable "syslog_allowed_cidrs" {
  description = "Client egress ranges allowed to reach syslog on 6514. Empty admits nobody."
  type        = list(string)
  default     = []
}

variable "webhook_rate_limit_per_5min" {
  type    = number
  default = 20000
}

# ------------------------------------------------------------------ services
variable "images" {
  description = "Image URI per service: ingest-web, ingest-worker, ingest-stream, vector."
  type        = map(string)
  validation {
    condition     = alltrue([for k in ["ingest-web", "ingest-worker", "ingest-stream", "vector"] : contains(keys(var.images), k)])
    error_message = "images needs ingest-web, ingest-worker, ingest-stream and vector."
  }
}

variable "service_sizing" {
  description = "Per-service cpu, memory and scaling bounds."
  type = map(object({
    cpu           = number
    memory        = number
    desired_count = number
    min           = number
    max           = number
  }))
  default = {
    ingest-web    = { cpu = 512, memory = 1024, desired_count = 2, min = 2, max = 6 }
    ingest-worker = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 10 }
    ingest-stream = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 8 }
    vector        = { cpu = 512, memory = 1024, desired_count = 2, min = 2, max = 6 }
  }
}

variable "log_retention_days" {
  type    = number
  default = 365
}
