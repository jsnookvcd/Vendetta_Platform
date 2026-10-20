variable "region" {
  description = "Primary lake region."
  type        = string
  default     = "us-east-1"
}

variable "secondary_region" {
  description = "Second Security Lake region; gets its own data lake and a replica of the lake KMS key."
  type        = string
  default     = "us-east-2"
}

variable "enable_secondary_region" {
  description = "Run Security Lake in secondary_region as well (the org SCP allows us-east-1 and us-east-2)."
  type        = bool
  default     = true
}

variable "data_lake_account_id" {
  description = "org output account_ids[\"data-lake\"]."
  type        = string
}

variable "ingest_account_id" {
  description = "org output account_ids[\"ingest\"]. Provider principal for every custom source and the only writer to the raw archive."
  type        = string
}

variable "organization_id" {
  description = "org output organization_id; used in aws:PrincipalOrgID conditions."
  type        = string
}

variable "member_access_role_name" {
  type    = string
  default = "OrganizationAccountAccessRole"
}

# ------------------------------------------------------------------ Security Lake
variable "security_lake_transition_days" {
  type    = number
  default = 90
}

variable "security_lake_expiration_days" {
  description = "Days Security Lake keeps normalized OCSF data. The raw archive keeps the source of record for raw_retention_days."
  type        = number
  default     = 730
}

variable "log_source_accounts" {
  description = "Accounts the AWS log sources collect from. Null means every account in the organization."
  type        = list(string)
  default     = null
}

variable "aws_log_sources" {
  description = "Native Security Lake sources => source version."
  type        = map(string)
  default = {
    CLOUD_TRAIL_MGMT = "2.0"
    VPC_FLOW         = "2.0"
    ROUTE53          = "2.0"
    SH_FINDINGS      = "2.0"
    LAMBDA_EXECUTION = "2.0"
    S3_DATA          = "2.0"
    EKS_AUDIT        = "2.0"
    WAF              = "2.0"
  }
}

variable "custom_sources" {
  description = "Vendetta connector family => OCSF event classes it writes. Source names are capped at 20 characters by Security Lake."
  type        = map(list(string))
  default = {
    crowdstrike         = ["DETECTION_FINDING", "PROCESS_ACTIVITY", "NETWORK_ACTIVITY", "AUTHENTICATION"]
    sentinelone         = ["DETECTION_FINDING", "PROCESS_ACTIVITY", "NETWORK_ACTIVITY"]
    defender            = ["DETECTION_FINDING", "PROCESS_ACTIVITY", "EMAIL_ACTIVITY", "AUTHENTICATION"]
    huntress            = ["DETECTION_FINDING"]
    entra               = ["AUTHENTICATION", "API_ACTIVITY"]
    okta                = ["AUTHENTICATION", "API_ACTIVITY"]
    m365                = ["API_ACTIVITY", "EMAIL_ACTIVITY"]
    google-workspace    = ["AUTHENTICATION", "API_ACTIVITY", "EMAIL_ACTIVITY"]
    guardduty-findings  = ["DETECTION_FINDING"]
    vendetta-detections = ["DETECTION_FINDING"]
  }
  validation {
    condition     = alltrue([for k in keys(var.custom_sources) : length(k) <= 20])
    error_message = "Security Lake custom source names are limited to 20 characters."
  }
}

variable "custom_source_external_id" {
  description = "External id the ingest account presents when it assumes each custom source's provider role. Set it in a tfvars file kept out of git, or TF_VAR_custom_source_external_id."
  type        = string
  sensitive   = true
}

# ------------------------------------------------------------------ raw archive
variable "ingest_pipeline_role_names" {
  description = "Roles in the ingest account allowed to write the raw archive and use the tenant keys for encryption."
  type        = list(string)
  default     = ["vcd-soc-ingest-firehose", "vcd-soc-ingest-worker-task"]
}

variable "raw_object_lock_mode" {
  type    = string
  default = "GOVERNANCE"
}

variable "raw_retention_days" {
  type    = number
  default = 2555
}

variable "extra_raw_sources" {
  description = "Raw archive source partitions beyond the custom source names (syslog, webhook)."
  type        = list(string)
  default     = ["syslog", "webhook"]
}

# ------------------------------------------------------------------ tenants
variable "tenants" {
  description = "platform_client_id => { name, tier }. One KMS key and one Lake Formation row filter per tenant."
  type = map(object({
    name = string
    tier = string
  }))
  default = {}
}

variable "require_tenant_encryption_context" {
  description = "Require kms:EncryptionContext:tenant_id = <id> on every tenant key operation."
  type        = bool
  default     = true
}

variable "analyst_principal_patterns" {
  description = "ArnLike patterns allowed to decrypt with tenant keys (analysts)."
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SOCAnalyst_*",
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SOCAdmin_*",
  ]
}

variable "evidence_principal_patterns" {
  description = "ArnLike patterns allowed to decrypt with tenant keys (evidence custody)."
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_EvidenceCustodian_*",
    "arn:aws:iam::*:role/vcd-soc-evidence-custodian",
  ]
}

# ------------------------------------------------------------------ Lake Formation
variable "lake_admin_arns" {
  description = "Lake Formation administrators besides the Terraform role."
  type        = list(string)
  default     = []
}

variable "tenant_filter_column" {
  description = "Column the per-tenant row filter tests. The Vendetta normalizer writes it as a top-level column on every custom source record."
  type        = string
  default     = "tenant_id"
}

variable "enable_tenant_cell_filters" {
  description = "Create the per-tenant data cells filters. Leave false until each custom source's Glue table exists (first crawler run)."
  type        = bool
  default     = false
}

variable "tenant_filter_grants" {
  description = "platform_client_id => principal ARNs granted SELECT through that tenant's filters (for example a client-scoped analyst role)."
  type        = map(list(string))
  default     = {}
}

# ------------------------------------------------------------------ Athena
variable "athena_bytes_scanned_cutoff" {
  description = "Per-query scan limit in bytes for the vcd-soc workgroup."
  type        = number
  default     = 107374182400 # 100 GiB
}

variable "athena_results_expiration_days" {
  type    = number
  default = 30
}
