variable "region" {
  description = "Home region for the organization trail, Identity Center and the log archive."
  type        = string
  default     = "us-east-1"
}

variable "allowed_regions" {
  description = "Regions workloads may use. Everything else is denied by SCP, apart from global services."
  type        = list(string)
  default     = ["us-east-1", "us-east-2"]
}

variable "account_emails" {
  description = "Root email per member account key. Required keys: log-archive, security-tooling, data-lake, ingest, soc-apps-prod, soc-apps-staging, evidence. Optional: network (recommended home for the network stack). Use plus-addressed aliases on a monitored mailbox; no default so no address ends up in the repo."
  type        = map(string)
  validation {
    condition = alltrue([
      for k in ["log-archive", "security-tooling", "data-lake", "ingest", "soc-apps-prod", "soc-apps-staging", "evidence"] :
      contains(keys(var.account_emails), k)
    ])
    error_message = "account_emails must contain log-archive, security-tooling, data-lake, ingest, soc-apps-prod, soc-apps-staging and evidence."
  }
}

variable "account_ou" {
  description = "Which OU each account key lands in."
  type        = map(string)
  default = {
    log-archive      = "Security"
    security-tooling = "Security"
    data-lake        = "Security"
    evidence         = "Security"
    ingest           = "Infrastructure"
    network          = "Infrastructure"
    soc-apps-prod    = "Workloads"
    soc-apps-staging = "Workloads"
  }
}

variable "member_access_role_name" {
  description = "Role Organizations creates in each new account and that the provider aliases assume."
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "scp_exempt_principal_arns" {
  description = "Principals exempt from the protective SCPs. ArnLike patterns. OrganizationAccountAccessRole is listed because Terraform runs through it and only management-account admins can assume it; those admins can detach SCPs anyway, so the exemption gives away nothing."
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/OrganizationAccountAccessRole",
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_BreakGlass_*",
    "arn:aws:iam::*:role/vcd-soc-breakglass",
  ]
}

variable "locked_bucket_arn_patterns" {
  description = "Bucket ARN patterns protected by name, in addition to the vendetta:retention=locked tag (see README on S3 tag conditions)."
  type        = list(string)
  default = [
    "arn:aws:s3:::vcd-soc-raw-*",
    "arn:aws:s3:::vcd-soc-ledger-*",
    "arn:aws:s3:::vcd-soc-log-archive-*",
  ]
}

variable "log_archive_retention_days" {
  description = "Object Lock retention on the organization CloudTrail and flow log archive."
  type        = number
  default     = 2555
}

variable "log_archive_object_lock_mode" {
  description = "GOVERNANCE lets break-glass shorten retention; COMPLIANCE cannot be overridden by anyone, including AWS."
  type        = string
  default     = "GOVERNANCE"
}

# ------------------------------------------------------------------ Identity Center
variable "enable_identity_center" {
  description = "Manage permission sets and assignments. Identity Center must already be enabled in the management account (console, once)."
  type        = bool
  default     = true
}

variable "permission_set_assignments" {
  description = "Assignment name => { permission_set (SOCAdmin, SOCAnalyst, EvidenceCustodian, BreakGlass), group_id (Identity Store group id synced from Entra via SCIM), accounts (account keys) }."
  type = map(object({
    permission_set = string
    group_id       = string
    accounts       = list(string)
  }))
  default = {}
}

variable "lake_query_workgroup" {
  description = "Athena workgroup SOCAnalyst may run queries in."
  type        = string
  default     = "vcd-soc"
}
