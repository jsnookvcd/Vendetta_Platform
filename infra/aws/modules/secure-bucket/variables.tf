variable "name" {
  description = "Bucket name. Callers pass a vcd-soc- prefixed name that includes the account id."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key used for default SSE-KMS encryption."
  type        = string
}

variable "object_lock_mode" {
  description = "GOVERNANCE or COMPLIANCE to enable Object Lock with a default retention; null leaves Object Lock off. Object Lock can only be turned on when the bucket is created."
  type        = string
  default     = null
  validation {
    condition     = var.object_lock_mode == null || contains(["GOVERNANCE", "COMPLIANCE"], coalesce(var.object_lock_mode, "GOVERNANCE"))
    error_message = "object_lock_mode must be GOVERNANCE, COMPLIANCE or null."
  }
}

variable "object_lock_retention_days" {
  description = "Default Object Lock retention in days."
  type        = number
  default     = 2555
}

variable "lifecycle_transitions" {
  description = "Storage class transitions for current versions."
  type = list(object({
    days          = number
    storage_class = string
  }))
  default = []
}

variable "expiration_days" {
  description = "Expire current versions after this many days; null keeps them."
  type        = number
  default     = null
}

variable "noncurrent_expiration_days" {
  description = "Expire noncurrent versions after this many days; null keeps them."
  type        = number
  default     = null
}

variable "policy_json" {
  description = "Extra bucket policy statements as a policy document JSON, merged with the TLS deny statements."
  type        = string
  default     = null
}

variable "tags" {
  description = "Extra tags for the bucket. Buckets with Object Lock also get vendetta:retention = locked, which the org SCP protects."
  type        = map(string)
  default     = {}
}
