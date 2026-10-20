variable "name" {
  type = string
}

variable "associations" {
  description = "Static key => resource ARN (ALB, API Gateway REST stage). Keys must be known at plan time."
  type        = map(string)
  default     = {}
}

variable "rate_limit_per_5min" {
  description = "Per-IP request limit over five minutes; null disables the rate rule."
  type        = number
  default     = null
}

variable "common_rule_count_overrides" {
  description = "Common rule set rules switched to count, e.g. SizeRestrictions_BODY for large webhook payloads."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  type    = number
  default = 365
}
