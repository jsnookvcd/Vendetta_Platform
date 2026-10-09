variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "vcd-darkweb"
}

variable "instance_type" {
  description = "t4g.small (2 vCPU, 2 GB) is the sweet spot. t4g.micro works for a handful of clients with Postgres tuned down."
  type        = string
  default     = "t4g.small"
}

variable "root_volume_gb" {
  type    = number
  default = 30
}

variable "repo_url" {
  description = "Git URL the instance clones on first boot. Use a deploy key or a public mirror. Leave empty to rsync code via SSM instead."
  type        = string
  default     = ""
}

variable "ssm_prefix" {
  type    = string
  default = "/darkweb"
}

variable "alert_emails" {
  description = "Addresses subscribed to the SNS alert topic. Each must confirm the subscription email."
  type        = list(string)
  default     = []
}

variable "evidence_retention_days" {
  description = "Object Lock default retention. Captures cannot be deleted or altered before this elapses."
  type        = number
  default     = 2555 # seven years
}

variable "object_lock_mode" {
  description = "COMPLIANCE cannot be overridden by anyone. Use GOVERNANCE while testing."
  type        = string
  default     = "GOVERNANCE"
}

# Jira is intentionally not provisioned here. When the IR desk is live, add
# JIRA_BASE_URL, JIRA_EMAIL and JIRA_API_TOKEN to SSM with aws ssm put-parameter.
