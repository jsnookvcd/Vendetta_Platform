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
  description = "Git URL the instance clones on first boot. The private platform repo over SSH, using the read-only deploy key stored in SSM at <ssm_prefix>/DEPLOY_KEY."
  type        = string
  default     = "git@github.com:jsnookvcd/Vendetta_Platform.git"
}

variable "git_ref" {
  description = "Branch or tag to deploy."
  type        = string
  default     = "main"
}

variable "module_subdir" {
  description = "Path to this module inside the repo. The stack is built and run from here."
  type        = string
  default     = "modules/dark-web-monitoring"
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

# ---- optional public HTTPS front (needed for SSO and the client portal) ----
variable "enable_alb" {
  description = "Front the console with a public HTTPS ALB. Leave false for SSM-only access."
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Hostname for the console, e.g. darkweb.vendettacd.io. Required when enable_alb is true."
  type        = string
  default     = ""
}

variable "hosted_zone_id" {
  description = "Route53 zone ID to create the ACM cert validation and the A record in. Leave blank to bring your own cert via acm_certificate_arn."
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Existing ACM certificate ARN for domain_name. Use instead of hosted_zone_id to manage DNS yourself."
  type        = string
  default     = ""
}

variable "alb_allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443/80. Restrict to office and VPN egress where possible."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
