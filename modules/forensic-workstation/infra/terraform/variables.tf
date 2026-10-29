variable "region" {
  description = "AWS region for the workstation and evidence bucket"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name"
  type        = string
  default     = "vendetta-fw"
}

variable "subnet_id" {
  description = "Subnet for the instance. Empty uses the default VPC with a public IP for egress only (no inbound rules exist)."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "Memory analysis and Plaso want RAM. m7i.2xlarge is 8 vCPU / 32 GiB; r7i.2xlarge (64 GiB) for large memory images."
  type        = string
  default     = "m7i.2xlarge"
}

variable "root_volume_gb" {
  description = "OS and tools"
  type        = number
  default     = 100
}

variable "cases_volume_gb" {
  description = "Size of the /cases volume holding evidence copies and work product"
  type        = number
  default     = 1000
}

variable "cases_volume_throughput" {
  description = "gp3 throughput in MiB/s for /cases. Timelining is I/O bound."
  type        = number
  default     = 500
}

variable "cases_volume_iops" {
  description = "gp3 IOPS for /cases"
  type        = number
  default     = 6000
}

variable "claude_backend" {
  description = "bedrock keeps evidence inside this AWS account (recommended). anthropic uses an API key stored in SSM."
  type        = string
  default     = "bedrock"
  validation {
    condition     = contains(["bedrock", "anthropic"], var.claude_backend)
    error_message = "claude_backend must be bedrock or anthropic."
  }
}

variable "claude_model" {
  description = "Model ID or Bedrock inference profile ID for Claude Code. Empty lets Claude Code choose its default."
  type        = string
  default     = ""
}

variable "bedrock_region" {
  description = "Region Claude Code calls Bedrock in. Anthropic models must be enabled under Bedrock model access there."
  type        = string
  default     = "us-east-1"
}

variable "enable_desktop" {
  description = "Install an XFCE desktop with xrdp (reached by SSM port forwarding to 3389) for GUI tools"
  type        = bool
  default     = true
}

variable "object_lock_mode" {
  description = "GOVERNANCE or COMPLIANCE retention on the evidence bucket"
  type        = string
  default     = "GOVERNANCE"
}

variable "evidence_retention_days" {
  description = "Object Lock retention for evidence and work product"
  type        = number
  default     = 365
}

variable "log_retention_days" {
  description = "Retention for session recordings and the MCP audit log"
  type        = number
  default     = 731
}

variable "idle_stop_hours" {
  description = "Stop the instance after this many hours under 5% CPU. 0 disables."
  type        = number
  default     = 3
}

variable "snapshot_retain_count" {
  description = "Daily snapshots of /cases to keep"
  type        = number
  default     = 14
}

variable "ssm_prefix" {
  description = "SSM Parameter Store path for workstation config"
  type        = string
  default     = "/vendetta/forensic-workstation"
}

variable "repo_url" {
  description = "Platform repo cloned on first boot. SSH URL plus a DEPLOY_KEY parameter for a private repo."
  type        = string
  default     = "https://github.com/jsnookvcd/Vendetta_Platform.git"
}

variable "git_ref" {
  description = "Branch or tag to check out"
  type        = string
  default     = "main"
}

variable "module_subdir" {
  description = "This module's directory inside the repo"
  type        = string
  default     = "modules/forensic-workstation"
}
