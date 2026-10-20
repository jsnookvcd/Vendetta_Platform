variable "region" {
  type    = string
  default = "us-east-1"
}

variable "network_account_id" {
  description = "Account that owns the Transit Gateway and egress VPC (the org stack's network account, or ingest until one exists)."
  type        = string
}

variable "member_access_role_name" {
  type    = string
  default = "OrganizationAccountAccessRole"
}

variable "organization_arn" {
  description = "org stack output organization_arn; the Transit Gateway is shared with the whole organization through RAM."
  type        = string
}

variable "flow_log_bucket_arn" {
  description = "org stack output log_archive_bucket_arn. Null disables flow logs on the egress VPC."
  type        = string
  default     = null
}

variable "egress_vpc_cidr" {
  description = "Egress VPC. Split into nine /26s: public, firewall and TGW subnets in three AZs."
  type        = string
  default     = "10.255.0.0/22"
}

variable "azs" {
  description = "Empty takes the first three AZs."
  type        = list(string)
  default     = []
}

variable "spoke_supernets" {
  description = "Every spoke CIDR lives inside these. Also the firewall HOME_NET."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "protected_cidrs" {
  description = "Data-lake and evidence VPC CIDRs. The Tor segment has blackhole routes for these."
  type        = list(string)
  default     = ["10.30.0.0/16", "10.40.0.0/16"]
}

variable "tor_cidrs" {
  description = "CIDRs of the Tor egress VPCs (soc-apps tor_vpc_cidr). Protected segments have blackhole routes for these."
  type        = list(string)
  default     = ["10.60.0.0/20", "10.61.0.0/20"]
}

variable "spoke_attachments" {
  description = <<-EOT
    Spoke VPC attachments created in member accounts (modules/vpc output transit_gateway_attachment_id).
    Second pass: apply network, apply the spoke stacks, then add their attachment ids here and apply network again.
    segment: spoke (normal workloads), protected (data-lake, evidence), tor (dark web Tor egress).
    tor_peer: a spoke the Tor segment may return traffic to (the dark web module's VPC).
  EOT
  type = map(object({
    attachment_id = string
    segment       = string
    tor_peer      = optional(bool, false)
  }))
  default = {}
  validation {
    condition     = alltrue([for a in values(var.spoke_attachments) : contains(["spoke", "protected", "tor"], a.segment)])
    error_message = "segment must be spoke, protected or tor."
  }
}

variable "domain_allowlist" {
  description = "Egress domains allowed by SNI / Host header. A leading *. matches every subdomain. AWS APIs reached through VPC endpoints do not need to be listed."
  type        = list(string)
  default = [
    # EDR and XDR vendors
    "api.crowdstrike.com",
    "api.us-2.crowdstrike.com",
    "*.sentinelone.net",
    "api.huntress.io",
    # Microsoft
    "graph.microsoft.com",
    "login.microsoftonline.com",
    "manage.office.com",
    "api.security.microsoft.com",
    "api.securitycenter.microsoft.com",
    # Identity
    "*.okta.com",
    # Google Workspace (Admin SDK plus the OAuth token endpoint a service account needs)
    "admin.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    # Source and releases
    "github.com",
    "api.github.com",
    # AWS endpoints with no interface endpoint in the spoke region: the global
    # STS endpoint, public ECR, and us-east-2 services used for DR copies.
    "sts.amazonaws.com",
    "public.ecr.aws",
    "kms.us-east-2.amazonaws.com",
    "s3.us-east-2.amazonaws.com",
    "*.s3.us-east-2.amazonaws.com",
  ]
}

variable "domain_rule_capacity" {
  description = "Stateful rule group capacity. Fixed at creation; size it for growth."
  type        = number
  default     = 500
}

variable "firewall_log_retention_days" {
  type    = number
  default = 365
}
