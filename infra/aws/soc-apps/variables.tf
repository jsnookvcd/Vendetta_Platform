variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  description = "prod (soc-apps-prod account) or staging (soc-apps-staging account). Each has its own backend key."
  type        = string
  validation {
    condition     = contains(["prod", "staging"], var.environment)
    error_message = "environment must be prod or staging."
  }
}

variable "account_id" {
  description = "org output account_ids[\"soc-apps-prod\"] or account_ids[\"soc-apps-staging\"]."
  type        = string
}

variable "member_access_role_name" {
  type    = string
  default = "OrganizationAccountAccessRole"
}

variable "organization_id" {
  description = "org output organization_id; ECR repositories allow pulls from the whole organization."
  type        = string
}

# ------------------------------------------------------------------ network
variable "vpc_cidr" {
  description = "Null picks 10.20.0.0/16 for prod and 10.21.0.0/16 for staging."
  type        = string
  default     = null
}

variable "transit_gateway_id" {
  type    = string
  default = null
}

variable "flow_log_bucket_arn" {
  type    = string
  default = null
}

variable "enable_tor_egress" {
  description = "Run Tor for dark web collection in its own VPC on the Transit Gateway tor segment (see network stack). Needs tor_image and transit_gateway_id."
  type        = bool
  default     = false
}

variable "tor_vpc_cidr" {
  description = "Null picks 10.60.0.0/20 for prod and 10.61.0.0/20 for staging. Must be listed in the network stack tor_cidrs."
  type        = string
  default     = null
}

variable "tor_image" {
  description = "Image built from modules/dark-web-monitoring/infra/tor, pushed to the vcd-soc/tor repository."
  type        = string
  default     = null
}

# ------------------------------------------------------------------ modules
variable "modules" {
  description = "Mirrors infra/terraform's module map, plus the modules that move to ECS. public = routed on the ALB by hostname. worker_command adds a <key>-worker service with the same image."
  type = map(object({
    cpu            = number
    memory         = number
    desired_count  = number
    min            = number
    max            = number
    public         = bool
    deploy         = optional(bool, true)
    db_name        = optional(string)
    worker_command = optional(list(string))
  }))
  default = {
    platform                 = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 6, public = true, db_name = "platform" }
    incident-response        = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 6, public = true, db_name = "irhub" }
    managed-services         = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 6, public = true, db_name = "msp", worker_command = ["python", "worker.py"] }
    dark-web-monitoring      = { cpu = 1024, memory = 2048, desired_count = 1, min = 1, max = 4, public = true, db_name = "darkweb", worker_command = ["python", "-m", "app.worker"] }
    vulnerability-management = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 6, public = true, db_name = "vulnmgmt" }
    penetration-testing      = { cpu = 512, memory = 1024, desired_count = 1, min = 1, max = 4, public = true, db_name = "pentest" }
    sabine                   = { cpu = 1024, memory = 2048, desired_count = 1, min = 1, max = 3, public = true, db_name = "sabine" }
    mdr                      = { cpu = 1024, memory = 2048, desired_count = 2, min = 2, max = 6, public = true, db_name = "mdr" }
    professional-services    = { cpu = 512, memory = 1024, desired_count = 1, min = 1, max = 4, public = true, db_name = "psvc" }
    evidence-export          = { cpu = 512, memory = 1024, desired_count = 1, min = 1, max = 3, public = false, db_name = "evidence_export" }
    ai-triage                = { cpu = 1024, memory = 2048, desired_count = 1, min = 1, max = 4, public = false, db_name = "ai_triage" }
    ingest                   = { cpu = 512, memory = 1024, desired_count = 2, min = 2, max = 4, public = true, db_name = "ingest" }
    project-management       = { cpu = 512, memory = 1024, desired_count = 1, min = 1, max = 3, public = true, db_name = "pmtool" }
  }
}

variable "default_image_tag" {
  description = "Image tag used for every module without an entry in image_tags (CI pushes the git sha)."
  type        = string
}

variable "image_tags" {
  description = "Per-module image tag override."
  type        = map(string)
  default     = {}
}

variable "module_environment" {
  description = "Extra plain environment per module, merged over the defaults."
  type        = map(map(string))
  default     = {}
}

variable "extra_ssm_secrets" {
  description = "Extra SSM parameter names per module, read from <ssm_prefix>/<module>/<NAME> into env var NAME (tool credentials, Entra SSO values, AZURE_SPEECH_KEY)."
  type        = map(list(string))
  default     = {}
}

variable "ssm_prefix" {
  type    = string
  default = "/vendetta"
}

# ------------------------------------------------------------------ hostnames and edge
variable "base_domain" {
  description = "Zone the module hostnames sit in. Matches infra/terraform's base_domain so the DNS cutover keeps every hostname."
  type        = string
  default     = "vendettacyber.io"
}

variable "module_hosts" {
  description = "Hostname label per module key, as in infra/terraform. Staging appends -staging to each label."
  type        = map(string)
  default = {
    platform                 = "platform"
    incident-response        = "ir"
    managed-services         = "msp"
    dark-web-monitoring      = "darkweb"
    vulnerability-management = "vuln"
    penetration-testing      = "pentest"
    sabine                   = "sabine"
    professional-services    = "osp"
    mdr                      = "mdr"
    project-management       = "pm"
    ingest                   = "ingest"
  }
}

variable "listener_priorities" {
  description = "Fixed ALB listener-rule priority per module, identical to infra/terraform."
  type        = map(number)
  default = {
    platform                 = 100
    incident-response        = 110
    managed-services         = 120
    dark-web-monitoring      = 130
    vulnerability-management = 140
    penetration-testing      = 150
    sabine                   = 155
    professional-services    = 157
    mdr                      = 160
    project-management       = 165
    ingest                   = 167
    network-operations       = 170
  }
}

variable "acm_certificate_arn" {
  description = "ACM certificate in this account covering every public module host."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 zone for base_domain. Blank leaves DNS to you (the cutover step)."
  type        = string
  default     = ""
}

variable "alb_allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "enable_cloudfront" {
  type    = bool
  default = false
}

variable "cloudfront_origin_hostname" {
  description = "Hostname on the ALB certificate that resolves to the ALB (e.g. origin.vendettacyber.io); CloudFront connects to it."
  type        = string
  default     = null
}

variable "cloudfront_certificate_arn" {
  description = "us-east-1 ACM certificate for the CloudFront aliases."
  type        = string
  default     = null
}

# ------------------------------------------------------------------ data stores
variable "db_instance_class" {
  type    = string
  default = "db.r7g.large"
}

variable "db_engine_version" {
  description = "Major version; RDS picks the current minor and auto minor upgrades stay on."
  type        = string
  default     = "16"
}

variable "db_allocated_storage" {
  type    = number
  default = 200
}

variable "db_max_allocated_storage" {
  type    = number
  default = 2000
}

variable "valkey_node_type" {
  type    = string
  default = "cache.r7g.large"
}

variable "valkey_engine_version" {
  type    = string
  default = "8.0"
}

variable "valkey_replicas" {
  type    = number
  default = 2
}

variable "opensearch_engine_version" {
  description = "Latest supported OpenSearch 2.x engine string in the region; check with aws opensearch list-versions."
  type        = string
  default     = "OpenSearch_2.19"
}

variable "opensearch_instance_type" {
  type    = string
  default = "r7g.large.search"
}

variable "opensearch_instance_count" {
  type    = number
  default = 3
}

variable "opensearch_volume_gb" {
  type    = number
  default = 200
}

variable "opensearch_dedicated_master" {
  type    = bool
  default = true
}

variable "opensearch_master_type" {
  type    = string
  default = "m7g.large.search"
}

variable "opensearch_ultrawarm" {
  description = "UltraWarm requires dedicated masters."
  type        = bool
  default     = false
}

variable "opensearch_warm_type" {
  type    = string
  default = "ultrawarm1.medium.search"
}

variable "opensearch_warm_count" {
  type    = number
  default = 2
}

variable "opensearch_master_role_arn" {
  description = "IAM master user for fine-grained access control. Null creates vcd-soc-<env>-opensearch-master, assumable by SOCAdmin."
  type        = string
  default     = null
}

variable "create_opensearch_service_linked_role" {
  description = "Set false if AWSServiceRoleForAmazonOpenSearchService already exists in the account."
  type        = bool
  default     = true
}

# ------------------------------------------------------------------ cross-account
variable "evidence_bucket_arn" {
  description = "evidence output ledger_bucket_arn, for the modules that preserve evidence. Null leaves EVIDENCE_BUCKET unset."
  type        = string
  default     = null
}

variable "evidence_kms_key_arn" {
  type    = string
  default = null
}

variable "bedrock_model_arns" {
  description = "Bedrock models and inference profiles SABINE and AI triage may invoke."
  type        = list(string)
  default = [
    "arn:aws:bedrock:*::foundation-model/anthropic.*",
    "arn:aws:bedrock:*:*:inference-profile/*anthropic.*",
  ]
}

variable "dr_region" {
  type    = string
  default = "us-east-2"
}

variable "enable_dr_replication" {
  description = "Replicate ECR images and RDS automated backups to dr_region (pilot light, DR.md). Usually off for staging."
  type        = bool
  default     = true
}

variable "alert_emails" {
  type    = list(string)
  default = []
}

variable "log_retention_days" {
  type    = number
  default = 365
}
