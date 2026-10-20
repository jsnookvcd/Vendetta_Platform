variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "vcd-platform"
}

variable "instance_type" {
  description = "One host runs every module stack (web + Postgres each) plus Tor. t4g.large (2 vCPU, 8 GB) is the comfortable default; t4g.medium works for a light client load with Postgres tuned down."
  type        = string
  default     = "t4g.large"
}

variable "root_volume_gb" {
  type    = number
  default = 60
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

# The modules that run on the host, with the port each binds and whether this stack
# deploys it. Ports match each module's docker-compose. Add a module here when it is
# ready to deploy.
variable "modules" {
  description = "key => { subdir, port, deploy }. Every built module; network-operations joins when it exists."
  type = map(object({
    subdir = string
    port   = number
    deploy = bool
  }))
  default = {
    platform = {
      subdir = "modules/platform"
      port   = 8300
      deploy = true
    }
    incident-response = {
      subdir = "modules/incident-response"
      port   = 8100
      deploy = true
    }
    managed-services = {
      subdir = "modules/managed-services"
      port   = 8200
      deploy = true
    }
    dark-web-monitoring = {
      subdir = "modules/dark-web-monitoring"
      port   = 8000
      deploy = true
    }
    vulnerability-management = {
      subdir = "modules/vulnerability-management"
      port   = 8400
      deploy = true
    }
    penetration-testing = {
      subdir = "modules/penetration-testing"
      port   = 8500
      deploy = true
    }
    sabine = {
      subdir = "modules/sabine"
      port   = 8600
      deploy = true
    }
    professional-services = {
      subdir = "modules/professional-services"
      port   = 8700
      deploy = true
    }
    mdr = {
      subdir = "modules/mdr"
      port   = 8800
      deploy = true
    }
    project-management = {
      subdir = "modules/project-management"
      port   = 8900
      deploy = true
    }
    ingest = {
      subdir = "modules/ingest"
      port   = 9000
      deploy = true
    }
  }
}

variable "listener_priorities" {
  description = "Fixed ALB listener-rule priority per module key, so adding a module never reshuffles the others."
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

variable "backup_retention_days" {
  description = "Days to keep nightly Postgres dumps in the backups bucket."
  type        = number
  default     = 35
}

variable "ssm_prefix" {
  type    = string
  default = "/vendetta"
}

variable "alert_emails" {
  description = "Addresses subscribed to the SNS alert topic. Each must confirm the subscription email."
  type        = list(string)
  default     = []
}

variable "evidence_retention_days" {
  description = "Object Lock default retention on the shared evidence bucket (dark web captures, IR preservation). Captures cannot be altered or deleted before this elapses."
  type        = number
  default     = 2555 # seven years
}

variable "object_lock_mode" {
  description = "COMPLIANCE cannot be overridden by anyone. Use GOVERNANCE while testing."
  type        = string
  default     = "GOVERNANCE"
}

# ------------------------------------------------------------------ ALB front
# The platform is multi-tenant staff tooling with client portals, so SSO and the
# portals need real HTTPS hostnames. The ALB routes each module by hostname.
variable "enable_alb" {
  description = "Public HTTPS front. Off by default; reach the consoles over SSM port forwarding until the hostnames and cert are ready."
  type        = bool
  default     = false
}

variable "base_domain" {
  description = "The zone the module hostnames sit in. Each module gets <key-host>.<base_domain>, so the control plane is platform.<base_domain>."
  type        = string
  default     = "vendettacyber.com"
}

variable "module_hosts" {
  description = "Hostname label per module key. The full host is <label>.<base_domain>."
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

variable "hosted_zone_id" {
  description = "Route53 zone id for base_domain; used to validate the cert and create the alias records. Leave blank to bring your own cert and manage DNS yourself."
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Existing cert covering every module host. Leave blank to have Terraform create and DNS-validate one in hosted_zone_id."
  type        = string
  default     = ""
}

variable "alb_allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB. Restrict to office / VPN egress where possible; client-portal users need their own ranges allowed."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
