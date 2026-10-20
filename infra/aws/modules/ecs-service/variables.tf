variable "name" {
  description = "Module key, e.g. incident-response. Also the Service Connect discovery name, so peers reach http://<name>:<service_connect_port>."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every named resource."
  type        = string
  default     = "vcd-soc-"
}

variable "cluster_arn" {
  type = string
}

variable "cluster_name" {
  description = "Cluster name, used in the autoscaling resource id."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  description = "The VPC CIDR is always allowed to reach the container port."
  type        = string
}

variable "subnet_ids" {
  description = "Private app subnets for the tasks."
  type        = list(string)
}

variable "assign_public_ip" {
  type    = bool
  default = false
}

variable "image" {
  description = "Full image URI including tag or digest."
  type        = string
}

variable "cpu" {
  description = "Fargate task CPU units (256, 512, 1024, 2048, 4096...)."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory in MiB; must be valid for the cpu value."
  type        = number
  default     = 1024
}

variable "command" {
  description = "Container command override; null keeps the image default."
  type        = list(string)
  default     = null
}

variable "container_port" {
  description = "Port the container listens on. Null for workers that serve nothing (they still call peers through Service Connect)."
  type        = number
  default     = 8000
}

variable "port_name" {
  description = "Port mapping name referenced by Service Connect."
  type        = string
  default     = "http"
}

variable "app_protocol" {
  description = "Port mapping appProtocol (http, http2, grpc) or null for plain TCP."
  type        = string
  default     = "http"
}

variable "service_connect_namespace_arn" {
  description = "Cloud Map namespace for Service Connect. Null turns Service Connect off."
  type        = string
  default     = null
}

variable "expose_service_connect" {
  description = "Publish this service in Service Connect (client alias <name>:<service_connect_port>). Client-only when false."
  type        = bool
  default     = true
}

variable "service_connect_port" {
  description = "Client alias port peers use."
  type        = number
  default     = 8000
}

variable "environment" {
  description = "Plain environment variables. Nothing secret belongs here."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Environment variable name => SSM parameter ARN or Secrets Manager ARN (optionally with :json-key:: suffix)."
  type        = map(string)
  default     = {}
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "log_kms_key_arn" {
  description = "KMS key for the log group; null uses CloudWatch default encryption."
  type        = string
  default     = null
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "min_capacity" {
  type    = number
  default = 1
}

variable "max_capacity" {
  type    = number
  default = 4
}

variable "cpu_target_percent" {
  description = "Target average CPU for the scaling policy."
  type        = number
  default     = 60
}

variable "load_balancer" {
  description = "Optional ALB attachment: the module creates an ip target group health-checked on health_check_path and a listener rule."
  type = object({
    listener_arn         = string
    priority             = number
    host_headers         = optional(list(string), [])
    path_patterns        = optional(list(string), [])
    health_check_path    = optional(string, "/healthz")
    deregistration_delay = optional(number, 30)
  })
  default = null
}

variable "external_target_group_arns" {
  description = "Target groups created by the caller (for example an NLB TCP group) to register this service in, on container_port."
  type        = list(string)
  default     = []
}

variable "health_check_grace_period_seconds" {
  type    = number
  default = 60
}

variable "source_security_group_ids" {
  description = "Security groups allowed to reach the container port (the ALB, peers)."
  type        = list(string)
  default     = []
}

variable "ingress_cidrs" {
  description = "Extra CIDRs allowed to reach the container port, beyond the VPC CIDR."
  type        = list(string)
  default     = []
}

variable "task_role_policies" {
  description = "Inline policies for the task role, name => policy JSON. Keys must be static; values may be known only after apply. Empty leaves the task role with no permissions."
  type        = map(string)
  default     = {}
}

variable "enable_execute_command" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
