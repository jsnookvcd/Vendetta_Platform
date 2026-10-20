variable "name" {
  description = "Name prefix for every resource, e.g. vcd-soc-ingest."
  type        = string
}

variable "cidr" {
  description = "VPC CIDR. A /16 or /20 from the org plan in infra/aws/README.md; spokes must not overlap."
  type        = string
}

variable "azs" {
  description = "Availability zones. Empty takes the first three in the region."
  type        = list(string)
  default     = []
}

variable "app_subnet_cidrs" {
  description = "Private app subnets, one per AZ. Empty derives /20s (or the equivalent 4 extra bits) from cidr."
  type        = list(string)
  default     = []
}

variable "data_subnet_cidrs" {
  description = "Private data subnets, one per AZ. Empty derives them from cidr after the app subnets."
  type        = list(string)
  default     = []
}

variable "create_public_subnets" {
  description = "Create public subnets and an internet gateway (for internet-facing load balancers)."
  type        = bool
  default     = false
}

variable "public_subnet_cidrs" {
  description = "Public subnets, one per AZ. Empty derives small subnets from the top of cidr."
  type        = list(string)
  default     = []
}

variable "enable_nat_gateway" {
  description = "One NAT gateway per AZ in the public subnets. Off by default: spokes egress through the central Transit Gateway and Network Firewall."
  type        = bool
  default     = false
}

variable "transit_gateway_id" {
  description = "Transit Gateway shared from the network account. When set, the VPC attaches in its app subnets and sends 0.0.0.0/0 from the private subnets to it."
  type        = string
  default     = null
}

variable "transit_gateway_destinations" {
  description = "Destinations routed to the Transit Gateway from the private route tables."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "flow_log_bucket_arn" {
  description = "Central log-archive bucket ARN for VPC flow logs (Parquet, hourly partitions). Null disables flow logs."
  type        = string
  default     = null
}

variable "gateway_endpoints" {
  description = "Gateway endpoints attached to every route table."
  type        = list(string)
  default     = ["s3", "dynamodb"]
}

variable "interface_endpoints" {
  description = "Interface endpoint service suffixes (com.amazonaws.<region>.<suffix>), placed in the app subnets with private DNS."
  type        = list(string)
  default = [
    "kms", "secretsmanager", "ssm", "ssmmessages", "ec2messages", "logs",
    "ecr.api", "ecr.dkr", "sts", "kinesis-streams", "sqs", "sns",
    "bedrock-runtime", "elasticloadbalancing", "monitoring", "events", "states", "es",
  ]
}

variable "tags" {
  type    = map(string)
  default = {}
}
