# Ingest VPC and its three ways in:
#   webhook push : API Gateway HTTP API -> VPC link -> internal ALB -> ingest-web
#   syslog       : internet-facing NLB, TLS on 6514 -> vector (TCP)
#   pull         : ingest-worker calls vendor APIs out through the central egress
#
# AWS WAF cannot be associated with an API Gateway HTTP API (only REST API
# stages), so the web ACL sits on the internal ALB behind the VPC link. Every
# webhook request still passes it.

data "aws_caller_identity" "current" {}

module "vpc" {
  source = "../modules/vpc"

  name                  = "vcd-soc-ingest"
  cidr                  = var.vpc_cidr
  create_public_subnets = true # NLB only; tasks stay in private subnets
  transit_gateway_id    = var.transit_gateway_id
  flow_log_bucket_arn   = var.flow_log_bucket_arn
}

# ------------------------------------------------------------------ internal ALB
resource "aws_security_group" "vpc_link" {
  name        = "vcd-soc-ingest-vpclink"
  description = "API Gateway VPC link ENIs"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "vpc_link" {
  security_group_id = aws_security_group.vpc_link.id
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = module.vpc.cidr
}

resource "aws_security_group" "alb" {
  name        = "vcd-soc-ingest-alb"
  description = "Internal webhook ALB"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_vpclink" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  referenced_security_group_id = aws_security_group.vpc_link.id
}

resource "aws_vpc_security_group_egress_rule" "alb" {
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = 8000
  to_port           = 8000
  cidr_ipv4         = module.vpc.cidr
}

resource "aws_lb" "webhook" {
  name                       = "vcd-soc-ingest-webhook"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = module.vpc.app_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

# Plain HTTP inside the VPC: TLS terminates at API Gateway and the hop from the
# VPC link to the ALB never leaves the VPC.
resource "aws_lb_listener" "webhook" {
  load_balancer_arn = aws_lb.webhook.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

module "waf" {
  source = "../modules/waf-acl"

  name                = "vcd-soc-ingest-webhook"
  associations        = { webhook_alb = aws_lb.webhook.arn }
  rate_limit_per_5min = var.webhook_rate_limit_per_5min
  # Vendor webhook bodies routinely exceed the 8 KB body inspection limit.
  common_rule_count_overrides = ["SizeRestrictions_BODY"]
  log_retention_days          = var.log_retention_days
}

# ------------------------------------------------------------------ API Gateway
resource "aws_apigatewayv2_vpc_link" "this" {
  name               = "vcd-soc-ingest"
  subnet_ids         = module.vpc.app_subnet_ids
  security_group_ids = [aws_security_group.vpc_link.id]
}

resource "aws_apigatewayv2_api" "webhook" {
  name          = "vcd-soc-ingest-webhook"
  protocol_type = "HTTP"
  description   = "Vendor and client webhook push into the Vendetta SOC"
}

resource "aws_apigatewayv2_integration" "webhook" {
  api_id                 = aws_apigatewayv2_api.webhook.id
  integration_type       = "HTTP_PROXY"
  integration_method     = "ANY"
  connection_type        = "VPC_LINK"
  connection_id          = aws_apigatewayv2_vpc_link.this.id
  integration_uri        = aws_lb_listener.webhook.arn
  payload_format_version = "1.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "webhook" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "ANY /api/ingest/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.webhook.id}"
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/vcd-soc/apigw/ingest-webhook"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 2000
    throttling_rate_limit  = 1000
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId = "$context.requestId"
      ip        = "$context.identity.sourceIp"
      time      = "$context.requestTime"
      method    = "$context.httpMethod"
      path      = "$context.path"
      status    = "$context.status"
      length    = "$context.responseLength"
      latency   = "$context.integrationLatency"
    })
  }
}

# ------------------------------------------------------------------ syslog NLB
resource "aws_security_group" "nlb" {
  name        = "vcd-soc-ingest-syslog-nlb"
  description = "Syslog over TLS from client ranges"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "nlb_syslog" {
  for_each          = toset(var.syslog_allowed_cidrs)
  security_group_id = aws_security_group.nlb.id
  description       = "syslog-tls from ${each.key}"
  ip_protocol       = "tcp"
  from_port         = 6514
  to_port           = 6514
  cidr_ipv4         = each.key
}

resource "aws_vpc_security_group_egress_rule" "nlb" {
  security_group_id = aws_security_group.nlb.id
  ip_protocol       = "tcp"
  from_port         = 6514
  to_port           = 6514
  cidr_ipv4         = module.vpc.cidr
}

resource "aws_lb" "syslog" {
  name                             = "vcd-soc-ingest-syslog"
  internal                         = false
  load_balancer_type               = "network"
  security_groups                  = [aws_security_group.nlb.id]
  subnets                          = module.vpc.public_subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
}

resource "aws_lb_target_group" "vector" {
  name                 = "vcd-soc-ingest-vector"
  port                 = 6514
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = module.vpc.vpc_id
  deregistration_delay = 60

  health_check {
    protocol            = "TCP"
    interval            = 30
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "syslog" {
  load_balancer_arn = aws_lb.syslog.arn
  port              = 6514
  protocol          = "TLS"
  certificate_arn   = var.syslog_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vector.arn
  }
}
