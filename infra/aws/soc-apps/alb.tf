# Internet-facing ALB with the same hostnames and listener-rule priorities as
# infra/terraform/alb.tf, so the cutover is a DNS change. WAF (AWS managed
# Common, KnownBadInputs, Amazon IP reputation) on the ALB; CloudFront optional.

locals {
  alb_ingress = {
    for pair in setproduct(var.alb_allowed_cidrs, [80, 443]) :
    "${pair[0]}|${pair[1]}" => { cidr = pair[0], port = pair[1] }
  }
  cloudfront_on = var.enable_cloudfront ? toset(["this"]) : toset([])
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Vendetta SOC public ALB"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each          = local.alb_ingress
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id = aws_security_group.alb.id
  description       = "Module containers"
  ip_protocol       = "tcp"
  from_port         = 8000
  to_port           = 8000
  cidr_ipv4         = local.vpc_cidr
}

resource "aws_lb" "this" {
  name                       = "${local.name}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = module.vpc.public_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "No module for this host."
      status_code  = "404"
    }
  }
}

module "waf" {
  source = "../modules/waf-acl"

  name               = "${local.name}-alb"
  associations       = { alb = aws_lb.this.arn }
  log_retention_days = var.log_retention_days
}

# ------------------------------------------------------------------ CloudFront (optional)
resource "aws_cloudfront_distribution" "this" {
  for_each        = local.cloudfront_on
  enabled         = true
  is_ipv6_enabled = true
  http_version    = "http2and3"
  price_class     = "PriceClass_100"
  aliases         = values(local.hosts)
  comment         = "${local.name} modules"

  origin {
    origin_id   = "alb"
    domain_name = var.cloudfront_origin_hostname
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    # AWS managed policies: CachingDisabled and AllViewer (forwards Host, so the
    # ALB host rules still match).
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.cloudfront_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  lifecycle {
    precondition {
      condition     = var.cloudfront_origin_hostname != null && var.cloudfront_certificate_arn != null
      error_message = "enable_cloudfront needs cloudfront_origin_hostname and cloudfront_certificate_arn."
    }
  }
}

# ------------------------------------------------------------------ DNS
resource "aws_route53_record" "host" {
  for_each = var.hosted_zone_id != "" ? local.hosts : {}
  zone_id  = var.hosted_zone_id
  name     = each.value
  type     = "A"

  alias {
    name                   = var.enable_cloudfront ? aws_cloudfront_distribution.this["this"].domain_name : aws_lb.this.dns_name
    zone_id                = var.enable_cloudfront ? aws_cloudfront_distribution.this["this"].hosted_zone_id : aws_lb.this.zone_id
    evaluate_target_health = !var.enable_cloudfront
  }
}
