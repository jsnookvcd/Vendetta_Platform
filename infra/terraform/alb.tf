# One ALB fronts every module, routing by hostname: platform.vendettacyber.com,
# ir.vendettacyber.com, msp.vendettacyber.com, darkweb.vendettacyber.com (the
# hosts follow base_domain). Off by default; enable it once the hostnames and
# cert are ready. See variables.tf for the knobs.

locals {
  alb_on    = var.enable_alb ? 1 : 0
  make_cert = var.enable_alb && var.acm_certificate_arn == "" && var.hosted_zone_id != "" ? 1 : 0
  cert_arn  = var.acm_certificate_arn != "" ? var.acm_certificate_arn : (local.make_cert == 1 ? aws_acm_certificate_validation.alb[0].certificate_arn : "")
  # Full hostname per deployed module, e.g. { platform = "platform.vendettacyber.com" }.
  hosts = { for k, m in local.deployed : k => "${lookup(var.module_hosts, k, k)}.${var.base_domain}" }
}

resource "aws_security_group" "alb" {
  count       = local.alb_on
  name        = "${var.name_prefix}-alb"
  description = "Vendetta Platform ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.alb_allowed_cidrs
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.alb_allowed_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  count              = local.alb_on
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = data.aws_subnets.default.ids
}

# One target group per deployed module, health-checked on /healthz.
resource "aws_lb_target_group" "mod" {
  for_each = var.enable_alb ? local.deployed : {}
  name     = substr("${var.name_prefix}-${each.key}", 0, 32)
  port     = each.value.port
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "mod" {
  for_each         = var.enable_alb ? local.deployed : {}
  target_group_arn = aws_lb_target_group.mod[each.key].arn
  target_id        = aws_instance.host.id
  port             = each.value.port
}

# Redirect 80 to 443.
resource "aws_lb_listener" "http" {
  count             = local.alb_on
  load_balancer_arn = aws_lb.this[0].arn
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

# HTTPS listener: default 404, then a host-based rule per module.
resource "aws_lb_listener" "https" {
  count             = local.alb_on
  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.cert_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "No module for this host."
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "host" {
  for_each     = var.enable_alb ? local.deployed : {}
  listener_arn = aws_lb_listener.https[0].arn
  priority     = lookup(var.listener_priorities, each.key, 500 + index(keys(local.deployed), each.key))

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mod[each.key].arn
  }
  condition {
    host_header {
      values = [local.hosts[each.key]]
    }
  }
}

# ------------------------------------------------------------------ certificate
resource "aws_acm_certificate" "alb" {
  count                     = local.make_cert
  domain_name               = values(local.hosts)[0]
  subject_alternative_names = slice(values(local.hosts), 1, length(values(local.hosts)))
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.make_cert == 1 ? {
    for dvo in aws_acm_certificate.alb[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}
  zone_id = var.hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "alb" {
  count                   = local.make_cert
  certificate_arn         = aws_acm_certificate.alb[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

# Alias record per module host -> ALB.
resource "aws_route53_record" "host" {
  for_each = var.enable_alb && var.hosted_zone_id != "" ? local.hosts : {}
  zone_id  = var.hosted_zone_id
  name     = each.value
  type     = "A"
  alias {
    name                   = aws_lb.this[0].dns_name
    zone_id                = aws_lb.this[0].zone_id
    evaluate_target_health = true
  }
}
