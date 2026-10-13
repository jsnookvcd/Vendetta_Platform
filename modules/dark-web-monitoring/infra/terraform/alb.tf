# Optional public HTTPS front for the console and client portal. Off by default
# (the module is reachable only over SSM port forwarding). Enable it when you need
# Entra ID SSO and the client portal, which require a real HTTPS hostname.
#
#   enable_alb       = true
#   domain_name      = "darkweb.vendettacd.io"
#   hosted_zone_id   = "Z..."              # Route53 zone to create the cert + record in
#   alb_allowed_cidrs = ["203.0.113.0/24"] # restrict to office / VPN egress where possible
#
# Bring-your-own certificate instead of Route53 DNS validation by setting
# acm_certificate_arn and leaving hosted_zone_id blank (you manage the DNS record).

locals {
  alb_on   = var.enable_alb ? 1 : 0
  make_cert = var.enable_alb && var.acm_certificate_arn == "" && var.hosted_zone_id != "" ? 1 : 0
  cert_arn = var.acm_certificate_arn != "" ? var.acm_certificate_arn : (local.make_cert == 1 ? aws_acm_certificate_validation.alb[0].certificate_arn : "")
}

resource "aws_security_group" "alb" {
  count       = local.alb_on
  name        = "${var.name_prefix}-alb"
  description = "Dark web console ALB"
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

# Let the ALB reach the web container on 8000; nothing else may.
resource "aws_security_group_rule" "instance_from_alb" {
  count                    = local.alb_on
  type                     = "ingress"
  from_port                = 8000
  to_port                  = 8000
  protocol                 = "tcp"
  security_group_id        = aws_security_group.instance.id
  source_security_group_id = aws_security_group.alb[0].id
}

# ---- certificate (Route53 DNS validation) ----
resource "aws_acm_certificate" "alb" {
  count             = local.make_cert
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.make_cert == 1 ? {
    for d in aws_acm_certificate.alb[0].domain_validation_options : d.domain_name => {
      name   = d.resource_record_name
      type   = d.resource_record_type
      record = d.resource_record_value
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

# ---- load balancer ----
resource "aws_lb" "console" {
  count              = local.alb_on
  name               = "${var.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = slice(data.aws_subnets.default.ids, 0, 2)
}

resource "aws_lb_target_group" "console" {
  count       = local.alb_on
  name        = "${var.name_prefix}-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "instance"
  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "console" {
  count            = local.alb_on
  target_group_arn = aws_lb_target_group.console[0].arn
  target_id        = aws_instance.monitor.id
  port             = 8000
}

resource "aws_lb_listener" "https" {
  count             = local.alb_on
  load_balancer_arn = aws_lb.console[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.cert_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.console[0].arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = local.alb_on
  load_balancer_arn = aws_lb.console[0].arn
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

resource "aws_route53_record" "console" {
  count   = var.enable_alb && var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.console[0].dns_name
    zone_id                = aws_lb.console[0].zone_id
    evaluate_target_health = true
  }
}
