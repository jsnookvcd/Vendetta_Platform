# One Fargate (ARM64) service: task definition, awslogs log group, Service
# Connect, CPU autoscaling, optional ALB target group and listener rule,
# deployment circuit breaker with rollback, and a security group that admits the
# container port from the VPC CIDR and from the listed source security groups.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  full_name = "${var.name_prefix}${var.name}"
  has_port  = var.container_port != null
  use_alb   = var.load_balancer != null && local.has_port
  use_sc    = var.service_connect_namespace_arn != null
  sc_expose = local.use_sc && var.expose_service_connect && local.has_port

  port_mappings = local.has_port ? [merge(
    {
      name          = var.port_name
      containerPort = var.container_port
      hostPort      = var.container_port
      protocol      = "tcp"
    },
    var.app_protocol == null ? {} : { appProtocol = var.app_protocol }
  )] : []

  container = merge(
    {
      name         = var.name
      image        = var.image
      essential    = true
      portMappings = local.port_mappings
      environment  = [for k in sort(keys(var.environment)) : { name = k, value = var.environment[k] }]
      secrets      = [for k in sort(keys(var.secrets)) : { name = k, valueFrom = var.secrets[k] }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = var.name
        }
      }
    },
    var.command == null ? {} : { command = var.command }
  )
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/vcd-soc/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

# ------------------------------------------------------------------ network
resource "aws_security_group" "this" {
  name        = local.full_name
  description = "ECS service ${var.name}"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = local.full_name })
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.this.id
  description       = "Egress; the VPC routes it to endpoints or the central firewall"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "cidr" {
  for_each          = local.has_port ? toset(concat([var.vpc_cidr], var.ingress_cidrs)) : toset([])
  security_group_id = aws_security_group.this.id
  description       = "Container port from ${each.key}"
  ip_protocol       = "tcp"
  from_port         = var.container_port
  to_port           = var.container_port
  cidr_ipv4         = each.key
}

resource "aws_vpc_security_group_ingress_rule" "sg" {
  # Keyed by position: security group ids are often unknown until apply.
  for_each                     = local.has_port ? { for i, sg in var.source_security_group_ids : tostring(i) => sg } : {}
  security_group_id            = aws_security_group.this.id
  description                  = "Container port from a source security group"
  ip_protocol                  = "tcp"
  from_port                    = var.container_port
  to_port                      = var.container_port
  referenced_security_group_id = each.value
}

# ------------------------------------------------------------------ load balancer
resource "aws_lb_target_group" "this" {
  for_each             = local.use_alb ? toset(["this"]) : toset([])
  name                 = substr(local.full_name, 0, 32)
  port                 = var.container_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = var.load_balancer.deregistration_delay

  health_check {
    path                = var.load_balancer.health_check_path
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = var.tags
}

resource "aws_lb_listener_rule" "this" {
  for_each     = local.use_alb ? toset(["this"]) : toset([])
  listener_arn = var.load_balancer.listener_arn
  priority     = var.load_balancer.priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["this"].arn
  }

  dynamic "condition" {
    for_each = length(var.load_balancer.host_headers) > 0 ? [1] : []
    content {
      host_header {
        values = var.load_balancer.host_headers
      }
    }
  }

  dynamic "condition" {
    for_each = length(var.load_balancer.path_patterns) > 0 ? [1] : []
    content {
      path_pattern {
        values = var.load_balancer.path_patterns
      }
    }
  }

  tags = var.tags
}

# ------------------------------------------------------------------ task + service
resource "aws_ecs_task_definition" "this" {
  family                   = local.full_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = jsonencode([local.container])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  tags = var.tags
}

resource "aws_ecs_service" "this" {
  name                              = local.full_name
  cluster                           = var.cluster_arn
  task_definition                   = aws_ecs_task_definition.this.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  enable_execute_command            = var.enable_execute_command
  propagate_tags                    = "SERVICE"
  enable_ecs_managed_tags           = true
  health_check_grace_period_seconds = local.use_alb || length(var.external_target_group_arns) > 0 ? var.health_check_grace_period_seconds : null

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = var.assign_public_ip
  }

  dynamic "load_balancer" {
    for_each = local.use_alb ? [aws_lb_target_group.this["this"].arn] : []
    content {
      target_group_arn = load_balancer.value
      container_name   = var.name
      container_port   = var.container_port
    }
  }

  dynamic "load_balancer" {
    for_each = local.has_port ? var.external_target_group_arns : []
    content {
      target_group_arn = load_balancer.value
      container_name   = var.name
      container_port   = var.container_port
    }
  }

  dynamic "service_connect_configuration" {
    for_each = local.use_sc ? [1] : []
    content {
      enabled   = true
      namespace = var.service_connect_namespace_arn

      dynamic "service" {
        for_each = local.sc_expose ? [1] : []
        content {
          port_name      = var.port_name
          discovery_name = var.name
          client_alias {
            port     = var.service_connect_port
            dns_name = var.name
          }
        }
      }

      log_configuration {
        log_driver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "${var.name}-service-connect"
        }
      }
    }
  }

  # Autoscaling owns the running count after the first apply.
  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener_rule.this]

  tags = var.tags
}

# ------------------------------------------------------------------ autoscaling
resource "aws_appautoscaling_target" "this" {
  service_namespace  = "ecs"
  resource_id        = "service/${var.cluster_name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.min_capacity
  max_capacity       = var.max_capacity
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.full_name}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.this.service_namespace
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value       = var.cpu_target_percent
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
