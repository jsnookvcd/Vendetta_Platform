# Regional WAFv2 web ACL with the AWS managed baseline (Common, KnownBadInputs,
# Amazon IP reputation), an optional per-IP rate limit, CloudWatch logging, and
# associations to ALBs or API Gateway REST stages.

locals {
  managed = {
    AWSManagedRulesAmazonIpReputationList = 10
    AWSManagedRulesKnownBadInputsRuleSet  = 20
    AWSManagedRulesCommonRuleSet          = 30
  }
}

resource "aws_wafv2_web_acl" "this" {
  name  = var.name
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = local.managed
    content {
      name     = rule.key
      priority = rule.value

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = rule.key == "AWSManagedRulesCommonRuleSet" ? var.common_rule_count_overrides : []
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  dynamic "rule" {
    for_each = var.rate_limit_per_5min == null ? [] : [var.rate_limit_per_5min]
    content {
      name     = "rate-limit"
      priority = 5

      action {
        block {}
      }

      statement {
        rate_based_statement {
          limit              = rule.value
          aggregate_key_type = "IP"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-rate-limit"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }
}

# WAF requires log group names that start with aws-waf-logs-.
resource "aws_cloudwatch_log_group" "this" {
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.this.arn]
}

resource "aws_wafv2_web_acl_association" "this" {
  for_each     = var.associations
  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}
