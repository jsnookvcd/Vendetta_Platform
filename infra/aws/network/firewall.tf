# AWS Network Firewall, strict rule order:
#   priority 10  vcd-soc-tor-isolation : drop Tor segment -> protected CIDRs, then
#                pass Tor segment egress (Tor relays have no stable domains)
#   priority 20  vcd-soc-egress-domains : TLS SNI / HTTP Host allowlist for HOME_NET
#   default      drop established flows that matched nothing, and alert on them

locals {
  # Network Firewall domain lists use a leading dot for "any subdomain".
  domains   = [for d in var.domain_allowlist : startswith(d, "*.") ? substr(d, 1, -1) : d]
  tor_rules = length(var.tor_cidrs) > 0 ? toset(["this"]) : toset([])
}

resource "aws_networkfirewall_rule_group" "domains" {
  name     = "vcd-soc-egress-domains"
  type     = "STATEFUL"
  capacity = var.domain_rule_capacity

  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = var.spoke_supernets
        }
      }
    }
    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["TLS_SNI", "HTTP_HOST"]
        targets              = local.domains
      }
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}

resource "aws_networkfirewall_rule_group" "tor" {
  for_each = local.tor_rules
  name     = "vcd-soc-tor-isolation"
  type     = "STATEFUL"
  capacity = 50

  rule_group {
    rule_variables {
      ip_sets {
        key = "TOR_NET"
        ip_set {
          definition = var.tor_cidrs
        }
      }
      ip_sets {
        key = "PROTECTED_NET"
        ip_set {
          definition = var.protected_cidrs
        }
      }
    }
    rules_source {
      rules_string = <<-EOT
        drop ip $TOR_NET any -> $PROTECTED_NET any (msg:"vcd-soc tor segment to protected cidr"; sid:1000001; rev:1;)
        pass ip $TOR_NET any -> any any (msg:"vcd-soc tor segment egress"; sid:1000002; rev:1;)
      EOT
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "this" {
  name = "vcd-soc-egress"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = ["aws:drop_established", "aws:alert_established"]

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    dynamic "stateful_rule_group_reference" {
      for_each = aws_networkfirewall_rule_group.tor
      content {
        priority     = 10
        resource_arn = stateful_rule_group_reference.value.arn
      }
    }

    stateful_rule_group_reference {
      priority     = 20
      resource_arn = aws_networkfirewall_rule_group.domains.arn
    }
  }
}

resource "aws_networkfirewall_firewall" "this" {
  name                = "vcd-soc-egress"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.this.arn
  vpc_id              = aws_vpc.egress.id
  delete_protection   = true

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall
    content {
      subnet_id = subnet_mapping.value.id
    }
  }
}

resource "aws_cloudwatch_log_group" "firewall" {
  for_each          = toset(["alert", "flow"])
  name              = "/vcd-soc/network-firewall/${each.key}"
  retention_in_days = var.firewall_log_retention_days
}

resource "aws_networkfirewall_logging_configuration" "this" {
  firewall_arn = aws_networkfirewall_firewall.this.arn
  logging_configuration {
    log_destination_config {
      log_type             = "ALERT"
      log_destination_type = "CloudWatchLogs"
      log_destination      = { logGroup = aws_cloudwatch_log_group.firewall["alert"].name }
    }
    log_destination_config {
      log_type             = "FLOW"
      log_destination_type = "CloudWatchLogs"
      log_destination      = { logGroup = aws_cloudwatch_log_group.firewall["flow"].name }
    }
  }
}
