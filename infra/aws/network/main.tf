# Central egress VPC. Per AZ: a TGW subnet, a firewall subnet and a public
# subnet with a NAT gateway. Traffic path for a spoke:
#   spoke -> TGW (spoke route table, 0.0.0.0/0) -> egress attachment ->
#   TGW subnet -> firewall endpoint -> firewall subnet -> NAT -> IGW
# and back the same way; appliance mode keeps both directions in one AZ.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs    = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, 3)
  az_idx = { for i, az in local.azs : az => i }

  supernet_routes = {
    for pair in setproduct(local.azs, var.spoke_supernets) :
    "${pair[0]}|${pair[1]}" => { az = pair[0], cidr = pair[1] }
  }

  firewall_endpoints = {
    for s in tolist(aws_networkfirewall_firewall.this.firewall_status[0].sync_states) :
    s.availability_zone => s.attachment[0].endpoint_id
  }
}

resource "aws_vpc" "egress" {
  cidr_block           = var.egress_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "vcd-soc-egress" }
}

resource "aws_default_security_group" "egress" {
  vpc_id = aws_vpc.egress.id
  tags   = { Name = "vcd-soc-egress-default-closed" }
}

resource "aws_internet_gateway" "egress" {
  vpc_id = aws_vpc.egress.id
  tags   = { Name = "vcd-soc-egress" }
}

resource "aws_subnet" "tgw" {
  for_each          = local.az_idx
  vpc_id            = aws_vpc.egress.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(var.egress_vpc_cidr, 4, each.value)
  tags              = { Name = "vcd-soc-egress-tgw-${each.key}" }
}

resource "aws_subnet" "firewall" {
  for_each          = local.az_idx
  vpc_id            = aws_vpc.egress.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(var.egress_vpc_cidr, 4, 4 + each.value)
  tags              = { Name = "vcd-soc-egress-firewall-${each.key}" }
}

resource "aws_subnet" "public" {
  for_each          = local.az_idx
  vpc_id            = aws_vpc.egress.id
  availability_zone = each.key
  cidr_block        = cidrsubnet(var.egress_vpc_cidr, 4, 8 + each.value)
  tags              = { Name = "vcd-soc-egress-public-${each.key}" }
}

resource "aws_eip" "nat" {
  for_each = local.az_idx
  domain   = "vpc"
  tags     = { Name = "vcd-soc-egress-nat-${each.key}" }
}

resource "aws_nat_gateway" "this" {
  for_each      = local.az_idx
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  tags          = { Name = "vcd-soc-egress-nat-${each.key}" }
  depends_on    = [aws_internet_gateway.egress]
}

# ------------------------------------------------------------------ route tables
resource "aws_route_table" "tgw" {
  for_each = local.az_idx
  vpc_id   = aws_vpc.egress.id
  tags     = { Name = "vcd-soc-egress-tgw-${each.key}" }
}

resource "aws_route" "tgw_to_firewall" {
  for_each               = local.az_idx
  route_table_id         = aws_route_table.tgw[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.firewall_endpoints[each.key]
}

resource "aws_route_table_association" "tgw" {
  for_each       = local.az_idx
  subnet_id      = aws_subnet.tgw[each.key].id
  route_table_id = aws_route_table.tgw[each.key].id
}

resource "aws_route_table" "firewall" {
  for_each = local.az_idx
  vpc_id   = aws_vpc.egress.id
  tags     = { Name = "vcd-soc-egress-firewall-${each.key}" }
}

resource "aws_route" "firewall_to_nat" {
  for_each               = local.az_idx
  route_table_id         = aws_route_table.firewall[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

resource "aws_route" "firewall_to_spokes" {
  for_each               = local.supernet_routes
  route_table_id         = aws_route_table.firewall[each.value.az].id
  destination_cidr_block = each.value.cidr
  transit_gateway_id     = aws_ec2_transit_gateway.this.id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route_table_association" "firewall" {
  for_each       = local.az_idx
  subnet_id      = aws_subnet.firewall[each.key].id
  route_table_id = aws_route_table.firewall[each.key].id
}

resource "aws_route_table" "public" {
  for_each = local.az_idx
  vpc_id   = aws_vpc.egress.id
  tags     = { Name = "vcd-soc-egress-public-${each.key}" }
}

resource "aws_route" "public_to_igw" {
  for_each               = local.az_idx
  route_table_id         = aws_route_table.public[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.egress.id
}

# Return traffic from the NAT goes back through the firewall in the same AZ.
resource "aws_route" "public_to_firewall" {
  for_each               = local.supernet_routes
  route_table_id         = aws_route_table.public[each.value.az].id
  destination_cidr_block = each.value.cidr
  vpc_endpoint_id        = local.firewall_endpoints[each.value.az]
}

resource "aws_route_table_association" "public" {
  for_each       = local.az_idx
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public[each.key].id
}

resource "aws_flow_log" "egress" {
  for_each                 = var.flow_log_bucket_arn == null ? toset([]) : toset(["this"])
  vpc_id                   = aws_vpc.egress.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = var.flow_log_bucket_arn
  max_aggregation_interval = 60
  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }
}
