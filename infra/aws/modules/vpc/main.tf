# Reusable VPC: three AZs, private app and data subnets, optional public
# subnets. Private subnets have no internet route of their own; egress goes to
# the central Transit Gateway (network stack) unless enable_nat_gateway is set.

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs    = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, 3)
  az_idx = { for i, az in local.azs : az => i }

  app_cidrs    = length(var.app_subnet_cidrs) > 0 ? var.app_subnet_cidrs : [for i, _ in local.azs : cidrsubnet(var.cidr, 4, i)]
  data_cidrs   = length(var.data_subnet_cidrs) > 0 ? var.data_subnet_cidrs : [for i, _ in local.azs : cidrsubnet(var.cidr, 4, 4 + i)]
  public_cidrs = length(var.public_subnet_cidrs) > 0 ? var.public_subnet_cidrs : [for i, _ in local.azs : cidrsubnet(var.cidr, 8, 240 + i)]

  public_azs = var.create_public_subnets ? local.az_idx : {}
  nat_azs    = var.create_public_subnets && var.enable_nat_gateway ? local.az_idx : {}
  use_tgw    = var.transit_gateway_id != null

  tgw_routes = local.use_tgw && !var.enable_nat_gateway ? {
    for pair in setproduct(local.azs, var.transit_gateway_destinations) :
    "${pair[0]}|${pair[1]}" => { az = pair[0], cidr = pair[1] }
  } : {}
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = var.name })
}

# Lock down the default security group so nothing lands in it by accident.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-default-closed" })
}

# ------------------------------------------------------------------ subnets
resource "aws_subnet" "app" {
  for_each          = local.az_idx
  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.app_cidrs[each.value]
  tags              = merge(var.tags, { Name = "${var.name}-app-${each.key}", Tier = "app" })
}

resource "aws_subnet" "data" {
  for_each          = local.az_idx
  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.data_cidrs[each.value]
  tags              = merge(var.tags, { Name = "${var.name}-data-${each.key}", Tier = "data" })
}

resource "aws_subnet" "public" {
  for_each          = local.public_azs
  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = local.public_cidrs[each.value]
  tags              = merge(var.tags, { Name = "${var.name}-public-${each.key}", Tier = "public" })
}

# ------------------------------------------------------------------ internet edge
resource "aws_internet_gateway" "this" {
  for_each = var.create_public_subnets ? toset(["this"]) : toset([])
  vpc_id   = aws_vpc.this.id
  tags     = merge(var.tags, { Name = var.name })
}

resource "aws_route_table" "public" {
  for_each = var.create_public_subnets ? toset(["this"]) : toset([])
  vpc_id   = aws_vpc.this.id
  tags     = merge(var.tags, { Name = "${var.name}-public" })
}

resource "aws_route" "public_igw" {
  for_each               = var.create_public_subnets ? toset(["this"]) : toset([])
  route_table_id         = aws_route_table.public["this"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this["this"].id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public["this"].id
}

resource "aws_eip" "nat" {
  for_each = local.nat_azs
  domain   = "vpc"
  tags     = merge(var.tags, { Name = "${var.name}-nat-${each.key}" })
}

resource "aws_nat_gateway" "this" {
  for_each      = local.nat_azs
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  tags          = merge(var.tags, { Name = "${var.name}-nat-${each.key}" })
}

# ------------------------------------------------------------------ private routing
resource "aws_route_table" "app" {
  for_each = local.az_idx
  vpc_id   = aws_vpc.this.id
  tags     = merge(var.tags, { Name = "${var.name}-app-${each.key}" })
}

resource "aws_route_table" "data" {
  for_each = local.az_idx
  vpc_id   = aws_vpc.this.id
  tags     = merge(var.tags, { Name = "${var.name}-data-${each.key}" })
}

resource "aws_route_table_association" "app" {
  for_each       = aws_subnet.app
  subnet_id      = each.value.id
  route_table_id = aws_route_table.app[each.key].id
}

resource "aws_route_table_association" "data" {
  for_each       = aws_subnet.data
  subnet_id      = each.value.id
  route_table_id = aws_route_table.data[each.key].id
}

resource "aws_route" "app_nat" {
  for_each               = local.nat_azs
  route_table_id         = aws_route_table.app[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

resource "aws_route" "data_nat" {
  for_each               = local.nat_azs
  route_table_id         = aws_route_table.data[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

# ------------------------------------------------------------------ transit gateway
# The attachment is accepted automatically (the network stack enables
# auto_accept_shared_attachments). Association with the right TGW route table
# happens in the network stack, which owns the Transit Gateway.
resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  for_each           = local.use_tgw ? toset(["this"]) : toset([])
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.this.id
  subnet_ids         = [for s in aws_subnet.app : s.id]
  dns_support        = "enable"
  tags               = merge(var.tags, { Name = var.name })
}

resource "aws_route" "app_tgw" {
  for_each               = local.tgw_routes
  route_table_id         = aws_route_table.app[each.value.az].id
  destination_cidr_block = each.value.cidr
  transit_gateway_id     = var.transit_gateway_id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.this]
}

resource "aws_route" "data_tgw" {
  for_each               = local.tgw_routes
  route_table_id         = aws_route_table.data[each.value.az].id
  destination_cidr_block = each.value.cidr
  transit_gateway_id     = var.transit_gateway_id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.this]
}

# ------------------------------------------------------------------ flow logs
resource "aws_flow_log" "this" {
  for_each                 = var.flow_log_bucket_arn == null ? toset([]) : toset(["this"])
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = var.flow_log_bucket_arn
  max_aggregation_interval = 60

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(var.tags, { Name = var.name })
}
