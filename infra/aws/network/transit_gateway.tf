# Transit Gateway with four route tables and no default association or
# propagation, so every attachment's reachability is explicit.
#
#   route table  associated with        propagations from          static routes
#   spoke        spoke attachments      spoke, protected, tor      0/0 -> egress
#   protected    protected attachments  spoke, protected           0/0 -> egress; tor CIDRs blackhole
#   tor          tor attachments        spokes with tor_peer=true  0/0 -> egress; protected CIDRs blackhole
#   egress       egress VPC attachment  every attachment           none
#
# The blackholes matter. Without them a Tor packet for a protected CIDR would
# follow 0/0 to the egress VPC, hit the firewall subnet's 10.0.0.0/8 route back
# into the TGW, and reach the protected VPC through the egress route table. The
# more specific blackhole drops it at the TGW first; the firewall's
# vcd-soc-tor-isolation rule is the second layer.

resource "aws_ec2_transit_gateway" "this" {
  description                     = "vcd-soc central transit gateway"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"
  tags                            = { Name = "vcd-soc-tgw" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "egress" {
  transit_gateway_id                              = aws_ec2_transit_gateway.this.id
  vpc_id                                          = aws_vpc.egress.id
  subnet_ids                                      = [for s in aws_subnet.tgw : s.id]
  appliance_mode_support                          = "enable"
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  tags                                            = { Name = "vcd-soc-egress" }
}

resource "aws_ec2_transit_gateway_route_table" "this" {
  for_each           = toset(["spoke", "protected", "tor", "egress"])
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  tags               = { Name = "vcd-soc-tgw-${each.key}" }
}

locals {
  attachments = var.spoke_attachments

  propagation_plan = {
    spoke     = [for k, a in local.attachments : k if contains(["spoke", "protected", "tor"], a.segment)]
    protected = [for k, a in local.attachments : k if contains(["spoke", "protected"], a.segment)]
    tor       = [for k, a in local.attachments : k if a.segment == "spoke" && a.tor_peer]
    egress    = keys(local.attachments)
  }

  propagations = {
    for pair in flatten([
      for rt, members in local.propagation_plan : [for k in members : { rt = rt, key = k }]
    ]) : "${pair.rt}|${pair.key}" => pair
  }

  blackholes = merge(
    { for c in var.protected_cidrs : "tor|${c}" => { rt = "tor", cidr = c } },
    { for c in var.tor_cidrs : "protected|${c}" => { rt = "protected", cidr = c } },
  )
}

resource "aws_ec2_transit_gateway_route_table_association" "egress" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this["egress"].id
}

resource "aws_ec2_transit_gateway_route_table_association" "spoke" {
  for_each                       = local.attachments
  transit_gateway_attachment_id  = each.value.attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.segment].id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "this" {
  for_each                       = local.propagations
  transit_gateway_attachment_id  = local.attachments[each.value.key].attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.rt].id
}

resource "aws_ec2_transit_gateway_route" "default_to_egress" {
  for_each                       = toset(["spoke", "protected", "tor"])
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.key].id
}

resource "aws_ec2_transit_gateway_route" "blackhole" {
  for_each                       = local.blackholes
  destination_cidr_block         = each.value.cidr
  blackhole                      = true
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.rt].id
}

# ------------------------------------------------------------------ RAM share
resource "aws_ram_resource_share" "tgw" {
  name                      = "vcd-soc-tgw"
  allow_external_principals = false
}

resource "aws_ram_resource_association" "tgw" {
  resource_arn       = aws_ec2_transit_gateway.this.arn
  resource_share_arn = aws_ram_resource_share.tgw.arn
}

resource "aws_ram_principal_association" "org" {
  principal          = var.organization_arn
  resource_share_arn = aws_ram_resource_share.tgw.arn
}
