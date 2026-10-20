output "transit_gateway_id" {
  description = "Pass to modules/vpc transit_gateway_id in every spoke stack."
  value       = aws_ec2_transit_gateway.this.id
}

output "transit_gateway_route_table_ids" {
  value = { for k, rt in aws_ec2_transit_gateway_route_table.this : k => rt.id }
}

output "egress_vpc_id" {
  value = aws_vpc.egress.id
}

output "firewall_arn" {
  value = aws_networkfirewall_firewall.this.arn
}

output "egress_public_ips" {
  description = "Stable egress addresses to give vendors and clients for API allowlisting."
  value       = [for e in aws_eip.nat : e.public_ip]
}
