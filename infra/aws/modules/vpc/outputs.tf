output "vpc_id" {
  value = aws_vpc.this.id
}

output "cidr" {
  value = aws_vpc.this.cidr_block
}

output "azs" {
  value = local.azs
}

output "app_subnet_ids" {
  value = [for az in local.azs : aws_subnet.app[az].id]
}

output "data_subnet_ids" {
  value = [for az in local.azs : aws_subnet.data[az].id]
}

output "public_subnet_ids" {
  value = [for az in keys(local.public_azs) : aws_subnet.public[az].id]
}

output "app_route_table_ids" {
  value = [for az in local.azs : aws_route_table.app[az].id]
}

output "data_route_table_ids" {
  value = [for az in local.azs : aws_route_table.data[az].id]
}

output "transit_gateway_attachment_id" {
  description = "Pass this to the network stack (spoke_attachments) so it associates the attachment with the right TGW route table."
  value       = try(aws_ec2_transit_gateway_vpc_attachment.this["this"].id, null)
}

output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}
