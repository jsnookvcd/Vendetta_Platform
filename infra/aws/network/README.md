# network

Runs in the network account (or ingest until a network account exists). Builds
the Transit Gateway, the egress VPC with NAT gateways, AWS Network Firewall
with the domain allowlist, and the Tor segment isolation.

Inputs: `network_account_id`, `organization_arn` and `flow_log_bucket_arn` from
org; `domain_allowlist`; `protected_cidrs` and `tor_cidrs`;
`spoke_attachments` on the second pass.

Second pass: after ingest and soc-apps apply, add their `vpc_attachment_id`
(and `tor_vpc_attachment_id`) outputs:

```hcl
spoke_attachments = {
  ingest    = { attachment_id = "tgw-attach-...", segment = "spoke" }
  apps-prod = { attachment_id = "tgw-attach-...", segment = "spoke", tor_peer = true }
  tor-prod  = { attachment_id = "tgw-attach-...", segment = "tor" }
}
```

Route tables and what they allow:

- spoke: associated with spokes; reaches spokes, protected and Tor; 0.0.0.0/0 to egress.
- protected: associated with data-lake and evidence; reaches spokes and protected; Tor CIDRs blackholed.
- tor: associated with Tor VPCs; reaches only `tor_peer` spokes; protected CIDRs blackholed; 0.0.0.0/0 to egress.
- egress: associated with the egress VPC; propagates every attachment for return traffic.

`egress_public_ips` is the list to give vendors and clients for API allowlists.
Domains in the allowlist are matched on TLS SNI and HTTP Host; a leading `*.`
matches every subdomain.
