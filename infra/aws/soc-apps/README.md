# soc-apps

Runs in soc-apps-prod or soc-apps-staging, chosen by `environment` and a
backend key per environment:

```bash
tofu init -reconfigure -backend-config=backend-prod.hcl
tofu apply -var environment=prod -var-file=prod.tfvars
```

Builds the ECS cluster and the `vendetta.internal` Service Connect namespace,
one service per entry in `modules` (each reachable by peers at
`http://<module>:8000`), a worker service where `worker_command` is set, ECR
repositories (`vcd-soc/<module>`, immutable tags, scan on push), RDS
PostgreSQL 16 Multi-AZ, Valkey, OpenSearch, the public ALB with WAF, optional
CloudFront, optional Tor egress VPC, and the DR copies (`dr.tf`).

Hostnames and listener priorities match `infra/terraform`: prod serves
`platform.<base_domain>`, `ir.`, `msp.`, `darkweb.`, `vuln.`, `pentest.`,
`sabine.`, `osp.` and `mdr.`; staging serves `<label>-staging.<base_domain>`.

Secrets: Terraform references SSM parameter ARNs under
`/vendetta/<module>/` and never handles their values. Copy them in with
`../scripts/copy-ssm-params.sh` and write `DATABASE_URL` with the database
bootstrap in the main README before the services start. Extra parameters per
module (tool credentials, `AZURE_SPEECH_KEY`) go in `extra_ssm_secrets`.

`base_domain` defaults to `vendettacyber.io`, the value in
`infra/terraform/variables.tf`, so the cutover keeps every hostname. Set it if
the SOC should serve a different zone.
