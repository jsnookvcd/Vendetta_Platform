# Platform infrastructure

Stands up the whole Vendetta Platform on one AWS host: the control plane, the IR
hub, managed services and dark web, each as its own container stack on its own port,
behind one load balancer that routes by hostname. This is the platform-wide stack;
the dark web module also keeps its own single-module stack under
modules/dark-web-monitoring/infra for running that module alone.

## What it builds

- One Graviton instance (t4g.large by default) that clones the private repo on
  first boot and brings up every deployed module with `docker compose`, each a
  separate project on its own port (control plane 8300, IR hub 8100, managed
  services 8200, dark web 8000).
- One ALB (optional, off by default) routing each module by hostname:
  platform.<domain>, ir.<domain>, msp.<domain>, darkweb.<domain>, with an ACM
  certificate covering all four and Route53 records. The instance has no inbound
  rules except the module ports from the ALB security group.
- A shared S3 evidence bucket with Object Lock (dark web captures and IR
  preservation), a shared SNS alert topic, per-module secret keys and Postgres
  passwords in SSM, an auto-recover alarm, and daily EBS snapshots.

Which modules deploy is the `modules` map in variables.tf. Add a module there when
it is ready; the planned ones are left out until they exist.

## Secrets and config

No secret is ever in Terraform state in plaintext. Terraform generates each
module's SECRET_KEY and POSTGRES_PASSWORD as SSM SecureStrings and writes the
non-secret defaults (bind address, shared bucket, SNS, the on-host cross-module
URLs) under `<ssm_prefix>/<module>/_defaults`.

You add the rest by hand as SSM parameters under `<ssm_prefix>/<module>/`, and the
host picks them up on boot and on the next deploy:

- The read-only GitHub deploy key at `<ssm_prefix>/DEPLOY_KEY`.
- Tool credentials for managed services, e.g.
  `/vendetta/managed-services/SENTINELONE_API_TOKEN`,
  `/vendetta/managed-services/CROWDSTRIKE_CLIENT_ID` and so on (see that module's
  .env.example for the full set).
- Entra ID SSO values per module, if used.
- The cross-module bearer tokens: each module authenticates to the others with a
  token derived from the target's SECRET_KEY, so set
  `/vendetta/<module>/PLATFORM_TOKEN` (and the hub token) from each module's
  settings page after first boot, and set the platform's own tokens to each module
  on the control plane's Connections page. The modules reach each other over
  localhost on the one host, so the URLs are already wired; only the tokens are
  manual.

## Deploy

```bash
cd infra/terraform
terraform init
terraform apply                 # instance only; reach consoles over SSM port forwarding
```

Reach a console without the ALB:

```bash
aws ssm start-session --target <instance_id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8300"],"localPortNumber":["8300"]}'
# then http://localhost:8300
```

Turn on the public front once DNS and the hostnames are ready:

```bash
terraform apply \
  -var enable_alb=true \
  -var base_domain=vendettacd.io \
  -var hosted_zone_id=Z0123456789 \
  -var 'alert_emails=["soc@vendettacd.io"]'
```

Validated here by HCL parse only; no `terraform plan` was run (no AWS
credentials in this environment). Run `terraform plan` against the target account
before applying.

## Notes

- One host keeps cost and operations simple and matches how the modules talk to
  each other (localhost). As load grows, split a module onto its own instance by
  setting `deploy = false` here and standing it up separately, or move Postgres to
  RDS; the module URLs then change from localhost to the new host.
- t4g.large (8 GB) runs four web stacks, four Postgres and Tor comfortably.
  t4g.medium works for a light client load with Postgres shared_buffers tuned down.
