# Platform infrastructure

Stands up the whole Vendetta Platform on one AWS host: the control plane, the IR
hub, managed services, dark web, vulnerability management and penetration testing,
each as its own container stack on its own port, joined to one docker network so
they reach each other by name, behind one load balancer that routes by hostname. This is the platform-wide stack;
the dark web module also keeps its own single-module stack under
modules/dark-web-monitoring/infra for running that module alone.

## What it builds

- One Graviton instance (t4g.large by default) that clones the private repo on
  first boot and brings up every deployed module with `docker compose`, each a
  separate project on its own port (control plane 8300, IR hub 8100, managed
  services 8200, dark web 8000, vulnerability management 8400, penetration
  testing 8500), all on one shared docker network ("vendetta") where each module
  answers at `http://<module-key>:8000`.
- One ALB (optional, off by default) routing each module by hostname:
  platform.<domain>, ir.<domain>, msp.<domain>, darkweb.<domain>, vuln.<domain>,
  pentest.<domain>, with an ACM certificate covering all of them and Route53
  records. Listener priorities are fixed per module (`listener_priorities`) so
  adding one never reshuffles the rest. The instance has no inbound rules except
  the module ports from the ALB security group.
- A shared S3 evidence bucket with Object Lock (dark web captures and IR
  preservation), a backups bucket for the nightly Postgres dumps, a shared SNS
  alert topic, every per-module secret in SSM, an auto-recover alarm, and daily
  EBS snapshots.

Which modules deploy is the `modules` map in variables.tf. Add a module there when
it is ready; the planned ones are left out until they exist.

## Secrets and config

No secret is ever in Terraform state in plaintext. Terraform generates, per module,
and stores as SSM SecureStrings under `<ssm_prefix>/<module>/`:

- `SECRET_KEY` (session signer) and `POSTGRES_PASSWORD`;
- `API_TOKEN`, the bearer other modules and the control plane present to that
  module's service API;
- `ENCRYPTION_KEY` (Fernet) for secrets the module stores, and
  `EVIDENCE_SIGNING_KEY` (Ed25519 seed) in the modules that sign a chain of custody;
- `ADMIN_PASSWORD` (for you to read once) and `ADMIN_PASSWORD_HASH` (what the host
  renders), the break-glass local login.

It also writes the cross-module wiring so nothing is typed in after boot:
`PLATFORM_TOKEN` (the control plane's API token) into every client module,
`PLATFORM_HUB_TOKEN` (the hub's) into every finding module, and `MODULE_DIRECTORY`
(each module's service URL, token and public URL) into the control plane. The
non-secret defaults, including the service URLs, the bind address, `COOKIE_SECURE`,
`PUBLIC_URL` and managed services' `ACTIONS_READONLY=true`, go under
`<ssm_prefix>/<module>/_defaults` and are updated on every apply.

You add by hand, as SSM parameters under `<ssm_prefix>/<module>/`:

- The read-only GitHub deploy key at `<ssm_prefix>/DEPLOY_KEY` (before first boot).
- Tool credentials for managed services, if you prefer SSM to the in-app
  Integrations page, e.g. `/vendetta/managed-services/SENTINELONE_API_TOKEN`.
- Entra ID SSO values per module, if you prefer SSM to the in-app SSO page.
- `ACTIONS_READONLY=false` for managed services when you are ready for live actions.

A scalar parameter overrides the same key in `_defaults`. The host renders every
module's `.env` from these with `infra/host/vendetta-env` at first boot and on
every `infra/redeploy.sh`, so a parameter added later reaches the containers on the
next deploy.

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
  -var base_domain=vendettacyber.com \
  -var hosted_zone_id=Z0123456789 \
  -var 'alert_emails=["soc@vendettacd.io"]'
```

This fronts the control plane at platform.vendettacyber.com, with ir., msp.,
darkweb., vuln. and pentest. under the same domain and one certificate. Run
`infra/redeploy.sh` afterwards so the modules pick up the bind address, secure
cookies and public URLs. The alert address stays on
the vendettacd.io corporate mailbox; only the hostnames use vendettacyber.com.

CI runs `terraform fmt -check` and `terraform validate`; no `terraform plan` has
been run (no AWS credentials in CI). Run `terraform plan` against the target
account before the first apply.

## Notes

- One host keeps cost and operations simple; the modules talk to each other over
  the shared docker network. As load grows, split a module onto its own instance by
  setting `deploy = false` here and standing it up separately, or move Postgres to
  RDS; the module's entry in `_defaults` and the control plane's `MODULE_DIRECTORY`
  then point at the new host.
- t4g.large (8 GB) runs six web stacks, six Postgres and Tor; watch memory once
  real sync volume lands and step up to t4g.xlarge if Postgres starts swapping.
