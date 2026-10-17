# First deploy to AWS

This module lives inside the Vendetta_Platform repo at `modules/dark-web-monitoring`, and it is self-contained: the Terraform, the Dockerfiles and the compose stack are all under this directory. The instance clones the private repo on first boot with a read-only deploy key and runs the stack from this subdirectory.

Run top to bottom from your Mac. Everything after Terraform happens over SSM; no ports are opened on the instance. Budget 30 to 45 minutes for the first run, most of it waiting on Tor to bootstrap and the first feed sweep. All commands are run from `modules/dark-web-monitoring`.

## 0. Prerequisites

- AWS CLI with a profile for the Vendetta account, and the Session Manager plugin installed.
- Terraform 1.6 or newer.

## 1. Create a read-only deploy key for the instance

The instance needs to clone the private repo. Create a dedicated key, add the public half to the repo, and store the private half in SSM. Do this before Terraform so the key exists when the instance first boots.

```
ssh-keygen -t ed25519 -f ./darkweb_deploy -N "" -C "darkweb-instance"
# On GitHub: Vendetta_Platform, Settings, Deploy keys, Add deploy key, paste darkweb_deploy.pub, leave write access OFF.
aws ssm put-parameter --name /darkweb/DEPLOY_KEY --type SecureString --value "file://$(pwd)/darkweb_deploy"
rm -f darkweb_deploy darkweb_deploy.pub
```

## 2. Stand up infrastructure

```
cd infra/terraform
terraform init
terraform validate
terraform plan -out tf.plan \
  -var 'alert_emails=["ir@vendettacd.io"]' \
  -var object_lock_mode=GOVERNANCE
terraform apply tf.plan
```

repo_url, git_ref and module_subdir default to this repo, main, and modules/dark-web-monitoring; override them only if that changes. Keep object_lock_mode at GOVERNANCE for the first deploy so nothing in the evidence bucket is permanent while you shake the stack out. Flip it to COMPLIANCE in a later apply once you trust it.

Confirm the SNS subscription email that arrives at each address in alert_emails. Unconfirmed addresses get no alerts.

## 3. Put the rest of the secrets into SSM

These never go into Terraform state. Generate the password hash on your Mac:

```
python3 -c "import bcrypt,getpass;print(bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt(12)).decode())"

aws ssm put-parameter --name /darkweb/ADMIN_PASSWORD_HASH --type SecureString --value '<hash>'
aws ssm put-parameter --name /darkweb/HIBP_API_KEY        --type SecureString --value '<key>'
aws ssm put-parameter --name /darkweb/RANSOMWARE_LIVE_API_KEY --type SecureString --value '<key>'
aws ssm put-parameter --name /darkweb/TEAMS_WEBHOOK_URL   --type SecureString --value '<url>'
aws ssm put-parameter --name /darkweb/COOKIE_SECURE       --type String --value 'false'
```

SECRET_KEY, POSTGRES_PASSWORD, EVIDENCE_BUCKET and SNS_TOPIC_ARN were created by Terraform. DEPLOY_KEY was created in step 1. Jira and the platform hub are intentionally left blank; add them later when those are live.

## 3. Bring up the stack

Open a shell on the instance:

```
aws ssm start-session --target "$(terraform output -raw instance_id)"
```

user_data cloned the repo and started the stack on first boot. `/opt/darkweb` is a symlink to the module directory inside the clone. Confirm:

```
cd /opt/darkweb && sudo docker compose ps
```

If the stack is not up, the clone likely failed because the deploy key was missing or wrong at boot. Fix the key in SSM (step 1), then:

```
sudo rm -rf /opt/vendetta_platform
sudo bash -c 'aws ssm get-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/DEPLOY_KEY" --with-decryption --query Parameter.Value --output text > /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519'
sudo git clone git@github.com:jsnookvcd/Vendetta_Platform.git /opt/vendetta_platform
sudo ln -sfn /opt/vendetta_platform/modules/dark-web-monitoring /opt/darkweb
cd /opt/darkweb && sudo bash scripts/deploy.sh
```

## 4. Go/no-go checks, in order

Run these on the instance. Do not point real clients at it until all four pass.

1. Stack is up:
```
sudo docker compose ps          # tor, db, web, worker all healthy/running
```

2. Tor is exiting through Tor. From your Mac, open the console (step 5) and hit /research/torcheck, or on the instance:
```
sudo docker compose exec worker python -c "from app.fetch import tor_check;print(tor_check())"
# expect IsTor: true and an exit IP
```

Or run the full diagnosis, which also covers steps 3 and 4:
```
sudo docker compose exec worker python -m app.diagnose
# heartbeat age under a minute, tor is_tor=True, a row per connector, and a status code and byte count per upstream
```
The same health is on the console's Connectors page and in the dashboard banner.

3. Clearnet feeds populated the dashboard. The worker runs the feeds on boot; after a minute the dashboard shows victim posts and the onion source count is in the hundreds.

4. One onion source actually crawls:
```
sudo docker compose logs worker | grep -i "onion crawl\|page changed\|profiled crawl"
```
A few failures are normal (leak sites go up and down). You want at least some successes.

## 5. Open the console

From your Mac:

```
cd infra/terraform
terraform output -raw connect | bash
```

Then browse to http://localhost:8000 and sign in as admin with the password you hashed. Everyone on the delivery team connects through their own SSM session, so IAM is the access control.

## 6. Onboard the first client

Add the client, set the business profile (industry, country, state, revenue and size bands) for IAB matching, add watch terms (primary domain, email domain, brand, executive names), and for an IR matter click Backfill to check the last year of collected data. Verify the client's domain in HIBP so the breach and stealer queries return data.

## 7. Platform wiring (when the hub is ready)

This runs standalone today. When the Vendetta Platform hub is live:

```
aws ssm put-parameter --name /darkweb/PLATFORM_HUB_URL   --type String       --value 'https://platform.internal'
aws ssm put-parameter --name /darkweb/PLATFORM_HUB_TOKEN --type SecureString  --value '<token>'
cd /opt/darkweb && sudo bash scripts/deploy.sh
```

The hub reads findings at /api/findings and the manifest at /api/module. Escalate turns a finding into an IR case in the engagement hub, attached to the Forensics and Analysis workstream.

## 8. Public HTTPS front for SSO and the client portal

SSM port forwarding is enough for the internal console. Microsoft 365 SSO and the client portal need a real HTTPS hostname, which the optional ALB provides. It stays off until you enable it.

Apply with the ALB on:

```
cd infra/terraform
terraform apply \
  -var 'alert_emails=["ir@vendettacd.io"]' \
  -var enable_alb=true \
  -var domain_name=darkweb.vendettacd.io \
  -var hosted_zone_id=Z0123456789ABC \
  -var 'alb_allowed_cidrs=["<office/VPN CIDR>"]'
```

This creates an ACM certificate (DNS-validated in that Route53 zone), an ALB with an HTTPS listener and an HTTP-to-HTTPS redirect, points the hostname at it, opens the instance to the ALB only on 8000, and sets WEB_BIND and COOKIE_SECURE for you. Restrict alb_allowed_cidrs to your office and VPN egress where you can; the login is still SSO or the admin break-glass, but there is no reason to expose it to the whole internet. To manage DNS yourself, set acm_certificate_arn and leave hosted_zone_id blank, then point domain_name at the ALB DNS name from `terraform output alb_dns_name`.

Then wire SSO to the hostname:

```
terraform output entra_redirect_url    # https://darkweb.vendettacd.io/auth/callback
aws ssm put-parameter --name /darkweb/ENTRA_REDIRECT_URL --type String --value '<that URL>'
```
Register the same URL as the redirect URI in the Entra app, add the tenant, client ID and secret to SSM (step from the Sign-in section of the README), and redeploy. Enable each client's portal from their page in the console.

## Rollback and teardown

- Redeploy after a code change: `cd /opt/darkweb && sudo bash scripts/deploy.sh`.
- Restore the database: pull the latest dump from s3://<evidence-bucket>/backups/ and `gunzip -c dump.sql.gz | docker compose exec -T db psql -U darkweb darkweb`.
- Tear down: `terraform destroy`. The evidence bucket has force_destroy off and, once in COMPLIANCE mode, locked objects survive destroy by design. Empty it deliberately only when retention has elapsed.
