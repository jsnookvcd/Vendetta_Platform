# First deploy to AWS

Run top to bottom from your Mac. Everything after Terraform happens over SSM; no ports are opened on the instance. Budget 30 to 45 minutes for the first run, most of it waiting on Tor to bootstrap and the first feed sweep.

## 0. Prerequisites

- AWS CLI with a profile for the Vendetta account, and the Session Manager plugin installed.
- Terraform 1.6 or newer.
- The code reachable by the instance: either push this repo to a private Git URL the instance can clone, or plan to copy it over SSM in step 3b.

## 1. Stand up infrastructure

```
cd infra/terraform
terraform init
terraform validate
terraform plan -out tf.plan \
  -var 'alert_emails=["ir@vendettacd.io"]' \
  -var object_lock_mode=GOVERNANCE \
  -var repo_url=git@github.com:vendettacd/vcd-darkweb.git
terraform apply tf.plan
```

Keep object_lock_mode at GOVERNANCE for the first deploy so nothing in the evidence bucket is permanent while you shake the stack out. Flip it to COMPLIANCE in a later apply once you trust it.

Confirm the SNS subscription email that arrives at each address in alert_emails. Unconfirmed addresses get no alerts.

## 2. Put secrets into SSM

These never go into Terraform state. Generate the password hash on your Mac:

```
python3 -c "import bcrypt,getpass;print(bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt(12)).decode())"

aws ssm put-parameter --name /darkweb/ADMIN_PASSWORD_HASH --type SecureString --value '<hash>'
aws ssm put-parameter --name /darkweb/HIBP_API_KEY        --type SecureString --value '<key>'
aws ssm put-parameter --name /darkweb/RANSOMWARE_LIVE_API_KEY --type SecureString --value '<key>'
aws ssm put-parameter --name /darkweb/TEAMS_WEBHOOK_URL   --type SecureString --value '<url>'
```

SECRET_KEY, POSTGRES_PASSWORD, EVIDENCE_BUCKET and SNS_TOPIC_ARN were created by Terraform. Jira and the VERDICT hub are intentionally left blank; add them later when those are live.

## 3. Bring up the stack

Open a shell on the instance:

```
aws ssm start-session --target "$(terraform output -raw instance_id)"
```

3a. If repo_url was set, user_data already cloned and started the stack. Confirm:

```
cd /opt/darkweb && sudo docker compose ps
```

3b. If repo_url was blank, copy the code up now (from your Mac, using the S3 bucket as a shuttle or scp over an SSM tunnel), then:

```
cd /opt/darkweb
sudo bash scripts/render_env.sh /opt/darkweb/.env
sudo docker compose up -d --build
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

## 7. Platform wiring (when VERDICT is ready)

This runs standalone today. When the hub is live:

```
aws ssm put-parameter --name /darkweb/VERDICT_HUB_URL   --type String       --value 'https://verdict.internal'
aws ssm put-parameter --name /darkweb/VERDICT_HUB_TOKEN --type SecureString  --value '<token>'
cd /opt/darkweb && sudo bash scripts/deploy.sh
```

The hub reads findings at /api/findings and the manifest at /api/module. Escalate turns a finding into an IR case in the engagement hub, attached to the Forensics and Analysis workstream.

## Rollback and teardown

- Redeploy after a code change: `cd /opt/darkweb && sudo bash scripts/deploy.sh`.
- Restore the database: pull the latest dump from s3://<evidence-bucket>/backups/ and `gunzip -c dump.sql.gz | docker compose exec -T db psql -U darkweb darkweb`.
- Tear down: `terraform destroy`. The evidence bucket has force_destroy off and, once in COMPLIANCE mode, locked objects survive destroy by design. Empty it deliberately only when retention has elapsed.
