# Forensic Workstation

An AWS forensic VM for Vendetta analysts with Claude built in. Claude Code runs
on the box against Amazon Bedrock, so evidence content never leaves Vendetta's
AWS account, and it drives a free DFIR toolset through an audited MCP server
that enforces the evidence-handling rules.

## What gets built

The Terraform in `infra/terraform` creates:

1. An Ubuntu 24.04 EC2 instance (m7i.2xlarge, 32 GiB by default) with no inbound
   ports. Analysts connect with SSM Session Manager; every session is recorded
   to CloudWatch.
2. A separate encrypted `/cases` EBS volume (1 TB gp3, 500 MiB/s) with daily
   snapshots kept 14 days.
3. An evidence bucket with versioning and Object Lock. Analysts upload to
   `intake/<case_id>/`; the workstation can read intake but can only write
   under `cases/`.
4. A customer-managed KMS key over the volume, the bucket and the logs.
5. An instance role allowing Claude models on Bedrock, the evidence bucket and
   log shipping, and nothing else.
6. A managed policy (`analyst_policy_arn` output) to attach to the analysts'
   group: start a session on this instance, start and stop it, upload to intake.
7. An idle alarm that stops the instance after 3 hours under 5% CPU.

First boot runs `scripts/provision.sh` (25 to 40 minutes). Progress is in
`/var/log/forensic-provision.log` and the login banner says when it is ready
and lists anything that failed to install.

## Toolset (all free)

1. Disk: The Sleuth Kit, libewf (ewfinfo, ewfverify, ewfmount), afflib, dc3dd,
   dcfldd, ddrescue, TestDisk/PhotoRec, foremost, scalpel, bulk_extractor where
   packaged, qemu-nbd for VMDK/VHD/VHDX/QCOW2, dislocker for BitLocker.
2. Memory: Volatility 3.
3. Windows artifacts: Eric Zimmerman's tools on .NET (MFTECmd, EvtxECmd, RECmd,
   PECmd, LECmd, JLECmd, SBECmd, AmcacheParser, AppCompatCacheParser, SrumECmd,
   SQLECmd, RBCmd, WxTCmd, bstrings), evtx_dump, regipy.
4. Detection over logs: Chainsaw and Hayabusa with current SigmaHQ rules.
5. Timelines: Plaso (log2timeline, psort, pinfo), Dissect (target-query,
   target-info, rdump), mactime.
6. Malware triage (static only): capa, FLOSS, YARA with signature-base,
   oletools, binwalk, radare2, exiftool, ssdeep.
7. Network: tshark (and Wireshark on the desktop).
8. Collections: Velociraptor for offline collector output.
9. Optional XFCE desktop over RDP, forwarded through SSM to localhost only.

## How Claude is wired in

Claude Code is installed system wide and configured through
`/etc/claude-code/managed-settings.json`, which analysts cannot change. The
forensic MCP server (`mcp/fw_forensics`) gives Claude 16 case-scoped tools:

`case_open`, `case_list`, `case_status`, `intake_list`, `evidence_pull`,
`evidence_verify`, `evidence_mount`, `evidence_unmount`, `tool_catalog`,
`run_tool`, `read_output`, `search_output`, `finding_add`, `findings_list`,
`audit_verify`, `case_export`.

The controls that matter are enforced by the operating system:

1. Evidence files are owned by root and mode 0440; the analyst account (which
   Claude runs as) can read but cannot write, rename or delete them. Images are
   mounted read-only with journal replay disabled.
2. The only privileged path is `fw-helper`, reached through a single sudoers
   rule. It pulls from intake (refusing to overwrite), hashes MD5/SHA-1/SHA-256,
   records the S3 version ID, and mounts and unmounts images.
3. Two hash-chained logs per case: `custody.jsonl` (root only: acquisition,
   mounts) and `audit.jsonl` (every MCP call plus every Bash command and file
   edit Claude makes, captured by a PostToolUse hook). Both are mirrored to
   CloudWatch as they are written, so a local edit shows up against the shipped
   copy. `audit_verify` checks both chains.
4. `run_tool` executes only allowlisted binaries, without a shell, in the case
   work directory, and rejects arguments that reach into another case.
5. `finding_add` requires a source artifact and a confirmed or assessed label,
   which feeds the report straight from evidence.

The Claude Code permission rules (deny edits to evidence, deny `sudo`) and the
`CLAUDE.md` operating rules sit on top of those controls as guidance.

## Deploy

Prerequisites: Terraform 1.6+, AWS credentials for the target account, and
Anthropic models enabled under Bedrock model access in `bedrock_region`.

```bash
cd modules/forensic-workstation/infra/terraform
cp terraform.tfvars.example terraform.tfvars   # adjust if needed
terraform init
terraform apply
```

Then attach the `analyst_policy_arn` output to the analysts' IAM group or
Identity Center permission set. Analysts need the AWS CLI and the Session
Manager plugin on their laptops.

If the platform repo is private, store a read-only deploy key before apply:

```bash
aws ssm put-parameter --type SecureString \
  --name /vendetta/forensic-workstation/DEPLOY_KEY --value file://deploy_key
```

and set `repo_url` to the SSH URL.

To use the Anthropic API instead of Bedrock, set `claude_backend = "anthropic"`
and store the key out of band; it is read at use time and never written to disk:

```bash
aws ssm put-parameter --type SecureString \
  --name /vendetta/forensic-workstation/ANTHROPIC_API_KEY --value sk-ant-...
```

## Analyst workflow

```bash
# 1. Start the box if the idle alarm stopped it
aws ec2 start-instances --instance-ids <instance_id>

# 2. Upload evidence from your laptop (E01, memory image, KAPE zip, EVTX folder)
aws s3 cp HOST01.E01 s3://<evidence_bucket>/intake/VCD-IR-2026-445-IFB/HOST01.E01
aws s3 cp --recursive ./kape_HOST02 s3://<evidence_bucket>/intake/VCD-IR-2026-445-IFB/kape_HOST02/

# 3. Connect (lands in /cases as the analyst user) and start Claude
aws ssm start-session --target <instance_id> --document-name vendetta-fw-AnalystShell
claude
```

Example prompts once Claude is running:

1. "Open case VCD-IR-2026-445-IFB, pull everything in intake, verify the E01
   against its embedded hashes and mount it."
2. "Build a Windows triage for HOST01: Prefetch, Amcache, Shimcache, Run keys,
   services, 4624/4625/4688/7045, and a Hayabusa timeline. Record findings."
3. "Run Volatility pslist, pstree, netscan, cmdline and malfind on mem.raw and
   tell me which processes look injected, with evidence."
4. "Draft the forensic findings section for the report from the recorded
   findings, then export the case."

For GUI tools, set an RDP password once (`sudo fw-helper rdp-password` from the
SSM shell), forward the port with the `connect_desktop` command from the
Terraform outputs, and point an RDP client at `localhost:13389`.

## Cost

At us-east-1 on-demand rates, m7i.2xlarge is roughly $0.40 per running hour and
the 1 TB gp3 case volume with the added throughput and IOPS roughly $110 per
month whether running or stopped. Bedrock usage is billed per token. The idle
stop keeps compute cost to hours actually worked.

## Tests

```bash
pip install ./mcp pytest && pytest tests
```

The tests cover the custody chain and tamper detection, intake through
`fw-helper` with a fake AWS CLI, `run_tool` guardrails, findings and export.
Image mounting needs real block devices and is verified on the instance.
