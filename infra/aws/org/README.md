# org

Runs in the management account. Builds the organization, the Security,
Infrastructure, Workloads and Sandbox OUs, the member accounts, the SCPs, the
delegated administrators, the organization CloudTrail into the log-archive
account, and the Identity Center permission sets (SOCAdmin, SOCAnalyst,
EvidenceCustodian, BreakGlass) with group assignments.

Inputs: `account_emails` (seven required keys plus optional `network`),
`permission_set_assignments` (Identity Store group ids synced from Entra),
`allowed_regions`.

Apply in two passes, because the log-archive provider alias needs the new
account id:

```bash
tofu init -backend-config=backend.hcl
tofu apply -target=aws_organizations_account.member
tofu apply
```

If the management account already has an organization, import it first:
`tofu import aws_organizations_organization.this o-xxxxxxxxxx`.

Outputs feed every other stack: `account_ids`, `organization_id`,
`organization_arn`, `log_archive_bucket_arn`.

Accounts carry `prevent_destroy` and `close_on_deletion = false`; removing one
from `account_emails` fails the plan until the lifecycle rule is lifted.
