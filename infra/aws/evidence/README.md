# evidence

Runs in the evidence account. Builds the ledger anchor bucket with Object Lock
COMPLIANCE (`retention_days`, seven years by default), its replica in
us-east-2 with the same lock, the ledger KMS keys, and the asymmetric anchor
signing key.

COMPLIANCE mode means no principal, the root user included, can shorten the
retention or delete a locked version until it expires. Run it with
`object_lock_mode = "GOVERNANCE"` in a sandbox account first.

Roles:

- `vcd-soc-evidence-key-admin`: key administration only. Assumable by SOCAdmin
  and BreakGlass sessions.
- `vcd-soc-evidence-custodian`: uses the keys and the ledger. Assumable by
  EvidenceCustodian sessions that pass an `approver` session tag and, with
  `require_mfa = true`, MFA.

The key policies name these roles directly, so IAM policies in the account
cannot widen access. KMS has no two-person rule; the main README explains what
this design records and what it leaves to process.

The signing key defaults to ECC_NIST_P256. The modules keep signing chains of
custody with their own Ed25519 seed. Whether KMS offers Ed25519 in this
account's regions was not confirmed; check before changing `signing_key_spec`.

Writers and signers: `ledger_writer_principal_arns` and
`signer_principal_arns` take soc-apps task role ARNs. The names are fixed
(`vcd-soc-<module>-task`) and the policies match them with ArnLike conditions,
so set them before soc-apps exists, for example
`arn:aws:iam::<soc-apps-prod id>:role/vcd-soc-incident-response-task`. Outputs for
soc-apps: `ledger_bucket_arn`, `ledger_kms_key_arn`.
