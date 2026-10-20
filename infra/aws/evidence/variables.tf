variable "region" {
  type    = string
  default = "us-east-1"
}

variable "replica_region" {
  type    = string
  default = "us-east-2"
}

variable "evidence_account_id" {
  description = "org output account_ids[\"evidence\"]."
  type        = string
}

variable "member_access_role_name" {
  type    = string
  default = "OrganizationAccountAccessRole"
}

variable "organization_id" {
  type = string
}

variable "object_lock_mode" {
  description = "COMPLIANCE: nobody, including the root user and AWS, can shorten retention or delete a locked version until it expires. Test with GOVERNANCE in a sandbox first."
  type        = string
  default     = "COMPLIANCE"
}

variable "retention_days" {
  description = "Default Object Lock retention for ledger anchors and the replica."
  type        = number
  default     = 2555
}

variable "signing_key_spec" {
  description = "KMS key spec for the asymmetric ledger anchor signing key. See README on Ed25519."
  type        = string
  default     = "ECC_NIST_P256"
}

variable "key_admin_principal_patterns" {
  description = "Who may assume vcd-soc-evidence-key-admin (administers keys, cannot use them)."
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SOCAdmin_*",
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_BreakGlass_*",
  ]
}

variable "custodian_principal_patterns" {
  description = "Who may assume vcd-soc-evidence-custodian (uses the keys), subject to the MFA and approver tag conditions."
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_EvidenceCustodian_*",
  ]
}

variable "require_mfa" {
  description = "Require aws:MultiFactorAuthPresent on custodian role assumption. See README: Identity Center sessions may not carry this key."
  type        = bool
  default     = true
}

variable "ledger_writer_principal_arns" {
  description = "Task roles in soc-apps accounts that append ledger anchors (soc-apps output task_role_arns). ArnLike patterns."
  type        = list(string)
  default     = []
}

variable "signer_principal_arns" {
  description = "Task roles allowed to countersign anchors with the KMS signing key. ArnLike patterns."
  type        = list(string)
  default     = []
}
