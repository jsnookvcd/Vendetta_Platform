"""The starter detection rule set, seeded once into the rules table.

Each rule matches the managed-services signal shape: `tools` against the finding's
`reason` (the source tool), `types` against its `type` (threat, detection, incident,
backup, rmm), `title_any` as case-insensitive substrings of the title, and
`min_severity`. Correlation groups matching signals by host, client or title and
opens an investigation once `threshold` of them land inside `window_minutes`.

After seeding these are data: an admin edits them on the Rules page and every edit
is versioned. Seeding never overwrites a rule that already exists.
"""
from __future__ import annotations

EDR = ["sentinelone", "crowdstrike", "huntress"]


def _rule(key, name, description, severity, mitre, response="none", *, tools=None, types=None,
          title_any=None, min_severity="low", group_by="host", window_minutes=60, threshold=1):
    return {
        "key": key, "name": name, "description": description, "enabled": True, "severity": severity,
        "match": {"tools": tools or [], "types": types or [], "title_any": title_any or [],
                  "min_severity": min_severity},
        "correlation": {"group_by": group_by, "window_minutes": window_minutes, "threshold": threshold},
        "mitre": mitre, "response": response,
    }


STARTER_RULES: list[dict] = [
    _rule("ransomware-behavior", "Ransomware behavior",
          "An endpoint tool reports encryption activity, a ransom note or mass file modification. "
          "Treat as an active incident until proven otherwise.",
          "critical", ["T1486"], "isolate_host", tools=EDR,
          title_any=["ransom", "encrypt", "mass file modification", "file renaming", "crypto locker", "lockbit"]),
    _rule("credential-dumping", "Credential dumping",
          "Access to LSASS memory, the SAM hive or NTDS.dit, or a known dumping tool.",
          "critical", ["T1003", "T1003.001", "T1003.003"], "isolate_host", tools=EDR,
          title_any=["lsass", "mimikatz", "credential dump", "procdump", "ntds.dit", "sam hive", "comsvcs"]),
    _rule("suspicious-powershell", "Suspicious PowerShell",
          "Encoded, obfuscated or download-cradle PowerShell flagged by an endpoint tool.",
          "high", ["T1059.001"], "block_indicator", tools=EDR,
          title_any=["powershell", "encodedcommand", "invoke-expression", "downloadstring", "amsi bypass"]),
    _rule("risky-sign-in", "Risky sign-in or impossible travel",
          "Entra ID Identity Protection reports a risky or anomalous sign-in to a client account.",
          "high", ["T1078", "T1078.004"], "disable_account", tools=["entra"],
          title_any=["impossible travel", "atypical travel", "risky sign-in", "unfamiliar sign-in",
                     "anonymous ip", "leaked credentials", "malicious ip", "token anomaly"]),
    _rule("mfa-fatigue", "MFA fatigue",
          "Repeated MFA prompts or denials against one account, the push-bombing pattern.",
          "high", ["T1621"], "disable_account", tools=["entra"],
          title_any=["mfa fatigue", "mfa push", "mfa denied", "mfa request", "repeated mfa", "fraud alert"]),
    _rule("password-spray", "Failed sign-in burst",
          "Five or more failed sign-in signals for one client inside thirty minutes, the shape of a "
          "spray or brute force run.",
          "medium", ["T1110", "T1110.003"], "block_indicator", tools=["entra", "aws"],
          title_any=["failed sign-in", "sign-in failure", "password spray", "brute force", "failed login",
                     "consolelogin failure"],
          group_by="client", window_minutes=30, threshold=5),
    _rule("mailbox-forwarding", "Mailbox forwarding or hiding rule",
          "A new inbox rule forwards mail outside the organization or hides messages, the usual "
          "follow-on to a mailbox compromise.",
          "high", ["T1114.003", "T1564.008"], "disable_account", tools=["entra", "huntress"],
          title_any=["forwarding rule", "inbox rule", "mail forward", "external forwarding",
                     "forwardingsmtpaddress", "redirect rule"]),
    _rule("cloud-credential-misuse", "Cloud credential misuse",
          "GuardDuty-style finding: instance credentials used from outside AWS, or anomalous IAM "
          "behavior from a credential that should not do that.",
          "critical", ["T1552.005", "T1078.004"], "disable_account", tools=["aws"],
          title_any=["instancecredentialexfiltration", "credential exfiltration", "unauthorizedaccess:iamuser",
                     "instance metadata", "imds", "anomalousbehavior", "credentialaccess:iamuser"]),
    _rule("scheduled-task-persistence", "Persistence via scheduled task or service",
          "A scheduled task, new service or run key created by an unusual process.",
          "medium", ["T1053.005", "T1543.003", "T1547.001"], "isolate_host", tools=EDR,
          title_any=["scheduled task", "schtasks", "persistence", "run key", "new service", "autorun"]),
    _rule("lateral-movement", "Lateral movement",
          "Remote service execution between internal hosts: PsExec, WMI, WinRM, RDP or admin shares.",
          "high", ["T1021", "T1021.001", "T1021.002", "T1021.006", "T1047", "T1570"], "isolate_host", tools=EDR,
          title_any=["lateral movement", "psexec", "remote service", "wmi", "winrm", "admin share",
                     "pass-the-hash", "rdp"]),
    _rule("backup-tampering", "Backup deletion or recovery tampering",
          "Shadow copies deleted, recovery disabled or backups removed, typically minutes before "
          "encryption starts.",
          "critical", ["T1490"], "isolate_host", tools=EDR + ["acronis"],
          title_any=["shadow cop", "vssadmin", "wbadmin", "bcdedit", "backup deleted", "deleted backup",
                     "backup plan removed", "protection plan revoked", "recovery disabled"]),
    _rule("backup-failures", "Repeated backup failures",
          "Three failed backup jobs on one host inside a day. Not an attack on its own, but it leaves "
          "the client unable to recover from one.",
          "medium", ["T1490"], "none", tools=["acronis"], types=["backup"],
          title_any=["fail", "missed", "error"], group_by="host", window_minutes=1440, threshold=3),
    _rule("security-tool-tampering", "Security tool tampering",
          "An endpoint agent reports tampering, uninstall or disablement, or Defender is switched off.",
          "high", ["T1562.001"], "isolate_host", tools=EDR + ["superops"],
          title_any=["tamper", "agent disabled", "agent uninstall", "defender disabled", "protection disabled",
                     "sensor offline unexpectedly"]),
    _rule("remote-access-tool", "Unsanctioned remote access tool",
          "A remote access tool the client does not use appears on a host.",
          "medium", ["T1219"], "block_indicator", tools=EDR + ["superops"],
          title_any=["anydesk", "teamviewer", "screenconnect", "atera", "splashtop", "remote access tool",
                     "ngrok"]),
    _rule("host-signal-burst", "Burst of signals on one host",
          "Five or more medium-or-higher signals from any tool on one host inside thirty minutes. "
          "Correlation catches the attack that no single alert describes.",
          "high", [], "isolate_host", min_severity="medium", group_by="host", window_minutes=30, threshold=5),
]
