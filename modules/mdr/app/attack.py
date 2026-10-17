"""MITRE ATT&CK (Enterprise) reference data for the rule set and the coverage grid.

Only the techniques the starter rules and common analyst edits use are listed; a
rule may name any technique id, and one this table does not know is reported as
unmapped on the coverage page rather than refused.
"""
from __future__ import annotations

import re

# Enterprise tactics in kill-chain order.
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
TACTIC_NAMES = dict(TACTICS)

# technique id -> (name, [tactic ids])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003": ("OS Credential Dumping", ["TA0006"]),
    "T1003.001": ("LSASS Memory", ["TA0006"]),
    "T1003.003": ("NTDS", ["TA0006"]),
    "T1021": ("Remote Services", ["TA0008"]),
    "T1021.001": ("Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["TA0008"]),
    "T1021.006": ("Windows Remote Management", ["TA0008"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1053.005": ("Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1059.001": ("PowerShell", ["TA0002"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1078.004": ("Cloud Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.003": ("Password Spraying", ["TA0006"]),
    "T1114.003": ("Email Forwarding Rule", ["TA0009"]),
    "T1204.002": ("Malicious File", ["TA0002"]),
    "T1219": ("Remote Access Software", ["TA0011"]),
    "T1486": ("Data Encrypted for Impact", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1543.003": ("Windows Service", ["TA0003", "TA0004"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1552.005": ("Cloud Instance Metadata API", ["TA0006"]),
    "T1562.001": ("Disable or Modify Tools", ["TA0005"]),
    "T1564.008": ("Email Hiding Rules", ["TA0005"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1567": ("Exfiltration Over Web Service", ["TA0010"]),
    "T1570": ("Lateral Tool Transfer", ["TA0008"]),
    "T1621": ("Multi-Factor Authentication Request Generation", ["TA0006"]),
}

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def valid_technique(tid: str) -> bool:
    return bool(TECHNIQUE_RE.match(tid or ""))


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, (tid, []))[0]


def tactics_for(tid: str) -> list[str]:
    """Tactics for a technique; a sub-technique not listed inherits its parent's."""
    if tid in TECHNIQUES:
        return TECHNIQUES[tid][1]
    parent = tid.split(".")[0]
    return TECHNIQUES.get(parent, ("", []))[1]
