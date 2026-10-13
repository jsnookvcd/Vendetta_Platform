"""Default IR playbook: the cards every case opens with, per workstream.

Each entry is (title, client_visible). Client-visible cards show as steps on the
client portal, and moving one is shared on the client timeline. Everything else is
internal. Edit this list to change the firm standard; it applies to cases opened
after the change. Analysts add, edit and remove cards per case."""
from __future__ import annotations

PLAYBOOK: dict[str, list[tuple[str, bool]]] = {
    "Scoping and Containment": [
        ("Kickoff and scoping call", True),
        ("Identify affected systems, accounts and data", False),
        ("Contain: isolate hosts, disable accounts, block indicators", True),
        ("Preserve volatile evidence before remediation", False),
        ("Confirm containment is holding", True),
    ],
    "Forensics and Analysis": [
        ("Collect logs and triage images", False),
        ("Build the incident timeline", False),
        ("Determine initial access and attacker activity", True),
        ("Assess data access and exfiltration", True),
        ("Extract indicators and feed them to containment", False),
    ],
    "Recovery and Restoration": [
        ("Validate backups and restore points", False),
        ("Restore or rebuild affected systems", True),
        ("Rotate credentials, keys and secrets", False),
        ("Monitored return to production", True),
    ],
    "Notification and Legal": [
        ("Engage breach counsel and the carrier", True),
        ("Maintain chain of custody and the evidence log", False),
        ("Notification analysis: regulatory, contractual, individuals", True),
        ("Law enforcement referral decision", False),
    ],
    "Resilience and Hardening": [
        ("Remediation and hardening recommendations", True),
        ("Final report", True),
        ("Lessons-learned review", True),
    ],
}
