"""Module and tool registry defaults, and the per-module probe map.

The default rows mirror modules/registry.yaml so a fresh control plane knows the
platform's shape on first boot. Everything is editable in the console afterward
(base_url, token, status). The probe map says, per module, how to read health and
an open-item count from a running module, so the overview can show live numbers."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .config import TOOL_NAMES

# key: (display_name, category, status, has_portal, position)
DEFAULT_MODULES = [
    ("incident-response", "Incident Response", "engagement-hub", "in-progress", True, 10),
    ("dark-web-monitoring", "Dark Web Monitoring", "managed-security", "production", True, 20),
    ("managed-services", "Managed Services", "managed-security", "in-progress", True, 30),
    ("vulnerability-management", "Vulnerability Management", "managed-security", "in-progress", True, 40),
    ("penetration-testing", "Penetration Testing", "offensive-security", "in-progress", True, 50),
    ("sabine", "SABINE", "agent", "in-progress", False, 55),
    ("professional-services", "Office of Special Projects", "vciso", "in-progress", True, 55),
    ("mdr", "Managed Detection and Response", "managed-security", "planned", False, 60),
    ("network-operations", "Network Operations", "managed-it", "planned", False, 70),
]

# Modules that serve the shared finding model at /api/findings. The hub pulls from
# these as its finding sources (discovered via GET /api/platform/modules).
# professional-services (Office of Special Projects) is intentionally NOT here: it
# delivers engagements, not detections, and escalates live risk to the IR hub instead
# of feeding the finding model.
FINDING_MODULES = {"dark-web-monitoring", "managed-services", "vulnerability-management",
                   "penetration-testing"}

# key: (display_name, kind, owner_module)
DEFAULT_TOOLS = [
    ("superops", "psa-rmm", "managed-services"),
    ("sentinelone", "edr", "managed-services"),
    ("crowdstrike", "edr", "managed-services"),
    ("huntress", "mdr", "managed-services"),
    ("acronis", "backup", "managed-services"),
]

# How to read a module's live state. manifest is the health/enabled check; items is
# the open-item list, with the JSON path to the array and the fields to judge
# severity/open-ness. Modules not listed here show no live count.
PROBE = {
    "dark-web-monitoring": {
        "manifest": "/api/module",
        "items": "/api/findings",
        "label": "open findings",
        "severity_key": "severity",
    },
    "incident-response": {
        "manifest": "/api/module",
        "items": "/api/ir-cases",
        "label": "open cases",
        "severity_key": "severity",
    },
    "managed-services": {
        "manifest": "/api/module",
        "items": "/api/findings",
        "label": "open alerts",
        "severity_key": "severity",
    },
    "vulnerability-management": {
        "manifest": "/api/module",
        "items": "/api/findings",
        "label": "open findings",
        "severity_key": "severity",
    },
    "penetration-testing": {
        "manifest": "/api/module",
        "items": "/api/findings",
        "label": "open findings",
        "severity_key": "severity",
    },
    "sabine": {
        "manifest": "/api/module",
        "items": "/api/queue",
        "label": "open work",
        "severity_key": "severity",
    },
}


def seed_registry(db: Session) -> None:
    from .db import Module, ToolConnection

    for key, name, category, status, portal, pos in DEFAULT_MODULES:
        if not db.get(Module, key):
            db.add(Module(key=key, display_name=name, category=category, status=status,
                          has_portal=portal, position=pos))
    for key, kind, owner in DEFAULT_TOOLS:
        if not db.get(ToolConnection, key):
            db.add(ToolConnection(key=key, display_name=TOOL_NAMES.get(key, key), kind=kind, owner_module=owner))
    db.commit()
