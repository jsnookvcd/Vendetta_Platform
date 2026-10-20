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
    ("professional-services", "Office of Special Projects", "vciso", "in-progress", True, 57),
    # Port 8800, host mdr.<domain>; serves the finding model (type investigation).
    ("mdr", "Managed Detection and Response", "managed-security", "in-progress", True, 60),
    # Port 8900, host pm.<domain>; staff-only delivery PM for IR and ProServ.
    ("project-management", "Project Management", "internal", "in-progress", False, 65),
    # Port 9000, host ingest.<domain>; serves Sigma and vendor detections as findings
    # and receives vendor pushes at /api/ingest/{connector}.
    ("ingest", "Telemetry Ingest", "managed-security", "in-progress", True, 62),
    ("network-operations", "Network Operations", "managed-it", "planned", False, 70),
]

# Modules that serve the shared finding model at /api/findings. The hub pulls from
# these as its finding sources (discovered via GET /api/platform/modules).
# professional-services (Office of Special Projects) is intentionally NOT here: it
# delivers engagements, not detections, and escalates live risk to the IR hub instead
# of feeding the finding model.
FINDING_MODULES = {"dark-web-monitoring", "managed-services", "vulnerability-management",
                   "penetration-testing", "mdr", "ingest"}

# Who may read the module directory (GET /api/platform/modules?module=<caller>) and
# which modules, with their tokens, each caller receives. The incident-response
# hub gets the modules it pulls findings from and nothing else: it is the
# escalation target itself, so there is no further module it escalates to, and it
# never reads the Office of Special Projects. SABINE is deliberately absent: its
# reach is the deployment-rendered MODULE_DIRECTORY in its own SSM parameter.
DIRECTORY_CONSUMERS = {"incident-response": FINDING_MODULES}

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
    # MDR serves its investigations as findings (type investigation).
    "mdr": {
        "manifest": "/api/module",
        "items": "/api/findings?status=active",
        "label": "open investigations",
        "severity_key": "severity",
    },
    # Telemetry Ingest serves open detections as findings (type sigma or alert).
    "ingest": {
        "manifest": "/api/module",
        "items": "/api/findings?status=active",
        "label": "open detections",
        "severity_key": "severity",
    },
    # Engagements carry no severity; the count is what the overview shows.
    "professional-services": {
        "manifest": "/api/module",
        "items": "/api/engagements",
        "label": "open engagements",
        "severity_key": "severity",
    },
    "project-management": {
        "manifest": "/api/module",
        "items": "/api/engagements",
        "label": "open engagements",
        "severity_key": "severity",
    },
}


def seed_registry(db: Session) -> None:
    from .db import Module, ToolConnection

    for key, name, category, status, portal, pos in DEFAULT_MODULES:
        row = db.get(Module, key)
        if not row:
            db.add(Module(key=key, display_name=name, category=category, status=status,
                          has_portal=portal, position=pos))
        elif row.status == "planned" and status != "planned":
            # A module that was only planned when this control plane first booted has
            # since been built: bring its row up to the registry. An operator's own
            # status choice on a live module is never overwritten.
            row.status, row.has_portal = status, portal
    for key, kind, owner in DEFAULT_TOOLS:
        if not db.get(ToolConnection, key):
            db.add(ToolConnection(key=key, display_name=TOOL_NAMES.get(key, key), kind=kind, owner_module=owner))
    db.commit()
