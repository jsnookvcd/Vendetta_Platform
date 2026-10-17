"""Staff directory and access levels.

The control plane is the system of record for Vendetta's own people the same way
it is for clients. A person is onboarded once here with an access profile, and
every module pulls the staff roster (GET /api/platform/staff?module=<key>) the
same way it pulls clients, so a module's SSO sign-in admits an internal user only
when the roster lists them for that module, with the role the roster says.
Deactivating a person here locks them out of every module on the next push.

Access levels, per module: none (cannot sign in there), viewer (opens every staff
page and reads every API, changes nothing), analyst (full operational access),
admin (also settings, SSO, connections and, on the platform, staff). The platform
role has the same viewer, analyst and admin levels. In SABINE, analyst decides low
and medium risk proposals; admin also decides high-risk hand-offs and sets the
autonomy policy. A viewer is enforced once per module in its auth layer: every
GET is served, every POST, PUT or DELETE answers 403.
Managed services additionally carries two capabilities on the grant: can_act (may
run response actions) and can_approve (may authorize a destructive action, the
second-person control).

Profiles are starting points. Applying one rewrites the grants; an admin can then
adjust any single module on the person's page.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Staff, StaffGrant, utcnow

PLATFORM_ROLES = ("viewer", "analyst", "admin")
MODULE_ROLES = ("none", "viewer", "analyst", "admin")

# Modules a grant can name: every module that is not merely planned.
GRANTABLE = ["incident-response", "managed-services", "dark-web-monitoring",
             "vulnerability-management", "penetration-testing", "professional-services", "sabine", "mdr"]

# profile key -> (label, description, platform role, {module: (role, config)})
PROFILES = {
    "administrator": (
        "Administrator",
        "Everything, everywhere: platform admin, admin in every module, runs and approves response actions.",
        "admin",
        {m: ("admin", {"can_act": True, "can_approve": True} if m == "managed-services" else {}) for m in GRANTABLE},
    ),
    "incident-responder": (
        "Incident responder",
        "Works cases end to end: IR hub, MDR investigations, managed services with response actions and approval, dark web, vuln and pentest findings.",
        "analyst",
        {
            "incident-response": ("analyst", {}),
            "managed-services": ("analyst", {"can_act": True, "can_approve": True}),
            "dark-web-monitoring": ("analyst", {}),
            "vulnerability-management": ("analyst", {}),
            "penetration-testing": ("analyst", {}),
            "professional-services": ("none", {}),
            "sabine": ("analyst", {}),
            "mdr": ("analyst", {}),
        },
    ),
    "soc-analyst": (
        "SOC analyst",
        "Triage and standard response in managed services (no approval of destructive actions), MDR investigations, dark web and vulnerability findings, and the IR hub.",
        "analyst",
        {
            "incident-response": ("analyst", {}),
            "managed-services": ("analyst", {"can_act": True, "can_approve": False}),
            "dark-web-monitoring": ("analyst", {}),
            "vulnerability-management": ("analyst", {}),
            "penetration-testing": ("none", {}),
            "professional-services": ("none", {}),
            "sabine": ("analyst", {}),
            "mdr": ("analyst", {}),
        },
    ),
    "offensive-security": (
        "Offensive security",
        "Penetration testing and vulnerability management only.",
        "analyst",
        {
            "incident-response": ("none", {}),
            "managed-services": ("none", {}),
            "dark-web-monitoring": ("none", {}),
            "vulnerability-management": ("analyst", {}),
            "penetration-testing": ("analyst", {}),
            "professional-services": ("none", {}),
            "sabine": ("none", {}),
            "mdr": ("none", {}),
        },
    ),
    "vciso-advisory": (
        "vCISO / advisory",
        "The Office of Special Projects (engagements and deliverables) and SABINE's briefs and queue; no SOC or offensive tooling.",
        "analyst",
        {**{m: ("none", {}) for m in GRANTABLE}, "professional-services": ("analyst", {}), "sabine": ("analyst", {})},
    ),
    "leadership": (
        "Leadership",
        "Reads everything and changes nothing: viewer on the platform and in every module, analyst in SABINE for its briefs and queue.",
        "viewer",
        {**{m: ("viewer", {"can_act": False, "can_approve": False} if m == "managed-services" else {}) for m in GRANTABLE},
         "sabine": ("analyst", {})},
    ),
}


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def grant_map(person: Staff) -> dict[str, StaffGrant]:
    return {g.module_key: g for g in person.grants}


def apply_profile(db: Session, person: Staff, profile: str) -> None:
    """Rewrite a person's platform role and module grants from a profile."""
    label, _desc, prole, mods = PROFILES[profile]
    person.platform_role = prole
    person.profile = profile
    existing = grant_map(person)
    for key in GRANTABLE:
        role, cfg = mods.get(key, ("none", {}))
        g = existing.get(key)
        if g is None:
            g = StaffGrant(staff_id=person.id, module_key=key)
            person.grants.append(g)
        g.role, g.config = role, dict(cfg)
    person.updated_at = utcnow()


def set_grant(db: Session, person: Staff, module_key: str, role: str, config: dict | None = None) -> StaffGrant:
    if module_key not in GRANTABLE or role not in MODULE_ROLES:
        raise ValueError("bad module or role")
    g = grant_map(person).get(module_key)
    if g is None:
        g = StaffGrant(staff_id=person.id, module_key=module_key)
        person.grants.append(g)
    g.role = role
    if config is not None:
        g.config = dict(config)
    if role == "viewer" and module_key == "managed-services":
        # A viewer never runs or approves response actions, whatever was ticked.
        g.config = {"can_act": False, "can_approve": False}
    person.profile = "custom"
    person.updated_at = utcnow()
    return g


def roster_for_module(db: Session, module_key: str) -> list[dict]:
    """What a module pulls: every active person with a non-none grant there."""
    rows = db.execute(select(Staff).where(Staff.active.is_(True)).order_by(Staff.email)).scalars().all()
    out = []
    for p in rows:
        g = grant_map(p).get(module_key)
        if g is None or g.role == "none":
            continue
        out.append({"email": p.email, "name": p.name, "title": p.title, "role": g.role,
                    "config": dict(g.config or {})})
    return out


def roster_all(db: Session) -> list[dict]:
    rows = db.execute(select(Staff).order_by(Staff.email)).scalars().all()
    return [{"email": p.email, "name": p.name, "title": p.title, "active": p.active,
             "platform_role": p.platform_role, "profile": p.profile,
             "modules": {g.module_key: {"role": g.role, "config": dict(g.config or {})} for g in p.grants}}
            for p in rows]


def governs(db: Session) -> bool:
    """True once at least one person is onboarded: from then on the roster decides
    who may sign in to the control plane, not the email domain."""
    return db.execute(select(Staff.id).limit(1)).first() is not None


def lookup(db: Session, email: str) -> Staff | None:
    return db.execute(select(Staff).where(Staff.email == normalize_email(email))).scalar_one_or_none()


# Bridges act for a person through other modules' grants rather than a grant of
# their own: the Slack responder checks the incident-response and sabine grants.
# A change to either grant reaches the bridge too, so it drops its cached roster.
BRIDGES = {"slack": {"incident-response", "sabine"}}


def modules_affected(person: Staff) -> set[str]:
    keys = {g.module_key for g in person.grants}
    return keys | {b for b, via in BRIDGES.items() if keys & via}
