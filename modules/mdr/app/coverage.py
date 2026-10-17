"""The rule set laid over the ATT&CK tactics: which tactics the enabled rules see,
through which techniques, and where the gaps are."""
from __future__ import annotations

from . import attack


def compute(rules: list[dict]) -> dict:
    """rules are Rule.as_dict() shapes. Pure."""
    tactic_rows = {tid: {"id": tid, "name": name, "rules": 0, "enabled_rules": 0, "techniques": {}}
                   for tid, name in attack.TACTICS}
    unmapped: dict[str, list[str]] = {}
    covered_techniques = set()
    no_technique = []
    for r in rules:
        mitre = r.get("mitre") or []
        if not mitre:
            no_technique.append(r["key"])
        tactics_hit = set()
        for tech in mitre:
            tactics = attack.tactics_for(tech)
            if not tactics:
                unmapped.setdefault(tech, []).append(r["key"])
                continue
            if r.get("enabled", True):
                covered_techniques.add(tech)
            for ta in tactics:
                row = tactic_rows[ta]
                t = row["techniques"].setdefault(tech, {"id": tech, "name": attack.technique_name(tech),
                                                        "rules": [], "enabled": 0})
                t["rules"].append(r["key"])
                if r.get("enabled", True):
                    t["enabled"] += 1
                tactics_hit.add(ta)
        for ta in tactics_hit:
            tactic_rows[ta]["rules"] += 1
            if r.get("enabled", True):
                tactic_rows[ta]["enabled_rules"] += 1
    tactics = []
    for tid, _ in attack.TACTICS:
        row = tactic_rows[tid]
        row["techniques"] = sorted(row["techniques"].values(), key=lambda t: t["id"])
        row["covered"] = row["enabled_rules"] > 0
        tactics.append(row)
    return {
        "tactics": tactics,
        "rules": len(rules),
        "enabled_rules": sum(1 for r in rules if r.get("enabled", True)),
        "techniques_covered": len(covered_techniques),
        "tactics_covered": sum(1 for t in tactics if t["covered"]),
        "correlation_rules": no_technique,
        "unmapped": [{"id": k, "rules": v} for k, v in sorted(unmapped.items())],
    }
