"""Starter Sigma rule set.

The rules live as YAML files in app/rules/. STARTER holds (filename, text) for each,
read once at import. seed(db) inserts every starter rule whose id is not yet in the
sigma_rules table and leaves existing rows alone, because an administrator may have
edited or disabled a seeded rule and a restart must not undo that.
"""
from __future__ import annotations

from pathlib import Path

from . import sigma

RULES_DIR = Path(__file__).resolve().parent / "rules"


def _load() -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted(RULES_DIR.glob("*.yml"))]


STARTER: list[tuple[str, str]] = _load()


def compiled() -> list[tuple[str, str, sigma.Rule]]:
    """Every starter rule compiled. A starter rule that does not compile is a bug, so
    the SigmaError propagates with the file name attached."""
    out = []
    for name, text in STARTER:
        try:
            out.append((name, text, sigma.compile(text)))
        except sigma.SigmaError as exc:
            raise sigma.SigmaError(f"starter rule {name}: {exc}") from exc
    return out


def seed(db) -> int:
    """Insert missing starter rules. Returns the number added."""
    from .db import SigmaRule, SigmaRuleVersion

    rules = compiled()
    existing = {rid for (rid,) in db.query(SigmaRule.id).filter(SigmaRule.id.in_([r.id for _, _, r in rules]))}
    added = 0
    for _name, text, rule in rules:
        if rule.id in existing:
            continue
        db.add(SigmaRule(id=rule.id, title=rule.title, level=rule.level, enabled=True, body=text,
                         tags=list(rule.tags), origin="seed", version=1, updated_by="seed"))
        db.add(SigmaRuleVersion(rule_id=rule.id, version=1, body=text, enabled=True, changed_by="seed",
                                note="starter rule set"))
        existing.add(rule.id)
        added += 1
    db.commit()
    return added
