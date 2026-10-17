"""The skills catalog: one registry every action string comes from. The reasoner
can only propose skills in it, the executor dispatches by it, the Autonomy page
is the catalog grouped by domain with the last run per skill, and /api/skills
serves the same."""
import ast
import pathlib

from app import auth, brain, executor, policy, skills
from app.db import SessionLocal

from test_brain import world  # noqa: F401  (fixture: mock platform and modules)

REASONER = pathlib.Path(__file__).resolve().parent.parent / "app" / "reasoner.py"


def _proposed_actions() -> set[str]:
    """Every action string the reasoner passes to propose(): literal second
    arguments, plus the branches of `action = "a" if ... else "b"` when the call
    passes a name."""
    tree = ast.parse(REASONER.read_text())
    out, named = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "propose" and len(node.args) >= 2:
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.add(arg.value)
            elif isinstance(arg, ast.Name):
                named.add(arg.id)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "action" for t in node.targets):
            v = node.value
            branches = [v.body, v.orelse] if isinstance(v, ast.IfExp) else [v]
            for c in branches:
                assert isinstance(c, ast.Constant) and isinstance(c.value, str), ast.dump(v)
                out.add(c.value)
    assert named <= {"action"}, named
    return out


def test_registry_covers_every_action_the_reasoner_proposes():
    proposed = _proposed_actions()
    assert proposed, "the scan found no propose() calls"
    missing = proposed - set(skills.REGISTRY)
    assert not missing, missing
    # every skill has an executor, a domain and a risk the policy knows
    for s in skills.REGISTRY.values():
        assert s.executor in executor.EXECUTORS, s.key
        assert s.domain in skills.DOMAINS and s.risk in skills.RISKS and s.default in policy.AUTONOMY
        assert s.description.endswith(".") and s.title
    # the policy view is derived from the registry, not kept separately
    assert set(policy.ACTIONS) == set(skills.REGISTRY)
    assert policy.ACTIONS["host_action"]["risk"] == "high" and not skills.get("host_action").can_auto
    assert not skills.get("host_action").reversible and not skills.get("escalate_finding").reversible
    assert {i.name for i in skills.get("escalate_finding").inputs} == {"finding_id"}
    assert all(s.chat for s in skills.chat_skills()) and "readiness_remediation" not in {s.key for s in skills.chat_skills()}


def test_unknown_action_cannot_be_proposed(world):  # noqa: F811
    import pytest
    from app import reasoner
    db = SessionLocal()
    with pytest.raises(KeyError):
        reasoner.propose(db, "reboot_the_world", "k", "t", "why", {}, {}, 0.5)


def test_catalog_page_groups_by_domain_and_shows_last_run(client, world):  # noqa: F811
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    r = client.get("/policy")
    assert r.status_code == 200
    for label in ("SOC", "Administration", "Professional services"):
        assert label in r.text
    assert "Re-sync a module whose roster pull is failing" in r.text and "never" in r.text
    assert "needs finding_id" in r.text and "chat" in r.text
    brain.cycle(SessionLocal())
    r = client.get("/policy")
    rows = {x["key"]: x for x in policy.table(SessionLocal())}
    assert rows["roster_sync"]["last_run"] is not None and rows["roster_sync"]["last_run_ok"] is True
    assert rows["roster_sync"]["last_run_by"] == "auto"
    assert rows["escalate_finding"]["last_run"] is None  # proposed, never carried out
    assert rows["roster_sync"]["last_run"].strftime("%b %d %H:%M") in r.text
    # the high-risk skill offers no auto option on the page
    assert '<option value="auto" selected' not in r.text.split("host_action")[1].split("</form>")[0]


def test_api_skills_returns_the_catalog(client, world):  # noqa: F811
    bearer = {"Authorization": f"Bearer {auth.api_token()}"}
    r = client.get("/api/skills", headers=bearer)
    assert r.status_code == 200
    body = r.json()
    assert [d["domain"] for d in body["domains"]] == ["soc", "admin", "services"]
    flat = {s["key"]: s for d in body["domains"] for s in d["skills"]}
    assert set(flat) == set(skills.REGISTRY)
    h = flat["host_action"]
    assert h["risk"] == "high" and h["can_auto"] is False and h["reversible"] is False and h["autonomy"] == "propose"
    assert h["module"] == "managed-services" and h["inputs"][0] == {"name": "finding_id", "type": "finding_id", "required": True}
    assert flat["roster_sync"]["last_run"] is None and flat["roster_sync"]["chat"] is True
    assert client.get("/api/skills").status_code == 401
