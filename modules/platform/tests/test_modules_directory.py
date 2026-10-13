"""The control-plane module directory the hub pulls its finding sources from."""
from app import auth


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_directory_lists_connected_finding_modules_with_tokens(admin):
    # Connect two finding-serving modules; leave another without a base_url.
    admin.post("/connections/module/vulnerability-management",
               data={"base_url": "http://localhost:8400", "api_token": "vtok", "status": "in-progress"})
    admin.post("/connections/module/managed-services",
               data={"base_url": "http://localhost:8200", "api_token": "mtok", "status": "in-progress"})
    out = admin.get("/api/platform/modules", headers=_bearer()).json()["modules"]
    by = {m["name"]: m for m in out}
    assert "vulnerability-management" in by and by["vulnerability-management"]["base_url"] == "http://localhost:8400"
    assert by["vulnerability-management"]["token"] == "vtok"  # decrypted for the hub
    assert by["managed-services"]["findings_path"] == "/api/findings"
    # a finding module with no base_url is not offered as a source
    assert "penetration-testing" not in by
    # non-finding modules (the hub, the platform) are never listed
    assert "incident-response" not in by and "platform" not in by


def test_directory_requires_bearer(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anon:
        assert anon.get("/api/platform/modules").status_code == 401
