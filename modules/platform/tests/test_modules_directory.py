"""The control-plane module directory, scoped to its caller: the hub names itself
and receives the finding modules it reads from, with their tokens, and nothing
else; no other caller receives any token."""
from app import auth


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_directory_lists_connected_finding_modules_with_tokens(admin):
    # Connect two finding-serving modules; leave another without a base_url.
    admin.post("/connections/module/vulnerability-management",
               data={"base_url": "http://localhost:8400", "api_token": "vtok", "status": "in-progress"})
    admin.post("/connections/module/managed-services",
               data={"base_url": "http://localhost:8200", "api_token": "mtok", "status": "in-progress"})
    out = admin.get("/api/platform/modules", params={"module": "incident-response"}, headers=_bearer()).json()["modules"]
    by = {m["name"]: m for m in out}
    assert "vulnerability-management" in by and by["vulnerability-management"]["base_url"] == "http://localhost:8400"
    assert by["vulnerability-management"]["token"] == "vtok"  # decrypted for the hub
    assert by["managed-services"]["findings_path"] == "/api/findings"
    # a finding module with no base_url is not offered as a source
    assert "penetration-testing" not in by
    # non-finding modules (the hub, the platform, the Office of Special Projects,
    # SABINE) are never listed
    assert not {"incident-response", "platform", "professional-services", "sabine"} & set(by)


def test_directory_is_served_to_the_hub_only(admin):
    admin.post("/connections/module/managed-services",
               data={"base_url": "http://localhost:8200", "api_token": "mtok", "status": "in-progress"})
    admin.post("/connections/module/professional-services",
               data={"base_url": "http://localhost:8700", "api_token": "otok", "status": "in-progress"})
    # a caller must name itself
    assert admin.get("/api/platform/modules", headers=_bearer()).status_code == 400
    # a client module or SABINE holding the platform token gets no directory at all
    for other in ("managed-services", "sabine", "professional-services", "platform"):
        r = admin.get("/api/platform/modules", params={"module": other}, headers=_bearer())
        assert r.status_code == 403 and "mtok" not in r.text and "otok" not in r.text
    # the hub gets the finding modules and not the Office of Special Projects
    out = admin.get("/api/platform/modules", params={"module": "incident-response"}, headers=_bearer()).json()["modules"]
    assert {m["name"] for m in out} == {"managed-services"}


def test_directory_requires_bearer(admin):
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anon:
        assert anon.get("/api/platform/modules").status_code == 401
