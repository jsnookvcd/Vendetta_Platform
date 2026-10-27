"""POST /api/engagements: a Project Management kickoff opens an OSP engagement,
creating the client when the roster has not reached OSP yet, and a retry returns
the same open engagement."""
from app import auth


def _bearer():
    return {"Authorization": f"Bearer {auth.api_token()}"}


def test_kickoff_opens_engagement_once(client):
    body = {"client": "Rize CU", "name": "Rize tabletop exercise", "kind": "tabletop", "scope": "AI attack TTX",
            "lead": "jordan@vendettacd.io", "starts_on": "2026-11-02", "ends_on": "2026-11-20"}
    r = client.post("/api/engagements", json=body, headers=_bearer())
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["kind"] == "tabletop" and e["status"] == "scoping" and e["subject"]["client"] == "Rize CU"
    again = client.post("/api/engagements", json=body, headers=_bearer())
    assert again.status_code == 200 and again.json()["id"] == e["id"]
    listed = client.get("/api/engagements", headers=_bearer()).json()
    assert [x["id"] for x in listed] == [e["id"]]


def test_open_needs_token_name_and_client(client):
    assert client.post("/api/engagements", json={"client": "X", "name": "n"}).status_code in (401, 403)
    assert client.post("/api/engagements", json={"client": "X"}, headers=_bearer()).status_code == 400
    assert client.post("/api/engagements", json={"name": "n"}, headers=_bearer()).status_code == 400
