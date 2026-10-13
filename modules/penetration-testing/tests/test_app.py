"""Engagements, findings, the retest loop, report, trend, portal and finding model."""
from app import auth
from app.db import Client, Engagement, Finding, RemediationStep, SessionLocal, User


def _client(name="Acme Corp", pid="plat-acme", portal=True):
    db = SessionLocal()
    c = Client(name=name, platform_client_id=pid, portal_enabled=portal, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _engagement(admin, cid, name="External Test", kind="external"):
    r = admin.post(f"/clients/{cid}/engagements", data={"name": name, "kind": kind}, follow_redirects=False)
    return r.headers["location"].split("/engagements/")[1]


def _finding(admin, eid, title="SQLi in login", severity="critical", cvss="9.1"):
    r = admin.post(f"/engagements/{eid}/findings",
                   data={"title": title, "asset": "/login", "cvss": cvss, "severity": severity,
                         "description": "d", "impact": "i", "remediation": "r"}, follow_redirects=False)
    return r.headers["location"].split("/findings/")[1]


def test_engagement_and_findings_and_recount(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "SQLi", "critical", "9.1")
    _finding(admin, eid, "XSS", "high", "7.4")
    db = SessionLocal()
    e = db.get(Engagement, eid)
    assert e.n_critical == 1 and e.n_high == 1 and e.n_total == 2
    assert db.query(Finding).filter_by(engagement_id=eid).count() == 2


def test_retest_loop_and_resolution(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    fid = _finding(admin, eid, "Thing", "high", "7.0")
    admin.post(f"/findings/{fid}/edit", data={"status": "retest_passed", "severity": "high", "cvss": "7.0"})
    f = SessionLocal().get(Finding, fid)
    assert f.status == "retest_passed" and f.retested_at is not None and f.resolved_at is not None and not f.is_open


def test_close_freezes_counts_for_trend(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "A", "critical", "9.5")
    admin.post(f"/engagements/{eid}/edit", data={"status": "closed", "published": "true"})
    db = SessionLocal()
    e = db.get(Engagement, eid)
    assert e.status == "closed" and e.closed_at is not None and e.n_critical == 1
    # portal trend picks up closed engagements
    from app.db import severity_trend
    tr = severity_trend(db, c.id)
    assert tr and tr[-1]["critical"] == 1


def test_report_renders(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "Reported finding", "medium", "5.0")
    page = admin.get(f"/engagements/{eid}/report").text
    assert "Penetration test report" in page and "Reported finding" in page


def test_api_findings_shape(admin):
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "V", "high", "8.0")
    out = admin.get("/api/findings", headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out and out[0]["module"] == "penetration-testing" and out[0]["type"] == "pentest-finding"
    assert out[0]["subject"]["platform_client_id"] == "plat-acme"


def test_portal_shows_shared_engagements_and_steps(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    fid = _finding(admin, eid, "Shared finding", "high", "7.5")
    admin.post(f"/findings/{fid}/steps", data={"text": "Fix the thing"})
    # unpublished engagement: hidden
    eid2 = _engagement(admin, c.id, name="Hidden Test")
    _finding(admin, eid2, "Hidden finding", "high", "7.5")
    admin.post(f"/engagements/{eid}/edit", data={"status": "reporting", "published": "true"})
    db = SessionLocal()
    db.add(User(email="it@acme.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    page = client.get("/portal").text
    assert "Shared finding" in page and "Hidden finding" not in page and "Technical view" in page
    # mark a step done from the portal
    sid = db.query(RemediationStep).join(Finding).filter(Finding.id == fid).one().id
    client.post(f"/portal/findings/{fid}/steps/{sid}", follow_redirects=False)
    assert SessionLocal().get(RemediationStep, sid).done is True


def test_portal_report_requires_published(admin, client):
    c = _client()
    eid = _engagement(admin, c.id)
    _finding(admin, eid, "F", "low", "2.0")  # engagement not published
    db = SessionLocal()
    db.add(User(email="it@acme.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    assert client.get(f"/portal/engagements/{eid}/report", follow_redirects=False).status_code == 404
