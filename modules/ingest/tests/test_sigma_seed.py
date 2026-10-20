"""The starter rule set: every rule compiles, ids are sound, each rule fires on the
behavior it names and stays quiet on a benign lookalike, and seed() is idempotent."""
import re

import pytest

from app import sigma, sigma_seed

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _ev(class_uid, activity_id, log, product, vendor, **attrs):
    ev = {"class_uid": class_uid, "activity_id": activity_id, "time": 1760000000000, "severity_id": 1,
          "metadata": {"product": {"name": product, "vendor_name": vendor}, "log_name": log, "tenant_uid": "t1"}}
    ev.update(attrs)
    return ev


def entra_audit(class_uid, activity_id, operation, **attrs):
    attrs.setdefault("api", {"operation": operation, "service": {"name": "Core Directory"}})
    attrs.setdefault("actor", {"user": {"name": "admin@acme.example"}})
    return _ev(class_uid, activity_id, "entra_audit", "Entra ID", "Microsoft", message=operation, **attrs)


def entra_signin(risk="none", ok=True, user="bob@acme.example", ip="203.0.113.9"):
    return _ev(3002, 1, "entra_signins", "Entra ID", "Microsoft", status_id=1 if ok else 2,
               user={"name": user}, src_endpoint={"ip": ip}, unmapped={"risk_level": risk})


def okta(operation, class_uid=6003, activity_id=99, **attrs):
    attrs.setdefault("api", {"operation": operation})
    attrs.setdefault("user", {"name": "dana@acme.example"})
    return _ev(class_uid, activity_id, "okta_system_log", "Okta", "Okta", **attrs)


def m365(operation, parameters=None):
    unmapped = {"parameters": parameters} if parameters is not None else {}
    return _ev(6003, 99, "m365_audit", "Exchange Online", "Microsoft", api={"operation": operation,
               "service": {"name": "Exchange"}}, actor={"user": {"name": "eve@acme.example"}}, unmapped=unmapped)


def cloudtrail(operation, source="cloudtrail.amazonaws.com", user_type="IAMUser", params=None, class_uid=6003):
    unmapped = {"request_parameters": params} if params is not None else {}
    return _ev(class_uid, 99, "cloudtrail", "CloudTrail", "AWS",
               api={"operation": operation, "service": {"name": source}},
               actor={"user": {"name": "deploy", "type": user_type}}, unmapped=unmapped)


def process(cmd, name="cmd.exe", path=None, log="crowdstrike_fdr"):
    return _ev(1007, 1, log, "Falcon", "CrowdStrike", device={"hostname": "WS01"},
               actor={"user": {"name": "alice"}},
               process={"name": name, "cmd_line": cmd,
                        "file": {"name": name, "path": path or f"C:\\Windows\\System32\\{name}"}})


B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
INBOX_PARAMS = [{"Name": "Name", "Value": "rss"}, {"Name": "ForwardTo", "Value": "x@evil.example"}]

CASES = {
    "entra_privileged_role_assignment.yml": (
        [entra_audit(3005, 1, "Add member to role", privileges=["Global Administrator"], user={"name": "m"}),
         entra_audit(3005, 1, "Add member to role", privileges=["62e90394-69f5-4237-9190-012177145e10"]),
         entra_audit(3005, 1, "Add eligible member to role", privileges=["Exchange Administrator"])],
        [entra_audit(3005, 1, "Add member to role", privileges=["Helpdesk Administrator"]),
         entra_audit(3005, 2, "Remove member from role", privileges=["Global Administrator"]),
         {**entra_audit(3005, 1, "Add member to role", privileges=["Global Administrator"]),
          "metadata": {"log_name": "okta_system_log"}}],
    ),
    "entra_application_consent.yml": (
        [entra_audit(3003, 1, "Consent to application")],
        [entra_audit(3003, 1, "Add app role assignment to service principal"),
         entra_audit(6003, 1, "Consent to application")],
    ),
    "entra_conditional_access_policy_changed.yml": (
        [entra_audit(6003, 3, "Update conditional access policy"),
         entra_audit(6003, 4, "Delete conditional access policy")],
        [entra_audit(6003, 1, "Add conditional access policy"),
         entra_audit(6003, 2, "Read conditional access policy")],
    ),
    "entra_federation_settings_changed.yml": (
        [entra_audit(6003, 3, "Set federation settings on domain"),
         entra_audit(6003, 3, "Set domain authentication")],
        [entra_audit(6003, 3, "Update application"), entra_audit(6003, 1, "Add domain to company")],
    ),
    "entra_mfa_method_deleted.yml": (
        [entra_audit(3001, 11, "User deleted security info"),
         entra_audit(6003, 99, "Admin deleted security info")],
        [entra_audit(3001, 10, "User registered security info"),
         entra_audit(3001, 4, "Reset user password")],
    ),
    "entra_high_risk_signin.yml": (
        [entra_signin(risk="high"), entra_signin(risk="HIGH", ok=False)],
        [entra_signin(risk="medium"), entra_signin(risk="none"),
         {**entra_signin(risk="high"), "class_uid": 6003}],
    ),
    "password_spray_source_ip.yml": (
        [entra_signin(ok=False), {**entra_signin(ok=False), "metadata": {"log_name": "okta_system_log"}}],
        [entra_signin(ok=True), {**entra_signin(ok=False), "class_uid": 6003}],
    ),
    "okta_mfa_fatigue.yml": (
        [okta("user.mfa.okta_verify.deny_push"),
         okta("user.authentication.auth_via_mfa", class_uid=3002, activity_id=1, status_id=2, is_mfa=True)],
        [okta("user.authentication.auth_via_mfa", class_uid=3002, activity_id=1, status_id=1, is_mfa=True),
         okta("user.session.start", class_uid=3002, activity_id=1, status_id=2, is_mfa=False),
         {**okta("user.mfa.okta_verify.deny_push"), "metadata": {"log_name": "entra_signins"}}],
    ),
    "m365_inbox_rule_forward_or_delete.yml": (
        [m365("New-InboxRule", INBOX_PARAMS),
         m365("Set-InboxRule", "-Identity x -DeleteMessage True"),
         m365("UpdateInboxRules", [{"Name": "RedirectTo", "Value": "x@evil.example"}])],
        [m365("New-InboxRule", [{"Name": "MoveToFolder", "Value": "Archive"}]),
         m365("Get-InboxRule", INBOX_PARAMS)],
    ),
    "m365_mailbox_external_forwarding.yml": (
        [m365("Set-Mailbox", [{"Name": "ForwardingSmtpAddress", "Value": "smtp:x@evil.example"}])],
        [m365("Set-Mailbox", [{"Name": "ProhibitSendQuota", "Value": "50GB"}]),
         m365("Get-Mailbox", [{"Name": "ForwardingSmtpAddress", "Value": ""}])],
    ),
    "m365_mailbox_permission_granted.yml": (
        [m365("Add-MailboxPermission", [{"Name": "AccessRights", "Value": "FullAccess"}])],
        [m365("Remove-MailboxPermission"), m365("Get-MailboxPermission")],
    ),
    "aws_logging_or_detection_disabled.yml": (
        [cloudtrail("StopLogging"), cloudtrail("DeleteTrail"), cloudtrail("UpdateTrail"),
         cloudtrail("PutEventSelectors"),
         cloudtrail("DeleteDetector", source="guardduty.amazonaws.com"),
         cloudtrail("UpdateDetector", source="guardduty.amazonaws.com", params={"detectorId": "d", "enable": False}),
         cloudtrail("UpdateDetector", source="guardduty.amazonaws.com",
                    params='{"detectorId": "d", "enable": false}')],
        [cloudtrail("StartLogging"), cloudtrail("LookupEvents"),
         cloudtrail("UpdateDetector", source="guardduty.amazonaws.com", params={"detectorId": "d", "enable": True}),
         cloudtrail("DeleteDetector", source="guardduty.amazonaws.com", class_uid=2004)],
    ),
    "aws_root_account_activity.yml": (
        [cloudtrail("ConsoleLogin", source="signin.amazonaws.com", user_type="Root", class_uid=3002),
         cloudtrail("CreateAccessKey", source="iam.amazonaws.com", user_type="Root"),
         {**cloudtrail("ConsoleLogin", source="signin.amazonaws.com", class_uid=3002), "actor": {},
          "user": {"type": "Root"}}],
        [cloudtrail("ConsoleLogin", source="signin.amazonaws.com", user_type="IAMUser", class_uid=3002),
         cloudtrail("CreateAccessKey", source="iam.amazonaws.com", user_type="AssumedRole"),
         cloudtrail("DescribeInstances", source="ec2.amazonaws.com", user_type="Root")],
    ),
    "aws_security_group_open_to_world.yml": (
        [cloudtrail("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
                    params={"groupId": "sg-1", "ipPermissions": {"items": [{"fromPort": 22, "ipRanges": {
                        "items": [{"cidrIp": "0.0.0.0/0"}]}}]}}),
         cloudtrail("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
                    params='{"ipv6Ranges": [{"cidrIpv6": "::/0"}]}')],
        [cloudtrail("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
                    params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}}),
         cloudtrail("RevokeSecurityGroupIngress", source="ec2.amazonaws.com", params={"cidrIp": "0.0.0.0/0"})],
    ),
    "aws_iam_admin_policy_attached_to_user.yml": (
        [cloudtrail("AttachUserPolicy", source="iam.amazonaws.com",
                    params={"userName": "backdoor", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})],
        [cloudtrail("AttachUserPolicy", source="iam.amazonaws.com",
                    params={"userName": "dev", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
         cloudtrail("AttachRolePolicy", source="iam.amazonaws.com",
                    params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})],
    ),
    "endpoint_encoded_powershell.yml": (
        [process(f"powershell.exe -NoP -enc {B64}", name="powershell.exe"),
         process(f"powershell.exe -EncodedCommand {B64}", name="powershell.exe"),
         process(f"pwsh -e {B64}", name="pwsh.exe"),
         process(f'powershell /ec "{B64}"', name="powershell.exe"),
         process(f"x -enc {B64}", name="PowerShell.EXE", path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                 "\\PowerShell.EXE")],
        [process("powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1", name="powershell.exe"),
         process("powershell.exe -e short", name="powershell.exe"),
         process(f"cmd.exe /c echo -enc {B64}", name="cmd.exe")],
    ),
    "endpoint_recovery_inhibition.yml": (
        [process("vssadmin.exe Delete Shadows /All /Quiet"),
         process("wmic shadowcopy delete /nointeractive"),
         process("powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}"),
         process("wbadmin delete catalog -quiet"),
         process("bcdedit /set {default} recoveryenabled No"),
         process("bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures")],
        [process("vssadmin list shadows"), process("wmic shadowcopy list brief"),
         process("bcdedit /enum"), process("bcdedit /set {default} recoveryenabled yes"),
         process("wbadmin start backup -backupTarget:E:")],
    ),
    "endpoint_lsass_dump.yml": (
        [process("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full"),
         process("procdump64.exe -accepteula -ma lsass.exe C:\\temp\\l.dmp"),
         process("procdump.exe /ma lsass.exe out.dmp")],
        [process("procdump.exe -ma chrome.exe out.dmp"),
         process("rundll32.exe comsvcs.dll,DllRegisterServer"),
         process("tasklist /fi \"imagename eq lsass.exe\"")],
    ),
    "okta_admin_privilege_granted.yml": (
        [okta("user.account.privilege.grant", class_uid=3005, activity_id=1)],
        [okta("user.account.privilege.revoke", class_uid=3005, activity_id=2),
         {**okta("user.account.privilege.grant"), "metadata": {"log_name": "entra_audit"}}],
    ),
    "okta_mfa_factor_reset.yml": (
        [okta("user.mfa.factor.deactivate", class_uid=3001, activity_id=11), okta("user.mfa.factor.reset_all")],
        [okta("user.mfa.factor.activate", class_uid=3001, activity_id=10), okta("user.mfa.attempt_bypass")],
    ),
}


def _rule(filename):
    return sigma.compile(dict(sigma_seed.STARTER)[filename])


def test_twenty_starter_rules_compile():
    assert len(sigma_seed.STARTER) == 20
    rules = [r for _, _, r in sigma_seed.compiled()]
    assert len(rules) == 20


def test_ids_unique_and_valid_uuids():
    rules = [r for _, _, r in sigma_seed.compiled()]
    ids = [r.id for r in rules]
    assert len(set(ids)) == len(ids)
    for r in rules:
        assert UUID.match(r.id), r.id


def test_rule_metadata_complete():
    import yaml
    for name, text in sigma_seed.STARTER:
        doc = yaml.safe_load(text)
        r = sigma.compile(text)
        assert doc["author"] == "Vendetta Cyber", name
        assert str(doc["date"]) == "2026-10-19", name
        assert doc["status"] in ("stable", "test"), name
        assert doc["falsepositives"], name
        assert r.description and r.mitre, name
        assert r.level in sigma.LEVELS
        for ch in ("\u2013", "\u2014"):
            assert ch not in text, name


def test_every_rule_has_cases():
    assert set(CASES) == {name for name, _ in sigma_seed.STARTER}


@pytest.mark.parametrize("filename", sorted(CASES))
def test_rule_fires_on_behavior(filename):
    rule = _rule(filename)
    positives, _ = CASES[filename]
    assert positives
    for i, ev in enumerate(positives):
        assert rule.matches(ev), f"{filename} positive #{i}"


@pytest.mark.parametrize("filename", sorted(CASES))
def test_rule_quiet_on_lookalike(filename):
    rule = _rule(filename)
    _, negatives = CASES[filename]
    assert negatives
    for i, ev in enumerate(negatives):
        assert not rule.matches(ev), f"{filename} negative #{i}"


def test_password_spray_threshold_keys():
    r = _rule("password_spray_source_ip.yml")
    assert r.threshold == {"count": 10, "group_by": ["src_endpoint.ip"], "distinct": "user.name"}
    assert r.timeframe_seconds == 600
    events = [entra_signin(ok=False, user=f"user{i}@acme.example", ip="198.51.100.7") for i in range(10)]
    assert all(r.matches(e) for e in events)
    assert {r.group_key(e) for e in events} == {"198.51.100.7"}
    assert len({r.distinct_value(e) for e in events}) == 10


def test_mfa_fatigue_threshold_keys():
    r = _rule("okta_mfa_fatigue.yml")
    assert r.threshold == {"count": 5, "group_by": ["user.name"], "distinct": ""}
    assert r.timeframe_seconds == 600
    assert r.group_key(okta("user.mfa.okta_verify.deny_push")) == "dana@acme.example"


def test_compile_failure_raises(monkeypatch):
    monkeypatch.setattr(sigma_seed, "STARTER", [("broken.yml", "title: x\nlogsource: {}\ndetection: {}\n")])
    with pytest.raises(sigma.SigmaError, match="broken.yml"):
        sigma_seed.compiled()


# ---------------------------------------------------------------- database
def test_seed_is_idempotent_and_never_overwrites(fresh_db):
    from app.db import SessionLocal, SigmaRule, SigmaRuleVersion

    db = SessionLocal()
    try:
        # init_db() already seeded the starter set.
        assert db.query(SigmaRule).count() == 20
        assert db.query(SigmaRuleVersion).count() == 20
        row = db.query(SigmaRule).first()
        assert row.origin == "seed" and row.updated_by == "seed" and row.version == 1
        v = db.query(SigmaRuleVersion).filter_by(rule_id=row.id).one()
        assert v.note == "starter rule set" and v.version == 1 and v.changed_by == "seed"
        assert sigma_seed.seed(db) == 0

        # An admin edit survives a reseed.
        edited = db.get(SigmaRule, "4ef632f5-62f6-4e01-afa2-4d0d251ab8ee")
        edited.body = edited.body.replace("count: 10", "count: 25")
        edited.enabled = False
        edited.version = 2
        edited.origin = "custom"
        db.commit()
        assert sigma_seed.seed(db) == 0
        db.expire_all()
        again = db.get(SigmaRule, "4ef632f5-62f6-4e01-afa2-4d0d251ab8ee")
        assert "count: 25" in again.body and again.enabled is False and again.version == 2

        # A deleted starter rule comes back.
        gone = db.get(SigmaRule, "0c1841fe-c3a5-44bc-8df1-ad6f16f42e0e")
        db.delete(gone)
        db.commit()
        assert sigma_seed.seed(db) == 1
        assert sigma_seed.seed(db) == 0
        back = db.get(SigmaRule, "0c1841fe-c3a5-44bc-8df1-ad6f16f42e0e")
        assert back.title == "Encoded PowerShell command line" and back.level == "high"
        assert "attack.t1059.001" in back.tags
        assert db.query(SigmaRule).count() == 20
    finally:
        db.close()


def test_seed_from_empty_table(fresh_db):
    from app.db import SessionLocal, SigmaRule, SigmaRuleVersion

    db = SessionLocal()
    try:
        db.query(SigmaRuleVersion).delete()
        db.query(SigmaRule).delete()
        db.commit()
        assert sigma_seed.seed(db) == 20
        assert sigma_seed.seed(db) == 0
        assert db.query(SigmaRuleVersion).count() == 20
    finally:
        db.close()
