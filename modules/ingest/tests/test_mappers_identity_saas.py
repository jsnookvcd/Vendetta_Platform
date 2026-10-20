"""Field-level tests for the identity and SaaS mappers: Okta, Microsoft 365 audit and
Google Workspace."""
import json
import pathlib

import pytest

from app import mappers, ocsf

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(src, name):
    return json.loads((FIXTURES / src / f"{name}.json").read_text())


def norm(src, name):
    return mappers.normalize(src, load(src, name))


# ---------------------------------------------------------------- Okta
def test_okta_session_start_success():
    ev = norm("okta_system_log", "session_start_success")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (3002, 1, 1, 1)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T13:01:22.418Z")
    assert ev["user"]["email_addr"] == "mlee@acme.example"
    assert ev["actor"]["user"]["uid"] == "00u8k2l3m4N5o6P7q8r9"
    loc = ev["src_endpoint"]["location"]
    assert ev["src_endpoint"]["ip"] == "198.51.100.61"
    assert loc["city"] == "Harrisburg" and loc["coordinates"] == [-76.8867, 40.2732]
    assert ev["auth_protocol"] == "FACTOR_PROVIDER"
    assert ev["unmapped"]["credential_type"] == "PASSWORD"
    assert ev["metadata"]["uid"] == "1f9a2b3c-8d4e-11f1-9c2b-31a5e7f0a001"


def test_okta_session_start_failure():
    ev = norm("okta_system_log", "session_start_failure")
    assert (ev["status_id"], ev["severity_id"]) == (2, 2)
    assert ev["status_detail"] == "INVALID_CREDENTIALS"


def test_okta_deny_push_is_mfa_auth_with_result():
    ev = norm("okta_system_log", "deny_push")
    assert (ev["class_uid"], ev["status_id"], ev["severity_id"]) == (3002, 2, 3)
    assert ev["is_mfa"] is True
    assert ev["unmapped"]["mfa_result"] == "FAILURE"
    assert ev["unmapped"]["mfa_factor"] == "OKTA_VERIFY_PUSH"


def test_okta_push_sent_and_auth_via_mfa():
    ev = norm("okta_system_log", "push_sent")
    assert ev["class_uid"] == 3002 and ev["unmapped"]["mfa_result"] == "SUCCESS"
    raw = load("okta_system_log", "push_sent")
    raw["eventType"] = "user.authentication.auth_via_mfa"
    assert mappers.normalize("okta_system_log", raw)["activity_id"] == 1


def test_okta_privilege_grant_is_user_access():
    ev = norm("okta_system_log", "privilege_grant")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (3005, 1, 3)
    assert ev["privileges"] == ["Super administrator"]
    assert ev["user"]["email_addr"] == "mlee@acme.example"
    assert ev["actor"]["user"]["email_addr"] == "it-admin@acme.example"
    raw = load("okta_system_log", "privilege_grant")
    raw["eventType"] = "user.account.privilege.revoke"
    raw["debugContext"]["debugData"] = {"privilegeRevoked": "Super administrator"}
    ev = mappers.normalize("okta_system_log", raw)
    assert (ev["class_uid"], ev["activity_id"]) == (3005, 2)


def test_okta_group_membership_add():
    ev = norm("okta_system_log", "group_membership_add")
    assert (ev["class_uid"], ev["activity_id"]) == (3006, 3)
    assert ev["group"] == {"name": "Finance Approvers", "uid": "00g5grp6789XYZabc0"}
    assert ev["user"]["name"] == "mlee@acme.example"
    raw = load("okta_system_log", "group_membership_add")
    raw["eventType"] = "group.user_membership.remove"
    assert mappers.normalize("okta_system_log", raw)["activity_id"] == 4


def test_okta_account_lock_is_account_change():
    ev = norm("okta_system_log", "account_lock")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"]) == (3001, 9, 2)
    raw = load("okta_system_log", "account_lock")
    raw["eventType"] = "user.account.update_profile"
    assert mappers.normalize("okta_system_log", raw)["activity_id"] == 99


def test_okta_application_update_and_other_are_api_activity():
    ev = norm("okta_system_log", "application_update")
    assert (ev["class_uid"], ev["activity_id"]) == (6003, 3)
    assert ev["api"]["operation"] == "application.lifecycle.update"
    assert ev["resources"][0]["name"] == "Salesforce.com"
    ev = norm("okta_system_log", "sso_other")
    assert (ev["class_uid"], ev["activity_id"]) == (6003, 99)


def test_okta_target_not_list_rejected():
    raw = load("okta_system_log", "group_membership_add")
    raw["target"] = {"id": "x"}
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("okta_system_log", raw)


# ---------------------------------------------------------------- Microsoft 365
def test_m365_new_inbox_rule_keeps_parameters():
    ev = norm("m365_audit", "new_inbox_rule_forward")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"], ev["status_id"]) == (6003, 1, 3, 1)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T16:20:31Z")
    p = ev["unmapped"]["parameters"]
    assert p["ForwardTo"] == "ap.archive@freemail.example"
    assert p["From"] == "billing@vendor.example"
    assert ev["unmapped"]["rule_risk"] == ["ForwardTo", "MarkAsRead"]
    assert ev["src_endpoint"]["ip"] == "203.0.113.200"  # port stripped
    assert ev["actor"]["user"]["email_addr"] == "ap@acme.example"
    assert ev["metadata"]["uid"] == "8d6f1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"


def test_m365_update_inbox_rules_from_owa():
    ev = norm("m365_audit", "update_inbox_rules_owa")
    assert (ev["activity_id"], ev["severity_id"]) == (3, 3)
    assert ev["src_endpoint"]["ip"] == "2001:db8:41::17"  # brackets and port stripped
    assert "MoveToFolder" in ev["unmapped"]["parameters"]["RuleActions"]


def test_m365_set_inbox_rule_and_benign_rule():
    raw = load("m365_audit", "new_inbox_rule_forward")
    raw["Operation"] = "Set-InboxRule"
    raw["Parameters"] = [{"Name": "Identity", "Value": "Invoices"}, {"Name": "MarkImportance", "Value": "High"}]
    ev = mappers.normalize("m365_audit", raw)
    assert (ev["activity_id"], ev["severity_id"]) == (3, 1)


def test_m365_set_mailbox_forwarding():
    ev = norm("m365_audit", "set_mailbox_forwarding")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (6003, 3, 3)
    assert ev["unmapped"]["forwarding"] == "smtp:ap.archive@freemail.example"
    assert ev["unmapped"]["parameters"]["ForwardingSmtpAddress"] == "smtp:ap.archive@freemail.example"


def test_m365_add_mailbox_permission_is_user_access():
    ev = norm("m365_audit", "add_mailbox_permission")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (3005, 1, 3)
    assert ev["privileges"] == ["FullAccess"]
    assert ev["user"]["name"] == "mlee@acme.example"
    assert ev["resources"] == [{"name": "ceo@acme.example", "type": "Mailbox"}]


def test_m365_web_resources():
    ev = norm("m365_audit", "file_downloaded")
    assert (ev["class_uid"], ev["activity_id"]) == (6001, 2)
    assert ev["web_resources"][0]["name"] == "Payroll 2026.xlsx"
    assert ev["web_resources"][0]["url_string"].startswith("https://acme.sharepoint.com/")
    assert "status_id" not in ev
    ev = norm("m365_audit", "anonymous_link_created")
    assert (ev["activity_id"], ev["severity_id"]) == (8, 2)
    ev = norm("m365_audit", "mail_items_accessed")
    assert (ev["class_uid"], ev["activity_id"]) == (6001, 2)
    assert ev["unmapped"]["mailbox_owner"] == "ceo@acme.example"
    assert ev["unmapped"]["items_accessed"] == 2
    assert ev["src_endpoint"]["ip"] == "198.51.100.61"
    raw = load("m365_audit", "file_downloaded")
    for op, aid in (("FileDeleted", 4), ("FileUploaded", 1), ("SharingSet", 8), ("FileAccessed", 2)):
        raw["Operation"] = op
        assert mappers.normalize("m365_audit", raw)["activity_id"] == aid


def test_m365_login_failed_and_succeeded():
    ev = norm("m365_audit", "user_login_failed")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (3002, 1, 2, 2)
    assert ev["http_request"]["user_agent"] == "python-requests/2.32.3"
    assert ev["unmapped"]["logon_error"] == "InvalidUserNameOrPassword"
    raw = load("m365_audit", "user_login_failed")
    raw["Operation"] = "UserLoggedIn"
    raw["ResultStatus"] = "Succeeded"
    assert mappers.normalize("m365_audit", raw)["status_id"] == 1


def test_m365_other_operation_is_api_activity_by_verb():
    ev = norm("m365_audit", "general_other")
    assert (ev["class_uid"], ev["activity_id"]) == (6003, 4)
    raw = load("m365_audit", "general_other")
    raw["Operation"] = "SearchQueryPerformed"
    assert mappers.normalize("m365_audit", raw)["activity_id"] == 99


def test_m365_parameters_not_list_rejected():
    raw = load("m365_audit", "new_inbox_rule_forward")
    raw["Parameters"] = "ForwardTo=evil@example.com"
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("m365_audit", raw)


# ---------------------------------------------------------------- Google Workspace
def test_google_login_success():
    raw = load("google_workspace", "login_success")
    ev = mappers.normalize("google_workspace", raw)
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (3002, 1, 1, 1)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T13:10:05.123Z")
    assert ev["is_mfa"] is True
    assert ev["user"]["email_addr"] == "mlee@acme.example"
    assert ev["metadata"]["uid"] == "-6512340987654321:2026-10-18T13:10:05.123Z"
    assert mappers.get("google_workspace").uid(raw) == "-6512340987654321:2026-10-18T13:10:05.123Z"


def test_google_login_failure_and_suspicious():
    ev = norm("google_workspace", "login_failure")
    assert (ev["status_id"], ev["severity_id"]) == (2, 2)
    assert ev["unmapped"]["failure_type"] == "login_failure_invalid_password"
    raw = load("google_workspace", "login_success")
    raw["events"][0]["name"] = "suspicious_login"
    ev = mappers.normalize("google_workspace", raw)
    assert (ev["class_uid"], ev["severity_id"]) == (3002, 4)


def test_google_assign_role_is_user_access():
    ev = norm("google_workspace", "assign_role")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (3005, 1, 3)
    assert ev["privileges"] == ["_SEED_ADMIN_ROLE"]
    assert ev["user"]["email_addr"] == "mlee@acme.example"
    assert ev["actor"]["user"]["email_addr"] == "it-admin@acme.example"


def test_google_admin_setting_maps_first_event_only():
    ev = norm("google_workspace", "admin_change_setting")
    assert (ev["class_uid"], ev["activity_id"]) == (6003, 3)
    assert ev["api"]["operation"] == "CHANGE_APPLICATION_SETTING"
    assert ev["unmapped"]["parameters"]["SETTING_NAME"] == "AUTO_FORWARDING_ENABLED"
    assert ev["unmapped"]["other_events"] == ["CHANGE_APPLICATION_SETTING"]


def test_google_token_authorize():
    ev = norm("google_workspace", "token_authorize")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (3003, 1, 2)
    assert "https://www.googleapis.com/auth/gmail.readonly" in ev["privileges"]
    assert ev["unmapped"]["app_name"] == "Mail Organizer Pro"


def test_google_drive():
    ev = norm("google_workspace", "drive_share_public")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (6001, 8, 3)
    assert ev["web_resources"] == [{"name": "Customer list 2026", "uid": "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                                    "type": "spreadsheet"}]
    ev = norm("google_workspace", "drive_download")
    assert (ev["activity_id"], ev["severity_id"]) == (7, 1)


def test_google_activity_without_events_rejected():
    raw = load("google_workspace", "login_success")
    raw["events"] = []
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("google_workspace", raw)
    raw["events"] = "login_success"
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("google_workspace", raw)
