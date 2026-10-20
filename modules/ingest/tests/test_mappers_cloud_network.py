"""Field-level tests for CloudTrail, GuardDuty and the generic CEF mapper."""
import json
import pathlib

import pytest

from app import mappers, ocsf
from app.mappers import aws, cef

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(src, name):
    return json.loads((FIXTURES / src / f"{name}.json").read_text())


def norm(src, name):
    return mappers.normalize(src, load(src, name))


# ---------------------------------------------------------------- CloudTrail
def test_cloudtrail_assumed_role_run_instances():
    ev = norm("cloudtrail", "assumed_role_run_instances")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (6003, 1, 1, 1)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:02:11Z")
    assert ev["api"]["operation"] == "RunInstances"
    assert ev["api"]["service"]["name"] == "ec2.amazonaws.com"
    u = ev["actor"]["user"]
    assert u["name"] == "AWSReservedSSO_AdministratorAccess_0a1b2c3d4e5f6a7b"  # sessionIssuer.userName
    assert u["type"] == "AssumedRole" and u["uid"].startswith("arn:aws:sts::111122223333:assumed-role/")
    assert u["uid_alt"] == "AROA4EXAMPLEROLEID123:mlee@acme.example"
    assert u["account"]["uid"] == "111122223333"
    assert ev["actor"]["session"]["is_mfa"] is False
    assert ev["src_endpoint"] == {"ip": "198.51.100.61"}
    assert ev["cloud"] == {"provider": "AWS", "account": {"uid": "111122223333"}, "region": "us-east-1"}
    assert ev["metadata"]["uid"] == "0f2e3d4c-5b6a-4798-8a7b-6c5d4e3f2a1b"


def test_cloudtrail_console_login_root_failure():
    ev = norm("cloudtrail", "console_login_root_failure")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (3002, 1, 2, 3)
    assert ev["is_mfa"] is False and ev["unmapped"]["mfa_used"] == "No"
    assert ev["user"]["name"] == "root"
    assert ev["status_detail"] == "Failed authentication"


def test_cloudtrail_console_login_success_with_mfa():
    ev = norm("cloudtrail", "console_login_iam_success")
    assert (ev["class_uid"], ev["status_id"], ev["severity_id"]) == (3002, 1, 1)
    assert ev["is_mfa"] is True and ev["user"]["name"] == "breakglass"


def test_cloudtrail_access_denied_read():
    ev = norm("cloudtrail", "access_denied_list_buckets")
    assert (ev["activity_id"], ev["status_id"], ev["severity_id"]) == (2, 2, 2)
    assert ev["status_code"] == "AccessDenied"
    assert ev["src_endpoint"]["ip"] == "2001:db8:41::17"
    assert ev["actor"]["user"]["credential_uid"] == "AKIAEXAMPLEKEY000002"
    assert ev["cloud"]["region"] == "eu-west-1"


def test_cloudtrail_service_principal_source_is_not_an_ip():
    ev = norm("cloudtrail", "service_stop_logging")
    assert (ev["activity_id"], ev["severity_id"]) == (3, 3)
    assert "ip" not in ev.get("src_endpoint", {})
    assert ev["src_endpoint"] == {"svc_name": "cloudformation.amazonaws.com"}
    assert ev["unmapped"]["source_ip_address"] == "cloudformation.amazonaws.com"
    assert ev["actor"]["user"]["name"] == "cloudformation.amazonaws.com"


@pytest.mark.parametrize("name,aid", [
    ("CreateUser", 1), ("PutObject", 1), ("RunInstances", 1), ("StartInstances", 1), ("AttachRolePolicy", 1),
    ("AddUserToGroup", 1), ("GetObject", 2), ("ListUsers", 2), ("DescribeInstances", 2), ("LookupEvents", 2),
    ("UpdateTrail", 3), ("ModifyInstanceAttribute", 3), ("SetDefaultPolicyVersion", 3), ("StopLogging", 3),
    ("DetachUserPolicy", 3), ("EnableMFADevice", 3), ("DisableKey", 3), ("DeleteBucket", 4), ("RemoveRoleFromInstanceProfile", 4),
    ("TerminateInstances", 4), ("AssumeRole", 99), ("Getaway", 99), ("Settle", 99), ("Addition", 99)])
def test_cloudtrail_verb_activity(name, aid):
    assert aws.verb_activity(name) == aid


def test_cloudtrail_eventbridge_wrapped_record():
    raw = load("cloudtrail", "assumed_role_run_instances")
    wrapped = {"version": "0", "detail-type": "AWS API Call via CloudTrail", "source": "aws.ec2", "detail": raw}
    ev = mappers.normalize("cloudtrail", wrapped)
    assert ev["api"]["operation"] == "RunInstances"
    assert mappers.get("cloudtrail").uid(wrapped) == raw["eventID"]


def test_cloudtrail_missing_event_name_rejected():
    raw = load("cloudtrail", "assumed_role_run_instances")
    raw.pop("eventName")
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("cloudtrail", raw)


# ---------------------------------------------------------------- GuardDuty
@pytest.mark.parametrize("score,sev", [(9.5, 5), (9, 5), (8.9, 4), (7, 4), (6.9, 3), (4, 3), (3.9, 2), (1, 2),
                                       ("x", 0)])
def test_guardduty_severity_bands(score, sev):
    assert aws.gd_severity(score) == sev


def test_guardduty_eventbridge_envelope():
    raw = load("guardduty", "eventbridge_exfiltration_high")
    ev = mappers.normalize("guardduty", raw)
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 2, 4)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:09:30.000Z")
    assert ev["finding_info"]["types"] == ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]
    assert ev["finding_info"]["uid"] == "16afba5c5c43e07c9e3e5e2e544e95df"
    assert ev["src_endpoint"]["ip"] == "203.0.113.200"
    assert ev["src_endpoint"]["location"]["country"] == "Netherlands"
    assert ev["actor"]["user"]["name"] == "app-server-role"
    assert ev["actor"]["user"]["credential_uid"] == "ASIAEXAMPLEKEY000009"
    assert ev["device"]["uid"] == "i-0abc1234def567890"
    assert ev["api"] == {"operation": "ListBuckets", "service": {"name": "s3.amazonaws.com"}}
    assert ev["cloud"] == {"provider": "AWS", "account": {"uid": "111122223333"}, "region": "us-east-1"}
    assert ev["unmapped"]["action_type"] == "AWS_API_CALL" and ev["unmapped"]["count"] == 3
    assert mappers.get("guardduty").uid(raw) == "16afba5c5c43e07c9e3e5e2e544e95df:2026-10-18T14:09:30.000Z"
    # the bare finding maps the same as the envelope
    assert mappers.normalize("guardduty", raw["detail"]) == ev


def test_guardduty_sdk_pascal_case_port_probe():
    ev = norm("guardduty", "sdk_port_probe_low")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 2)
    assert ev["device"]["hostname"] == "ip-10-1-2-3.eu-west-1.compute.internal"
    assert ev["device"]["os"] == {"name": "Linux"}
    assert ev["src_endpoint"]["ip"] == "192.0.2.45"
    assert ev["dst_endpoint"] == {"port": 22}
    assert ev["cloud"]["region"] == "eu-west-1"


def test_guardduty_archived_is_close():
    raw = load("guardduty", "sdk_port_probe_low")
    raw["Service"]["Archived"] = True
    assert mappers.normalize("guardduty", raw)["activity_id"] == 3


def test_guardduty_without_type_rejected():
    raw = load("guardduty", "eventbridge_exfiltration_high")
    raw["detail"].pop("type")
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("guardduty", raw)


# ---------------------------------------------------------------- CEF
def test_cef_header_escaping():
    fields, ext = cef.parse_header(r"0|Ven\|dor|Prod\\uct|1.0|100|Name with spaces|5|src=10.0.0.1")
    assert fields == ["0", "Ven|dor", "Prod\\uct", "1.0", "100", "Name with spaces", "5"]
    assert ext == "src=10.0.0.1"
    with pytest.raises(ocsf.MappingError):
        cef.parse_header("0|only|three")


def test_cef_extension_escaping_and_spaces():
    ext = cef.parse_extension(r"msg=a value with spaces and a\=b and c\\d src=10.0.0.1 request=https://x/?a=b&c=d "
                              r"cs1Label=Rule Name cs1=allow web\nnext")
    assert ext == {"msg": "a value with spaces and a=b and c\\d", "src": "10.0.0.1",
                   "request": "https://x/?a=b&c=d", "cs1Label": "Rule Name", "cs1": "allow web\nnext"}
    assert cef.parse_extension("") == {}


def test_cef_severity_scale():
    assert [cef.cef_severity(v) for v in ("0", "3", "10", "11", "Low", "Medium", "High", "Very-High", "?")] == \
        [0, 3, 10, 10, 2, 5, 7, 9, 0]


def test_cef_firewall_traffic_is_network_activity():
    ev = norm("cef", "paloalto_traffic_deny")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"], ev["status_id"]) == (4001, 5, 2, 2)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:22:05Z")  # from rt, not the Vector timestamp
    assert ev["metadata"]["product"] == {"name": "PAN-OS", "vendor_name": "Palo Alto Networks"}
    assert ev["src_endpoint"] == {"ip": "10.20.4.42", "port": 50122}
    assert ev["dst_endpoint"] == {"ip": "203.0.113.77", "port": 4444}
    assert ev["connection_info"] == {"protocol_name": "tcp"}
    assert ev["actor"]["user"]["name"] == "corp\\jdoe"
    assert ev["device"]["hostname"] == "PA-FW01"
    assert ev["unmapped"]["custom"] == {"Rule": "block-outbound-high-ports", "Source Zone": "trust"}
    assert ev["unmapped"]["extension"]["sourceTranslatedAddress"] == "198.51.100.23"
    assert ev["traffic"] == {"bytes_in": 0, "bytes_out": 74}
    assert mappers.get("cef").uid(load("cef", "paloalto_traffic_deny")) == ""


def test_cef_high_severity_without_endpoints_is_detection():
    ev = norm("cef", "threat_no_endpoints_high")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 5)
    assert ev["time"] == 1792333325441
    assert ev["metadata"]["product"] == {"name": "Sentry|EDR", "vendor_name": "Acme Security"}
    assert ev["finding_info"]["title"] == "Ransomware note written"
    assert ev["finding_info"]["types"] == ["MAL-2001"]
    assert ev["message"] == "Ransom note README=DECRYPT.txt written by svc\\proc on host ACME-WS042"
    assert ev["unmapped"]["extension"]["fname"] == "README=DECRYPT.txt"
    assert ev["device"]["hostname"] == "sentry-mgr01"


def test_cef_low_severity_rfc5424_is_api_other():
    ev = norm("cef", "rfc5424_low_info")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (6003, 99, 2)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:30:00.000Z")  # from the 5424 header
    assert ev["device"]["hostname"] == "vpn-gw01"
    assert ev["unmapped"]["custom"] == {"Session Seconds": "0"}


def test_cef_rfc3164_without_rt_uses_vector_timestamp():
    raw = {"message": "<14>Oct 18 14:22:05 fw02 CEF:0|V|P|1|1|n|2|src=10.0.0.1 dst=10.0.0.2",
           "timestamp": "2026-10-18T14:22:05.500Z"}
    ev = mappers.normalize("cef", raw)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:22:05.500Z")
    assert ev["device"]["hostname"] == "fw02" and ev["activity_id"] == 6


def test_cef_rt_formats():
    assert cef._cef_time("Oct 18 2026 14:22:05") == ocsf.to_epoch_ms("2026-10-18T14:22:05Z")
    assert cef._cef_time("Oct 18 2026 14:22:05.250 +02:00") == ocsf.to_epoch_ms("2026-10-18T12:22:05.250Z")
    assert cef._cef_time("1792333325441") == 1792333325441
    assert cef._cef_time("Oct 18 2026 14:22:05 EST") is None


@pytest.mark.parametrize("raw", [
    {"message": "no cef here"},
    {"message": 42},
    {"message": "CEF:0|V|P|1|1|n"},
    {"message": "<14>Oct 18 14:22:05 fw02 CEF:0|V|P|1|1|n|2|src=10.0.0.1"},  # no usable time at all
])
def test_cef_malformed(raw):
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("cef", raw)


def test_cef_record_exactly_as_vector_posts_it():
    # Shape captured from deploy/vector.toml posting to a local sink: the raw line, Vector's
    # receive time with nanoseconds, and the sender's address.
    ev = norm("cef", "vector_rfc3164_no_rt")
    assert (ev["class_uid"], ev["activity_id"]) == (4001, 6)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:22:05.655Z")
    assert ev["device"]["hostname"] == "PA-FW01"
    assert ev["unmapped"]["syslog_peer"] == "10.20.0.1"
