"""Field-level tests for the EDR mappers: CrowdStrike alerts and FDR, SentinelOne,
Defender XDR and Huntress."""
import json
import pathlib

import pytest

from app import mappers, ocsf

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(src, name):
    return json.loads((FIXTURES / src / f"{name}.json").read_text())


def norm(src, name):
    return mappers.normalize(src, load(src, name))


def techniques(ev):
    return [a["technique"]["uid"] for a in ev["finding_info"].get("attacks", [])]


# ---------------------------------------------------------------- CrowdStrike alerts
def test_crowdstrike_alert_new_powershell():
    ev = norm("crowdstrike_alerts", "epp_powershell_new")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 4)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T14:22:05.441Z")
    fi = ev["finding_info"]
    assert fi["uid"].endswith(":51539607575-10304-6512656")
    assert fi["attacks"] == [{"technique": {"uid": "T1059.001", "name": "PowerShell"},
                              "tactic": {"uid": "TA0002", "name": "Execution"}}]
    assert ev["device"]["hostname"] == "ACME-WS042" and ev["device"]["ip"] == "10.20.4.42"
    assert ev["process"]["name"] == "powershell.exe"
    assert ev["process"]["cmd_line"].startswith("powershell.exe -NoP")
    assert ev["process"]["file"]["hashes"][0]["value"].startswith("de96a6e6")
    assert ev["process"]["parent_process"]["name"] == "WINWORD.EXE"
    assert ev["process"]["parent_process"]["parent_process"]["name"] == "explorer.exe"
    assert ev["actor"]["user"]["name"] == "jdoe"
    assert ev["actor"]["user"]["email_addr"] == "jdoe@acme.example"
    assert ev["unmapped"]["confidence"] == 80 and ev["unmapped"]["status"] == "new"
    assert ocsf.summary(ev)["host"] == "ACME-WS042"


def test_crowdstrike_alert_closed_is_close_activity_at_update_time():
    raw = load("crowdstrike_alerts", "credential_dump_closed")
    ev = mappers.normalize("crowdstrike_alerts", raw)
    assert (ev["activity_id"], ev["severity_id"]) == (3, 5)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T09:45:30.512Z")
    assert techniques(ev) == ["T1003.001"]
    # each version of an alert is its own record for dedupe
    m = mappers.get("crowdstrike_alerts")
    assert m.uid(raw) == f"{raw['composite_id']}:2026-10-18T09:45:30.512Z"


def test_crowdstrike_alert_numeric_severity_without_name():
    raw = load("crowdstrike_alerts", "epp_powershell_new")
    raw.pop("severity_name")
    raw["severity"] = 50
    assert mappers.normalize("crowdstrike_alerts", raw)["severity_id"] == 3


def test_crowdstrike_alert_without_composite_id_is_rejected():
    raw = load("crowdstrike_alerts", "epp_powershell_new")
    raw.pop("composite_id")
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("crowdstrike_alerts", raw)


def test_crowdstrike_alert_device_not_object_is_rejected():
    raw = load("crowdstrike_alerts", "epp_powershell_new")
    raw["device"] = "ACME-WS042"
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("crowdstrike_alerts", raw)


# ---------------------------------------------------------------- CrowdStrike FDR
def test_fdr_process_rollup2():
    ev = norm("crowdstrike_fdr", "process_rollup2")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (1007, 1, 1)
    assert ev["time"] == 1792333325441
    assert ev["process"]["name"] == "cmd.exe"
    assert ev["process"]["file"]["path"].endswith("\\System32\\cmd.exe")
    assert ev["process"]["cmd_line"].startswith("cmd.exe /c whoami")
    assert ev["process"]["parent_process"]["name"] == "powershell.exe"
    assert ev["process"]["pid"] == 7420
    assert ev["device"] == {"hostname": "ACME-WS042", "uid": "4d2e9c1b7a5f4e3d8c6b2a1f0e9d8c7b",
                            "ip": "198.51.100.23", "os": {"name": "Win"}}
    assert ev["actor"]["user"]["name"] == "jdoe"
    assert ev["metadata"]["uid"] == "b6a1f0c2-3d4e-11f1-8a9b-0a1b2c3d4e5f"


def test_fdr_synthetic_process_rollup2_is_also_a_launch():
    raw = load("crowdstrike_fdr", "process_rollup2")
    raw["event_simpleName"] = "SyntheticProcessRollup2"
    assert mappers.normalize("crowdstrike_fdr", raw)["class_uid"] == 1007


def test_fdr_dns_request():
    ev = norm("crowdstrike_fdr", "dns_request")
    assert (ev["class_uid"], ev["activity_id"]) == (4003, 1)
    assert ev["query"]["hostname"] == "update-cdn.badexample.net"
    assert ev["device"]["uid"] == "4d2e9c1b7a5f4e3d8c6b2a1f0e9d8c7b"
    assert "hostname" not in ev["device"]  # no ComputerName on this event


def test_fdr_network_connect():
    ev = norm("crowdstrike_fdr", "network_connect_ip4")
    assert (ev["class_uid"], ev["activity_id"]) == (4001, 1)
    assert ev["dst_endpoint"] == {"ip": "203.0.113.77", "port": 443}
    assert ev["src_endpoint"]["ip"] == "10.20.4.42" and ev["src_endpoint"]["port"] == 50122
    assert ev["connection_info"] == {"protocol_name": "tcp", "direction_id": 2}


def test_fdr_logon_failed():
    ev = norm("crowdstrike_fdr", "user_logon_failed2")
    assert (ev["class_uid"], ev["activity_id"], ev["status_id"], ev["severity_id"]) == (3002, 1, 2, 2)
    assert ev["user"]["name"] == "administrator" and ev["logon_type_id"] == 3
    assert ev["src_endpoint"]["ip"] == "10.20.4.99"
    assert ev["status_code"] == "0xc000006d"


def test_fdr_user_logon_success():
    raw = load("crowdstrike_fdr", "user_logon_failed2")
    raw["event_simpleName"] = "UserLogon"
    ev = mappers.normalize("crowdstrike_fdr", raw)
    assert ev["status_id"] == 1 and ev["severity_id"] == 1 and "status_code" not in ev


def test_fdr_other_event_types_are_skipped():
    assert norm("crowdstrike_fdr", "agent_online_skipped") is None


def test_fdr_bad_timestamp_and_missing_fields_rejected():
    raw = load("crowdstrike_fdr", "dns_request")
    raw["timestamp"] = "yesterday"
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("crowdstrike_fdr", raw)
    raw = load("crowdstrike_fdr", "network_connect_ip4")
    raw["RemoteAddressIP4"] = "not-an-ip"
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("crowdstrike_fdr", raw)


# ---------------------------------------------------------------- SentinelOne
def test_sentinelone_malicious_not_mitigated_is_critical():
    ev = norm("sentinelone_threats", "ransomware_not_mitigated")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 5)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T15:02:44.118204Z")
    assert sorted(techniques(ev)) == ["T1486", "T1490"]  # T1486 listed twice, kept once
    assert ev["device"]["hostname"] == "ACME-LT017" and ev["device"]["ip"] == "10.30.2.17"
    assert ev["file"]["hashes"][0] == {"algorithm_id": 3, "algorithm": "SHA-256",
                                       "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
    assert ev["actor"]["user"]["name"] == "ACME\\mlee"
    assert ev["unmapped"]["mitigation_status"] == "not_mitigated"
    assert ev["unmapped"]["confidence"] == "malicious"
    assert ev["finding_info"]["types"] == ["Ransomware", "dynamic"]


def test_sentinelone_suspicious_resolved_is_close():
    ev = norm("sentinelone_threats", "suspicious_resolved")
    assert (ev["activity_id"], ev["severity_id"]) == (3, 3)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-17T10:40:12.500000Z")
    assert ev["unmapped"]["mitigation_actions"] == [
        {"action": "quarantine", "status": "success", "at": "2026-10-17T08:15:03.000000Z"}]


def test_sentinelone_false_positive_is_informational():
    raw = load("sentinelone_threats", "ransomware_not_mitigated")
    raw["threatInfo"]["analystVerdict"] = "false_positive"
    assert mappers.normalize("sentinelone_threats", raw)["severity_id"] == 1


def test_sentinelone_threat_info_not_object_rejected():
    raw = load("sentinelone_threats", "suspicious_resolved")
    raw["threatInfo"] = ["bad"]
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("sentinelone_threats", raw)


# ---------------------------------------------------------------- Defender
def test_defender_endpoint_alert_evidence():
    ev = norm("defender_alerts", "mde_credential_theft")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 4)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T11:02:57.3573845Z")
    assert techniques(ev) == ["T1003.003", "T1003"]
    assert ev["device"]["hostname"] == "acme-dc01.corp.acme.example"
    assert ev["device"]["ip"] == "10.20.0.10"
    assert ev["actor"]["user"]["email_addr"] == "it-admin2@acme.example"
    assert ev["process"]["name"] == "ntdsutil.exe" and ev["process"]["pid"] == 4416
    assert ev["process"]["parent_process"]["name"] == "cmd.exe"
    assert ev["src_endpoint"]["ip"] == "10.20.4.99"
    u = ev["unmapped"]
    assert u["incident_id"] == "28282" and u["service_source"] == "microsoftDefenderForEndpoint"
    assert u["detection_source"] == "edr" and u["category"] == "CredentialAccess"
    assert ev["finding_info"]["types"] == ["CredentialAccess"]


def test_defender_resolved_office_alert():
    raw = load("defender_alerts", "mdo_phish_resolved")
    ev = mappers.normalize("defender_alerts", raw)
    assert (ev["activity_id"], ev["severity_id"]) == (3, 3)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T09:12:44.1Z")
    assert "device" not in ev
    assert ev["actor"]["user"]["name"] == "ap@acme.example"
    assert ev["unmapped"]["determination"] == "phishing"
    assert mappers.get("defender_alerts").uid(raw) == f"{raw['id']}:{raw['lastUpdateDateTime']}"


def test_defender_evidence_not_list_rejected():
    raw = load("defender_alerts", "mde_credential_theft")
    raw["evidence"] = {"@odata.type": "#microsoft.graph.security.deviceEvidence"}
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("defender_alerts", raw)


# ---------------------------------------------------------------- Huntress
def test_huntress_critical_incident():
    ev = norm("huntress_incidents", "critical_sent")
    assert (ev["class_uid"], ev["activity_id"], ev["severity_id"]) == (2004, 1, 5)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-18T13:05:00Z")
    assert ev["finding_info"]["uid"] == "1844201"
    assert ev["finding_info"]["types"] == ["footholds", "process_detections"]
    assert ev["device"] == {"uid": "7781234", "os": {"name": "windows"}}
    assert ev["unmapped"]["indicator_counts"] == {"footholds": 1, "process_detections": 2}
    assert ev["unmapped"]["remediations"][0]["type"] == "delete_scheduled_task"


def test_huntress_closed_low():
    ev = norm("huntress_incidents", "low_closed")
    assert (ev["activity_id"], ev["severity_id"]) == (3, 2)
    assert ev["time"] == ocsf.to_epoch_ms("2026-10-17T15:30:00Z")


def test_huntress_missing_times_rejected():
    raw = load("huntress_incidents", "critical_sent")
    for k in ("sent_at", "status_updated_at", "updated_at"):
        raw.pop(k)
    with pytest.raises(ocsf.MappingError):
        mappers.normalize("huntress_incidents", raw)
