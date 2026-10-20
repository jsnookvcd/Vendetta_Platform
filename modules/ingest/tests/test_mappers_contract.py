"""Contract tests every wave 1 mapper must pass, run over every recorded fixture.

- each fixture normalizes to an event that passes ocsf.validate (or is a known skip);
- normalization is deterministic and does not mutate the raw record;
- malformed input raises ocsf.MappingError and never any other exception, including
  for type-confused copies of every fixture.
"""
import copy
import json
import pathlib

import pytest

from app import mappers, ocsf, receipts

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
WAVE1 = ["crowdstrike_alerts", "crowdstrike_fdr", "sentinelone_threats", "defender_alerts", "huntress_incidents",
         "okta_system_log", "m365_audit", "google_workspace", "cloudtrail", "guardduty", "cef"]
DETECTIONS = {"crowdstrike_alerts", "sentinelone_threats", "defender_alerts", "huntress_incidents", "guardduty"}
SKIPS = {("crowdstrike_fdr", "agent_online_skipped")}


def _cases():
    out = []
    for src in WAVE1:
        files = sorted((FIXTURES / src).glob("*.json"))
        for f in files:
            out.append(pytest.param(src, f.stem, id=f"{src}/{f.stem}"))
    return out


def load(src, name):
    return json.loads((FIXTURES / src / f"{name}.json").read_text())


def test_every_source_has_at_least_two_mapped_fixtures():
    for src in WAVE1:
        mapped = [f for f in (FIXTURES / src).glob("*.json") if (src, f.stem) not in SKIPS]
        assert len(mapped) >= 2, src


def test_registration_and_detection_flags():
    for src in WAVE1:
        m = mappers.get(src)
        assert m is not None, src
        assert m.detection is (src in DETECTIONS), src
        assert m.vendor and m.product and m.name and m.family
    assert "bucket" in mappers.get("cloudtrail").doors
    assert "bucket" in mappers.get("crowdstrike_fdr").doors
    assert "syslog" in mappers.get("cef").doors


@pytest.mark.parametrize("src,name", _cases())
def test_fixture_normalizes_validates_and_is_deterministic(src, name):
    raw = load(src, name)
    before = copy.deepcopy(raw)
    ev = mappers.normalize(src, raw)
    assert raw == before, "mapper mutated the raw record"
    if (src, name) in SKIPS:
        assert ev is None
        return
    assert ev is not None
    assert ocsf.validate(ev) == []
    assert isinstance(ev["time"], int)
    assert ev["severity_id"] in ocsf.SEVERITY_IDS
    # the tenant is the pipeline's to stamp, never the mapper's
    assert "tenant_uid" not in ev["metadata"]
    assert "tenant_id" not in (ev.get("unmapped") or {})
    # no empty top-level objects
    assert all(v not in ({}, []) for v in ev.values())
    again = mappers.normalize(src, copy.deepcopy(raw))
    assert receipts.canonical(ev) == receipts.canonical(again)
    m = mappers.get(src)
    assert m.uid(raw) == m.uid(copy.deepcopy(raw))
    if m.detection:
        assert ev["class_uid"] == 2004
        assert ev["finding_info"]["title"]


MALFORMED_COMMON = [{}, {"unexpected": True}, {"time": "not a time"}]


@pytest.mark.parametrize("src", WAVE1)
@pytest.mark.parametrize("raw", MALFORMED_COMMON)
def test_malformed_common_raises_mapping_error(src, raw):
    with pytest.raises(ocsf.MappingError):
        mappers.normalize(src, raw)


@pytest.mark.parametrize("src", WAVE1)
def test_non_object_raises_mapping_error(src):
    for raw in ([], "text", 5, None):
        with pytest.raises(ocsf.MappingError):
            mappers.normalize(src, raw)
        with pytest.raises(ocsf.MappingError):
            mappers.get(src).map(raw)


def _mutations(raw):
    """Type-confused copies: every value, at the top level and one level down, replaced
    by values of the wrong type."""
    junk = ["x", 7, ["x"], {"x": 1}, None, True]
    for k in list(raw):
        for j in junk:
            c = copy.deepcopy(raw)
            c[k] = j
            yield c
        if isinstance(raw[k], dict):
            for k2 in list(raw[k]):
                for j in junk:
                    c = copy.deepcopy(raw)
                    c[k][k2] = j
                    yield c


@pytest.mark.parametrize("src,name", _cases())
def test_type_confused_records_never_raise_anything_but_mapping_error(src, name):
    raw = load(src, name)
    for c in _mutations(raw):
        try:
            ev = mappers.normalize(src, c)
        except ocsf.MappingError:
            continue
        if ev is not None:
            assert ocsf.validate(ev) == []
        mappers.get(src).uid(c)  # must not raise either
