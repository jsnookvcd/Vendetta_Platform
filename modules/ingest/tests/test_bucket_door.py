"""Bucket door: split_object over CloudTrail, FDR and array files, and BucketReader
with fake SQS and S3 clients."""
import gzip
import io
import json
import pathlib
import sys

import pytest

from app import mappers
from app.connectors import bucket
from app.connectors.bucket import BucketError, BucketReader, object_refs, split_object

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def fx(src, name):
    return json.loads((FIXTURES / src / f"{name}.json").read_text())


# ---------------------------------------------------------------- split_object
def test_cloudtrail_file_gzipped_splits_records():
    recs = [fx("cloudtrail", "assumed_role_run_instances"), fx("cloudtrail", "console_login_root_failure")]
    body = gzip.compress(json.dumps({"Records": recs + [42, "junk"]}).encode())
    out = split_object("AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/18/111122223333_CloudTrail_us-east-1_20261018T1405Z_abc.json.gz", body)
    assert out == recs and out.skipped == 2
    assert [mappers.normalize("cloudtrail", r)["class_uid"] for r in out] == [6003, 3002]


def test_gzip_detected_by_magic_bytes_without_suffix():
    body = gzip.compress(json.dumps({"Records": [{"eventID": "1"}]}).encode())
    assert split_object("no-suffix", body) == [{"eventID": "1"}]


def test_fdr_json_lines_with_bad_lines():
    lines = [json.dumps(fx("crowdstrike_fdr", "process_rollup2")), "", "not json", "[1,2]",
             json.dumps(fx("crowdstrike_fdr", "dns_request"))]
    out = split_object("data/2026-10-18/part-00000.gz", gzip.compress("\n".join(lines).encode()))
    assert [r["event_simpleName"] for r in out] == ["ProcessRollup2", "DnsRequest"]
    assert out.skipped == 2


def test_json_array_and_single_object():
    out = split_object("x.json", json.dumps([{"a": 1}, None, {"b": 2}]).encode())
    assert out == [{"a": 1}, {"b": 2}] and out.skipped == 1
    single = split_object("finding.json", json.dumps(fx("guardduty", "sdk_port_probe_low")).encode())
    assert len(single) == 1 and single.skipped == 0


def test_digest_and_empty_files_split_to_nothing():
    assert split_object("AWSLogs/111122223333/CloudTrail-Digest/us-east-1/2026/10/18/x.json.gz",
                        gzip.compress(b'{"awsAccountId":"1"}')) == []
    assert split_object("empty.json", b"  \n") == []


def test_not_json_object_scalars_are_skipped():
    out = split_object("x.jsonl", b'"a"\n1\ntrue\n{"ok": 1}\n')
    assert out == [{"ok": 1}] and out.skipped == 3


def test_bad_gzip_and_binary_raise_bucket_error():
    with pytest.raises(BucketError):
        split_object("x.json.gz", b"\x1f\x8bnot really gzip")
    with pytest.raises(BucketError):
        split_object("x.bin", b"\xff\xfe\x00\x81")


def test_decompressed_size_limit(monkeypatch):
    monkeypatch.setattr(bucket, "MAX_OBJECT_BYTES", 1024)
    with pytest.raises(BucketError):
        split_object("big.json.gz", gzip.compress(b"{}\n" * 5000))


def test_boto3_not_imported_at_module_load():
    src = (pathlib.Path(bucket.__file__)).read_text()
    top = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
    assert not any("boto3" in ln for ln in top)


# ---------------------------------------------------------------- notifications
def s3_event(bucket_name, key, name="ObjectCreated:Put"):
    return {"Records": [{"eventVersion": "2.1", "eventSource": "aws:s3", "eventName": name,
                         "s3": {"bucket": {"name": bucket_name}, "object": {"key": key, "size": 100}}}]}


def test_object_refs_variants():
    assert object_refs(json.dumps(s3_event("b", "AWSLogs/a+b%3Dc.json.gz"))) == ([("b", "AWSLogs/a b=c.json.gz")], True)
    sns = {"Type": "Notification", "MessageId": "m", "Message": json.dumps(s3_event("b", "k"))}
    assert object_refs(json.dumps(sns)) == ([("b", "k")], True)
    eb = {"version": "0", "detail-type": "Object Created", "source": "aws.s3",
          "detail": {"bucket": {"name": "b"}, "object": {"key": "k"}}}
    assert object_refs(json.dumps(eb)) == ([("b", "k")], True)
    assert object_refs(json.dumps({"Event": "s3:TestEvent", "Bucket": "b"})) == ([], True)
    assert object_refs(json.dumps(s3_event("b", "k", "ObjectRemoved:Delete"))) == ([], True)
    assert object_refs("not json") == ([], False)
    assert object_refs(json.dumps({"hello": "world"})) == ([], False)


# ---------------------------------------------------------------- BucketReader
class FakeBody:
    def __init__(self, data):
        self._b = io.BytesIO(data)

    def read(self):
        return self._b.read()


class FakeS3:
    def __init__(self, objects):
        self.objects = objects
        self.reads = []

    def get_object(self, Bucket, Key):
        self.reads.append((Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise RuntimeError("NoSuchKey")
        return {"Body": FakeBody(self.objects[(Bucket, Key)])}


class FakeSQS:
    def __init__(self, messages):
        self.messages = list(messages)
        self.deleted = []
        self.received_with = None

    def receive_message(self, **kw):
        self.received_with = kw
        return {"Messages": self.messages}

    def delete_message(self, QueueUrl, ReceiptHandle):
        self.deleted.append(ReceiptHandle)


def msg(i, body):
    return {"MessageId": f"m{i}", "ReceiptHandle": f"rh{i}", "Body": json.dumps(body)}


TRAIL = "acme-cloudtrail-logs"
FDR = "acme-fdr"
CT_KEY = "AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/18/f.json.gz"
FDR_KEY = "fdr/data/part-0001.gz"


def ct_object():
    return gzip.compress(json.dumps({"Records": [fx("cloudtrail", "assumed_role_run_instances"),
                                                 fx("cloudtrail", "access_denied_list_buckets")]}).encode())


def make_reader(messages, objects, sink, allowed=(TRAIL, FDR)):
    sqs, s3 = FakeSQS(messages), FakeS3(objects)
    reader = BucketReader(sqs, s3, "https://sqs.us-east-1.amazonaws.com/999/ingest-bucket", allowed, sink,
                          routes={TRAIL: "conn-cloudtrail", f"{FDR}/fdr/": "conn-fdr"}, wait_seconds=0)
    return reader, sqs, s3


def test_reader_routes_splits_sinks_and_deletes():
    got = []
    objects = {(TRAIL, CT_KEY): ct_object(),
               (FDR, FDR_KEY): gzip.compress((json.dumps(fx("crowdstrike_fdr", "process_rollup2")) + "\n").encode())}
    sns = {"Type": "Notification", "Message": json.dumps(s3_event(FDR, FDR_KEY))}
    reader, sqs, s3 = make_reader([msg(1, s3_event(TRAIL, CT_KEY)), msg(2, sns)], objects,
                                  lambda route, recs: got.append((route, recs)))
    counts = reader.poll_once()
    assert [(route, len(recs)) for route, recs in got] == [("conn-cloudtrail", 2), ("conn-fdr", 1)]
    assert sqs.deleted == ["rh1", "rh2"]
    assert counts["deleted"] == 2 and counts["records"] == 3 and counts["objects"] == 2
    assert sqs.received_with["MaxNumberOfMessages"] == 10


def test_reader_refuses_bucket_not_on_allowlist():
    got = []
    reader, sqs, s3 = make_reader([msg(1, s3_event("someone-elses-bucket", CT_KEY))],
                                  {("someone-elses-bucket", CT_KEY): ct_object()}, lambda r, x: got.append(r))
    counts = reader.poll_once()
    assert s3.reads == [] and got == [] and sqs.deleted == []
    assert counts["refused"] == 1 and counts["kept"] == 1


def test_reader_refuses_message_mixing_allowed_and_foreign_buckets_before_reading_any():
    body = s3_event(TRAIL, CT_KEY)
    body["Records"] += s3_event("evil", "k")["Records"]
    reader, sqs, s3 = make_reader([msg(1, body)], {(TRAIL, CT_KEY): ct_object()}, lambda r, x: None)
    reader.poll_once()
    assert s3.reads == [] and sqs.deleted == []


def test_reader_allowlisted_bucket_without_route_is_refused():
    reader, sqs, s3 = make_reader([msg(1, s3_event(FDR, "other-prefix/x.gz"))], {}, lambda r, x: None)
    assert reader.poll_once()["refused"] == 1
    assert s3.reads == [] and sqs.deleted == []


def test_reader_keeps_message_when_sink_fails():
    def sink(route, recs):
        raise RuntimeError("database down")
    reader, sqs, s3 = make_reader([msg(1, s3_event(TRAIL, CT_KEY))], {(TRAIL, CT_KEY): ct_object()}, sink)
    counts = reader.poll_once()
    assert s3.reads == [(TRAIL, CT_KEY)] and sqs.deleted == [] and counts["errors"] == 1


def test_reader_keeps_message_when_object_missing_or_unreadable():
    reader, sqs, s3 = make_reader([msg(1, s3_event(TRAIL, CT_KEY)), msg(2, s3_event(TRAIL, "bad.json.gz"))],
                                  {(TRAIL, "bad.json.gz"): b"\x1f\x8bbroken"}, lambda r, x: None)
    counts = reader.poll_once()
    assert sqs.deleted == [] and counts["errors"] == 2


def test_reader_deletes_test_events_and_removals_without_sinking():
    got = []
    reader, sqs, s3 = make_reader([msg(1, {"Event": "s3:TestEvent"}),
                                   msg(2, s3_event(TRAIL, CT_KEY, "ObjectRemoved:Delete"))], {},
                                  lambda r, x: got.append(r))
    reader.poll_once()
    assert sqs.deleted == ["rh1", "rh2"] and got == [] and s3.reads == []


def test_reader_keeps_unparseable_messages():
    reader, sqs, s3 = make_reader([{"MessageId": "m1", "ReceiptHandle": "rh1", "Body": "garbage"}], {},
                                  lambda r, x: None)
    assert reader.poll_once()["kept"] == 1 and sqs.deleted == []


def test_reader_object_with_only_skipped_entries_is_deleted_without_sink():
    got = []
    reader, sqs, s3 = make_reader([msg(1, s3_event(TRAIL, CT_KEY))],
                                  {(TRAIL, CT_KEY): gzip.compress(b'{"Records": [1, 2]}')}, lambda r, x: got.append(r))
    counts = reader.poll_once()
    assert got == [] and sqs.deleted == ["rh1"] and counts["skipped"] == 2


def test_route_longest_prefix_wins():
    r = BucketReader(FakeSQS([]), FakeS3({}), "q", ["b"], lambda *a: None,
                     routes={"b": "all", "b/AWSLogs/": "trail", "b/AWSLogs/222/": "trail-222"})
    assert r.route_for("b", "other/x") == "all"
    assert r.route_for("b", "AWSLogs/111/x") == "trail"
    assert r.route_for("b", "AWSLogs/222/x") == "trail-222"
    assert r.route_for("c", "AWSLogs/222/x") is None


def test_from_boto3_imports_lazily(monkeypatch):
    made = []

    class FakeSession:
        def __init__(self, region_name=None):
            self.region = region_name

        def client(self, name):
            made.append((name, self.region))
            return object()

    fake = type(sys)("boto3")
    fake.session = type(sys)("boto3.session")
    fake.session.Session = FakeSession
    monkeypatch.setitem(sys.modules, "boto3", fake)
    r = BucketReader.from_boto3("q", ["b"], lambda *a: None, region="us-east-1", routes={"b": "x"})
    assert made == [("sqs", "us-east-1"), ("s3", "us-east-1")] and r.route_for("b", "k") == "x"
