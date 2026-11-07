import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from k8s_event_triage.parse import InputError, parse_timestamp, read_events
from k8s_event_triage.policy import Policy


def test_empty_and_blank_input_are_explicit(parse_rows):
    events, stats = parse_rows(b"\xef\xbb\xbf\r\n\t \n")
    assert events == ()
    assert (stats.input_record_count, stats.physical_line_count, stats.blank_line_count) == (
        0,
        2,
        2,
    )
    assert stats.input_sha256 == hashlib.sha256(b"\xef\xbb\xbf\r\n\t \n").hexdigest()
    events, stats = parse_rows(b"")
    assert events == () and stats.input_bytes == stats.physical_line_count == 0


def test_bom_crlf_provenance_and_multiplicity(record_factory, parse_rows):
    row = record_factory(body="probe failed: snowman \u2603 and escaped control \x1b")
    line = json.dumps(row).encode()
    raw = b"\xef\xbb\xbf" + line + b"\r\n\n" + line + b"\r\n"
    events, stats = parse_rows(raw)
    assert len(events) == 2 and stats.blank_line_count == 1
    assert [event.provenance.line for event in events] == [1, 3]
    assert events[1].provenance.byte_offset == 3 + len(line) + 3
    assert (
        events[0].provenance.raw_sha256
        == hashlib.sha256(b"\xef\xbb\xbf" + line + b"\r\n").hexdigest()
    )
    assert events[0].provenance.canonical_sha256 == events[1].provenance.canonical_sha256
    assert events[0].body == row["body"]
    assert stats.input_bytes == len(raw) and stats.input_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b"null",
        b"42",
        b'"text"',
        b"{",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"x":1,"x":2}',
        b'{"x":{"nested":1,"nested":2}}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"\n\xef\xbb\xbf{}",
        b"{}{}",
    ],
)
def test_strict_json_admission(payload, parse_rows, capsys):
    with pytest.raises(InputError) as failure:
        parse_rows(payload)
    assert failure.value.line is not None and failure.value.source == "events.jsonl"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "section,key",
    [
        (None, "timestamp"),
        (None, "body"),
        (None, "attributes"),
        (None, "resource"),
        ("resource", "k8s.object.kind"),
        ("resource", "k8s.object.name"),
        ("attributes", "k8s.event.reason"),
    ],
)
def test_missing_required_fields(section, key, record_factory, parse_rows):
    row = record_factory()
    del (row if section is None else row[section])[key]
    with pytest.raises(InputError):
        parse_rows([row])


@pytest.mark.parametrize(
    "section,key,value",
    [
        (None, "body", {}),
        (None, "resource", []),
        (None, "attributes", "metadata"),
        (None, "severity_number", True),
        (None, "severity_number", 25),
        (None, "severity_text", 13),
        ("resource", "k8s.node.name", False),
        ("resource", "k8s.object.uid", ""),
        ("resource", "k8s.object.name", " pod "),
        ("attributes", "k8s.namespace.name", 1),
        ("attributes", "k8s.event.reason", ""),
        ("attributes", "k8s.event.count", 0),
        ("attributes", "k8s.event.count", -1),
        ("attributes", "k8s.event.count", True),
        ("attributes", "k8s.event.count", 1.0),
        ("attributes", "k8s.event.count", "1"),
        ("attributes", "k8s.event.count", None),
        (None, "observed_timestamp", None),
        ("attributes", "k8s.event.start_time", "yesterday"),
    ],
)
def test_wrong_field_types_are_errors(section, key, value, record_factory, parse_rows):
    row = record_factory()
    (row if section is None else row[section])[key] = value
    with pytest.raises(InputError):
        parse_rows([row])


@pytest.mark.parametrize(
    "value",
    [
        "2024-06-01T10:00:00",
        "2024-06-01 10:00:00Z",
        "2024-06-01T10:00:00.0000001Z",
        "2024-02-30T10:00:00Z",
        "2024-06-01T10:00:60Z",
        "2024-06-01T10:00:00+24:00",
        "2024-06-01T10:00:00+00:60",
        "2024-06-01T10:00:00-00:00",
        1717236000,
    ],
)
def test_timestamp_rejects_unsupported_or_invalid_values(value):
    with pytest.raises(ValueError, match="timestamp"):
        parse_timestamp(value)


def test_timestamp_normalizes_offsets_without_truncating():
    expected = datetime(2024, 6, 1, 10, 0, 0, 123456, tzinfo=UTC)
    assert parse_timestamp("2024-06-01T15:30:00.123456+05:30") == expected
    assert parse_timestamp("2024-06-01T06:00:00.123456-04:00") == expected
    assert parse_timestamp("2024-06-01T10:00:00.123Z").microsecond == 123000


def test_missing_optional_fields_remain_unknown_and_default_count_is_disclosed(
    record_factory, parse_rows
):
    row = record_factory(
        cluster=None, namespace=None, node=None, container=None, object_uid=None, uid=None
    )
    for key in ("k8s.event.count",):
        del row["attributes"][key]
    del row["observed_timestamp"]
    del row["severity_text"]
    events, stats = parse_rows([row])
    (event,) = events
    assert event.count == 1 and event.count_defaulted
    assert event.observed_timestamp is None and event.node.affected_node is None
    assert event.object.identity.namespace is None and event.object.identity.cluster is None
    assert event.object.identity.identifier_kind == "name"
    assert event.severity_text == "Unknown" and event.limitations
    assert (
        stats.defaulted_count_records,
        stats.missing_cluster_records,
        stats.missing_namespace_records,
    ) == (1, 1, 1)
    assert event.source_attribution.producer_service == "k8s-events"


def test_extra_metadata_and_json_order_are_preserved(record_factory, parse_rows):
    row = record_factory()
    row["extra"] = {"controller": ["owner-a", {"uid": "u1"}]}
    first = json.dumps(row, sort_keys=True).encode()
    second = json.dumps(row, indent=None, separators=(",", ":")).encode()
    events, _ = parse_rows(first + b"\n" + second)
    assert events[0].provenance.canonical_sha256 == events[1].provenance.canonical_sha256
    assert events[0].provenance.raw_sha256 != events[1].provenance.raw_sha256
    assert json.loads(events[0].canonical_payload)["extra"] == row["extra"]


def test_admission_limits_are_inclusive_and_count_physical_bytes(record_factory, parse_rows):
    row = record_factory(body="\u2603")
    raw = (json.dumps(row, ensure_ascii=False) + "\r\n").encode()
    policy = replace(Policy(), max_input_bytes=len(raw), max_line_bytes=len(raw), max_records=1)
    assert len(parse_rows(raw, policy)[0]) == 1
    for field, code in (("max_input_bytes", "input_limit"), ("max_line_bytes", "line_limit")):
        with pytest.raises(InputError) as error:
            parse_rows(raw, replace(policy, **{field: len(raw) - 1}))
        assert error.value.code == code
    with pytest.raises(InputError) as error:
        parse_rows([row, row], replace(Policy(), max_records=1))
    assert error.value.code == "record_limit" and error.value.line == 2
    events, stats = parse_rows(raw + b"\n\n", replace(Policy(), max_records=1))
    assert len(events) == 1 and stats.blank_line_count == 2


def test_late_malformed_input_has_line_provenance_and_no_partial_output(
    record_factory, parse_rows, capsys
):
    first = json.dumps(record_factory()).encode() + b"\n\n"
    with pytest.raises(InputError) as error:
        parse_rows(first + b"{bad json}")
    assert error.value.line == 3 and capsys.readouterr().out == ""


def test_io_error_is_explicit(tmp_path):
    with pytest.raises(InputError) as error:
        read_events(tmp_path / "missing.jsonl", Policy())
    assert error.value.code == "io_error"


def test_clock_disagreements_are_disclosed_without_fabricating_timestamps(
    record_factory, parse_rows
):
    row = record_factory(at=10, observed=9)
    row["attributes"]["k8s.event.start_time"] = "2024-06-01T00:00:11Z"
    events, _ = parse_rows([row])
    assert len(events[0].limitations) == 2
    assert events[0].timestamp > events[0].observed_timestamp


def test_nested_duplicate_key_error_escapes_terminal_controls(parse_rows):
    with pytest.raises(InputError) as error:
        parse_rows(b'{"\\u001b":1,"\\u001b":2}')
    assert "\x1b" not in str(error.value) and "\\x1b" in str(error.value)


@pytest.mark.parametrize("location", ["key", "nested-value"])
def test_unicode_escape_surrogates_stay_strict_in_extra_metadata(
    location, record_factory, parse_rows
):
    row = record_factory()
    row["extra"] = {"\ud800": "value"} if location == "key" else {"items": ["\udfff"]}
    with pytest.raises(InputError, match="unpaired Unicode surrogate"):
        parse_rows([row])


@pytest.mark.parametrize("escaped", [False, True])
def test_valid_unicode_and_literal_escape_survive_admission(escaped, record_factory, parse_rows):
    row = record_factory(body="probe failed: \U0001f680 and literal \\ud800")
    payload = (json.dumps(row, ensure_ascii=escaped) + "\n").encode("utf-8")
    (event,), _ = parse_rows(payload)
    assert event.body == row["body"]
    assert json.loads(event.canonical_payload) == row


def test_reused_decoder_remains_strict_after_rejected_records(record_factory, parse_rows):
    row = record_factory()
    for invalid in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\\udfff"}'):
        with pytest.raises(InputError):
            parse_rows(invalid)
        (event,), _ = parse_rows([row])
        assert json.loads(event.canonical_payload) == row
