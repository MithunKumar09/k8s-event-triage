import hashlib
import json
from dataclasses import FrozenInstanceError, asdict, replace

import pytest

from k8s_event_triage.group import aggregate
from k8s_event_triage.model import order_events
from k8s_event_triage.policy import Policy


def test_canonical_values_keep_each_original_record_and_public_serialization(
    record_factory, parse_rows
):
    rows = [
        record_factory(uid=f"e-{index}", body=f"message {index} \U0001f680") for index in range(3)
    ]
    for index, row in enumerate(rows):
        row["extra"] = {"values": [index, True, -0.0, "\\ud800"]}
    events, _ = parse_rows(rows)
    for event, row in zip(events, rows, strict=True):
        expected = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        assert event.canonical_payload == expected
        assert event.provenance.canonical_sha256 == hashlib.sha256(expected.encode()).hexdigest()
        serialized = asdict(event)
        assert serialized["canonical_payload"] == expected
        assert set(serialized["provenance"]) == {
            "source",
            "line",
            "byte_offset",
            "raw_sha256",
            "canonical_sha256",
        }
        assert replace(event).canonical_payload == expected
        with pytest.raises(FrozenInstanceError):
            event.canonical_payload = "changed"
        with pytest.raises(FrozenInstanceError):
            event.provenance.canonical_sha256 = "changed"


def test_repeated_payloads_ignore_only_json_layout_not_scalar_types(record_factory, parse_rows):
    row = record_factory(reason="Started", body="Started container app")
    first = json.dumps(row, sort_keys=True).encode() + b"\r\n"
    second = json.dumps(row, separators=(",", ":")).encode() + b"\n"
    events, _ = parse_rows(first + second)
    grouped = aggregate(events, Policy(), include_noise_groups=False)
    assert grouped.repeated_payload_candidates == 1
    assert events[0].provenance.raw_sha256 != events[1].provenance.raw_sha256
    rows = []
    for value in (True, 1, 1.0):
        candidate = dict(row, extra=value)
        rows.append(candidate)
    events, _ = parse_rows(rows)
    assert aggregate(events, Policy()).repeated_payload_candidates == 0


def test_two_stage_event_order_matches_full_digest_order(record_factory, parse_rows):
    rows = [
        record_factory(uid=uid, at=at, body=body)
        for uid, at, body in (
            ("z", 1, "z"),
            ("a", 0, "z"),
            ("a", 0, "a"),
            (None, 0, "b"),
            ("a", 0, "a"),
        )
    ]
    events, _ = parse_rows(rows)
    expected = sorted(events, key=lambda event: event.sort_key)
    assert order_events(reversed(events)) == expected


def test_deep_and_brace_rich_metadata_retains_original_canonicalization(record_factory, parse_rows):
    row = record_factory(body="normal data " + "{" * 150)
    nested = "leaf"
    for _ in range(150):
        nested = [nested]
    row["extra"] = nested
    (event,), _ = parse_rows([row])
    assert json.loads(event.canonical_payload) == row


def test_context_catalog_keeps_first_source_for_duplicate_controller_records(
    record_factory, triage
):
    scale = record_factory(
        uid="scale",
        kind="Deployment",
        name="service",
        object_uid="deployment",
        at=0,
        reason="ScalingReplicaSet",
        body="Scaled up replica set service-template to 3",
        severity="Normal",
    )
    create = record_factory(
        uid="create",
        kind="ReplicaSet",
        name="service-template",
        object_uid="rs",
        at=1,
        reason="SuccessfulCreate",
        body="Created pod: api-abcdef123-pod1",
        severity="Normal",
    )
    failure = record_factory(
        uid="oom", at=2, reason="OOMKilling", body="Container app was OOMKilled"
    )
    report = triage([scale, scale, create, failure])
    context = [event for event in report.context_evidence if event.reason == "ScalingReplicaSet"]
    assert len(context) == 1 and context[0].provenance.line == 1
