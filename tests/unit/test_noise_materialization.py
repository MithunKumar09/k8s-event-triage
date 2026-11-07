"""Report-only noise materialization must preserve the complete analysis contract."""

import pytest

from k8s_event_triage.correlate import build_report
from k8s_event_triage.group import aggregate
from k8s_event_triage.parse import InputError
from k8s_event_triage.policy import Policy
from k8s_event_triage.render import render


def compare(rows, parse_rows, mode="auto"):
    policy = Policy(count_mode=mode)
    events, stats = parse_rows(rows, policy)
    full = aggregate(events, policy)
    light = aggregate(events, policy, include_noise_groups=False)
    for field in (
        "input_record_count",
        "noise_record_count",
        "context_record_count",
        "signal_record_count",
        "repeated_payload_candidates",
    ):
        assert getattr(full, field) == getattr(light, field)
    before, after = (build_report(value, events, stats, policy) for value in (full, light))
    for structured in (False, True):
        assert render(before, json_output=structured) == render(after, json_output=structured)
    assert len(events) == stats.input_record_count == len(rows)
    assert all(event.provenance.line == index + 1 for index, event in enumerate(events))
    return full, light, events


@pytest.mark.parametrize("mode", ["auto", "occurrence", "cumulative"])
def test_identical_normal_rows_keep_multiplicity_and_count_disclosures(
    mode, record_factory, parse_rows
):
    row = record_factory(reason="Started", body="Started container app", severity="Normal")
    full, light, events = compare([row] * 3, parse_rows, mode)
    assert light.noise_record_count == full.input_record_count == len(events) == 3
    assert light.repeated_payload_candidates == 2
    if mode == "occurrence":
        assert not light.groups
    else:
        assert light.groups == full.groups


@pytest.mark.parametrize(
    "kind,reason,body,severity",
    [
        ("Pod", "Pulling", 'Pulling image "repo/app:v1"', "Normal"),
        ("Pod", "Pulled", 'Successfully pulled image "repo/app:v1"', "Normal"),
        ("Pod", "Created", "Created container app", "Normal"),
        ("Pod", "Started", "Started container app", "Warning"),
        ("Pod", "Killing", "Stopping container app", "Normal"),
        ("Pod", "Killing", "Stopping container app; OOMKilled", "Normal"),
        ("Pod", "Created", "Failed to create container: runtime error", "Normal"),
        ("Pod", "BackOff", 'Back-off pulling image "repo/app:v1"', "Normal"),
        (
            "Pod",
            "Scheduled",
            "Successfully assigned production/api-abcdef123-pod1 to node-a",
            "Normal",
        ),
        ("ReplicaSet", "SuccessfulCreate", "Created pod: api-abcdef123-pod1", "Normal"),
        ("Deployment", "ScalingReplicaSet", "Scaled up replica set api-abcdef123 to 3", "Normal"),
        ("Node", "NodeHasDiskPressure", "Node has DiskPressure", "Normal"),
    ],
)
def test_lifecycle_and_failure_context_matches_full_path(
    kind, reason, body, severity, record_factory, parse_rows
):
    compare([record_factory(kind=kind, reason=reason, body=body, severity=severity)], parse_rows)


def test_mixed_noise_and_oom_keep_complete_reason_group(record_factory, parse_rows):
    rows = [
        record_factory(uid="ordinary", reason="Killing", body="Stopping container app"),
        record_factory(uid="oom", reason="Killing", body="Stopping container app; OOMKilled"),
    ]
    full, light, _ = compare(rows, parse_rows)
    assert light.groups == full.groups
    assert light.groups[0].counts.observed_occurrences == 2
    assert light.groups[0].evidence[0].counts.observed_occurrences == 1


@pytest.mark.parametrize("mode", ["auto", "cumulative", "occurrence"])
def test_nonoccurrence_noise_still_uses_strict_counter_resolution(mode, record_factory, parse_rows):
    rows = [
        record_factory(count=count, observed=index, reason="Started", body="Started container app")
        for index, count in enumerate((1, 2, 3))
    ]
    if mode == "occurrence":
        events, _ = parse_rows(rows)
        with pytest.raises(InputError, match="occurrence mode"):
            aggregate(events, Policy(count_mode=mode), include_noise_groups=False)
    else:
        full, light, _ = compare(rows, parse_rows, mode)
        assert light.groups == full.groups


def test_missing_noise_identity_stays_disclosed(record_factory, parse_rows):
    row = record_factory(uid=None, reason="Started", body="Started container app")
    full, light, _ = compare([row], parse_rows)
    assert light.groups == full.groups and light.groups[0].counts.mode == "ambiguous"


def test_noise_series_identity_conflict_is_not_hidden(record_factory, parse_rows):
    rows = [
        record_factory(reason="Started", body="Started container app", object_uid=value)
        for value in ("one", "two")
    ]
    events, _ = parse_rows(rows)
    with pytest.raises(InputError, match="identity conflicts"):
        aggregate(events, Policy(), include_noise_groups=False)
