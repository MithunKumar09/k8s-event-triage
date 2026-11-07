import json
from dataclasses import asdict
from itertools import permutations

import pytest

from k8s_event_triage.group import combine_counts
from k8s_event_triage.model import Confidence, CountQuality, Severity
from k8s_event_triage.render import render


@pytest.mark.parametrize(
    "kind,reason,body,severity,issues",
    [
        ("Pod", "OOMKilling", "Container app exceeded memory limit (512Mi)", "critical", 1),
        ("Pod", "Killing", "Container app was OOMKilled", "critical", 1),
        ("Node", "NodeNotReady", "Node is not ready", "critical", 1),
        ("Node", "NodeHasDiskPressure", "Node has DiskPressure", "critical", 1),
        ("Pod", "BackOff", "Back-off restarting failed container app in pod api", "critical", 0),
        ("Pod", "Failed", 'Failed to pull image "repo/app:bad": manifest not found', "critical", 1),
        ("Pod", "Failed", 'Failed to pull image "repo/app:bad": unauthorized', "critical", 1),
        ("Pod", "Failed", "container setup failed", "critical", 0),
        ("Pod", "FailedCreatePodSandBox", "CNI setup failed", "critical", 0),
        ("Pod", "FailedScheduling", "0/3 nodes: Insufficient cpu", "warning", 0),
        ("Pod", "Unhealthy", "Readiness probe failed: timeout", "warning", 0),
        ("Pod", "Unhealthy", "Liveness probe failed: timeout", "warning", 0),
        ("Pod", "FailedMount", 'MountVolume.SetUp failed: configmap "cfg" not found', "warning", 0),
        ("Pod", "Evicted", "The node had condition: [MemoryPressure].", "warning", 0),
        ("Pod", "UnknownReason", "new driver warning", "warning", 0),
        ("Pod", "Killing", "Container app failed liveness probe, will be restarted", "warning", 1),
    ],
)
def test_reason_specific_direct_and_transient_rules(
    kind, reason, body, severity, issues, record_factory, triage
):
    report = triage(
        [
            record_factory(
                kind=kind,
                reason=reason,
                body=body,
                severity="Normal" if reason == "Failed" else "Warning",
            )
        ]
    )
    assert len(report.incidents) == issues
    finding = report.incidents[0].members[0] if issues else report.observations[0]
    assert finding.diagnosis.severity == severity
    assert finding.diagnosis.evidence_ids and finding.evidence.first.body == body


@pytest.mark.parametrize(
    "reason,body,severity",
    [
        ("BackOff", "Back-off restarting failed container app in pod api", Severity.CRITICAL),
        ("Failed", "container setup failed", Severity.CRITICAL),
        ("FailedCreatePodSandBox", "CNI setup failed", Severity.CRITICAL),
        ("FailedScheduling", "0/3 nodes: Insufficient cpu", Severity.WARNING),
        ("Unhealthy", "Readiness probe failed: timeout", Severity.WARNING),
        ("Unhealthy", "Liveness probe failed: timeout", Severity.WARNING),
        ("FailedMount", 'MountVolume.SetUp failed: configmap "cfg" not found', Severity.WARNING),
        ("Evicted", "The node had condition: [MemoryPressure].", Severity.WARNING),
        ("UnknownReason", "new driver warning", Severity.WARNING),
    ],
)
def test_supported_recurrence_promotes_by_reason(reason, body, severity, record_factory, triage):
    rows = [
        record_factory(uid=f"e-{index}", at=time, reason=reason, body=body)
        for index, time in enumerate((0, 60, 120))
    ]
    report = triage(rows)
    assert len(report.incidents) == 1 and report.incidents[0].severity == severity
    assert report.incidents[0].recurrent
    assert "uninterrupted outage" in report.incidents[0].hypothesis


def test_readiness_multi_pod_burst_and_generic_lifecycle_do_not_bypass_duration(
    record_factory, triage
):
    rows = [
        record_factory(
            uid=f"e-{index}",
            object_uid=f"p-{index % 2}",
            name=f"app-abcdef123-{'aaaaa' if index % 2 else 'bbbbb'}",
            at=index,
        )
        for index in range(6)
    ]
    rows.append(
        record_factory(
            uid="normal", reason="Started", body="Started container app", severity="Normal", at=200
        )
    )
    assert triage(rows).incidents == ()


def test_liveness_termination_is_corroboration_but_readiness_started_is_not(record_factory, triage):
    rows = [
        record_factory(uid="probe", body="Liveness probe failed: timeout"),
        record_factory(
            uid="kill",
            at=10,
            reason="Killing",
            body="Container app failed liveness probe, will be restarted",
        ),
    ]
    report = triage(rows)
    assert len(report.incidents) == 1 and len(report.incidents[0].members) == 2
    assert report.incidents[0].severity == Severity.WARNING
    ordinary = [
        record_factory(uid="readiness"),
        record_factory(
            uid="start", at=200, reason="Started", body="Started container app", severity="Normal"
        ),
    ]
    assert triage(ordinary).incidents == ()


def test_generic_image_pair_reports_normal_backoff_with_separate_reason_counts(
    record_factory, triage
):
    rows = [
        record_factory(uid="failed", reason="Failed", body="Error: ErrImagePull"),
        record_factory(
            uid="backoff",
            at=30,
            reason="BackOff",
            severity="Normal",
            body='Back-off pulling image "repo/app:v1"',
        ),
    ]
    report = triage(rows)
    assert len(report.incidents) == 1
    assert {
        part.reason: part.counts.observed_occurrences for part in report.incidents[0].reason_counts
    } == {"Failed": 1, "BackOff": 1}


def test_setup_corroboration_is_specific_and_not_image_diagnosis(record_factory, triage):
    rows = [
        record_factory(uid="failed", reason="Failed", body="Failed to create container sandbox"),
        record_factory(
            uid="sandbox", at=30, reason="FailedCreatePodSandBox", body="CNI sandbox setup rejected"
        ),
    ]
    report = triage(rows)
    assert len(report.incidents) >= 1
    assert all(
        member.diagnosis.reportable for incident in report.incidents for member in incident.members
    )
    assert not any(
        member.evidence.signature.family == "image"
        for incident in report.incidents
        for member in incident.members
    )


def test_workload_oom_restart_synthesis_preserves_members_counts_confidence(record_factory, triage):
    rows = []
    for index, suffix in enumerate(("aaaaa", "bbbbb")):
        values = {"name": f"shop-abcdef123-{suffix}", "object_uid": f"pod-{index}"}
        rows.extend(
            [
                record_factory(
                    uid=f"oom-{index}",
                    reason="OOMKilling",
                    at=index,
                    body="Container app exceeded memory limit (512Mi)",
                    **values,
                ),
                record_factory(
                    uid=f"restart-{index}",
                    reason="BackOff",
                    at=index + 10,
                    body="Back-off restarting failed container app in pod shop",
                    **values,
                ),
            ]
        )
    report = triage(rows)
    (incident,) = report.incidents
    assert incident.scope == "workload" and incident.name == "shop"
    assert len(incident.affected_objects) == 2 and len(incident.members) == 4
    assert {
        value.reason: value.counts.observed_occurrences for value in incident.reason_counts
    } == {"OOMKilling": 2, "BackOff": 2}
    assert incident.confidence == Confidence.HIGH
    assert all(
        item.attribution.basis == "inferred" and item.attribution.confidence == Confidence.MEDIUM
        for item in incident.members
    )
    assert len({item.id for item in incident.members}) == 4
    assert report.observations == ()


@pytest.mark.parametrize(
    "variant",
    [
        "different-cause",
        "different-image",
        "contradictory-image",
        "different-limit",
        "different-namespace",
        "different-cluster",
    ],
)
def test_unrelated_workload_mechanisms_or_scopes_stay_separate(variant, record_factory, triage):
    first = record_factory(
        uid="a",
        name="shop-abcdef123-aaaaa",
        object_uid="p1",
        reason="Failed",
        body='Failed to pull image "repo/app:v1": manifest not found',
    )
    second = record_factory(
        uid="b",
        name="shop-abcdef123-bbbbb",
        object_uid="p2",
        reason="Failed",
        body='Failed to pull image "repo/app:v1": manifest not found',
    )
    if variant == "different-cause":
        second["attributes"]["k8s.event.reason"] = "OOMKilling"
        second["body"] = "Container app exceeded memory limit (512Mi)"
    elif variant == "different-image":
        second["body"] = 'Failed to pull image "repo/other:v1": manifest not found'
    elif variant == "contradictory-image":
        second["body"] = 'Failed to pull image "repo/app:v1": unauthorized'
    elif variant == "different-limit":
        first["attributes"]["k8s.event.reason"] = second["attributes"]["k8s.event.reason"] = (
            "OOMKilling"
        )
        first["body"] = "Container app exceeded memory limit (512Mi)"
        second["body"] = "Container app exceeded memory limit (1Gi)"
    elif variant == "different-namespace":
        second["attributes"]["k8s.namespace.name"] = "other"
    else:
        second["resource"]["k8s.cluster.name"] = "other"
    assert len(triage([first, second]).incidents) == 2


def test_no_transitive_connected_component_synthesis(record_factory, triage):
    rows = [
        record_factory(
            uid=f"e-{index}",
            name=f"shop-abcdef123-{suffix}",
            object_uid=f"p-{index}",
            at=time,
            reason="OOMKilling",
            body="Container app exceeded memory limit (512Mi)",
        )
        for index, (suffix, time) in enumerate((("aaaaa", 0), ("bbbbb", 100), ("ccccc", 200)))
    ]
    report = triage(rows)
    assert len(report.incidents) == 2
    assert sorted(len(item.members) for item in report.incidents) == [1, 2]


def test_quiet_gaps_and_ambiguous_repetition_never_create_persistence(record_factory, triage):
    rows = [
        record_factory(uid=f"e-{index}", at=time)
        for index, time in enumerate((0, 1, 2, 1200, 1201, 1202))
    ]
    assert triage(rows).incidents == ()
    repeated = [record_factory(at=time) for time in (0, 60, 120)]
    report = triage(repeated)
    assert report.incidents == ()
    assert report.observations[0].evidence.counts.occurrence_quality == CountQuality.AMBIGUOUS
    assert report.series_disclosures[0].counts.input_record_count == 3


def test_nested_mixed_count_summaries_preserve_cumulative_quantities(record_factory, analyze):
    rows = [
        record_factory(uid="one"),
        record_factory(uid="series", count=2, observed=1),
        record_factory(uid="series", count=4, observed=2),
    ]
    mixed = analyze(rows)[0].groups[0].counts
    independent = analyze([record_factory(uid="other")])[0].groups[0].counts
    combined = combine_counts((mixed, independent))
    assert (
        combined.observed_occurrences,
        combined.source_reported_total,
        combined.observed_increments,
    ) == (2, 4, 2)
    assert combined.mode == "mixed" and combined.occurrence_quality == CountQuality.LOWER_BOUND


def test_prioritization_does_not_compare_lifetime_counters_to_occurrences(record_factory, triage):
    rows = [
        record_factory(
            uid=f"e-{index}",
            object_uid="observed",
            name="observed-pod",
            reason="OOMKilling",
            body="Container app was OOMKilled",
        )
        for index in range(3)
    ]
    rows.append(
        record_factory(
            uid="lifetime",
            count=1_000_000,
            object_uid="counter",
            name="counter-pod",
            reason="OOMKilling",
            body="Container app was OOMKilled",
        )
    )
    report = triage(rows)
    assert len(report.incidents) == 2
    assert report.incidents[0].members[0].object.name == "observed-pod"
    assert report.incidents[1].reason_counts[0].counts.source_reported_total == 1_000_000


def test_text_json_determinism_full_evidence_and_semantic_shuffle_invariance(
    record_factory, triage
):
    specific = 'Failed to pull image "repo/app:bad": ' + "details " * 1000 + "manifest not found"
    rows = [
        record_factory(uid="terminal", reason="Failed", body=specific),
        record_factory(uid="generic", reason="Failed", body="Error: ErrImagePull", at=1),
        record_factory(
            uid="backoff",
            reason="BackOff",
            body='Back-off pulling image "repo/app:bad"',
            at=2,
            severity="Normal",
        ),
    ]
    report = triage(rows)
    assert render(report) == render(report) and render(report, json_output=True) == render(
        report, json_output=True
    )
    assert b"manifest not found" in render(report)
    payload = json.loads(render(report, json_output=True))
    assert payload["incidents"][0]["members"][0]["evidence"]["first"]["body"] == specific
    assert "generated_at" not in payload
    baseline = [
        (item.id, [(member.id, asdict(member.evidence.counts)) for member in item.members])
        for item in report.incidents
    ]
    for order in permutations(rows):
        other = triage(list(order))
        assert [
            (item.id, [(member.id, asdict(member.evidence.counts)) for member in item.members])
            for item in other.incidents
        ] == baseline
