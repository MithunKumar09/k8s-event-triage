from copy import deepcopy
from itertools import permutations

import pytest

from k8s_event_triage.model import Disposition


@pytest.mark.parametrize("span,recurrent", [(119.999, False), (120, True), (120.001, True)])
def test_recurrence_span_boundaries_are_inclusive(span, recurrent, record_factory, analyze):
    rows = [record_factory(uid=f"e-{index}", at=time) for index, time in enumerate((0, 60, span))]
    (evidence,) = analyze(rows)[0].groups[0].evidence
    (episode,) = evidence.episodes
    assert episode.recurrent is recurrent and episode.independent_observations == 3
    assert (episode.last - episode.first).total_seconds() == span


def test_two_observations_cannot_establish_recurrence(record_factory, analyze):
    rows = [record_factory(uid=f"e-{index}", at=time) for index, time in enumerate((0, 120))]
    (episode,) = analyze(rows)[0].groups[0].evidence[0].episodes
    assert not episode.recurrent and episode.independent_observations == 2


@pytest.mark.parametrize("gap,episodes", [(599.999, 1), (600, 1), (600.001, 3)])
def test_adjacent_episode_gap_boundaries(gap, episodes, record_factory, analyze):
    rows = [record_factory(uid=f"e-{index}", at=index * gap) for index in range(3)]
    (evidence,) = analyze(rows)[0].groups[0].evidence
    assert len(evidence.episodes) == episodes
    assert any(item.recurrent for item in evidence.episodes) is (episodes == 1)


def test_distant_transient_bursts_are_not_one_persistent_pattern(record_factory, analyze):
    rows = [
        record_factory(uid=f"e-{index}", at=time)
        for index, time in enumerate((0, 1, 2, 1000, 1001, 1002))
    ]
    (evidence,) = analyze(rows)[0].groups[0].evidence
    assert evidence.counts.observed_occurrences == 6
    assert len(evidence.episodes) == 2 and not any(item.recurrent for item in evidence.episodes)
    assert (evidence.last.timestamp - evidence.first.timestamp).total_seconds() == 1002


def test_cumulative_recurrence_requires_independent_growth_intervals(record_factory, analyze):
    rows = [
        record_factory(count=count, observed=index * 40) for index, count in enumerate((1, 2, 3, 4))
    ]
    (evidence,) = analyze(rows)[0].groups[0].evidence
    (episode,) = evidence.episodes
    assert episode.recurrent and episode.independent_observations == 3
    assert episode.time_basis == "observation_interval" and episode.observed_increments == 3
    assert (episode.last - episode.first).total_seconds() == 120
    assert evidence.first.timestamp == evidence.last.timestamp  # No fabricated occurrence time.
    for counters in ((1, 100), (1, 100, 100, 100), (100, 100, 100, 100)):
        rows = [
            record_factory(count=count, observed=index * 120)
            for index, count in enumerate(counters)
        ]
        (evidence,) = analyze(rows)[0].groups[0].evidence
        assert not any(item.recurrent for item in evidence.episodes)


def test_long_growth_intervals_cannot_bridge_unobserved_time(record_factory, analyze):
    rows = [
        record_factory(count=count, observed=index * 601)
        for index, count in enumerate((1, 2, 3, 4))
    ]
    (evidence,) = analyze(rows)[0].groups[0].evidence
    assert len(evidence.episodes) == 3 and not any(item.recurrent for item in evidence.episodes)
    assert sum(item.observed_increments for item in evidence.episodes) == 3


def test_episodes_are_scoped_by_container_and_failure_signature(record_factory, analyze):
    rows = [
        record_factory(uid=f"e-{index}", at=time, container=container, body=body)
        for index, (time, container, body) in enumerate(
            (
                (0, "app", "Readiness probe failed: timeout"),
                (60, "other", "Readiness probe failed: timeout"),
                (120, "app", "Liveness probe failed: connection refused"),
            )
        )
    ]
    group = analyze(rows)[0].groups[0]
    assert len(group.evidence) == 3
    assert not any(episode.recurrent for item in group.evidence for episode in item.episodes)


def test_rare_specific_signature_survives_many_retries_and_shuffling(record_factory, analyze):
    specific = (
        'Failed to pull image "repo/app:missing": '
        + "x " * 3000
        + "manifest for repo/app:missing not found"
    )
    rows = [
        record_factory(uid=f"retry-{index}", at=index, reason="Failed", body="Error: ErrImagePull")
        for index in range(100)
    ]
    rows.insert(50, record_factory(uid="rare", at=50, reason="Failed", body=specific))
    baseline = analyze(rows)[0].groups[0]
    reverse = analyze(list(reversed(rows)))[0].groups[0]
    assert len(baseline.evidence) == 2
    assert baseline.evidence[0].signature.subtype == "manifest-not-found"
    assert baseline.evidence[0].first.body == specific
    assert baseline.evidence[0].counts.observed_occurrences == 1
    assert baseline.evidence[1].counts.observed_occurrences == 100
    assert [item.id for item in baseline.evidence] == [item.id for item in reverse.evidence]
    assert [item.first.provenance.record_id for item in baseline.evidence] == [
        item.first.provenance.record_id for item in reverse.evidence
    ]
    assert [item.last.provenance.record_id for item in baseline.evidence] == [
        item.last.provenance.record_id for item in reverse.evidence
    ]


def test_representatives_use_timestamps_identity_and_digest_not_arrival(record_factory, analyze):
    rows = [record_factory(uid=uid, at=at) for uid, at in (("z", 120), ("b", 0), ("a", 0))]
    baseline = analyze(rows)[0].groups[0].evidence[0]
    assert baseline.first.event_uid == "a" and baseline.last.event_uid == "z"
    for order in permutations(rows):
        candidate = analyze(list(order))[0].groups[0].evidence[0]
        assert candidate.id == baseline.id and candidate.episodes == baseline.episodes
        assert candidate.first.provenance.record_id == baseline.first.provenance.record_id
        assert candidate.last.provenance.record_id == baseline.last.provenance.record_id


def test_unclassified_and_contradictory_variants_are_not_dropped(record_factory, analyze):
    bodies = [
        "Unrecognized driver failure A",
        "Unrecognized driver failure B",
        'Failed to pull image "repo/app:v1": unauthorized: access denied',
        'Failed to pull image "repo/app:v1": manifest not found',
    ]
    group = analyze(
        [
            record_factory(uid=f"e-{index}", reason="Failed", body=body)
            for index, body in enumerate(bodies)
        ]
    )[0].groups[0]
    assert len(group.evidence) == 4
    assert {item.first.body for item in group.evidence} == set(bodies)
    assert {item.signature.subtype for item in group.evidence} >= {
        "manifest-not-found",
        "access-denied",
    }


def test_noise_insertion_cannot_change_or_bridge_failure_episodes(record_factory, analyze):
    failures = [
        record_factory(uid=f"failure-{index}", at=time)
        for index, time in enumerate((0, 1, 2, 1200, 1201, 1202))
    ]
    baseline = analyze(failures)[0]
    noise = [
        record_factory(
            uid=f"noise-{index}",
            at=time,
            reason="Started",
            severity="Normal",
            body="Started container app",
        )
        for index, time in enumerate((300, 600, 900))
    ]
    result = analyze(failures + noise)[0]
    before = [
        item
        for group in baseline.groups
        for item in group.evidence
        if item.disposition == Disposition.SIGNAL
    ]
    after = [
        item
        for group in result.groups
        for item in group.evidence
        if item.disposition == Disposition.SIGNAL
    ]
    assert [(item.id, item.episodes, item.counts) for item in before] == [
        (item.id, item.episodes, item.counts) for item in after
    ]
    assert result.noise_record_count == 3


def test_cumulative_container_change_preserves_series_without_allocating_totals(
    record_factory, analyze
):
    rows = [
        record_factory(count=count, container=container, observed=index * 60)
        for index, (count, container) in enumerate(((1, "one"), (2, "two"), (3, "two")))
    ]
    group = analyze(rows)[0].groups[0]
    assert group.counts.source_reported_total == 3 and len(group.evidence) == 2
    assert all(
        item.counts.source_reported_total is None and item.episodes == () for item in group.evidence
    )


def test_count_mode_and_policy_digest_travel_with_finalization(record_factory, analyze):
    for mode in ("occurrence", "cumulative", "auto"):
        result = analyze([record_factory()], mode)[0]
        assert result.requested_count_mode == mode and len(result.effective_policy_sha256) == 64
    changed = deepcopy(record_factory())
    changed["observed_timestamp"] = "2024-06-01T00:00:00.000001Z"
    result, events, _ = analyze([record_factory(), changed], "occurrence")
    assert result.groups[0].counts.observed_occurrences == 2
    assert events[0].provenance.canonical_sha256 != events[1].provenance.canonical_sha256
