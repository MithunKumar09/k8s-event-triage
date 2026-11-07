from itertools import permutations

import pytest

from k8s_event_triage.model import CountQuality
from k8s_event_triage.parse import InputError


@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
def test_identical_count_one_records_keep_multiplicity(mode, record_factory, analyze):
    row = record_factory()
    result, events, _ = analyze([row, row, row], mode)
    counts = result.groups[0].counts
    assert len(events) == counts.input_record_count == result.input_record_count == 3
    assert result.repeated_payload_candidates == 2
    (evidence,) = result.groups[0].evidence
    assert len(evidence.source_references) == 3
    assert evidence.first.timestamp == evidence.last.timestamp
    assert not any(episode.recurrent for episode in evidence.episodes)
    if mode == "occurrence":
        assert counts.observed_occurrences == 3 and counts.occurrence_quality == CountQuality.EXACT
        assert (
            counts.source_reported_total is None and counts.cumulative_no_growth_observations == 0
        )
    elif mode == "cumulative":
        assert counts.observed_occurrences is None
        assert (counts.source_reported_total, counts.observed_increments) == (1, 0)
        assert counts.cumulative_no_growth_observations == 2
    else:
        assert counts.observed_occurrences is None
        assert (counts.occurrence_lower_bound, counts.occurrence_upper_bound) == (1, 3)
        assert counts.occurrence_quality == CountQuality.AMBIGUOUS and counts.limitations


@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
def test_same_identity_count_one_at_different_times(mode, record_factory, analyze):
    rows = [record_factory(at=time) for time in (0, 60, 120)]
    result, _, _ = analyze(rows, mode)
    counts = result.groups[0].counts
    (evidence,) = result.groups[0].evidence
    assert (evidence.last.timestamp - evidence.first.timestamp).total_seconds() == 120
    if mode == "occurrence":
        assert counts.observed_occurrences == 3 and evidence.episodes[0].recurrent
    elif mode == "cumulative":
        assert (counts.source_reported_total, counts.observed_increments) == (1, 0)
        assert evidence.episodes == ()
    else:
        assert counts.observed_occurrences is None
        assert (counts.occurrence_lower_bound, counts.occurrence_upper_bound) == (1, 3)
        assert evidence.episodes == ()


@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
def test_distinct_identities_count_one_are_independent_under_assessment(
    mode, record_factory, analyze
):
    rows = [record_factory(uid=f"event-{index}", at=index * 60) for index in range(3)]
    result, _, _ = analyze(rows, mode)
    counts = result.groups[0].counts
    assert counts.input_record_count == 3 and len(result.groups[0].series) == 3
    if mode == "cumulative":
        assert (counts.source_reported_total, counts.observed_increments) == (3, 0)
        assert counts.observed_occurrences is None
    else:
        assert counts.observed_occurrences == 3 and counts.occurrence_quality == CountQuality.EXACT


@pytest.mark.parametrize(
    "snapshots,total,growth,no_growth",
    [
        ([1, 2, 3], 3, 2, 0),
        ([1, 1, 2, 3], 3, 2, 1),
        ([5, 7, 7], 7, 2, 1),
        ([3, 3], 3, 0, 1),
    ],
)
@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
def test_mandatory_cumulative_examples(
    snapshots, total, growth, no_growth, mode, record_factory, analyze
):
    rows = [
        record_factory(count=value, observed=index * 60) for index, value in enumerate(snapshots)
    ]
    if snapshots[:2] == [1, 1]:
        rows[1] = rows[0]  # First two snapshots are completely identical, not just equal counters.
    if mode == "occurrence":
        with pytest.raises(InputError, match="occurrence mode"):
            analyze(rows, mode)
        return
    result, _, _ = analyze(rows, mode)
    counts = result.groups[0].counts
    assert counts.mode == "cumulative" and counts.observed_occurrences is None
    assert (counts.source_reported_total, counts.observed_increments) == (total, growth)
    assert counts.cumulative_no_growth_observations == no_growth
    assert counts.input_record_count == len(snapshots)
    assert counts.increment_quality == counts.source_total_quality == CountQuality.EXACT


def test_input_permutations_preserve_count_mode_and_quantities(record_factory, analyze):
    for snapshots in ([1, 2, 3], [5, 7, 7], [1, 1, 1]):
        rows = [
            record_factory(count=count, at=120 - index * 60, observed=index * 60)
            for index, count in enumerate(snapshots)
        ]
        baseline = analyze(rows)[0].groups[0]
        for order in permutations(rows):
            group = analyze(list(order))[0].groups[0]
            assert group.counts == baseline.counts
            assert [item.id for item in group.evidence] == [item.id for item in baseline.evidence]
            assert [item.first.provenance.record_id for item in group.evidence] == [
                item.first.provenance.record_id for item in baseline.evidence
            ]


def test_append_contracts_for_all_modes(record_factory, analyze):
    row = record_factory()
    for mode in ("occurrence", "cumulative", "auto"):
        before = analyze([row, row], mode)[0].groups[0].counts
        after = analyze([row, row, row], mode)[0].groups[0].counts
        assert after.input_record_count == before.input_record_count + 1
        if mode == "occurrence":
            assert after.observed_occurrences == before.observed_occurrences + 1
        elif mode == "cumulative":
            assert after.source_reported_total == before.source_reported_total == 1
            assert after.observed_increments == before.observed_increments == 0
            assert (
                after.cumulative_no_growth_observations
                == before.cumulative_no_growth_observations + 1
            )
        else:
            assert after.observed_occurrences is before.observed_occurrences is None
            assert after.occurrence_upper_bound == before.occurrence_upper_bound + 1


def test_distinct_uids_with_identical_messages_and_times_are_not_duplicates(
    record_factory, analyze
):
    rows = [record_factory(uid=f"e-{index}") for index in range(3)]
    result, _, _ = analyze(rows)
    assert result.groups[0].counts.observed_occurrences == 3
    assert result.repeated_payload_candidates == 0


def test_changed_observation_metadata_is_not_payload_equality(record_factory, analyze):
    result, _, _ = analyze([record_factory(observed=time) for time in (0, 60, 120)])
    assert result.repeated_payload_candidates == 0
    assert result.groups[0].counts.mode == "ambiguous"


def test_namespaced_event_name_fallback_is_labelled(record_factory, analyze):
    rows = [
        record_factory(uid=None, count=count, observed=index) for index, count in enumerate((1, 3))
    ]
    for row in rows:
        row["attributes"]["k8s.event.name"] = "api-event"
    group = analyze(rows, "cumulative")[0].groups[0]
    assert (group.counts.source_reported_total, group.counts.observed_increments) == (3, 2)
    assert group.series[0].identity.basis == "event_name"
    assert any("inferred" in text for text in group.counts.limitations)


def test_missing_series_identity_discloses_ambiguity_or_errors(record_factory, analyze):
    row = record_factory(uid=None)
    group = analyze([row, row, row])[0].groups[0]
    assert group.counts.observed_occurrences is None
    assert (group.counts.occurrence_lower_bound, group.counts.occurrence_upper_bound) == (1, 3)
    with pytest.raises(InputError, match="requires an event UID"):
        analyze([row], "cumulative")
    row["attributes"]["k8s.event.count"] = 5
    with pytest.raises(InputError, match="requires an event UID"):
        analyze([row])


@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
@pytest.mark.parametrize("change", ["object", "reason", "namespace"])
def test_one_event_uid_cannot_identify_conflicting_objects_or_reasons(
    mode, change, record_factory, analyze
):
    first, second = record_factory(), record_factory()
    if change == "object":
        second["resource"]["k8s.object.uid"] = "different-pod"
    elif change == "reason":
        second["attributes"]["k8s.event.reason"] = "Failed"
    else:
        second["attributes"]["k8s.namespace.name"] = "another"
    with pytest.raises(InputError, match="conflicts"):
        analyze([first, second], mode)


def test_series_uids_are_cluster_isolated(record_factory, analyze):
    result, _, _ = analyze(
        [record_factory(cluster=cluster, count=3) for cluster in ("a", "b", None)]
    )
    assert len(result.groups) == 3
    assert all(group.counts.source_reported_total == 3 for group in result.groups)


@pytest.mark.parametrize("problem", ["missing", "conflicting"])
def test_unusable_chronology_preserves_maximum_without_invented_growth(
    problem, record_factory, analyze
):
    rows = [record_factory(count=5, observed=0), record_factory(count=7, observed=60)]
    if problem == "missing":
        del rows[1]["observed_timestamp"]
    else:
        rows[1]["observed_timestamp"] = rows[0]["observed_timestamp"]
    counts = analyze(rows)[0].groups[0].counts
    assert counts.source_reported_total == 7 and counts.observed_increments is None
    assert counts.increment_quality == CountQuality.UNAVAILABLE and counts.limitations


def test_event_time_does_not_replace_counter_observation_chronology(record_factory, analyze):
    rows = [
        record_factory(count=count, at=120 - index * 60, observed=index * 60)
        for index, count in enumerate((1, 2, 3))
    ]
    counts = analyze(rows)[0].groups[0].counts
    assert counts.source_reported_total == 3 and counts.observed_increments == 2


def test_decrease_is_lower_bound_not_invented_reset_segments(record_factory, analyze):
    rows = [
        record_factory(count=count, observed=index * 60) for index, count in enumerate((1, 5, 2, 4))
    ]
    group = analyze(list(reversed(rows)))[0].groups[0]
    assert group.counts.source_reported_total == 5 and group.counts.observed_increments is None
    assert group.counts.source_total_quality == CountQuality.LOWER_BOUND
    assert group.series[0].growth_intervals == ()


def test_new_event_uid_is_a_separate_counter_series(record_factory, analyze):
    rows = [
        record_factory(uid=uid, count=count, observed=time)
        for uid, count, time in (("a", 1, 0), ("a", 3, 60), ("b", 5, 120), ("b", 7, 180))
    ]
    counts = analyze(rows)[0].groups[0].counts
    assert (counts.source_reported_total, counts.observed_increments) == (10, 4)


def test_mixed_modes_expose_separate_quantities(record_factory, analyze):
    rows = [
        record_factory(uid="occurrence"),
        record_factory(uid="series", count=2, observed=1),
        record_factory(uid="series", count=4, observed=2),
    ]
    counts = analyze(rows)[0].groups[0].counts
    assert counts.mode == "mixed"
    assert (
        counts.observed_occurrences,
        counts.source_reported_total,
        counts.observed_increments,
    ) == (1, 4, 2)
    assert counts.occurrence_quality == CountQuality.LOWER_BOUND
    assert counts.occurrence_lower_bound is counts.occurrence_upper_bound is None


def test_known_occurrences_and_ambiguous_repeats_retain_bounds(record_factory, analyze):
    repeated = record_factory(uid="ambiguous")
    counts = (
        analyze([record_factory(uid="independent"), repeated, repeated, repeated])[0]
        .groups[0]
        .counts
    )
    assert counts.mode == "mixed" and counts.observed_occurrences == 1
    assert (counts.occurrence_lower_bound, counts.occurrence_upper_bound) == (2, 4)


def test_counters_are_not_allocated_across_changing_diagnostic_facets(record_factory, analyze):
    rows = [
        record_factory(count=count, observed=index * 60, reason="Failed", body=body)
        for index, (count, body) in enumerate(
            (
                (1, "Error: ErrImagePull"),
                (2, 'Failed to pull image "repo/app:bad": manifest not found'),
                (3, "Error: ImagePullBackOff"),
            )
        )
    ]
    group = analyze(rows)[0].groups[0]
    assert (group.counts.source_reported_total, group.counts.observed_increments) == (3, 2)
    assert len(group.evidence) == 3
    for item in group.evidence:
        assert item.counts.source_reported_total is item.counts.observed_increments is None
        assert item.counts.source_total_quality == CountQuality.UNAVAILABLE
        assert item.episodes == () and item.counts.limitations


def test_count_resolution_precedes_noise_filtering(record_factory, analyze):
    rows = [
        record_factory(
            count=2, reason="Pulling", body='Pulling image "repo/app:v1"', severity="Normal"
        )
    ]
    with pytest.raises(InputError, match="occurrence mode"):
        analyze(rows, "occurrence")
    counts = analyze(rows, "auto")[0].groups[0].counts
    assert counts.mode == "cumulative" and counts.source_reported_total == 2
