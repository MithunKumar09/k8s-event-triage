from pathlib import Path

import pytest

from k8s_event_triage.group import aggregate
from k8s_event_triage.model import Disposition
from k8s_event_triage.parse import read_events
from k8s_event_triage.policy import Policy

_INPUTS = Path(__file__).resolve().parents[2] / "test-cases"


@pytest.fixture(scope="module")
def known_inputs():
    results = {}
    for name in ("01-healthy.jsonl", "02-memory-leak.jsonl", "03-image-pull-failure.jsonl"):
        events, stats = read_events(_INPUTS / name, Policy())
        results[name] = (aggregate(events, Policy()), events, stats)
    return results


def test_known_inputs_preserve_20k_rows_and_independent_count_contract(known_inputs):
    for result, events, stats in known_inputs.values():
        assert result.input_record_count == stats.input_record_count == len(events) == 20_000
        assert (
            result.signal_record_count + result.context_record_count + result.noise_record_count
            == 20_000
        )
        assert sum(group.counts.observed_occurrences for group in result.groups) == 20_000
        assert all(group.counts.mode == "occurrence" for group in result.groups)
        assert stats.defaulted_count_records == 0


def test_healthy_transients_retained_without_artificial_recurrence(known_inputs):
    result, _, _ = known_inputs["01-healthy.jsonl"]
    signals = [
        item
        for group in result.groups
        for item in group.evidence
        if item.disposition == Disposition.SIGNAL
    ]
    assert (
        signals
    )  # Healthy does contain isolated warnings; they must survive for Phase 3 decisions.
    assert not any(episode.recurrent for item in signals for episode in item.episodes)
    assert not any(
        item.signature.family in {"memory", "node", "image", "restart"} for item in signals
    )
    assert result.noise_record_count > result.signal_record_count


def test_known_oom_and_restart_counts_stay_separate_and_keep_four_pods(known_inputs):
    result, events, _ = known_inputs["02-memory-leak.jsonl"]
    observations = {}
    affected = set()
    for group in result.groups:
        for item in group.evidence:
            if item.disposition == Disposition.SIGNAL and item.signature.family in {
                "memory",
                "restart",
            }:
                observations[group.key.reason] = (
                    observations.get(group.key.reason, 0) + item.counts.observed_occurrences
                )
                affected.add(group.key.object)
    assert observations == {"OOMKilling": 26, "BackOff": 91, "Killing": 26}
    assert len(affected) == 4
    assert all(event.count == 1 for event in events)


def test_known_image_counts_normal_backoff_and_rare_manifest_are_retained(known_inputs):
    result, _, _ = known_inputs["03-image-pull-failure.jsonl"]
    totals = {}
    affected = set()
    manifest = []
    backoffs = []
    for group in result.groups:
        for item in group.evidence:
            if item.signature.family == "image":
                totals[group.key.reason] = (
                    totals.get(group.key.reason, 0) + item.counts.observed_occurrences
                )
                affected.add(group.key.object)
                if item.signature.subtype == "manifest-not-found":
                    manifest.append(item)
                if group.key.reason == "BackOff":
                    backoffs.append(item)
    assert totals == {"Failed": 24, "BackOff": 18} and len(affected) == 3
    assert sum(item.counts.observed_occurrences for item in manifest) == 3
    assert all(
        "manifest" in item.first.body and "not found" in item.first.body for item in manifest
    )
    assert all(item.first.severity_text == "Normal" for item in backoffs)
    assert any(
        item.disposition == Disposition.CONTEXT and item.signature.subtype == "ScalingReplicaSet"
        for group in result.groups
        for item in group.evidence
    )
