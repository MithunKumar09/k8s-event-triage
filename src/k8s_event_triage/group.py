"""Resolve counters before filtering; preserve every accepted observation."""

from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta
from functools import lru_cache
from itertools import pairwise
from typing import Literal

from .classify import classify
from .model import (
    Aggregation,
    Classification,
    ContainerIdentity,
    CountMode,
    CountQuality,
    CountSummary,
    DiagnosticSignature,
    Disposition,
    Episode,
    Event,
    EventGroup,
    Evidence,
    GrowthInterval,
    ObjectReasonKey,
    SeriesIdentity,
    SeriesResult,
    order_events,
    stable_id,
)
from .parse import InputError
from .policy import Policy

_EXACT = CountQuality.EXACT
_UNAVAILABLE = CountQuality.UNAVAILABLE


def _input_error(event: Event, message: str) -> InputError:
    return InputError(
        message, source=event.provenance.source, line=event.provenance.line, code="count_semantics"
    )


def _series_identity(event: Event) -> SeriesIdentity:
    cluster = event.object.identity.cluster
    if event.event_uid:
        return SeriesIdentity(cluster, "uid", None, event.event_uid)
    if event.event_name and event.object.raw_namespace:
        return SeriesIdentity(cluster, "event_name", event.object.raw_namespace, event.event_name)
    key = ObjectReasonKey(event.object.identity, event.reason)
    return SeriesIdentity(cluster, "unavailable", event.object.identity.namespace, key.id)


@lru_cache(maxsize=256)
def _occurrences(size: int, limitations: tuple[str, ...] = ()) -> CountSummary:
    """Reuse immutable quantities only; observations and provenance stay separate."""
    return CountSummary(
        "occurrence",
        size,
        size,
        None,
        None,
        size,
        size,
        _EXACT,
        _UNAVAILABLE,
        _UNAVAILABLE,
        0,
        limitations,
    )


def _ambiguous(size: int, limitations: tuple[str, ...]) -> CountSummary:
    return CountSummary(
        "ambiguous",
        size,
        None,
        None,
        None,
        1,
        size,
        CountQuality.AMBIGUOUS if size > 1 else _UNAVAILABLE,
        _UNAVAILABLE,
        _UNAVAILABLE,
        0,
        limitations,
    )


def _cumulative(
    identity: SeriesIdentity, rows: tuple[Event, ...], limitations: tuple[str, ...]
) -> SeriesResult:
    total = max(event.count for event in rows)
    counts = CountSummary(
        "cumulative",
        len(rows),
        None,
        total,
        None,
        None,
        None,
        _UNAVAILABLE,
        _EXACT,
        _UNAVAILABLE,
        None,
        limitations,
    )
    if any(event.observed_timestamp is None for event in rows):
        counts = replace(
            counts,
            limitations=(
                *limitations,
                "missing observed_timestamp; counter increments unavailable",
            ),
        )
        return SeriesResult(identity, counts, rows, ())
    ordered = order_events(rows, observed_first=True)
    by_time: dict[datetime | None, set[int]] = defaultdict(set)
    for event in ordered:
        by_time[event.observed_timestamp].add(event.count)
    if any(len(values) > 1 for values in by_time.values()):
        counts = replace(
            counts,
            limitations=(
                *limitations,
                "conflicting counters at one observation time; increments unavailable",
            ),
        )
        return SeriesResult(identity, counts, rows, ())
    no_growth = sum(first.count == second.count for first, second in pairwise(ordered))
    if any(second.count < first.count for first, second in pairwise(ordered)):
        counts = replace(
            counts,
            source_total_quality=CountQuality.LOWER_BOUND,
            cumulative_no_growth_observations=no_growth,
            limitations=(
                *limitations,
                "counter decrease under one series identity; "
                "maximum is a lower bound; reset segments not inferred",
            ),
        )
        return SeriesResult(identity, counts, rows, ())
    intervals = []
    for first, second in pairwise(ordered):
        if second.count > first.count:
            # All observation timestamps were checked above; no event-time allocation.
            assert first.observed_timestamp is not None and second.observed_timestamp is not None
            intervals.append(
                GrowthInterval(
                    first.observed_timestamp, second.observed_timestamp, second.count - first.count
                )
            )
    growth = sum(interval.increment for interval in intervals)
    counts = replace(
        counts,
        observed_increments=growth,
        increment_quality=_EXACT,
        cumulative_no_growth_observations=no_growth,
    )
    return SeriesResult(identity, counts, rows, tuple(intervals))


def _resolve(identity: SeriesIdentity, records: list[Event], mode: CountMode) -> SeriesResult:
    rows = (records[0],) if len(records) == 1 else tuple(order_events(records))
    limitations = (
        ("series identity inferred from namespaced event name",)
        if identity.basis == "event_name"
        else ()
    )
    for event in rows:
        if type(event.count) is not int or event.count < 1:
            raise _input_error(event, "count must be a positive integer")
    if mode == CountMode.OCCURRENCE:
        invalid = next((event for event in rows if event.count != 1), None)
        if invalid:
            raise _input_error(invalid, "occurrence mode rejects source counts above one")
        return SeriesResult(identity, _occurrences(len(rows), limitations), rows, ())
    if mode == CountMode.CUMULATIVE or any(event.count > 1 for event in rows):
        if identity.basis == "unavailable":
            raise _input_error(
                rows[0], "cumulative mode requires an event UID or namespaced event name"
            )
        return _cumulative(identity, rows, limitations)
    if identity.basis == "unavailable":
        counts = _ambiguous(
            len(rows),
            (
                *limitations,
                "event identity unavailable; independent occurrences versus snapshots unresolved",
            ),
        )
    elif len(rows) > 1:
        counts = _ambiguous(
            len(rows),
            (
                *limitations,
                "repeated identity with only count-1 records; "
                "occurrence/replay ambiguity unresolved",
            ),
        )
    else:
        counts = _occurrences(
            1, (*limitations, "distinct count-1 identity uses assessment occurrence semantics")
        )
    return SeriesResult(identity, counts, rows, ())


def _combine(parts: list[CountSummary]) -> CountSummary:
    if len(parts) == 1:
        return parts[0]
    modes = {part.mode for part in parts}
    mode: Literal["occurrence", "cumulative", "ambiguous", "mixed"] = (
        parts[0].mode if len(modes) == 1 else "mixed"
    )
    limitations = {text for part in parts for text in part.limitations}
    if len(modes) > 1:
        limitations.add("mixed count quantities; no combined exact occurrence total")
    known = [part for part in parts if part.observed_occurrences is not None]
    cumulative = [
        part
        for part in parts
        if part.mode == "cumulative"
        or (part.mode == "mixed" and part.occurrence_lower_bound is None)
    ]
    occurrences = sum(part.observed_occurrences or 0 for part in known) if known else None
    source = (
        sum(part.source_reported_total or 0 for part in cumulative)
        if cumulative and all(part.source_reported_total is not None for part in cumulative)
        else None
    )
    increments = (
        sum(part.observed_increments or 0 for part in cumulative)
        if cumulative and all(part.observed_increments is not None for part in cumulative)
        else None
    )
    bounded = all(
        part.occurrence_lower_bound is not None and part.occurrence_upper_bound is not None
        for part in parts
    )
    lower = sum(part.occurrence_lower_bound or 0 for part in parts) if bounded else None
    upper = sum(part.occurrence_upper_bound or 0 for part in parts) if bounded else None
    occurrence_quality = (
        _EXACT
        if mode == "occurrence"
        else CountQuality.LOWER_BOUND
        if known
        else CountQuality.AMBIGUOUS
        if mode == "ambiguous"
        else _UNAVAILABLE
    )
    source_quality = (
        _UNAVAILABLE
        if source is None
        else CountQuality.LOWER_BOUND
        if any(part.source_total_quality == CountQuality.LOWER_BOUND for part in cumulative)
        else _EXACT
    )
    no_growth = (
        sum(part.cumulative_no_growth_observations or 0 for part in cumulative)
        if all(part.cumulative_no_growth_observations is not None for part in cumulative)
        else None
    )
    return CountSummary(
        mode,
        sum(part.input_record_count for part in parts),
        occurrences,
        source,
        increments,
        lower,
        upper,
        occurrence_quality,
        source_quality,
        _EXACT if increments is not None else _UNAVAILABLE,
        no_growth,
        tuple(sorted(limitations)),
    )


def combine_counts(parts: tuple[CountSummary, ...]) -> CountSummary:
    """Combine disjoint evidence quantities, preserving nested mixed-mode totals."""
    if not parts:
        raise ValueError("at least one disjoint count summary is required")
    return _combine(list(parts))


def _occurrence_episodes(evidence_id: str, rows: list[Event], policy: Policy) -> list[Episode]:
    if not rows:
        return []
    ordered = order_events(rows)
    bursts: list[list[Event]] = [[ordered[0]]]
    gap = timedelta(seconds=policy.episode_gap_seconds)
    for event in ordered[1:]:
        if event.timestamp - bursts[-1][-1].timestamp > gap:
            bursts.append([])
        bursts[-1].append(event)
    episodes = []
    for burst in bursts:
        first, last = burst[0].timestamp, burst[-1].timestamp
        recurrent = len(burst) >= policy.recurrence_count and last - first >= timedelta(
            seconds=policy.recurrence_span_seconds
        )
        identifier = stable_id(
            "episode",
            evidence_id,
            "occurrence",
            first.isoformat(),
            last.isoformat(),
            tuple(event.provenance.record_id for event in burst),
        )
        episodes.append(
            Episode(identifier, "occurrence", "event", first, last, len(burst), None, recurrent)
        )
    return episodes


def _growth_episodes(evidence_id: str, series: SeriesResult, policy: Policy) -> list[Episode]:
    bursts: list[list[GrowthInterval]] = []
    gap = timedelta(seconds=policy.episode_gap_seconds)
    for interval in series.growth_intervals:
        if (
            not bursts
            or interval.start - bursts[-1][-1].end > gap
            or interval.end - interval.start > gap
            or bursts[-1][-1].end - bursts[-1][-1].start > gap
        ):
            bursts.append([])
        bursts[-1].append(interval)
    episodes = []
    for burst in bursts:
        first, last = burst[0].start, burst[-1].end
        recurrent = (
            len(burst) >= max(2, policy.recurrence_count)
            and last - first >= timedelta(seconds=policy.recurrence_span_seconds)
            and all(interval.end - interval.start <= gap for interval in burst)
        )
        identifier = stable_id(
            "episode",
            evidence_id,
            "cumulative",
            series.identity.id,
            tuple((item.start.isoformat(), item.end.isoformat(), item.increment) for item in burst),
        )
        episodes.append(
            Episode(
                identifier,
                "cumulative",
                "observation_interval",
                first,
                last,
                len(burst),
                sum(item.increment for item in burst),
                recurrent,
                tuple(burst),
                series.identity.id,
            )
        )
    return episodes


def _evidence(
    key: ObjectReasonKey,
    container: ContainerIdentity | None,
    signature: DiagnosticSignature,
    disposition: Disposition,
    records: list[Event],
    resolved: dict[SeriesIdentity, SeriesResult],
    policy: Policy,
) -> Evidence:
    identifier = stable_id(
        "evidence", key.id, container.token if container else None, signature.id, disposition.value
    )
    if len(records) == 1:
        event = records[0]
        series = resolved[_series_identity(event)]
        if len(series.observations) == 1:
            single_episodes = (
                tuple(_occurrence_episodes(identifier, records, policy))
                if disposition == Disposition.SIGNAL and series.counts.mode == "occurrence"
                else ()
            )
            return Evidence(
                identifier,
                container,
                signature,
                disposition,
                event,
                event,
                series.counts,
                (event.provenance,),
                single_episodes,
            )
    ordered = tuple(order_events(records))
    selected: dict[SeriesIdentity, list[Event]] = defaultdict(list)
    for event in ordered:
        selected[_series_identity(event)].append(event)
    parts = []
    occurrence_rows = []
    episodes = []
    for identity in sorted(selected, key=lambda item: item.id):
        series = resolved[identity]
        rows = selected[identity]
        if series.counts.mode == "occurrence":
            parts.append(_occurrences(len(rows), series.counts.limitations))
            occurrence_rows.extend(rows)
        elif series.counts.mode == "ambiguous":
            parts.append(_ambiguous(len(rows), series.counts.limitations))
        elif len(rows) == len(series.observations):
            parts.append(series.counts)
            if disposition == Disposition.SIGNAL:
                episodes.extend(_growth_episodes(identifier, series, policy))
        else:
            parts.append(
                replace(
                    series.counts,
                    input_record_count=len(rows),
                    source_reported_total=None,
                    observed_increments=None,
                    source_total_quality=_UNAVAILABLE,
                    increment_quality=_UNAVAILABLE,
                    cumulative_no_growth_observations=None,
                    limitations=(
                        *series.counts.limitations,
                        "series spans diagnostic/container facets; counters not allocated",
                    ),
                )
            )
    if disposition == Disposition.SIGNAL:
        episodes.extend(_occurrence_episodes(identifier, occurrence_rows, policy))
    episodes.sort(key=lambda item: (item.first, item.last, item.id))
    return Evidence(
        identifier,
        container,
        signature,
        disposition,
        ordered[0],
        ordered[-1],
        _combine(parts),
        tuple(event.provenance for event in ordered),
        tuple(episodes),
    )


def aggregate(
    events: tuple[Event, ...], policy: Policy, *, include_noise_groups: bool = True
) -> Aggregation:
    """Finalize counts without erasing observations or provenance.

    Reports may omit materialization of wholly ordinary occurrence groups.
    Every retained group remains complete; ambiguous/cumulative groups and all
    signal/context groups always retain the full counting/evidence path.
    """
    policy.validate()
    if len(events) > policy.max_records:
        raise InputError(
            "record admission limit exceeded", source="aggregation", code="record_limit"
        )
    records_by_series: dict[SeriesIdentity, list[Event]] = defaultdict(list)
    object_by_series: dict[SeriesIdentity, ObjectReasonKey] = {}
    for event in events:
        identity = _series_identity(event)
        key = ObjectReasonKey(event.object.identity, event.reason)
        previous = object_by_series.setdefault(identity, key)
        if previous != key:
            raise _input_error(
                event, "event series identity conflicts with affected object or reason"
            )
        records_by_series[identity].append(event)
    # Resolve the entire series, including early count-1 rows, before lifecycle filtering.
    mode = CountMode(policy.count_mode)
    classified: dict[int, Classification] = {}
    required: set[ObjectReasonKey] = set()
    skipped_noise = 0
    if not include_noise_groups:
        for identity, rows in records_by_series.items():
            key = object_by_series[identity]
            for event in rows:
                classification = classify(event)
                classified[id(event)] = classification
                if classification.disposition != Disposition.NOISE:
                    required.add(key)
            # Resolve only this conclusive occurrence contract without allocating
            # series/evidence state. Other contracts must use _resolve unchanged.
            independent = (
                mode == CountMode.OCCURRENCE
                or (mode == CountMode.AUTO and identity.basis != "unavailable" and len(rows) == 1)
            ) and all(type(event.count) is int and event.count == 1 for event in rows)
            if not independent:
                required.add(key)
        skipped_noise = sum(
            len(rows)
            for identity, rows in records_by_series.items()
            if object_by_series[identity] not in required
        )
    resolved = {
        identity: _resolve(identity, rows, mode)
        for identity, rows in sorted(
            (
                (identity, rows)
                for identity, rows in records_by_series.items()
                if include_noise_groups or object_by_series[identity] in required
            ),
            key=lambda item: item[0].id,
        )
    }
    by_object: dict[ObjectReasonKey, list[SeriesResult]] = defaultdict(list)
    for identity, result in resolved.items():
        by_object[object_by_series[identity]].append(result)
    signal = context = 0
    noise = skipped_noise
    groups = []
    for key, series in sorted(by_object.items(), key=lambda item: item[0].id):
        facets: dict[
            tuple[ContainerIdentity | None, DiagnosticSignature, Disposition], list[Event]
        ] = defaultdict(list)
        for result in series:
            for event in result.observations:
                classification = classify(event) if include_noise_groups else classified[id(event)]
                if classification.disposition == Disposition.NOISE:
                    noise += 1
                    continue
                if classification.disposition == Disposition.SIGNAL:
                    signal += 1
                else:
                    context += 1
                assert classification.signature is not None
                facets[
                    (event.container, classification.signature, classification.disposition)
                ].append(event)
        evidence = [
            _evidence(key, container, signature, disposition, rows, resolved, policy)
            for (container, signature, disposition), rows in facets.items()
        ]
        evidence.sort(
            key=lambda item: (
                -item.signature.specificity,
                item.signature.family,
                item.signature.subtype,
                item.id,
            )
        )
        groups.append(
            EventGroup(
                key, _combine([item.counts for item in series]), tuple(series), tuple(evidence)
            )
        )
    # Equal whole records necessarily normalize to the same series identity.
    # Singleton series cannot repeat; retain exact canonical comparison otherwise.
    repeated = 0
    for rows in records_by_series.values():
        if len(rows) < 2:
            continue
        candidates: dict[tuple[datetime, datetime | None, int], list[Event]] = defaultdict(list)
        for event in rows:
            candidates[(event.timestamp, event.observed_timestamp, event.count)].append(event)
        repeated += sum(
            len(matches) - len({event.provenance.canonical_sha256 for event in matches})
            for matches in candidates.values()
            if len(matches) > 1
        )
    return Aggregation(
        mode, policy.digest(), tuple(groups), len(events), signal, context, noise, repeated
    )
