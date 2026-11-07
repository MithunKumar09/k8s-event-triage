"""Two deterministic UTF-8/LF renderers over the same immutable report."""

import json
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from functools import lru_cache

from .model import CountSummary, Report


@lru_cache(maxsize=64)
def _layout(kind: type) -> tuple[str, ...]:
    return tuple(sorted(field.name for field in fields(kind)))


def _json_bytes(value: object) -> bytes:
    """Serialize the immutable report without deep copies or pretty-print loops."""
    memo: dict[int, str | dict[str, object]] = {}

    def default(item: object) -> str | dict[str, object]:
        cached = memo.get(id(item))
        if cached is not None:
            return cached
        converted = _default(item)
        if len(memo) < 100_000:
            memo[id(item)] = converted
        return converted

    return (
        json.dumps(
            value,
            default=default,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ": "),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def escape_text(value: str) -> str:
    """Escape source-controlled terminal/bidi/control characters, retaining evidence."""
    return json.dumps(value, ensure_ascii=True)[1:-1]


@lru_cache(maxsize=256)
def _utc_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: datetime) -> str:
    return (
        _utc_timestamp(value)
        if value.tzinfo is UTC
        else value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _default(value: object) -> str | dict[str, object]:
    if isinstance(value, datetime):
        return _timestamp(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {name: getattr(value, name) for name in _layout(type(value))}
    raise TypeError(f"unsupported report value: {type(value).__name__}")


def _counts(value: CountSummary) -> str:
    pieces = [f"rows={value.input_record_count}", f"mode={value.mode}"]
    if value.observed_occurrences is not None:
        pieces.append(
            f"observed occurrences={value.observed_occurrences} ({value.occurrence_quality})"
        )
    else:
        pieces.append("observed occurrences=unavailable")
    if value.occurrence_lower_bound is not None and value.mode in {"ambiguous", "mixed"}:
        pieces.append(
            f"occurrences unresolved, possible {value.occurrence_lower_bound}"
            f"..{value.occurrence_upper_bound}"
        )
    if value.source_reported_total is not None:
        pieces.append(
            f"source-reported total={value.source_reported_total} ({value.source_total_quality})"
        )
    if value.mode in {"cumulative", "mixed"}:
        if value.source_reported_total is None:
            pieces.append(f"source-reported total=unavailable ({value.source_total_quality})")
        increment = (
            value.observed_increments if value.observed_increments is not None else "unavailable"
        )
        pieces.append(f"observed increments={increment} ({value.increment_quality})")
    if value.cumulative_no_growth_observations:
        pieces.append(
            f"cumulative no-growth observations={value.cumulative_no_growth_observations}"
        )
    return "; ".join(pieces)


def render(report: Report, *, json_output: bool = False) -> bytes:
    if json_output:
        return _json_bytes(report)
    lines = [
        "KUBERNETES CLUSTER EVENT TRIAGE",
        f"Records ingested: {report.input.input_record_count:,} | "
        f"Filtered as noise: {report.noise_record_count:,} | "
        f"Context: {report.context_record_count:,} | Issues: {len(report.incidents)}",
        f"Count mode: {report.count_mode} | Policy SHA-256: {report.effective_policy_sha256}",
        f"Input SHA-256: {report.input.input_sha256} | "
        f"Repeated-payload candidates: {report.repeated_payload_candidates}",
    ]
    if not report.input.input_record_count:
        lines.append("Empty input: 0 records; no conclusion about cluster health.")
    elif not report.incidents:
        lines.append(
            "No reportable incidents; evidence limitations apply."
            if report.limitations
            else "no issues detected"
        )
    for number, incident in enumerate(report.incidents, 1):
        namespace = escape_text(incident.namespace or "not applicable/unknown")
        pattern = (
            "recurrent observations"
            if incident.recurrent
            else "direct or corroborated observations"
        )
        lines.extend(
            [
                "",
                f"[{incident.severity.upper()}] {escape_text(incident.name)} ({incident.scope}; "
                f"cluster={escape_text(incident.cluster or 'unknown')}; namespace={namespace})",
                f"Incident {number}: {incident.id}",
                f"Affected objects: {len(incident.affected_objects)} | "
                f"Event range: {_timestamp(incident.first)} .. {_timestamp(incident.last)}",
                f"Pattern: {pattern}; event types are not crash totals.",
                f"Likely cause (confidence={incident.confidence}): "
                f"{escape_text(incident.hypothesis)}",
            ]
        )
        for reason in incident.reason_counts:
            lines.append(f"  {escape_text(reason.reason)}: {_counts(reason.counts)}")
        for member in incident.members:
            evidence = member.evidence
            container = evidence.container
            label = f"{container.kind}/{container.name}" if container else "unknown"
            lines.extend(
                [
                    f"  Object {escape_text(member.object.identity.kind)}/"
                    f"{escape_text(member.object.name)} "
                    f"uid={escape_text(member.object.uid or 'unknown')} "
                    f"container={escape_text(label)} "
                    f"affected nodes={escape_text(','.join(member.affected_nodes) or 'unknown')}",
                    f"    Ownership: {member.attribution.basis} ({member.attribution.confidence}); "
                    f"{escape_text(member.attribution.explanation)}",
                    f"    {escape_text(evidence.first.reason)} / "
                    f"{escape_text(evidence.signature.subtype)}: {_counts(evidence.counts)}",
                    f"    Range: {_timestamp(evidence.first.timestamp)} .. "
                    f"{_timestamp(evidence.last.timestamp)}; evidence={evidence.id}",
                    f"    Rule: {escape_text(member.diagnosis.rule)}; "
                    f"cause confidence={member.diagnosis.confidence}",
                ]
            )
            representatives = [evidence.first]
            if evidence.last.provenance.record_id != evidence.first.provenance.record_id:
                representatives.append(evidence.last)
            for event in representatives:
                ref = event.provenance
                lines.append(
                    f"    Evidence {ref.record_id} ({escape_text(ref.source)}:{ref.line}): "
                    f"{escape_text(event.body)}"
                )
            for limitation in evidence.counts.limitations:
                lines.append(f"    Count limitation: {escape_text(limitation)}")
        for association in incident.associations:
            if association.kind in {"rollout", "node", "dependency"}:
                lines.append(
                    f"  Association ({association.kind}; {association.confidence}): "
                    f"{escape_text(association.explanation)}; "
                    f"evidence={','.join(association.evidence_ids)}"
                )
        lines.append(f"Next verification: {escape_text(incident.next_verification)}")
    if report.observations:
        lines.extend(
            [
                "",
                f"Nonreportable observations: {len(report.observations)} "
                "(full evidence retained in JSON)",
            ]
        )
        for item in report.observations:
            lines.append(
                f"  {escape_text(item.object.name)} / {escape_text(item.evidence.first.reason)}: "
                f"{_counts(item.evidence.counts)}; {escape_text(item.diagnosis.rule)}; "
                f"evidence={item.id}"
            )
    for series in report.series_disclosures:
        lines.append(f"Series {series.identity.id}: {_counts(series.counts)}")
        for limitation in series.counts.limitations:
            lines.append(f"  Count limitation: {escape_text(limitation)}")
    for limitation in report.limitations:
        lines.append(f"Limitation: {escape_text(limitation)}")
    return ("\n".join(lines) + "\n").encode("utf-8")
