"""Immutable observations and quantities; event counts never mean crash counts."""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

_ID_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
_MIN_TIME = datetime.min.replace(tzinfo=UTC)


def stable_id(prefix: str, *parts: object) -> str:
    payload = _ID_ENCODER.encode(parts)
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()}"


class CountMode(StrEnum):
    AUTO = "auto"
    OCCURRENCE = "occurrence"
    CUMULATIVE = "cumulative"


class CountQuality(StrEnum):
    EXACT = "exact"
    LOWER_BOUND = "lower_bound"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"


class Disposition(StrEnum):
    SIGNAL = "signal"
    CONTEXT = "context"
    NOISE = "noise"


@dataclass(frozen=True, slots=True)
class ObjectIdentity:
    cluster: str | None
    scope: Literal["cluster", "namespace"]
    namespace: str | None
    kind: str
    identifier_kind: Literal["uid", "name"]
    identifier: str

    @property
    def token(self) -> tuple[str | None, ...]:
        return (
            self.cluster,
            self.scope,
            self.namespace,
            self.kind,
            self.identifier_kind,
            self.identifier,
        )


@dataclass(frozen=True, slots=True)
class KubernetesObject:
    identity: ObjectIdentity
    name: str
    uid: str | None
    raw_namespace: str | None
    api_version: str | None
    resource_version: str | None


@dataclass(frozen=True, slots=True)
class ContainerIdentity:
    kind: Literal["container", "init", "ephemeral", "unknown"]
    name: str

    @property
    def token(self) -> tuple[str, str]:
        return (self.kind, self.name)


@dataclass(frozen=True, slots=True)
class NodeAssociation:
    affected_node: str | None
    resource_node: str | None
    scheduling_node: str | None
    reporter_node: str | None
    basis: Literal["object", "resource", "scheduling", "unknown", "conflicting"]


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    component: str | None
    basis: Literal["inferred", "unknown"]
    producer_service: str | None


@dataclass(frozen=True, slots=True)
class SourceReference:
    source: str
    line: int
    byte_offset: int
    raw_sha256: str
    canonical_sha256: str

    @property
    def record_id(self) -> str:
        return f"record-{self.canonical_sha256}"


@dataclass(frozen=True, slots=True)
class Event:
    object: KubernetesObject
    container: ContainerIdentity | None
    raw_fieldpath: str | None
    node: NodeAssociation
    source_attribution: SourceAttribution
    reason: str
    action: str | None
    body: str
    timestamp: datetime
    observed_timestamp: datetime | None
    start_timestamp: datetime | None
    event_uid: str | None
    event_name: str | None
    count: int
    count_defaulted: bool
    severity_text: str
    severity_number: int | None
    provenance: SourceReference
    canonical_payload: str
    limitations: tuple[str, ...]
    enrichment: tuple[tuple[str, str], ...] = ()

    @property
    def sort_key(self) -> tuple[datetime, str, str, int]:
        return (
            self.timestamp,
            self.event_uid or self.event_name or "",
            self.provenance.canonical_sha256,
            self.provenance.line,
        )


@dataclass(frozen=True, slots=True)
class InputStats:
    input_record_count: int
    physical_line_count: int
    blank_line_count: int
    input_bytes: int
    input_sha256: str
    defaulted_count_records: int
    missing_cluster_records: int
    missing_namespace_records: int


def order_events(events: Iterable[Event], *, observed_first: bool = False) -> list[Event]:
    """Preserve sort_key order, calculating canonical digests only for ties."""

    def primary(event: Event) -> tuple[datetime, datetime, str]:
        first = (event.observed_timestamp or _MIN_TIME) if observed_first else event.timestamp
        return first, event.timestamp, event.event_uid or event.event_name or ""

    ordered = sorted(events, key=primary)
    if not ordered:
        return ordered
    start, previous = 0, primary(ordered[0])
    for index in range(1, len(ordered) + 1):
        current = primary(ordered[index]) if index < len(ordered) else None
        if current == previous:
            continue
        if index - start > 1:
            ordered[start:index] = sorted(
                ordered[start:index],
                key=lambda event: (event.provenance.canonical_sha256, event.provenance.line),
            )
        start = index
        if current is not None:
            previous = current
    return ordered


@dataclass(frozen=True, slots=True)
class ObjectReasonKey:
    object: ObjectIdentity
    reason: str

    @property
    def id(self) -> str:
        return stable_id("group", self.object.token, self.reason)


@dataclass(frozen=True, slots=True)
class SeriesIdentity:
    cluster: str | None
    basis: Literal["uid", "event_name", "unavailable"]
    namespace: str | None
    value: str

    @property
    def id(self) -> str:
        return stable_id("series", self.cluster, self.basis, self.namespace, self.value)


@dataclass(frozen=True, slots=True)
class CountSummary:
    mode: Literal["occurrence", "cumulative", "ambiguous", "mixed"]
    input_record_count: int
    observed_occurrences: int | None
    source_reported_total: int | None
    observed_increments: int | None
    occurrence_lower_bound: int | None
    occurrence_upper_bound: int | None
    occurrence_quality: CountQuality
    source_total_quality: CountQuality
    increment_quality: CountQuality
    cumulative_no_growth_observations: int | None
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GrowthInterval:
    start: datetime
    end: datetime
    increment: int


@dataclass(frozen=True, slots=True)
class SeriesResult:
    identity: SeriesIdentity
    counts: CountSummary
    observations: tuple[Event, ...]
    growth_intervals: tuple[GrowthInterval, ...]


@dataclass(frozen=True, slots=True)
class DiagnosticTarget:
    kind: str
    name: str
    cluster: str | None = None
    namespace: str | None = None

    @property
    def token(self) -> tuple[str | None, ...]:
        return (self.kind, self.name, self.cluster, self.namespace)


@dataclass(frozen=True, slots=True)
class DiagnosticSignature:
    family: str
    subtype: str
    targets: tuple[DiagnosticTarget, ...] = ()
    variant: str = ""
    specificity: int = 0

    @property
    def id(self) -> str:
        return stable_id(
            "signature",
            self.family,
            self.subtype,
            tuple(target.token for target in self.targets),
            self.variant,
        )


@dataclass(frozen=True, slots=True)
class Classification:
    disposition: Disposition
    signature: DiagnosticSignature | None


@dataclass(frozen=True, slots=True)
class Episode:
    id: str
    basis: Literal["occurrence", "cumulative"]
    time_basis: Literal["event", "observation_interval"]
    first: datetime
    last: datetime
    independent_observations: int
    observed_increments: int | None
    recurrent: bool
    growth_intervals: tuple[GrowthInterval, ...] = ()
    series_id: str | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    container: ContainerIdentity | None
    signature: DiagnosticSignature
    disposition: Disposition
    first: Event
    last: Event
    counts: CountSummary
    source_references: tuple[SourceReference, ...]
    episodes: tuple[Episode, ...]


@dataclass(frozen=True, slots=True)
class EventGroup:
    """Counts cover all admitted rows of this reason, before lifecycle filtering.

    Failure reporting must use signal evidence, whose per-facet counters may be
    unavailable when a source series changes facets. Never sum shared series twice.
    """

    key: ObjectReasonKey
    counts: CountSummary
    series: tuple[SeriesResult, ...]
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class Aggregation:
    requested_count_mode: CountMode
    effective_policy_sha256: str
    groups: tuple[EventGroup, ...]
    input_record_count: int
    signal_record_count: int
    context_record_count: int
    noise_record_count: int
    repeated_payload_candidates: int


class Severity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Attribution:
    workload: ObjectIdentity | None
    name: str | None
    generation: str | None
    basis: Literal["confirmed", "inferred", "unknown"]
    confidence: Confidence
    evidence_ids: tuple[str, ...]
    explanation: str


@dataclass(frozen=True, slots=True)
class Association:
    kind: Literal["ownership", "rollout", "cause-symptom", "node", "dependency", "corroboration"]
    target: str
    evidence_ids: tuple[str, ...]
    confidence: Confidence
    explanation: str


@dataclass(frozen=True, slots=True)
class Diagnosis:
    severity: Severity
    reportable: bool
    rule: str
    hypothesis: str
    confidence: Confidence
    next_verification: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    object: KubernetesObject
    evidence: Evidence
    attribution: Attribution
    diagnosis: Diagnosis
    mechanism: tuple[str, ...]
    associations: tuple[Association, ...]
    limitations: tuple[str, ...]
    object_names: tuple[str, ...]
    affected_nodes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReasonCount:
    reason: str
    counts: CountSummary


@dataclass(frozen=True, slots=True)
class Incident:
    id: str
    scope: Literal["workload", "object", "node", "dependency"]
    name: str
    cluster: str | None
    namespace: str | None
    severity: Severity
    hypothesis: str
    confidence: Confidence
    next_verification: str
    members: tuple[Finding, ...]
    reason_counts: tuple[ReasonCount, ...]
    first: datetime
    last: datetime
    recurrent: bool
    affected_objects: tuple[ObjectIdentity, ...]
    associations: tuple[Association, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SeriesDisclosure:
    identity: SeriesIdentity
    object: ObjectReasonKey
    counts: CountSummary
    source_references: tuple[SourceReference, ...]
    growth_intervals: tuple[GrowthInterval, ...]


@dataclass(frozen=True, slots=True)
class Report:
    schema_version: str
    tool_version: str
    count_mode: CountMode
    effective_policy_sha256: str
    input: InputStats
    noise_record_count: int
    context_record_count: int
    signal_record_count: int
    repeated_payload_candidates: int
    incidents: tuple[Incident, ...]
    observations: tuple[Finding, ...]
    series_disclosures: tuple[SeriesDisclosure, ...]
    context_evidence: tuple[Event, ...]
    limitations: tuple[str, ...]
