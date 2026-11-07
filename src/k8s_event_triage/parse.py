"""Bounded JSONL admission, explicit identity, and lossless source references."""

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal

from .model import (
    ContainerIdentity,
    Event,
    InputStats,
    KubernetesObject,
    NodeAssociation,
    ObjectIdentity,
    SourceAttribution,
    SourceReference,
)
from .policy import Policy

type JSONValue = None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]

_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)
_CONTAINER = re.compile(r"spec\.(containers|initContainers|ephemeralContainers)\{([^{}\s]+)\}")
_SCHEDULED = re.compile(r"Successfully assigned ([^/\s]+)/([^\s]+) to ([^\s]+)")
_SURROGATE = re.compile("[\ud800-\udfff]")
_ENRICHMENT_KEYS = tuple(
    f"k8s.{prefix}.{suffix}"
    for prefix in ("deployment", "replicaset", "statefulset", "daemonset", "job", "cronjob", "node")
    for suffix in ("name", "uid")
)
# Built-in cluster-scoped kinds. Unknown custom kinds keep their supplied namespace;
# this offline tool cannot discover CRD scope without a cluster/schema connection.
_CLUSTER_KINDS = frozenset(
    {
        "Node",
        "Namespace",
        "PersistentVolume",
        "ClusterRole",
        "ClusterRoleBinding",
        "StorageClass",
        "CustomResourceDefinition",
        "CSIDriver",
        "CSINode",
        "VolumeAttachment",
        "PriorityClass",
        "RuntimeClass",
        "ComponentStatus",
        "MutatingWebhookConfiguration",
        "ValidatingWebhookConfiguration",
    }
)
_KUBELET_REASONS = frozenset(
    {
        "Pulling",
        "Pulled",
        "Created",
        "Started",
        "Killing",
        "BackOff",
        "Unhealthy",
        "OOMKilling",
        "Evicted",
        "Failed",
        "FailedMount",
        "FailedCreatePodSandBox",
    }
)


class InputError(ValueError):
    """An input/admission failure suitable for CLI exit 3, without partial output."""

    def __init__(
        self, message: str, *, source: str, line: int | None = None, code: str = "invalid_record"
    ) -> None:
        self.source = source
        self.line = line
        self.code = code
        location = f"{source!r}" + (f":{line}" if line is not None else "")
        super().__init__(f"{location}: {code}: {message}")


def _object(value: JSONValue, field: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    return value


def _text(values: dict[str, JSONValue], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{key} must be a nonempty string without surrounding whitespace")
    return value


def _optional_text(values: dict[str, JSONValue], key: str) -> str | None:
    if values.get(key) is None:
        return None
    return _text(values, key)


def parse_timestamp(value: JSONValue, field: str = "timestamp") -> datetime:
    """RFC3339 with a known offset and at most six fractional digits; always UTC."""
    if not isinstance(value, str):
        raise ValueError(
            f"{field} requires RFC3339 with a known timezone and <=6 fractional digits"
        )
    return _timestamp_text(value, field)


@lru_cache(maxsize=256)
def _timestamp_text(value: str, field: str) -> datetime:
    if not _TIMESTAMP.fullmatch(value) or value.endswith("-00:00"):
        raise ValueError(
            f"{field} requires RFC3339 with a known timezone and <=6 fractional digits"
        )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{field} is not a valid supported timestamp") from error


def _optional_timestamp(values: dict[str, JSONValue], key: str) -> datetime | None:
    if key not in values:
        return None
    return parse_timestamp(values[key], key)


def _pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> JSONValue:
    raise ValueError(f"non-JSON numeric constant {value!r}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


_DECODER = json.JSONDecoder(
    object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_finite_float
)
_CANONICAL_ENCODER = json.JSONEncoder(
    sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
)


class _CanonicalRecord:
    """Memoize representation of already validated, immutable source text."""

    __slots__ = ("_text", "_payload", "_digest")

    def __init__(self, text: str, payload: str | None = None) -> None:
        self._text = text
        self._payload = payload
        self._digest: str | None = None

    @property
    def payload(self) -> str:
        if self._payload is None:
            self._payload = _CANONICAL_ENCODER.encode(_DECODER.decode(self._text))
            self._text = ""
        return self._payload

    @property
    def digest(self) -> str:
        if self._digest is None:
            self._digest = hashlib.sha256(self.payload.encode()).hexdigest()
        return self._digest


class _DeferredReference(SourceReference):
    __slots__ = ("_encoded_hash",)
    _encoded_hash: str | _CanonicalRecord

    @property
    def canonical_sha256(self) -> str:
        value = self._encoded_hash
        return value if isinstance(value, str) else value.digest

    @canonical_sha256.setter
    def canonical_sha256(self, value: str) -> None:
        object.__setattr__(self, "_encoded_hash", value)


class _DeferredEvent(Event):
    __slots__ = ("_encoded_payload",)
    _encoded_payload: str | _CanonicalRecord

    @property
    def canonical_payload(self) -> str:
        value = self._encoded_payload
        return value if isinstance(value, str) else value.payload

    @canonical_payload.setter
    def canonical_payload(self, value: str) -> None:
        object.__setattr__(self, "_encoded_payload", value)


def _unicode(value: JSONValue) -> None:
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise ValueError("unpaired Unicode surrogate in JSON string")
    elif isinstance(value, list):
        for item in value:
            _unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _unicode(key)
            _unicode(item)


@lru_cache(maxsize=256)
def _container(fieldpath: str | None) -> ContainerIdentity | None:
    match = _CONTAINER.fullmatch(fieldpath or "")
    if not match:
        return None
    if match[1] == "initContainers":
        return ContainerIdentity("init", match[2])
    if match[1] == "ephemeralContainers":
        return ContainerIdentity("ephemeral", match[2])
    return ContainerIdentity("container", match[2])


@lru_cache(maxsize=256)
def _source(kind: str, reason: str, producer: str | None) -> SourceAttribution:
    component = None
    if kind == "Pod":
        if reason in {"Scheduled", "FailedScheduling"}:
            component = "default-scheduler"
        elif reason in _KUBELET_REASONS:
            component = "kubelet"
    elif kind == "ReplicaSet" and reason in {"SuccessfulCreate", "SuccessfulDelete"}:
        component = "replicaset-controller"
    elif kind == "Deployment" and reason == "ScalingReplicaSet":
        component = "deployment-controller"
    elif kind == "Node" and reason in {"NodeNotReady", "NodeHasDiskPressure"}:
        component = "node-controller"
    return SourceAttribution(component, "inferred" if component else "unknown", producer)


@lru_cache(maxsize=256)
def _identity(
    cluster: str | None,
    scope: Literal["cluster", "namespace"],
    namespace: str | None,
    kind: str,
    identifier_kind: Literal["uid", "name"],
    identifier: str,
) -> ObjectIdentity:
    return ObjectIdentity(cluster, scope, namespace, kind, identifier_kind, identifier)


@lru_cache(maxsize=256)
def _metadata(
    identity: ObjectIdentity,
    name: str,
    uid: str | None,
    raw_namespace: str | None,
    api_version: str | None,
    resource_version: str | None,
) -> KubernetesObject:
    return KubernetesObject(identity, name, uid, raw_namespace, api_version, resource_version)


@lru_cache(maxsize=256)
def _node(
    affected: str | None,
    resource: str | None,
    scheduling: str | None,
    reporter: str | None,
    basis: Literal["object", "resource", "scheduling", "unknown", "conflicting"],
) -> NodeAssociation:
    return NodeAssociation(affected, resource, scheduling, reporter, basis)


def _normalize(record: dict[str, JSONValue], reference: SourceReference, payload: str) -> Event:
    resource = _object(record.get("resource"), "resource")
    attributes = _object(record.get("attributes"), "attributes")
    timestamp = parse_timestamp(record.get("timestamp"))
    observed = _optional_timestamp(record, "observed_timestamp")
    start = _optional_timestamp(attributes, "k8s.event.start_time")
    reason = _text(attributes, "k8s.event.reason")
    kind, name = _text(resource, "k8s.object.kind"), _text(resource, "k8s.object.name")
    body = record.get("body")
    if not isinstance(body, str):
        raise ValueError("body must be a string")
    count_defaulted = "k8s.event.count" not in attributes
    count = attributes.get("k8s.event.count", 1)
    if type(count) is not int or count < 1:
        raise ValueError("k8s.event.count must be a positive integer")
    cluster = _optional_text(resource, "k8s.cluster.name")
    uid = _optional_text(resource, "k8s.object.uid")
    raw_namespace = _optional_text(attributes, "k8s.namespace.name")
    resource_namespace = _optional_text(resource, "k8s.namespace.name")
    fieldpath = _optional_text(resource, "k8s.object.fieldpath")
    limitations: list[str] = []
    if count_defaulted:
        limitations.append("missing event count defaults to one")
    if cluster is None:
        limitations.append("cluster identity unavailable; unknown clusters cannot be disambiguated")
    cluster_scoped = kind in _CLUSTER_KINDS
    if raw_namespace and resource_namespace and raw_namespace != resource_namespace:
        if not cluster_scoped:
            raise ValueError("conflicting namespace metadata")
        limitations.append("conflicting raw namespaces preserved on cluster-scoped object")
    if raw_namespace is None and resource_namespace is not None:
        raw_namespace = resource_namespace
        limitations.append("namespace taken from resource metadata")
    namespace = None if cluster_scoped else raw_namespace
    if not cluster_scoped and namespace is None:
        limitations.append("object namespace unavailable; no default namespace inferred")
    if not uid:
        limitations.append("object identity uses name; generations cannot be disambiguated")
    if kind not in _CLUSTER_KINDS and namespace is None and kind != "Pod":
        limitations.append("custom object scope cannot be discovered offline")
    identity = _identity(
        cluster,
        "cluster" if cluster_scoped else "namespace",
        namespace,
        kind,
        "uid" if uid else "name",
        uid or name,
    )
    obj = _metadata(
        identity,
        name,
        uid,
        raw_namespace,
        _optional_text(resource, "k8s.object.api_version"),
        _optional_text(resource, "k8s.object.resource_version"),
    )
    resource_node = _optional_text(resource, "k8s.node.name")
    scheduled = _SCHEDULED.fullmatch(body) if kind == "Pod" and reason == "Scheduled" else None
    scheduling_node = None
    if scheduled and scheduled[1] == namespace and scheduled[2] == name:
        scheduling_node = scheduled[3]
    if kind == "Node":
        node = _node(name, resource_node, None, None, "object")
        if resource_node and resource_node != name:
            limitations.append(
                "resource node conflicts with affected Node object; object name retained"
            )
    elif kind == "Pod" and resource_node and scheduling_node and resource_node != scheduling_node:
        node = _node(None, resource_node, scheduling_node, None, "conflicting")
        limitations.append("conflicting Pod node association; affected node unavailable")
    elif kind == "Pod":
        node = _node(
            resource_node or scheduling_node,
            resource_node,
            scheduling_node,
            None,
            "resource" if resource_node else "scheduling" if scheduling_node else "unknown",
        )
    else:
        node = _node(None, resource_node, None, None, "unknown")
    severity = _optional_text(record, "severity_text")
    if severity is None:
        limitations.append("source severity unavailable")
    number = record.get("severity_number")
    severity_number: int | None = None
    if number is not None:
        if type(number) is not int or not 0 <= number <= 24:
            raise ValueError("severity_number must be an integer in 0..24")
        severity_number = number
    container = _container(fieldpath) if kind == "Pod" else None
    if fieldpath and container is None:
        limitations.append(
            "fieldpath does not identify a named container; container remains unknown"
        )
    if observed and observed < timestamp:
        limitations.append("observation precedes event timestamp; clocks may differ")
    if start and start > timestamp:
        limitations.append("event start time exceeds event timestamp")
    enrichment = tuple(
        (key, _text(resource, key)) for key in _ENRICHMENT_KEYS if resource.get(key) is not None
    )
    return _DeferredEvent(
        obj,
        container,
        fieldpath,
        node,
        _source(kind, reason, _optional_text(resource, "service.name")),
        reason,
        _optional_text(attributes, "k8s.event.action"),
        body,
        timestamp,
        observed,
        start,
        _optional_text(attributes, "k8s.event.uid"),
        _optional_text(attributes, "k8s.event.name"),
        count,
        count_defaulted,
        severity or "Unknown",
        severity_number,
        reference,
        payload,
        tuple(limitations),
        enrichment,
    )


def read_events(path: Path, policy: Policy) -> tuple[tuple[Event, ...], InputStats]:
    """Read physical lines with explicit byte/record limits; never skip bad records.

    Line limits include line terminators. A BOM is accepted only at byte zero.
    Canonical payloads retain all extra metadata; raw digests include original line bytes.
    """
    policy.validate()
    events: list[Event] = []
    source = path.name
    total_bytes = physical = blanks = 0
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                raw = stream.readline(
                    min(policy.max_line_bytes + 1, policy.max_input_bytes - total_bytes + 1)
                )
                if not raw:
                    break
                physical += 1
                offset = total_bytes
                total_bytes += len(raw)
                if total_bytes > policy.max_input_bytes:
                    raise InputError(
                        "input byte admission limit exceeded",
                        source=source,
                        line=physical,
                        code="input_limit",
                    )
                if len(raw) > policy.max_line_bytes:
                    raise InputError(
                        "physical line byte admission limit exceeded",
                        source=source,
                        line=physical,
                        code="line_limit",
                    )
                digest.update(raw)
                try:
                    text = raw.decode("utf-8-sig" if physical == 1 else "utf-8", errors="strict")
                    if not text.strip(" \t\r\n"):
                        blanks += 1
                        continue
                    if len(events) >= policy.max_records:
                        raise InputError(
                            "record admission limit exceeded",
                            source=source,
                            line=physical,
                            code="record_limit",
                        )
                    value: JSONValue = _DECODER.decode(text)
                    record = _object(value, "record")
                    # Strict UTF-8 cannot contain surrogate code points. Only JSON
                    # Unicode escapes can introduce them after decoding.
                    if "\\u" in text:
                        _unicode(record)
                    # Rare deep documents retain eager encoder validation, including
                    # its recursion error behavior. Counting braces overestimates
                    # depth when they occur in strings, so it cannot miss deep input.
                    payload = (
                        _CANONICAL_ENCODER.encode(record)
                        if text.count("{") + text.count("[") > 128
                        else None
                    )
                    canonical = _CanonicalRecord(text if payload is None else "", payload)
                    reference = _DeferredReference(
                        source,
                        physical,
                        offset,
                        hashlib.sha256(raw).hexdigest(),
                        "",
                    )
                    object.__setattr__(reference, "_encoded_hash", canonical)
                    event = _normalize(record, reference, "")
                    object.__setattr__(event, "_encoded_payload", canonical)
                    events.append(event)
                except (ValueError, RecursionError) as error:
                    if isinstance(error, InputError):
                        raise
                    raise InputError(str(error), source=source, line=physical) from error
    except OSError as error:
        raise InputError(
            f"cannot read input ({type(error).__name__}, errno={error.errno})",
            source=source,
            code="io_error",
        ) from error
    stats = InputStats(
        len(events),
        physical,
        blanks,
        total_bytes,
        digest.hexdigest(),
        sum(event.count_defaulted for event in events),
        sum(event.object.identity.cluster is None for event in events),
        sum(
            event.object.identity.scope == "namespace" and event.object.identity.namespace is None
            for event in events
        ),
    )
    return tuple(events), stats
