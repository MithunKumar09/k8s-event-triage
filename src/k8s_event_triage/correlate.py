"""Direct typed evidence links and fixed-anchor incident synthesis; no graph closure."""

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from itertools import islice
from typing import Literal

from . import __version__
from .classify import Support, diagnose
from .group import combine_counts
from .model import (
    Aggregation,
    Association,
    Attribution,
    Confidence,
    ContainerIdentity,
    Disposition,
    Event,
    Evidence,
    Finding,
    Incident,
    InputStats,
    ObjectIdentity,
    ObjectReasonKey,
    ReasonCount,
    Report,
    SeriesDisclosure,
    Severity,
    order_events,
    stable_id,
)
from .policy import Policy

_POD_NAME = re.compile(r"(.+)-([a-z0-9]{6,10})-([a-z0-9]{5})")
_CREATED = re.compile(r"Created pod:\s*(\S+)")
_SCALED = re.compile(r"Scaled up replica set (\S+) to ([1-9]\d*)")
_OWNER_FIELDS = (
    ("deployment", "Deployment"),
    ("statefulset", "StatefulSet"),
    ("daemonset", "DaemonSet"),
    ("cronjob", "CronJob"),
    ("job", "Job"),
    ("replicaset", "ReplicaSet"),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    key: ObjectReasonKey
    evidence: Evidence
    rows: tuple[Event, ...]
    attribution: Attribution
    ownership_links: tuple[Association, ...]
    affected_node: str | None
    node_source_ids: tuple[str, ...]

    @property
    def scope(self) -> tuple[ObjectIdentity, ContainerIdentity | None]:
        return self.key.object, self.evidence.container


@dataclass(frozen=True, slots=True)
class _Timeline:
    times: tuple[datetime, ...]
    ids: tuple[str, ...]

    def nearby(self, rows: tuple[Event, ...], seconds: int) -> tuple[str, ...]:
        found = set()
        limit = timedelta(seconds=seconds)
        for row in rows:
            offset = bisect_left(self.times, row.timestamp)
            for index in (offset - 1, offset):
                if 0 <= index < len(self.times) and abs(self.times[index] - row.timestamp) <= limit:
                    found.add(self.ids[index])
        return tuple(sorted(found))


def _unknown(explanation: str) -> Attribution:
    return Attribution(None, None, None, "unknown", Confidence.LOW, (), explanation)


def _named_owner(event: Event, kind: str, name: str, uid: str | None) -> ObjectIdentity:
    return ObjectIdentity(
        event.object.identity.cluster,
        "namespace",
        event.object.identity.namespace,
        kind,
        "uid" if uid else "name",
        uid or name,
    )


class _Context:
    def __init__(self, events: tuple[Event, ...]) -> None:
        self.generations: dict[tuple[str | None, str | None, str, str], set[ObjectIdentity]] = (
            defaultdict(set)
        )
        self.created: dict[tuple[str | None, str | None, str], list[Event]] = defaultdict(list)
        self.scaled: dict[tuple[str | None, str | None, str], list[Event]] = defaultdict(list)
        self.records: dict[str, Event] = {}
        self.record_candidates: dict[tuple[object, ...], list[Event]] = defaultdict(list)
        self.indexed_records: set[tuple[object, ...]] = set()
        self.pod_nodes: dict[ObjectIdentity, dict[str, Event]] = defaultdict(dict)
        self.node_uids: dict[ObjectIdentity, set[str]] = defaultdict(set)
        for event in order_events(events):
            obj = event.object
            self.generations[
                (obj.identity.cluster, obj.identity.namespace, obj.identity.kind, obj.name)
            ].add(obj.identity)
            self.record_candidates[self._record_key(event)].append(event)
            if obj.identity.kind == "Pod" and event.node.affected_node:
                self.pod_nodes[obj.identity].setdefault(event.node.affected_node, event)
                uid = dict(event.enrichment).get("k8s.node.uid")
                if uid:
                    self.node_uids[obj.identity].add(uid)
            if obj.identity.kind == "ReplicaSet" and event.reason == "SuccessfulCreate":
                match = _CREATED.fullmatch(event.body)
                if match:
                    self.created[(obj.identity.cluster, obj.identity.namespace, match[1])].append(
                        event
                    )
            if obj.identity.kind == "Deployment" and event.reason == "ScalingReplicaSet":
                match = _SCALED.fullmatch(event.body)
                if match:
                    self.scaled[(obj.identity.cluster, obj.identity.namespace, match[1])].append(
                        event
                    )

    @staticmethod
    def _record_key(event: Event) -> tuple[object, ...]:
        return (
            event.object.identity,
            event.reason,
            event.event_uid,
            event.event_name,
            event.timestamp,
            event.observed_timestamp,
            event.count,
        )

    def _remember(self, event: Event) -> str:
        key = self._record_key(event)
        if key not in self.indexed_records:
            for candidate in self.record_candidates[key]:
                self.records.setdefault(candidate.provenance.record_id, candidate)
            self.indexed_records.add(key)
        return event.provenance.record_id

    def unique(self, event: Event) -> bool:
        obj = event.object
        return (
            len(
                self.generations[
                    (obj.identity.cluster, obj.identity.namespace, obj.identity.kind, obj.name)
                ]
            )
            == 1
        )

    def node_assignment(self, event: Event) -> tuple[str | None, tuple[str, ...]]:
        known = self.pod_nodes.get(event.object.identity, {})
        if len(known) != 1 or event.object.uid is None:
            return None, ()
        name = next(iter(known))
        support = known[name]
        return name, (self._remember(support),)

    def ownership(
        self, rows: tuple[Event, ...], policy: Policy
    ) -> tuple[Attribution, tuple[Association, ...]]:
        first = rows[0]
        obj = first.object
        if obj.identity.kind == "Node" or not obj.identity.cluster or not obj.identity.namespace:
            return _unknown("workload association requires a known namespaced cluster scope"), ()
        if obj.identity.kind != "Pod":
            if obj.identity.kind not in {
                "Deployment",
                "ReplicaSet",
                "StatefulSet",
                "DaemonSet",
                "Job",
                "CronJob",
                "ReplicationController",
            }:
                return _unknown("affected resource is not a recognized workload controller"), ()
            return Attribution(
                obj.identity,
                obj.name,
                obj.uid,
                "confirmed",
                Confidence.HIGH,
                (self._remember(first),),
                "affected controller identity is explicit",
            ), ()
        claims = []
        generations = set()
        for row in rows:
            metadata = dict(row.enrichment)
            present = {kind for prefix, kind in _OWNER_FIELDS if metadata.get(f"k8s.{prefix}.name")}
            if len(present) > 1 and not (
                present <= {"Deployment", "ReplicaSet"} or present <= {"CronJob", "Job"}
            ):
                return _unknown("contradictory explicit controller kinds; no naming fallback"), ()
            for prefix, kind in _OWNER_FIELDS:
                name = metadata.get(f"k8s.{prefix}.name")
                if name:
                    claims.append((kind, name, metadata.get(f"k8s.{prefix}.uid")))
                    generations.add(
                        metadata.get("k8s.replicaset.uid") or metadata.get("k8s.replicaset.name")
                    )
                    break
        if claims:
            labels = {(kind, name) for kind, name, _ in claims}
            uids = {uid for _, _, uid in claims if uid}
            if len(labels) != 1 or len(uids) > 1 or len(generations - {None}) > 1:
                return _unknown(
                    "contradictory explicit controller metadata; no naming fallback"
                ), ()
            kind, name = next(iter(labels))
            uid = next(iter(uids), None)
            if (
                not uid
                and len(
                    self.generations.get(
                        (obj.identity.cluster, obj.identity.namespace, kind, name), set()
                    )
                )
                > 1
            ):
                return _unknown("controller name has multiple UID generations"), ()
            generation = next(iter(generations - {None}), None)
            if not self.unique(first):
                generation = f"ambiguous-pod-generation:{obj.identity.identifier}"
            return Attribution(
                _named_owner(first, kind, name, uid),
                name,
                generation,
                "confirmed",
                Confidence.HIGH if uid else Confidence.MEDIUM,
                (self._remember(first),),
                "explicit OTel controller enrichment; verify ownerReferences if needed",
            ), ()
        if not self.unique(first) or obj.uid is None:
            return _unknown("Pod generation is ambiguous; naming inference disabled"), ()
        candidates = [
            event
            for event in self.created.get(
                (obj.identity.cluster, obj.identity.namespace, obj.name), ()
            )
            if event.timestamp <= first.timestamp
        ]
        if any(not self.unique(event) for event in candidates):
            return _unknown(
                "ambiguous explicit controller generations; naming fallback disabled"
            ), ()
        parents = {event.object.identity for event in candidates}
        if len(parents) > 1:
            return _unknown("multiple explicit parent controllers; naming fallback disabled"), ()
        if candidates:
            creation = max(candidates, key=lambda item: item.sort_key)
            parent = creation.object
            links = [
                Association(
                    "ownership",
                    parent.name,
                    (self._remember(creation),),
                    Confidence.HIGH,
                    "ReplicaSet creation event names this unique Pod generation",
                )
            ]
            scale_events = [
                event
                for event in self.scaled.get(
                    (obj.identity.cluster, obj.identity.namespace, parent.name), ()
                )
                if event.timestamp <= creation.timestamp and self.unique(event)
            ]
            deployments = {event.object.identity for event in scale_events}
            if len(deployments) == 1:
                scale = max(scale_events, key=lambda item: item.sort_key)
                refs = (self._remember(scale), self._remember(creation))
                links.append(
                    Association(
                        "ownership",
                        scale.object.name,
                        refs,
                        Confidence.HIGH,
                        "Deployment scale event and ReplicaSet creation "
                        "form a direct named ownership chain",
                    )
                )
                if first.timestamp - scale.timestamp <= timedelta(
                    seconds=policy.correlation_seconds
                ):
                    links.append(
                        Association(
                            "rollout",
                            scale.object.name,
                            refs,
                            Confidence.MEDIUM,
                            "scale-up precedes failure onset within correlation threshold; "
                            "temporal association is not proof of causation",
                        )
                    )
                return Attribution(
                    scale.object.identity,
                    scale.object.name,
                    parent.uid or parent.name,
                    "confirmed",
                    Confidence.HIGH,
                    refs,
                    "controller events name an unambiguous Deployment/ReplicaSet/Pod chain",
                ), tuple(links)
            return Attribution(
                parent.identity,
                parent.name,
                parent.uid or parent.name,
                "confirmed",
                Confidence.HIGH,
                (self._remember(creation),),
                "ReplicaSet explicitly created this Pod; Deployment ownership is not established",
            ), tuple(links)
        match = _POD_NAME.fullmatch(obj.name)
        if match:
            name, template = match[1], f"{match[1]}-{match[2]}"
            return Attribution(
                _named_owner(first, "Deployment", name, None),
                name,
                template,
                "inferred",
                Confidence.MEDIUM,
                (self._remember(first),),
                "Deployment/ReplicaSet generation inferred from Pod naming; verify ownerReferences",
            ), ()
        return _unknown("no supported controller chain or recognizable Pod naming pattern"), ()


def _targets(item: _Candidate, kind: str) -> tuple[str, ...]:
    return tuple(target.name for target in item.evidence.signature.targets if target.kind == kind)


def _error_kind(body: str) -> str:
    lower = body.lower()
    if "not found" in lower or "notfound" in lower:
        return "not-found"
    if "denied" in lower or "unauthorized" in lower or "forbidden" in lower:
        return "denied"
    if "timeout" in lower or "timed out" in lower or "deadline exceeded" in lower:
        return "timeout"
    status = re.search(r"status(?:code| code)?\s*[:=]?\s*(\d{3})", lower)
    if status:
        return f"http-{status[1]}"
    return body


def _base_mechanism(item: _Candidate) -> tuple[str, ...]:
    signature = item.evidence.signature
    family, subtype = signature.family, signature.subtype
    if family == "image":
        return family, subtype, next(iter(_targets(item, "image")), "unknown-image")
    if family == "memory":
        return family, "oom", next(iter(_targets(item, "memory-limit")), "unknown-limit")
    if family == "mount":
        return (
            family,
            _error_kind(signature.variant),
            *tuple(str(target.token) for target in signature.targets),
        )
    if family == "probe":
        probe = subtype.split("-", 1)[0]
        return (
            family,
            probe,
            "termination" if subtype == "liveness-termination" else _error_kind(signature.variant),
        )
    if family == "scheduling":
        constraints = []
        for target in signature.targets:
            resource = re.search(r"insufficient (cpu|memory|ephemeral-storage)", target.name, re.I)
            constraints.append(resource[0].lower() if resource else target.name.lower())
        return family, *tuple(sorted(constraints))
    if family == "restart":
        return family, "container-restart"
    if family == "node":
        return family, subtype
    return family, subtype, signature.variant


def _near(first: _Candidate, second: _Candidate, seconds: int) -> bool:
    points = sorted({row.timestamp for row in second.rows})
    return bool(_Timeline(tuple(points), tuple("near" for _ in points)).nearby(first.rows, seconds))


def _episode_compatible(first: _Candidate, second: _Candidate, seconds: int) -> bool:
    """Every episode needs a direct peer; broad min/max spans cannot bridge silence."""
    limit = timedelta(seconds=seconds)

    def matches(left: _Candidate, right: _Candidate) -> bool:
        times = tuple(row.timestamp for row in left.rows)
        right_times = tuple(sorted({row.timestamp for row in right.rows}))
        timeline = _Timeline(right_times, tuple("near" for _ in right_times))
        recurrent = tuple(episode for episode in right.evidence.episodes if episode.recurrent)
        cursor = 0
        for episode in left.evidence.episodes:
            rows = left.rows[bisect_left(times, episode.first) : bisect_right(times, episode.last)]
            if rows and timeline.nearby(rows, seconds):
                continue
            while cursor < len(recurrent) and episode.first - recurrent[cursor].last > limit:
                cursor += 1
            if (
                episode.recurrent
                and cursor < len(recurrent)
                and recurrent[cursor].first - episode.last <= limit
            ):
                continue
            return False
        return True

    return (
        matches(first, second)
        and matches(second, first)
        and (
            bool(first.evidence.episodes and second.evidence.episodes)
            or _near(first, second, seconds)
        )
    )


class _Links:
    def __init__(
        self, candidates: tuple[_Candidate, ...], policy: Policy, context: _Context
    ) -> None:
        self.policy = policy
        self.context = context
        self.items = {item.evidence.id: item for item in candidates}
        self.supports: dict[str, set[Support]] = defaultdict(set)
        self.links: dict[str, list[Association]] = defaultdict(list)
        self.mechanisms = {item.evidence.id: _base_mechanism(item) for item in candidates}
        self.dependency_roots: dict[str, str] = {}
        self.node_roots: dict[str, str] = {}
        known_images: dict[tuple[ObjectIdentity, ContainerIdentity | None], set[str]] = defaultdict(
            set
        )
        known_limits: dict[tuple[ObjectIdentity, ContainerIdentity | None], set[str]] = defaultdict(
            set
        )
        for item in candidates:
            known_images[item.scope].update(_targets(item, "image"))
            known_limits[item.scope].update(_targets(item, "memory-limit"))
        self.references: dict[str, str] = {}
        points: dict[tuple[object, ...], list[tuple[datetime, str]]] = defaultdict(list)
        memory_roots: dict[tuple[ObjectIdentity, ContainerIdentity | None], set[str]] = defaultdict(
            set
        )
        for item in candidates:
            family = item.evidence.signature.family
            own = _targets(item, "image" if family == "image" else "memory-limit")
            known = known_images[item.scope] if family == "image" else known_limits[item.scope]
            reference = own[0] if own else next(iter(known)) if len(known) == 1 else "unknown"
            self.references[item.evidence.id] = reference
            if family == "memory":
                self.mechanisms[item.evidence.id] = ("memory", "oom", reference)
                memory_roots[item.scope].add(reference)
            if family == "image":
                for category in (item.key.reason, item.evidence.signature.subtype):
                    points[(item.scope, "image", reference, category)].extend(
                        (row.timestamp, item.evidence.id) for row in item.rows
                    )
            elif family == "memory":
                points[(item.scope, "memory", reference)].extend(
                    (row.timestamp, item.evidence.id) for row in item.rows
                )
            elif family == "probe" and item.evidence.signature.subtype == "liveness-termination":
                points[(item.scope, "probe-termination")].extend(
                    (row.timestamp, item.evidence.id) for row in item.rows
                )
            elif family in {"setup", "failure"}:
                if any(
                    token in item.evidence.signature.variant.lower()
                    for token in ("sandbox", "setup", "create container")
                ):
                    points[(item.scope, "setup", item.key.reason)].extend(
                        (row.timestamp, item.evidence.id) for row in item.rows
                    )
        self.timelines: dict[tuple[object, ...], _Timeline] = {}
        for key, entries in points.items():
            ordered = sorted(set(entries))
            self.timelines[key] = _Timeline(
                tuple(time for time, _ in ordered), tuple(identifier for _, identifier in ordered)
            )
        for item in candidates:
            self._local(item, memory_roots)
        self._multiple(candidates)
        self._nodes(candidates)

    def _query(self, item: _Candidate, key: tuple[object, ...]) -> tuple[str, ...]:
        timeline = self.timelines.get(key)
        return timeline.nearby(item.rows, self.policy.correlation_seconds) if timeline else ()

    def _add(
        self,
        item: _Candidate,
        support: Support,
        identifiers: tuple[str, ...],
        kind: str = "cause-symptom",
    ) -> None:
        if not identifiers:
            return
        self.supports[item.evidence.id].add(support)
        association_kind: Literal["corroboration", "cause-symptom"] = (
            "corroboration" if kind == "corroboration" else "cause-symptom"
        )
        self.links[item.evidence.id].append(
            Association(
                association_kind,
                support.value,
                tuple(sorted(set((item.evidence.id, *identifiers)))),
                Confidence.MEDIUM,
                f"{support.value}; compatible object/container scope and nearby event evidence",
            )
        )

    def _local(
        self,
        item: _Candidate,
        memory_roots: dict[tuple[ObjectIdentity, ContainerIdentity | None], set[str]],
    ) -> None:
        family, subtype = item.evidence.signature.family, item.evidence.signature.subtype
        reference = self.references[item.evidence.id]
        if family == "image":
            other_reason = "BackOff" if item.key.reason == "Failed" else "Failed"
            self._add(
                item,
                Support.IMAGE_PAIR,
                self._query(item, (item.scope, "image", reference, other_reason)),
            )
            root = subtype if subtype in {"manifest-not-found", "access-denied"} else "pull-failure"
            if root == "pull-failure":
                causes = [
                    name
                    for name in ("manifest-not-found", "access-denied")
                    if self._query(item, (item.scope, "image", reference, name))
                ]
                if len(causes) == 1:
                    root = causes[0]
                    identifiers = self._query(item, (item.scope, "image", reference, root))
                    self.links[item.evidence.id].append(
                        Association(
                            "cause-symptom",
                            root,
                            identifiers,
                            Confidence.MEDIUM,
                            "unique nearby terminal cause for this object's image pull",
                        )
                    )
            self.mechanisms[item.evidence.id] = ("image", root, reference)
        elif family == "restart" and len(memory_roots[item.scope]) == 1:
            reference = next(iter(memory_roots[item.scope]))
            identifiers = self._query(item, (item.scope, "memory", reference))
            self._add(item, Support.OOM_RESTART, identifiers)
            if identifiers:
                self.mechanisms[item.evidence.id] = ("memory", "oom", reference)
        elif family == "probe" and subtype.startswith("liveness-"):
            if subtype != "liveness-termination":
                self._add(
                    item,
                    Support.PROBE_TERMINATION,
                    self._query(item, (item.scope, "probe-termination")),
                )
                if Support.PROBE_TERMINATION in self.supports[item.evidence.id]:
                    self.mechanisms[item.evidence.id] = ("probe", "liveness", "termination")
        elif family in {"setup", "failure"}:
            opposite = (
                "Failed"
                if item.key.reason == "FailedCreatePodSandBox"
                else "FailedCreatePodSandBox"
            )
            if any(
                token in item.evidence.signature.variant.lower()
                for token in ("sandbox", "setup", "create container")
            ):
                self._add(
                    item, Support.SETUP_PAIR, self._query(item, (item.scope, "setup", opposite))
                )

    def _multiple(self, candidates: tuple[_Candidate, ...]) -> None:
        buckets: dict[tuple[object, ...], list[_Candidate]] = defaultdict(list)
        for item in candidates:
            obj = item.key.object
            if not obj.cluster or not obj.namespace or item.evidence.counts.mode != "occurrence":
                continue
            family = item.evidence.signature.family
            mechanism = self.mechanisms[item.evidence.id]
            if family == "mount" and item.evidence.signature.targets:
                buckets[("dependency", obj.cluster, obj.namespace, mechanism)].append(item)
            elif family == "scheduling" and item.evidence.signature.targets:
                buckets[("constraint", obj.cluster, obj.namespace, mechanism)].append(item)
            elif family == "eviction" and item.evidence.signature.subtype in {
                "memory-pressure",
                "disk-pressure",
            }:
                if item.affected_node:
                    node = item.affected_node
                    if (
                        len(
                            self.context.generations.get(
                                (obj.cluster, None, "Node", node or ""), set()
                            )
                        )
                        <= 1
                    ):
                        buckets[
                            ("pressure", obj.cluster, node, item.evidence.signature.subtype)
                        ].append(item)
        for key, items in buckets.items():
            points = sorted(
                (row.timestamp, item.evidence.id, item.key.object)
                for item in items
                for row in item.rows
            )
            left = 0
            owners: dict[ObjectIdentity, int] = defaultdict(int)
            latest: dict[ObjectIdentity, str] = {}
            qualifying: dict[str, tuple[str, ...]] = {}
            proofs: dict[str, str] = {}
            covered = -1
            for right, (timestamp, _, owner) in enumerate(points):
                owners[owner] += 1
                latest[owner] = points[right][1]
                while timestamp - points[left][0] > timedelta(
                    seconds=self.policy.correlation_seconds
                ):
                    owners[points[left][2]] -= 1
                    if owners[points[left][2]] == 0:
                        del owners[points[left][2]]
                    left += 1
                if (
                    len(owners) >= self.policy.corroboration_objects
                    and right - left + 1 >= self.policy.corroboration_observations
                ):
                    witness = tuple(sorted({latest[value] for value in islice(owners, 2)}))
                    explanation = (
                        f"{len(owners)} objects and {right - left + 1} independent observations "
                        f"in [{points[left][0].isoformat()}, {timestamp.isoformat()}]"
                    )
                    for _, identifier, _ in points[max(left, covered + 1) : right + 1]:
                        qualifying.setdefault(identifier, witness)
                        proofs.setdefault(identifier, explanation)
                    covered = right
            if not qualifying:
                continue
            support = (
                Support.DEPENDENCY
                if key[0] == "dependency"
                else Support.CONSTRAINT
                if key[0] == "constraint"
                else Support.PRESSURE
            )
            token = stable_id("association", *tuple(str(part) for part in key))
            for item in items:
                if item.evidence.id not in qualifying:
                    continue
                self.supports[item.evidence.id].add(support)
                kind: Literal["dependency", "corroboration"] = (
                    "dependency" if support == Support.DEPENDENCY else "corroboration"
                )
                identifiers = tuple(sorted({item.evidence.id, *qualifying[item.evidence.id]}))
                self.links[item.evidence.id].append(
                    Association(
                        kind,
                        token,
                        identifiers,
                        Confidence.MEDIUM,
                        support.value + "; " + proofs[item.evidence.id],
                    )
                )
                if support == Support.DEPENDENCY:
                    self.dependency_roots[item.evidence.id] = token

    def _nodes(self, candidates: tuple[_Candidate, ...]) -> None:
        nodes: dict[tuple[str | None, str], list[_Candidate]] = defaultdict(list)
        for item in candidates:
            if item.evidence.signature.family == "node" and item.key.object.kind == "Node":
                nodes[(item.key.object.cluster, item.rows[0].object.name)].append(item)
        for item in candidates:
            if item.key.object.kind != "Pod" or not item.key.object.cluster:
                continue
            if not item.affected_node:
                continue
            name = item.affected_node
            generation_claims = self.context.node_uids[item.key.object]
            if len(generation_claims) > 1:
                continue
            for node in nodes.get((item.key.object.cluster, name), ()):
                if generation_claims:
                    if (
                        node.key.object.identifier_kind != "uid"
                        or node.key.object.identifier not in generation_claims
                    ):
                        continue
                elif (
                    len(self.context.generations[(item.key.object.cluster, None, "Node", name)])
                    != 1
                ):
                    continue
                family, subtype = item.evidence.signature.family, item.evidence.signature.subtype
                pressure = (
                    family == "eviction"
                    and subtype == "disk-pressure"
                    and node.evidence.signature.subtype == "disk-pressure"
                )
                explicit = (
                    family in {"setup", "failure", "warning"}
                    and bool(
                        re.search(
                            rf"\bnode\s+(?:{re.escape(name)}\s+)?"
                            r"(?:is\s+)?(?:notready|not ready)\b",
                            item.evidence.signature.variant,
                            re.I,
                        )
                    )
                    and node.evidence.signature.subtype == "not-ready"
                )
                if not (pressure or explicit) or not _near(
                    item, node, self.policy.correlation_seconds
                ):
                    continue
                support = Support.NODE_PRESSURE if pressure else Support.NODE_FAILURE
                self.supports[item.evidence.id].add(support)
                self.links[item.evidence.id].append(
                    Association(
                        "node",
                        node.evidence.id,
                        (item.evidence.id, node.evidence.id),
                        Confidence.MEDIUM,
                        "matching affected node, compatible condition, generation and "
                        "nearby evidence; reporter is not used",
                    )
                )
                timeline = _Timeline(
                    tuple(sorted({row.timestamp for row in node.rows})),
                    tuple("node" for _ in sorted({row.timestamp for row in node.rows})),
                )
                if all(
                    timeline.nearby((row,), self.policy.correlation_seconds) for row in item.rows
                ):
                    self.node_roots[item.evidence.id] = node.evidence.id
                    break


def _incident(
    members: tuple[Finding, ...],
    scope: Literal["workload", "object", "node", "dependency"],
    name: str,
    cluster: str | None,
    namespace: str | None,
) -> Incident:
    ordered = tuple(
        sorted(members, key=lambda item: (-item.evidence.signature.specificity, item.id))
    )
    first = min(item.evidence.first.timestamp for item in ordered)
    last = max(item.evidence.last.timestamp for item in ordered)
    by_reason: dict[str, list[Finding]] = defaultdict(list)
    for item in ordered:
        by_reason[item.evidence.first.reason].append(item)
    counts = tuple(
        ReasonCount(reason, combine_counts(tuple(item.evidence.counts for item in values)))
        for reason, values in sorted(by_reason.items())
    )
    objects = tuple(
        sorted(
            {item.object.identity for item in ordered},
            key=lambda obj: stable_id("object", obj.token),
        )
    )
    associations = tuple(
        sorted(
            {link for item in ordered for link in item.associations},
            key=lambda link: (link.kind, link.target, link.evidence_ids),
        )
    )
    root = ordered[0]
    if scope == "node":
        root = next((item for item in ordered if item.object.identity.kind == "Node"), root)
    hypothesis = root.diagnosis.hypothesis
    if root.mechanism[0] == "memory" and any(
        item.evidence.signature.family == "restart" for item in ordered
    ):
        hypothesis = "OOM evidence with related restart backoff. " + hypothesis
    if any(link.kind == "rollout" for link in associations):
        hypothesis += (
            " An evidence-linked scale-up preceded failure onset; "
            "rollout causation remains a hypothesis."
        )
    limitations = tuple(
        sorted(
            {text for item in ordered for text in item.limitations}
            | {
                "event reason counts are observations, not independent crash totals",
                "silence or generic Started events do not establish recovery",
            }
        )
    )
    identifier = stable_id(
        "incident", scope, cluster, namespace, name, tuple(item.id for item in ordered)
    )
    return Incident(
        identifier,
        scope,
        name,
        cluster,
        namespace,
        Severity.CRITICAL
        if any(item.diagnosis.severity == Severity.CRITICAL for item in ordered)
        else Severity.WARNING,
        hypothesis,
        root.diagnosis.confidence,
        root.diagnosis.next_verification,
        ordered,
        counts,
        first,
        last,
        any(episode.recurrent for item in ordered for episode in item.evidence.episodes),
        objects,
        associations,
        limitations,
    )


def build_report(
    aggregation: Aggregation, events: tuple[Event, ...], stats: InputStats, policy: Policy
) -> Report:
    """Finalize one immutable report. Inference never manufactures reportability."""
    if (
        aggregation.effective_policy_sha256 != policy.digest()
        or aggregation.input_record_count != stats.input_record_count
    ):
        raise ValueError("aggregation/input/effective policy mismatch")
    context = _Context(events)
    rows_by_source = {(event.provenance.source, event.provenance.line): event for event in events}
    candidates = []
    for group in aggregation.groups:
        for evidence in group.evidence:
            if evidence.disposition != Disposition.SIGNAL:
                continue
            rows = tuple(
                rows_by_source[(ref.source, ref.line)] for ref in evidence.source_references
            )
            attribution, ownership_links = context.ownership(rows, policy)
            affected_node_name, node_sources = context.node_assignment(rows[0])
            candidates.append(
                _Candidate(
                    group.key,
                    evidence,
                    rows,
                    attribution,
                    ownership_links,
                    affected_node_name,
                    node_sources,
                )
            )
    candidates.sort(
        key=lambda item: (
            item.evidence.first.timestamp,
            -item.evidence.signature.specificity,
            item.evidence.id,
        )
    )
    linker = _Links(tuple(candidates), policy, context)
    findings = []
    by_id = {item.evidence.id: item for item in candidates}
    for item in candidates:
        associations = [*item.ownership_links, *linker.links[item.evidence.id]]
        if item.affected_node:
            associations.append(
                Association(
                    "node",
                    item.affected_node,
                    item.node_source_ids,
                    Confidence.HIGH,
                    "affected-node association from resource/scheduling evidence "
                    "on the same Pod UID",
                )
            )
        identifiers = tuple(
            sorted(
                {
                    item.evidence.id,
                    *tuple(
                        identifier
                        for association in associations
                        if association.kind
                        in {"cause-symptom", "corroboration", "dependency", "node"}
                        for identifier in association.evidence_ids
                        if identifier in by_id
                    ),
                }
            )
        )
        diagnosis = diagnose(
            item.evidence,
            frozenset(linker.supports[item.evidence.id]),
            affected_node=item.key.object.kind == "Node",
        )
        diagnosis = replace(diagnosis, evidence_ids=identifiers)
        limitations = {text for row in item.rows for text in row.limitations}
        limitations.update(item.evidence.counts.limitations)
        if item.attribution.basis != "confirmed":
            limitations.add(item.attribution.explanation)
        if item.evidence.counts.mode in {"cumulative", "mixed"}:
            limitations.add(
                "source counters/growth intervals do not provide exact event-time-window totals"
            )
        findings.append(
            Finding(
                item.evidence.id,
                item.rows[0].object,
                item.evidence,
                item.attribution,
                diagnosis,
                linker.mechanisms[item.evidence.id],
                tuple(
                    sorted(
                        set(associations),
                        key=lambda link: (link.kind, link.target, link.evidence_ids),
                    )
                ),
                tuple(sorted(limitations)),
                tuple(sorted({row.object.name for row in item.rows})),
                tuple(
                    sorted(
                        {row.node.affected_node for row in item.rows if row.node.affected_node}
                        | ({item.affected_node} if item.affected_node else set())
                    )
                ),
            )
        )
    buckets: list[list[Finding]] = []
    descriptors: list[
        tuple[Literal["workload", "object", "node", "dependency"], str, str | None, str | None]
    ] = []
    latest_anchor: dict[tuple[object, ...], int] = {}
    for finding in findings:
        if not finding.diagnosis.reportable:
            continue
        obj = finding.object.identity
        scope: Literal["workload", "object", "node", "dependency"] = "object"
        name, namespace = f"{obj.kind}/{finding.object.name}", obj.namespace
        key: tuple[object, ...] = ("object", obj, finding.evidence.container, finding.mechanism)
        node_root = linker.node_roots.get(finding.id)
        if finding.evidence.signature.family == "node" and obj.kind == "Node":
            scope, name, namespace = "node", finding.object.name, None
            key = ("node", obj, finding.mechanism)
        elif node_root:
            node_candidate = by_id[node_root]
            scope, name, namespace = "node", node_candidate.rows[0].object.name, None
            key = ("node", node_candidate.key.object, linker.mechanisms[node_root])
        elif finding.id in linker.dependency_roots:
            scope = "dependency"
            name = ", ".join(
                f"{target.kind}/{target.name}" for target in finding.evidence.signature.targets
            )
            key = ("dependency", linker.dependency_roots[finding.id])
        elif finding.attribution.workload is not None:
            scope, name = "workload", finding.attribution.name or name
            key = (
                "workload",
                finding.attribution.workload,
                finding.attribution.generation,
                finding.evidence.container,
                finding.mechanism,
            )
        index = latest_anchor.get(key)
        if index is not None and _episode_compatible(
            by_id[finding.id], by_id[buckets[index][0].id], policy.correlation_seconds
        ):
            buckets[index].append(finding)
        else:
            latest_anchor[key] = len(buckets)
            buckets.append([finding])
            descriptors.append((scope, name, obj.cluster, namespace))
    incidents = [
        _incident(tuple(members), *descriptor)
        for members, descriptor in zip(buckets, descriptors, strict=True)
    ]

    def ranking(incident: Incident) -> tuple[int, int, float, int, datetime, str]:
        recurrent_span = max(
            (
                (episode.last - episode.first).total_seconds()
                for member in incident.members
                for episode in member.evidence.episodes
                if episode.recurrent
            ),
            default=0.0,
        )
        comparable = (
            sum(value.counts.observed_occurrences or 0 for value in incident.reason_counts)
            if all(value.counts.mode == "occurrence" for value in incident.reason_counts)
            else 0
        )
        return (
            0 if incident.severity == Severity.CRITICAL else 1,
            -len(incident.affected_objects),
            -recurrent_span,
            -comparable,
            incident.first,
            incident.id,
        )

    incidents.sort(key=ranking)
    disclosures = tuple(
        SeriesDisclosure(
            series.identity,
            group.key,
            series.counts,
            tuple(row.provenance for row in series.observations),
            series.growth_intervals,
        )
        for group in aggregation.groups
        for series in group.series
        if series.counts.mode != "occurrence"
    )
    used_records = {
        identifier
        for item in findings
        for association in item.associations
        for identifier in association.evidence_ids
        if identifier in context.records
    }
    report_limitations = []
    if not events:
        report_limitations.append("empty input; no conclusion about cluster health")
    if stats.missing_cluster_records or stats.missing_namespace_records:
        report_limitations.append(
            "incomplete object identity limits associations and health conclusions"
        )
    if stats.defaulted_count_records:
        report_limitations.append(
            "missing source counts assumed one; see input defaulted_count_records"
        )
    if disclosures:
        report_limitations.append(
            "non-occurrence count semantics present; inspect series disclosures and count quality"
        )
    return Report(
        "1",
        __version__,
        aggregation.requested_count_mode,
        policy.digest(),
        stats,
        aggregation.noise_record_count,
        aggregation.context_record_count,
        aggregation.signal_record_count,
        aggregation.repeated_payload_candidates,
        tuple(incidents),
        tuple(item for item in findings if not item.diagnosis.reportable),
        disclosures,
        tuple(
            sorted(
                (context.records[identifier] for identifier in used_records),
                key=lambda item: item.sort_key,
            )
        ),
        tuple(report_limitations),
    )
