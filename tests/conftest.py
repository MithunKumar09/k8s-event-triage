"""Small synthetic OTel rows with explicitly controlled clocks and identities."""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from k8s_event_triage.group import aggregate
from k8s_event_triage.parse import read_events
from k8s_event_triage.policy import Policy


@pytest.fixture
def record_factory() -> Callable[..., dict[str, Any]]:
    def make(
        *,
        count: int = 1,
        uid: str | None = "event-1",
        at: float = 0,
        observed: float | None = None,
        reason: str = "Unhealthy",
        body: str = "Readiness probe failed: HTTP probe failed with statuscode: 503",
        kind: str = "Pod",
        name: str = "api-abcdef123-pod1",
        object_uid: str | None = "pod-1",
        namespace: str | None = "production",
        cluster: str | None = "cluster-a",
        node: str | None = "node-a",
        container: str | None = "app",
        severity: str = "Warning",
    ) -> dict[str, Any]:
        base = datetime(2024, 6, 1, tzinfo=UTC)

        def stamp(seconds: float) -> str:
            return (
                (base + timedelta(seconds=seconds))
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )

        attributes: dict[str, Any] = {"k8s.event.reason": reason, "k8s.event.count": count}
        resource: dict[str, Any] = {
            "k8s.object.kind": kind,
            "k8s.object.name": name,
            "k8s.object.resource_version": "1",
            "service.name": "k8s-events",
        }
        for key, value in (("k8s.event.uid", uid), ("k8s.namespace.name", namespace)):
            if value is not None:
                attributes[key] = value
        for key, value in (
            ("k8s.cluster.name", cluster),
            ("k8s.object.uid", object_uid),
            ("k8s.node.name", node),
        ):
            if value is not None:
                resource[key] = value
        if container is not None:
            resource["k8s.object.fieldpath"] = f"spec.containers{{{container}}}"
        return {
            "timestamp": stamp(at),
            "observed_timestamp": stamp(at if observed is None else observed),
            "severity_text": severity,
            "severity_number": 13,
            "body": body,
            "attributes": attributes,
            "resource": resource,
        }

    return make


@pytest.fixture
def parse_rows(tmp_path: Path) -> Callable[..., Any]:
    def parse(records: list[dict[str, Any]] | bytes, policy: Policy | None = None):
        path = tmp_path / "events.jsonl"
        payload = (
            records
            if isinstance(records, bytes)
            else b"".join((json.dumps(row, ensure_ascii=True) + "\n").encode() for row in records)
        )
        path.write_bytes(payload)
        return read_events(path, policy or Policy())

    return parse


@pytest.fixture
def analyze(parse_rows) -> Callable[..., Any]:
    def run(records, mode="auto", **policy_values):
        policy = Policy(count_mode=mode, **policy_values)
        events, stats = parse_rows(records, policy)
        return aggregate(events, policy), events, stats

    return run


@pytest.fixture
def triage(parse_rows) -> Callable[..., Any]:
    from k8s_event_triage.correlate import build_report

    def run(records, mode="auto", **policy_values):
        policy = Policy(count_mode=mode, **policy_values)
        events, stats = parse_rows(records, policy)
        return build_report(aggregate(events, policy), events, stats, policy)

    return run
