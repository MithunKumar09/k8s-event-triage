import pytest

from k8s_event_triage.model import Disposition
from k8s_event_triage.parse import InputError


@pytest.mark.parametrize("resource_node", [None, "node-other", "node-affected"])
def test_node_identity_is_cluster_scoped_and_affected_name_wins(
    resource_node, record_factory, analyze
):
    rows = [
        record_factory(
            kind="Node",
            name="node-affected",
            object_uid="node-uid",
            node=resource_node,
            namespace=namespace,
            uid=f"event-{index}",
            reason="NodeNotReady",
            body="Node is not ready",
        )
        for index, namespace in enumerate(("one", "two"))
    ]
    result, events, _ = analyze(rows)
    assert len(result.groups) == 1
    for event in events:
        assert event.object.identity.namespace is None and event.object.identity.scope == "cluster"
        assert event.node.affected_node == "node-affected"
        assert event.node.resource_node == resource_node and event.node.reporter_node is None
        assert event.container is None
    assert {event.object.raw_namespace for event in events} == {"one", "two"}


def test_object_uid_namespace_cluster_and_generation_isolation(record_factory, analyze):
    rows = [
        record_factory(uid=f"e-{index}", **changes)
        for index, changes in enumerate(
            [
                {},
                {"namespace": "another"},
                {"cluster": "cluster-b"},
                {"cluster": None},
                {"object_uid": "recreated"},
                {"object_uid": None},
            ]
        )
    ]
    result, _, _ = analyze(rows)
    assert len(result.groups) == 6
    assert {group.counts.observed_occurrences for group in result.groups} == {1}


def test_name_fallback_is_tagged_and_resource_versions_do_not_split_identity(
    record_factory, analyze
):
    rows = [record_factory(uid="e-1", object_uid=None), record_factory(uid="e-2", object_uid=None)]
    rows[1]["resource"]["k8s.object.resource_version"] = "99"
    result, events, _ = analyze(rows)
    assert len(result.groups) == 1 and result.groups[0].counts.observed_occurrences == 2
    assert events[0].object.identity.identifier_kind == "name"
    rows.append(record_factory(uid="e-3", object_uid=rows[0]["resource"]["k8s.object.name"]))
    result, _, _ = analyze(rows)
    assert len(result.groups) == 2  # UID text matching a name is still a different tagged identity.


def test_uid_identity_preserves_changed_display_names(record_factory, analyze):
    result, events, _ = analyze(
        [record_factory(uid="e-1"), record_factory(uid="e-2", name="renamed")]
    )
    assert len(result.groups) == 1
    assert {event.object.name for event in events} == {"api-abcdef123-pod1", "renamed"}


def test_node_uid_recreation_and_cluster_isolation(record_factory, analyze):
    rows = [
        record_factory(
            kind="Node",
            name="node-a",
            object_uid=uid,
            cluster=cluster,
            uid=f"e-{index}",
            reason="NodeNotReady",
        )
        for index, (uid, cluster) in enumerate(
            [
                ("node-generation-1", "cluster-a"),
                ("node-generation-2", "cluster-a"),
                ("node-generation-1", "cluster-b"),
                ("node-generation-1", None),
            ]
        )
    ]
    assert len(analyze(rows)[0].groups) == 4


def test_namespaced_fallback_and_conflicting_metadata(record_factory, parse_rows):
    row = record_factory(namespace=None)
    row["resource"]["k8s.namespace.name"] = "resource-namespace"
    event = parse_rows([row])[0][0]
    assert event.object.identity.namespace == "resource-namespace"
    assert "namespace taken from resource metadata" in event.limitations
    row["attributes"]["k8s.namespace.name"] = "different"
    with pytest.raises(InputError, match="conflicting namespace"):
        parse_rows([row])


def test_named_container_kinds_and_unknown_container_stay_separate(record_factory, analyze):
    paths = [
        "spec.containers{app}",
        "spec.initContainers{app}",
        "spec.ephemeralContainers{app}",
        "spec.containers[0]",
    ]
    rows = [record_factory(uid=f"e-{index}") for index in range(4)]
    for row, path in zip(rows, paths, strict=True):
        row["resource"]["k8s.object.fieldpath"] = path
    result, events, _ = analyze(rows)
    assert len(result.groups) == 1 and len(result.groups[0].evidence) == 4
    assert {event.container.kind if event.container else None for event in events} == {
        "container",
        "init",
        "ephemeral",
        None,
    }
    assert events[-1].raw_fieldpath == paths[-1] and events[-1].container is None


def test_pod_scheduling_association_requires_matching_object_scope(record_factory, parse_rows):
    body = "Successfully assigned production/api-abcdef123-pod1 to node-scheduled"
    row = record_factory(reason="Scheduled", body=body, node=None, severity="Normal")
    event = parse_rows([row])[0][0]
    assert event.node.affected_node == "node-scheduled" and event.node.basis == "scheduling"
    assert (
        event.node.reporter_node is None
        and event.source_attribution.component == "default-scheduler"
    )
    row["resource"]["k8s.node.name"] = "node-conflict"
    event = parse_rows([row])[0][0]
    assert event.node.affected_node is None and event.node.basis == "conflicting"
    row["body"] = "Successfully assigned different/api-abcdef123-pod1 to node-unrelated"
    del row["resource"]["k8s.node.name"]
    assert parse_rows([row])[0][0].node.affected_node is None


@pytest.mark.parametrize(
    "kind,reason,component",
    [
        ("Pod", "BackOff", "kubelet"),
        ("Pod", "FailedScheduling", "default-scheduler"),
        ("ReplicaSet", "SuccessfulCreate", "replicaset-controller"),
        ("Deployment", "ScalingReplicaSet", "deployment-controller"),
        ("Node", "NodeHasDiskPressure", "node-controller"),
        ("Pod", "UnknownReason", None),
    ],
)
def test_source_attribution_is_labelled_and_not_application_ownership(
    kind, reason, component, record_factory, parse_rows
):
    event = parse_rows([record_factory(kind=kind, reason=reason)])[0][0]
    assert event.source_attribution.component == component
    assert event.source_attribution.basis == ("inferred" if component else "unknown")
    assert event.source_attribution.producer_service == "k8s-events"
    assert event.node.reporter_node is None


def test_controller_context_is_preserved_without_incident_or_recurrence(record_factory, analyze):
    row = record_factory(
        kind="Deployment",
        reason="ScalingReplicaSet",
        severity="Normal",
        body="Scaled up replica set api-abcdef123 to 3",
        node=None,
    )
    result, _, _ = analyze([row])
    (evidence,) = result.groups[0].evidence
    assert evidence.disposition == Disposition.CONTEXT and evidence.episodes == ()
    assert result.signal_record_count == result.noise_record_count == 0
    assert result.context_record_count == 1
