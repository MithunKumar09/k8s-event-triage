import pytest

from k8s_event_triage.model import Confidence


def _oom(record_factory, *, uid="oom", name="app-abcdef123-aaaaa", object_uid="pod", at=0, **extra):
    return record_factory(
        uid=uid,
        name=name,
        object_uid=object_uid,
        at=at,
        reason="OOMKilling",
        body="Container app exceeded memory limit (512Mi)",
        **extra,
    )


def test_explicit_workload_metadata_precedes_naming_and_keeps_confidence(record_factory, triage):
    row = _oom(record_factory)
    row["resource"].update(
        {"k8s.deployment.name": "explicit-owner", "k8s.deployment.uid": "owner-uid"}
    )
    (incident,) = triage([row]).incidents
    assert incident.name == "explicit-owner"
    assert incident.members[0].attribution.basis == "confirmed"
    assert incident.members[0].attribution.workload.identifier == "owner-uid"
    assert incident.members[0].attribution.confidence == Confidence.HIGH


def test_contradictory_controller_enrichment_prevents_naming_fallback(record_factory, triage):
    first = _oom(record_factory, uid="one")
    second = _oom(record_factory, uid="two", at=60)
    first["resource"].update({"k8s.deployment.name": "one", "k8s.deployment.uid": "uid1"})
    second["resource"].update({"k8s.deployment.name": "two", "k8s.deployment.uid": "uid2"})
    report = triage([first, second])
    assert report.incidents[0].scope == "object"
    assert report.incidents[0].members[0].attribution.basis == "unknown"
    first["resource"]["k8s.statefulset.name"] = "contradictory-kind"
    assert triage([first]).incidents[0].scope == "object"


def test_missing_and_reused_object_identity_make_synthesis_conservative(record_factory, triage):
    rows = [
        _oom(record_factory, uid="one", name="not-a-controller-name", object_uid="p1"),
        _oom(record_factory, uid="two", name="unrelated-object", object_uid="p2"),
    ]
    assert len(triage(rows).incidents) == 2
    assert all(item.scope == "object" for item in triage(rows).incidents)
    same_name = [
        _oom(record_factory, uid="first", object_uid="old"),
        _oom(record_factory, uid="second", object_uid="new", at=1),
    ]
    report = triage(same_name)
    assert len(report.incidents) == 2
    assert all(item.members[0].attribution.basis == "unknown" for item in report.incidents)


@pytest.mark.parametrize("distance,linked", [(119.999, True), (120, True), (120.001, False)])
def test_rollout_requires_chain_and_onset_proximity(distance, linked, record_factory, triage):
    scale = record_factory(
        uid="scale",
        kind="Deployment",
        name="application",
        object_uid="deployment",
        reason="ScalingReplicaSet",
        body="Scaled up replica set application-template to 3",
        at=0,
        severity="Normal",
    )
    creation = record_factory(
        uid="create",
        kind="ReplicaSet",
        name="application-template",
        object_uid="rs",
        reason="SuccessfulCreate",
        body="Created pod: app-abcdef123-aaaaa",
        at=0,
        severity="Normal",
    )
    failure = _oom(record_factory, at=distance)
    report = triage([scale, creation, failure])
    (incident,) = report.incidents
    assert incident.name == "application" and incident.members[0].attribution.basis == "confirmed"
    assert any(link.kind == "rollout" for link in incident.associations) is linked
    if linked:
        assert (
            len(
                [
                    event
                    for event in report.context_evidence
                    if event.reason in {"ScalingReplicaSet", "SuccessfulCreate"}
                ]
            )
            == 2
        )
        assert "causation remains a hypothesis" in incident.hypothesis
    coincident = triage([scale, failure])
    assert not any(
        link.kind == "rollout"
        for incident in coincident.incidents
        for link in incident.associations
    )


def test_ambiguous_controller_generations_do_not_establish_rollout(record_factory, triage):
    rows = [
        record_factory(
            uid=f"c-{index}",
            kind="ReplicaSet",
            name="application-template",
            object_uid=uid,
            reason="SuccessfulCreate",
            body="Created pod: app-abcdef123-aaaaa",
            at=index,
            severity="Normal",
        )
        for index, uid in enumerate(("old-rs", "new-rs"))
    ]
    rows.append(_oom(record_factory, at=10))
    (incident,) = triage(rows).incidents
    assert not any(link.kind == "rollout" for link in incident.associations)
    assert incident.members[0].attribution.basis == "unknown"


def test_node_object_name_and_namespace_isolation_with_pressure_symptom(record_factory, triage):
    node = record_factory(
        uid="node-event",
        kind="Node",
        name="affected-node",
        object_uid="node-uid",
        namespace="ignored-provenance",
        node="reporter-context",
        reason="NodeHasDiskPressure",
        body="Node has DiskPressure",
    )
    pod = record_factory(
        uid="eviction",
        name="pod",
        object_uid="pod-uid",
        namespace="different-namespace",
        node="affected-node",
        reason="Evicted",
        body="The node had condition: [DiskPressure].",
        at=1,
    )
    report = triage([node, pod])
    (incident,) = report.incidents
    assert (
        incident.scope == "node" and incident.name == "affected-node" and incident.namespace is None
    )
    assert len(incident.members) == 2 and len(incident.affected_objects) == 2
    assert report.observations == ()
    pod["resource"]["k8s.node.name"] = "reporter-context"
    unrelated = triage([node, pod])
    assert len(unrelated.incidents) == 1 and len(unrelated.incidents[0].members) == 1
    assert len(unrelated.observations) == 1


def test_recreated_node_uid_requires_generation_evidence(record_factory, triage):
    nodes = [
        record_factory(
            uid=f"node-{index}",
            kind="Node",
            name="node-a",
            object_uid=uid,
            reason="NodeHasDiskPressure",
            body="Node has DiskPressure",
            at=index * 600,
        )
        for index, uid in enumerate(("old", "new"))
    ]
    pod = record_factory(
        uid="pod",
        name="pod",
        node="node-a",
        reason="Evicted",
        body="The node had condition: [DiskPressure].",
        at=1,
    )
    report = triage(nodes + [pod])
    assert len(report.incidents) == 2 and len(report.observations) == 1
    pod["resource"]["k8s.node.uid"] = "old"
    report = triage(nodes + [pod])
    assert len(report.incidents) == 2 and report.observations == ()
    assert sorted(len(item.members) for item in report.incidents) == [1, 2]


def test_unrelated_same_node_and_probe_url_are_not_causal_links(record_factory, triage):
    node = record_factory(
        uid="node",
        kind="Node",
        name="node-a",
        object_uid="node-uid",
        reason="NodeNotReady",
        body="Node is not ready",
    )
    probe = record_factory(
        uid="probe",
        node="node-a",
        body='Readiness probe failed: Get "http://shared-service/ready": timeout',
        at=1,
    )
    independent = _oom(
        record_factory, uid="oom", name="different-abcdef123-aaaaa", object_uid="other", at=1
    )
    report = triage([node, probe, independent])
    assert len(report.incidents) == 2 and len(report.observations) == 1
    assert not any(
        link.kind == "dependency" for item in report.observations for link in item.associations
    )
    assert all(len(item.members) == 1 for item in report.incidents)


def test_scheduling_evidence_can_supply_node_association_without_reporter_inference(
    record_factory, triage
):
    scheduled = record_factory(
        uid="schedule",
        name="pod",
        node=None,
        reason="Scheduled",
        severity="Normal",
        body="Successfully assigned production/pod to node-a",
    )
    failed = record_factory(
        uid="evicted",
        name="pod",
        node=None,
        reason="Evicted",
        at=10,
        body="The node had condition: [DiskPressure].",
    )
    node = record_factory(
        uid="condition",
        kind="Node",
        name="node-a",
        object_uid="node-uid",
        reason="NodeHasDiskPressure",
        body="Node has DiskPressure",
        at=10,
    )
    report = triage([scheduled, failed, node])
    assert len(report.incidents) == 1 and len(report.incidents[0].members) == 2
    pod = next(item for item in report.incidents[0].members if item.object.identity.kind == "Pod")
    assert pod.affected_nodes == ("node-a",)
    assert pod.evidence.first.node.reporter_node is None
    assert any(event.reason == "Scheduled" for event in report.context_evidence)


@pytest.mark.parametrize("distance,issues", [(119.999, 1), (120, 1), (120.001, 0)])
def test_multi_object_dependency_window_boundaries(distance, issues, record_factory, triage):
    body = 'MountVolume.SetUp failed for volume "config": configmap "settings" not found'
    rows = [
        record_factory(uid="a1", name="a", object_uid="a", reason="FailedMount", body=body),
        record_factory(uid="a2", name="a", object_uid="a", reason="FailedMount", body=body),
        record_factory(
            uid="b1", name="b", object_uid="b", at=distance, reason="FailedMount", body=body
        ),
    ]
    report = triage(rows)
    assert len(report.incidents) == issues
    if issues:
        (incident,) = report.incidents
        assert incident.scope == "dependency" and incident.name == "configmap/settings"
        assert len(incident.affected_objects) == 2
        assert incident.reason_counts[0].counts.observed_occurrences == 3


@pytest.mark.parametrize("difference", ["namespace", "type", "generic-volume", "different-cause"])
def test_generic_or_incompatible_dependencies_do_not_promote(difference, record_factory, triage):
    body = 'MountVolume.SetUp failed for volume "config": configmap "settings" not found'
    rows = [
        record_factory(
            uid=f"e-{index}",
            object_uid="a" if index < 2 else "b",
            name="a" if index < 2 else "b",
            reason="FailedMount",
            body=body,
            at=index,
        )
        for index in range(3)
    ]
    if difference == "namespace":
        rows[2]["attributes"]["k8s.namespace.name"] = "other"
    elif difference == "type":
        rows[2]["body"] = body.replace("configmap", "secret")
    elif difference == "generic-volume":
        for row in rows:
            row["body"] = 'MountVolume.SetUp failed for volume "config": timeout'
    else:
        rows[2]["body"] = body.replace("not found", "permission denied")
    assert triage(rows).incidents == ()


def test_transitive_dependency_bridge_is_not_correlated(record_factory, triage):
    bodies = [
        'configmap "a" and secret "b" not found',
        'configmap "a" not found',
        'secret "b" not found',
    ]
    rows = [
        record_factory(
            uid=f"e-{index}",
            object_uid=f"p-{index}",
            name=f"pod-{index}",
            reason="FailedMount",
            body="MountVolume.SetUp failed: " + body,
            at=index,
        )
        for index, body in enumerate(bodies)
    ]
    assert triage(rows).incidents == ()


def test_scheduler_constraints_need_compatible_explicit_capacity_evidence(record_factory, triage):
    rows = [
        record_factory(
            uid=f"e-{index}",
            object_uid="a" if index < 2 else "b",
            name="a" if index < 2 else "b",
            reason="FailedScheduling",
            at=index,
            body="0/3 nodes are available: Insufficient cpu",
        )
        for index in range(3)
    ]
    report = triage(rows)
    assert len(report.incidents) == 2 and all(
        item.severity == "warning" for item in report.incidents
    )
    rows[2]["body"] = "0/3 nodes are available: Insufficient memory"
    assert triage(rows).incidents == ()


@pytest.mark.parametrize("kind", ["ConfigMap", "Secret", "Service", "CustomResource"])
def test_non_controller_resources_keep_object_scope(kind, record_factory, triage):
    rows = [
        record_factory(
            uid=f"e-{index}",
            kind=kind,
            object_uid="resource-uid",
            name="resource",
            at=index * 60,
            reason="ValidationWarning",
            body="resource validation warning",
        )
        for index in range(3)
    ]
    (incident,) = triage(rows).incidents
    assert incident.scope == "object"
    assert incident.members[0].attribution.basis == "unknown"
