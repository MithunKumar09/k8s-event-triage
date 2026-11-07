import pytest

from k8s_event_triage.classify import classify
from k8s_event_triage.model import Disposition


@pytest.mark.parametrize(
    "reason,body",
    [
        ("Pulling", 'Pulling image "repo/app:v1"'),
        ("Pulled", 'Successfully pulled image "repo/app:v1"'),
        ("Created", "Created container app"),
        ("Started", "Started container app"),
        ("Killing", "Stopping container app"),
        ("SuccessfulCreate", "Created pod: app-a"),
        ("SuccessfulDelete", "Deleted pod: app-a"),
        ("Completed", "Completed successfully"),
    ],
)
@pytest.mark.parametrize("severity", ["Normal", "Warning"])
def test_ordinary_lifecycle_is_noise_after_body_inspection(
    reason, body, severity, record_factory, analyze
):
    result, _, _ = analyze([record_factory(reason=reason, body=body, severity=severity)])
    assert result.noise_record_count == 1 and result.signal_record_count == 0
    assert result.groups[0].evidence == ()


@pytest.mark.parametrize(
    "reason,body,family,subtype",
    [
        ("Killing", "Container app was OOMKilled (exit code 137)", "memory", "oom"),
        ("OOMKilling", "Container app exceeded memory limit (512Mi)", "memory", "oom"),
        ("BackOff", 'Back-off pulling image "repo/app:v1"', "image", "image-backoff"),
        (
            "Failed",
            'Failed to pull image "repo/app:bad": manifest unknown',
            "image",
            "manifest-not-found",
        ),
        ("Failed", 'Failed to pull image "repo/app:v1": unauthorized', "image", "access-denied"),
        (
            "BackOff",
            "Back-off restarting failed container app in pod app-a",
            "restart",
            "container-restart",
        ),
        ("Created", "Failed to create container: runtime error", "failure", "unclassified"),
        ("NodeHasDiskPressure", "Node condition changed", "node", "disk-pressure"),
        ("FailedCreatePodSandBox", "CNI setup rejected", "setup", "pod-sandbox"),
    ],
)
def test_diagnostics_override_normal_severity_and_lifecycle(
    reason, body, family, subtype, record_factory, parse_rows
):
    event = parse_rows([record_factory(reason=reason, body=body, severity="Normal")])[0][0]
    result = classify(event)
    assert result.disposition == Disposition.SIGNAL
    assert (result.signature.family, result.signature.subtype) == (family, subtype)
    if "512Mi" in body:
        assert result.signature.targets[0].name == "512Mi"


@pytest.mark.parametrize(
    "kind,reason,body",
    [
        ("ReplicaSet", "SuccessfulCreate", "Created pod: app-a"),
        ("ReplicaSet", "SuccessfulDelete", "Deleted pod: app-a"),
        ("Deployment", "ScalingReplicaSet", "Scaled up replica set app-123 to 3"),
        ("Pod", "Scheduled", "Successfully assigned production/api-abcdef123-pod1 to node-b"),
    ],
)
def test_attribution_context_is_retained_without_failure_observations(
    kind, reason, body, record_factory, analyze
):
    result = analyze([record_factory(kind=kind, reason=reason, body=body, severity="Normal")])[0]
    assert result.context_record_count == 1 and result.signal_record_count == 0
    assert result.groups[0].evidence[0].first.body == body
    assert result.groups[0].evidence[0].episodes == ()


def test_dependency_targets_are_typed_scoped_and_not_generic_volume_names(
    record_factory, parse_rows
):
    row = record_factory(
        reason="FailedMount",
        body='MountVolume.SetUp failed for volume "config": configmap "settings" not found',
    )
    signature = classify(parse_rows([row])[0][0]).signature
    (target,) = signature.targets
    assert (target.kind, target.name, target.cluster, target.namespace) == (
        "configmap",
        "settings",
        "cluster-a",
        "production",
    )
    row["body"] = 'MountVolume.SetUp failed for volume "config": timeout'
    assert classify(parse_rows([row])[0][0]).signature.targets == ()


def test_scheduler_constraints_and_probe_type_are_distinct_without_causal_inference(
    record_factory, parse_rows
):
    body = (
        "0/3 nodes are available: 1 Insufficient cpu, 1 Insufficient memory, "
        "1 had untolerated taint {dedicated: gpu}"
    )
    row = record_factory(reason="FailedScheduling", body=body, node=None)
    signature = classify(parse_rows([row])[0][0]).signature
    assert len(signature.targets) == 3
    assert {target.kind for target in signature.targets} == {"scheduler-constraint"}
    row = record_factory(
        body='Readiness probe failed: Get "http://10.0.0.1/ready": context deadline exceeded'
    )
    signature = classify(parse_rows([row])[0][0]).signature
    assert signature.subtype == "readiness-timeout"
    assert [(target.kind, target.name) for target in signature.targets] == [("probe", "readiness")]


def test_unknown_warning_variants_remain_evidence(record_factory, analyze):
    rows = [
        record_factory(uid=f"e-{index}", reason="UnknownReason", body=body)
        for index, body in enumerate(("new driver message A", "new driver message B"))
    ]
    result = analyze(rows)[0]
    assert result.signal_record_count == 2 and len(result.groups[0].evidence) == 2
