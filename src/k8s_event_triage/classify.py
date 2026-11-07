"""Reason/body interpretation, lifecycle disposition and reportability rules."""

import re
from enum import StrEnum

from .model import (
    Classification,
    Confidence,
    Diagnosis,
    DiagnosticSignature,
    DiagnosticTarget,
    Disposition,
    Event,
    Evidence,
    Severity,
)

_ORDINARY = frozenset(
    {
        "Pulling",
        "Pulled",
        "Created",
        "Started",
        "Scheduled",
        "Killing",
        "SuccessfulCreate",
        "SuccessfulDelete",
        "ScalingReplicaSet",
        "Completed",
        "NodeReady",
        "NodeHasSufficientMemory",
        "NodeHasNoDiskPressure",
        "NodeHasSufficientPID",
    }
)
_CONTROLLERS = frozenset({"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob"})
_OOM = re.compile(
    r"\boomkilled\b|\boomkilling\b|memory cgroup out of memory|exceeded memory limit", re.I
)
_IMAGE = re.compile(r"(?:pull(?:ing)? image|image)\s+[\"']([^\"']+)[\"']", re.I)
_MEMORY_LIMIT = re.compile(r"memory limit\s*\(?([\d.]+\s*[KMGTPE]i?(?:B)?)", re.I)
_DEPENDENCY = re.compile(r"\b(configmap|secret|persistentvolumeclaim)\s+[\"']([^\"']+)[\"']", re.I)
_CONSTRAINT = re.compile(
    r"insufficient (?:cpu|memory|ephemeral-storage)|(?:un)?tolerated taint|"
    r"node affinity|pod affinity|anti-affinity|node selector",
    re.I,
)
_FAILURE_CLAUSE = re.compile(
    r"\bfailed(?:\s+to\b|\s*[:.])|\berror\s*[:=]|\bback[- ]off\b|"
    r"\b(?:out of memory|diskpressure|notready|connection refused|access denied)\b",
    re.I,
)


def classify(event: Event) -> Classification:
    """Inspect failure signatures first, even on Normal lifecycle records.

    Signatures retain complete unclassified variants. A probe URL is message
    evidence only, never an inferred upstream dependency. No severity, incident,
    ownership, or causal-correlation decision is made here.
    """
    body, lower, reason = event.body, event.body.lower(), event.reason
    signature: DiagnosticSignature | None = None
    if reason == "OOMKilling" or _OOM.search(body):
        limit = _MEMORY_LIMIT.search(body)
        targets: tuple[DiagnosticTarget, ...] = (
            (DiagnosticTarget("memory-limit", limit[1]),) if limit else ()
        )
        signature = DiagnosticSignature("memory", "oom", targets, body, 4)
    elif any(
        token in lower
        for token in (
            "errimagepull",
            "imagepullbackoff",
            "back-off pulling image",
            "failed to pull image",
            "failed pulling image",
        )
    ) or ("manifest" in lower and ("not found" in lower or "unknown" in lower)):
        image = _IMAGE.search(body)
        targets = (DiagnosticTarget("image", image[1]),) if image else ()
        if "manifest" in lower and ("not found" in lower or "unknown" in lower):
            subtype, specificity = "manifest-not-found", 5
        elif any(
            token in lower
            for token in (
                "unauthorized",
                "access denied",
                "pull access denied",
                "authentication required",
                "denied:",
                "forbidden",
                "failed to authorize",
                "authorization failed",
            )
        ):
            subtype, specificity = "access-denied", 5
        elif "back-off pulling image" in lower or "imagepullbackoff" in lower:
            subtype, specificity = "image-backoff", 1
        else:
            subtype, specificity = "image-pull", 1
        signature = DiagnosticSignature("image", subtype, targets, body, specificity)
    elif (
        "back-off restarting failed container" in lower
        or "backoff restarting failed container" in lower
    ):
        signature = DiagnosticSignature("restart", "container-restart", variant=body, specificity=1)
    elif reason == "FailedScheduling":
        constraints = sorted(
            {clause.strip() for clause in re.split(r"[,;]", body) if _CONSTRAINT.search(clause)}
        )
        targets = tuple(DiagnosticTarget("scheduler-constraint", text) for text in constraints)
        signature = DiagnosticSignature(
            "scheduling",
            "constraints" if targets else "unclassified",
            targets,
            body,
            3 if targets else 0,
        )
    elif reason == "Unhealthy":
        probe = next(
            (name for name in ("readiness", "liveness", "startup") if f"{name} probe" in lower),
            "unknown",
        )
        cause = (
            "timeout"
            if any(token in lower for token in ("timeout", "timed out", "deadline exceeded"))
            else "connection-refused"
            if "connection refused" in lower
            else "failure"
        )
        signature = DiagnosticSignature(
            "probe", f"{probe}-{cause}", (DiagnosticTarget("probe", probe),), body, 2
        )
    elif "liveness probe" in lower and any(
        token in lower for token in ("will be restarted", "killing", "terminating", "termination")
    ):
        signature = DiagnosticSignature(
            "probe", "liveness-termination", (DiagnosticTarget("probe", "liveness"),), body, 3
        )
    elif reason == "FailedMount":
        dependencies = sorted(
            {(match[1].lower(), match[2]) for match in _DEPENDENCY.finditer(body)}
        )
        targets = tuple(
            DiagnosticTarget(
                kind, name, event.object.identity.cluster, event.object.identity.namespace
            )
            for kind, name in dependencies
        )
        signature = DiagnosticSignature(
            "mount",
            "named-dependency" if targets else "unclassified",
            targets,
            body,
            3 if targets else 0,
        )
    elif reason in {"NodeNotReady", "NodeHasDiskPressure"}:
        signature = DiagnosticSignature(
            "node",
            "not-ready" if reason == "NodeNotReady" else "disk-pressure",
            variant=body,
            specificity=4,
        )
    elif reason == "Evicted":
        subtype = (
            "disk-pressure"
            if "diskpressure" in lower
            else "memory-pressure"
            if "memory" in lower
            else "unclassified"
        )
        signature = DiagnosticSignature("eviction", subtype, variant=body, specificity=2)
    elif reason in {"Failed", "FailedCreatePodSandBox"}:
        signature = DiagnosticSignature(
            "setup",
            "pod-sandbox" if reason == "FailedCreatePodSandBox" else "unclassified",
            variant=body,
        )
    elif _FAILURE_CLAUSE.search(body):
        signature = DiagnosticSignature("failure", "unclassified", variant=body)
    elif event.severity_text.lower() != "normal" and reason not in _ORDINARY:
        signature = DiagnosticSignature("warning", "unclassified", variant=body)
    if signature is not None:
        return Classification(Disposition.SIGNAL, signature)
    if reason in _ORDINARY:
        if reason == "Scheduled" or event.object.identity.kind in _CONTROLLERS:
            return Classification(
                Disposition.CONTEXT, DiagnosticSignature("lifecycle", reason, variant=body)
            )
        return Classification(Disposition.NOISE, None)
    return Classification(Disposition.CONTEXT, DiagnosticSignature("context", reason, variant=body))


class Support(StrEnum):
    IMAGE_PAIR = "compatible image failure and backoff"
    OOM_RESTART = "direct OOM and restart corroboration"
    SETUP_PAIR = "explicit setup-failure corroboration"
    PROBE_TERMINATION = "explicit liveness-driven termination"
    DEPENDENCY = "multiple objects reference the same typed scoped dependency"
    CONSTRAINT = "multiple objects report compatible explicit scheduler constraints"
    PRESSURE = "multiple Pods report compatible pressure on the same affected node"
    NODE_PRESSURE = "compatible affected-Node pressure evidence"
    NODE_FAILURE = "explicit affected-node failure association"


def diagnose(
    evidence: Evidence, supports: frozenset[Support] = frozenset(), *, affected_node: bool = False
) -> Diagnosis:
    """Reason-specific reportability is independent of source/log severity."""
    family, subtype = evidence.signature.family, evidence.signature.subtype
    recurrent = any(episode.recurrent for episode in evidence.episodes)
    severity = Severity.WARNING
    reportable = recurrent
    rule = "supported recurrence" if recurrent else "transient or insufficient independent evidence"
    confidence = Confidence.MEDIUM if recurrent else Confidence.LOW
    hypothesis = "Unclassified warning evidence; its underlying cause is not established."
    next_check = "Inspect the affected object's status and controller/application logs."
    if family == "memory":
        severity, reportable, confidence = Severity.CRITICAL, True, Confidence.HIGH
        rule = "direct OOM evidence"
        hypothesis = (
            "Container memory was exhausted. Memory growth/leak or an undersized limit "
            "are hypotheses requiring memory metrics and limit verification."
        )
        next_check = (
            "Check last termination reason, memory limit and RSS trend before changing resources."
        )
    elif family == "node":
        if affected_node:
            severity, reportable, confidence = Severity.CRITICAL, True, Confidence.HIGH
            rule = "direct affected-Node condition evidence"
        hypothesis = "The affected Node reports " + (
            "disk pressure."
            if subtype == "disk-pressure"
            else "NotReady; the underlying node fault is unproven."
        )
        next_check = (
            "Inspect Node conditions, kubelet status, disk usage and affected Pod placement."
        )
    elif family == "restart":
        severity = Severity.CRITICAL
        reportable = recurrent or Support.OOM_RESTART in supports
        if Support.OOM_RESTART in supports:
            rule, confidence = Support.OOM_RESTART.value, Confidence.HIGH
            hypothesis = (
                "Restart backoff is corroborated by direct OOM evidence on the same container."
            )
        else:
            hypothesis = (
                "The container repeatedly fails to restart; termination cause needs verification."
            )
        next_check = (
            "Inspect last termination state and previous container logs; "
            "verify OOM metrics if linked."
        )
    elif family == "image":
        severity = Severity.CRITICAL
        terminal = subtype in {"manifest-not-found", "access-denied"}
        reportable = terminal or recurrent or Support.IMAGE_PAIR in supports
        if terminal:
            rule, confidence = "explicit terminal image error", Confidence.HIGH
            hypothesis = (
                "The image manifest/tag is unavailable to this pull. "
                "Verify the exact image reference."
                if subtype == "manifest-not-found"
                else "The registry rejected authorization for the image pull."
            )
        else:
            hypothesis = (
                "Image pulls are failing/backing off; inspect registry, "
                "image reference and credentials."
            )
            if Support.IMAGE_PAIR in supports:
                rule, confidence = Support.IMAGE_PAIR.value, Confidence.MEDIUM
        next_check = (
            "Verify the quoted image/tag in the registry and pull credentials; "
            "inspect rollout history."
        )
    elif family in {"setup", "failure"}:
        severity = Severity.CRITICAL
        reportable = recurrent or bool(supports & {Support.SETUP_PAIR, Support.NODE_FAILURE})
        if Support.SETUP_PAIR in supports:
            rule, confidence = Support.SETUP_PAIR.value, Confidence.MEDIUM
        elif Support.NODE_FAILURE in supports:
            rule, confidence = Support.NODE_FAILURE.value, Confidence.MEDIUM
        hypothesis = (
            "Container/Pod setup is failing; the event body identifies the failing setup stage."
        )
        next_check = (
            "Inspect Pod sandbox/runtime/CNI events and node runtime logs for the quoted error."
        )
    elif family == "scheduling":
        reportable = recurrent or Support.CONSTRAINT in supports
        if Support.CONSTRAINT in supports:
            rule, confidence = Support.CONSTRAINT.value, Confidence.MEDIUM
        hypothesis = (
            "The scheduler reports placement constraints; preserve CPU, memory, "
            "taint and affinity distinctions."
        )
        next_check = (
            "Compare Pod requests, node allocatable capacity, taints and scheduling constraints."
        )
    elif family == "probe":
        termination = subtype == "liveness-termination" or (
            subtype.startswith("liveness-") and Support.PROBE_TERMINATION in supports
        )
        reportable = recurrent or termination
        if termination:
            rule, confidence = Support.PROBE_TERMINATION.value, Confidence.HIGH
        hypothesis = (
            "Liveness probes are driving container termination."
            if termination
            else "Readiness/liveness probes are failing; "
            "a probe URL alone does not establish an upstream cause."
        )
        next_check = (
            "Inspect the specific probe, application logs and endpoint response "
            "before changing probe settings."
        )
    elif family == "mount":
        reportable = recurrent or Support.DEPENDENCY in supports
        if Support.DEPENDENCY in supports:
            rule, confidence = Support.DEPENDENCY.value, Confidence.MEDIUM
        hypothesis = "Volume setup is failing against the quoted dependency or mount operation."
        next_check = (
            "Verify the named ConfigMap/Secret/PVC in its namespace and inspect mount/CSI events."
        )
    elif family == "eviction":
        reportable = recurrent or bool(supports & {Support.PRESSURE, Support.NODE_PRESSURE})
        if supports & {Support.PRESSURE, Support.NODE_PRESSURE}:
            rule, confidence = "corroborated resource-pressure eviction", Confidence.MEDIUM
        hypothesis = (
            "Pod eviction reports resource pressure; verify the affected node "
            "and pressure condition."
        )
        next_check = (
            "Inspect eviction messages, Node pressure and resource use "
            "before rescheduling workloads."
        )
    elif Support.NODE_FAILURE in supports:
        reportable, rule, confidence = True, Support.NODE_FAILURE.value, Confidence.MEDIUM
        hypothesis = "The warning explicitly references a nearby, compatible affected-Node failure."
    if recurrent:
        hypothesis += (
            " Recurrent observations are supported; uninterrupted outage "
            "or recovery is not established."
        )
    return Diagnosis(severity, reportable, rule, hypothesis, confidence, next_check, (evidence.id,))
