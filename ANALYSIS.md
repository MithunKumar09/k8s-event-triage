# Kubernetes event triage: unknown scenarios

Each file is an independent scenario in `prod-us-east-1`; all times below are UTC on 2024-06-01. Counts describe event observations, not crashes. Both formats were captured twice with identical bytes. [Capture manifest](outputs/manifest.json) records inputs, commands, policy and executable lineage; [release verification](VERIFICATION.md) records the corresponding acceptance evidence.

## 04 — Checkout readiness failures following scale-up

`production/checkout-service` has recurrent readiness failures across five Pods. Controller evidence records scale-up to five at 10:21:59.977Z. Between 10:22:07.319Z and 10:29:56.262Z, 178 `Unhealthy` observations say **“Readiness probe failed: HTTP probe failed with statuscode: 404”**; `checkout-service-7d4f8b9c5-005e2` supplies the first (source line 14887). Another 20 timeouts and 24 connection refusals affect this workload; two timeouts remain nonreportable. The seven warning incidents preserve distinct signatures, not seven proven root causes. Controller links support ownership; timing and repeated 404s suggest a probe-path/application-route regression, without proving rollout causation. [Text](outputs/04-test-a.stdout.txt), [JSON](outputs/04-test-a.json).

**Next five minutes:** halt further releases; compare probe path/port and application routes with the previous template, inspect Pod logs, test the endpoint, and check ready endpoints. If a regression is confirmed, restore a verified compatible revision; retain readiness protection.

**Confidence:** high for recurring readiness failure, medium for the proposed cause. Manifests, endpoint responses and application logs are needed; continuous outage and recovery are unproven.

## 05 — Node disk pressure with cross-workload evictions

Cluster-scoped `node-4` reports **“Node node-4 status is now: NodeHasDiskPressure”** at 10:15:00.000Z (source line 9848). The critical incident groups that single `NodeHasDiskPressure` event with eight `Evicted` observations through 10:16:37.935Z. At 10:15:15.359Z, `batch-reporter-820090759-b420b` reports **“The node had condition: [DiskPressure].”** Two further node-4 evictions at 10:19:28.413Z and 10:19:56.562Z remain observations outside the correlation window: ten distinct Pods across `data`, `production` and `staging` overall. This supports a shared node-pressure mechanism and later recurrence; uninterrupted pressure is unproven. Most workload ownership is inferred. [Text](outputs/05-test-b.stdout.txt), [JSON](outputs/05-test-b.json).

**Next five minutes:** cordon node-4, inspect free bytes/inodes and kubelet/runtime storage, identify abnormal log or writable-layer growth, and reclaim confirmed disposable data through supported cleanup. Check healthy capacity and disruption budgets before any voluntary drain; verify replacement readiness.

**Confidence:** high for disk-pressure evictions; the exhausted filesystem and responsible consumer remain unknown. Filesystem metrics, kubelet logs and Node-condition history would resolve them. Recovery is unproven.

## 06 — Data-pipeline scheduling capacity shortfall

`data/data-pipeline` has recurring `FailedScheduling` across six Pods after a controller-confirmed scale-up to twelve at 10:19:59.977Z. From 10:20:04.679Z to 10:29:59.677Z, two warning incidents retain 133 CPU-only and 44 mixed CPU/memory observations on the same six identities. `data-pipeline-3c7d2e1a9-83990` reports **“0/6 nodes are available: 6 Insufficient cpu.”** (source line 13398); mixed messages include **“3 Insufficient cpu, 3 Insufficient memory.”** Preemption messages provide no successful placement. The failure concerns requested resources fitting eligible nodes; actual CPU utilization is not established. Scale-up is a plausible trigger, not a proven underlying cause. [Text](outputs/06-test-c.stdout.txt), [JSON](outputs/06-test-c.json).

**Next five minutes:** compare Pod requests with node allocatable capacity and existing allocations; inspect autoscaler status/limits. Reduce verified nonessential demand or add eligible capacity; adjust requests only with workload evidence. Check whether pending Pods subsequently schedule.

**Confidence:** high for scheduling constraints, medium for their cause. Pod specifications, allocation totals, autoscaler logs and live status are needed. Recurrence is supported; uninterrupted unavailability and recovery remain unproven.

Operational interpretation follows Kubernetes guidance on [HTTP/readiness probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/), [Deployment rollback](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#rolling-back-a-deployment), [node-pressure eviction](https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/), [safe draining](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/) and [resource-request scheduling](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/). These references support remediation principles; scenario findings come from the retained captures and source events.
