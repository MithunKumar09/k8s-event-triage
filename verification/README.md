# Verification records

Use descriptive stage names and dates when adding release evidence. Numeric project phases are not needed to understand a record or reproduce its checks.

| Stage | Scope |
|---|---|
| Scenario validation | Known scenarios, unknown-scenario analyses, counting semantics and diagnostic evidence |
| Release validation | Packaging, dependency integrity, cross-platform installation, containers and benchmarks |
| Source certification | Exact executable revision, wheel digest, source-bound captures and clean-checkout reproduction |
| Performance validation | Complete CLI timing, CPU/RSS measurements and explicit environment limitations |
| Publication verification | Private destination, remote revision/file inventory and actual hosted CI |

The current records are:

- [Release verification](../VERIFICATION.md): current certification and dated historical results.
- [Source certification](source-release.json): executable lineage and the current Linux acceptance results.
- [Release-validation baseline](release.json): the earlier working-tree verification record. Its pending checks describe that historical checkpoint.
- [Capture manifest](../outputs/manifest.json): the executable revision, wheel, policy, inputs and repeated output hashes.
- [Linux performance validation](linux-recovery-performance.csv): all 72 complete-process measurements from the current acceptance batch.
- [GitHub Actions](https://github.com/MithunKumar09/k8s-event-triage/actions): hosted workflow results for individual commits.

For future records, use filenames such as `performance-validation-YYYY-MM-DD.json` or `source-certification-YYYY-MM-DD.json`, replacing the date with the actual verification date. Passive records can use `verification_stage` and, when applicable, explicit comparison labels such as `baseline` and `certified`.

Keep historical and current results distinct. Preserve the original evidence before revising its presentation, retain exact measurements and hashes, and record successful checks only after they run. Documentation-only updates keep the existing executable revision and wheel digest when all bound files remain identical. Executable changes require renewed certification and captures under the existing release process.
