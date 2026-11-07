# Kubernetes event triage

An offline Python 3.12 CLI for strict OTel-shaped Kubernetes JSONL events. It filters lifecycle noise, resolves occurrence/cumulative counts, and produces prioritized incidents with exact object evidence, time ranges, confidence and next checks. It never contacts a cluster or external API at runtime.

## Requirements and installation

Use CPython **3.12.x**. Runtime dependencies: **Python standard library only**. Development/build tools and their complete dependency closure are pinned with SHA-256 hashes in `requirements-dev.lock`. Downloading tools or the Docker base image needs network access; processing inputs does not. GNU Make is optional for direct Python commands, and required for Make targets. Docker requires a running Linux engine. Keep supplied assessment data and captures in the private reviewer repository.

From a fresh copy of this repository, on Linux/macOS:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install --index-url https://pypi.org/simple --timeout 120 --retries 3 --require-hashes --only-binary=:all: -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m build --wheel --no-isolation
python3.12 -m venv build/runtime
build/runtime/bin/python -m pip install --no-index --no-deps dist/*.whl
build/runtime/bin/k8s-triage test-cases/01-healthy.jsonl
```

On Windows PowerShell, use `py -3.12 -m venv .venv`, `.venv/Scripts/python.exe` instead of `.venv/bin/python`, and `build/runtime/Scripts/python.exe` / `build/runtime/Scripts/k8s-triage.exe` for the separate runtime. Supply the actual wheel filename rather than a PowerShell wildcard to pip. Do not depend on a pre-existing environment or any `.internal/` file.

Equivalent Make commands:

```sh
make install PYTHON=python3.12
make check build
make run INPUT=test-cases/02-memory-leak.jsonl
make run INPUT=test-cases/03-image-pull-failure.jsonl ARGS=--json
make audit
```

`VENV`, `VPY`, `PIP_ARGS` and `PYTEST_ARGS` are overridable. For offline development, first obtain all platform-compatible locked wheels using `pip download --require-hashes --only-binary=:all: -r requirements-dev.lock -d wheelhouse`, then use `make install PIP_ARGS='--no-index --find-links wheelhouse'`. Pip verifies every downloaded dependency against the lock. Build uses those installed tools with isolation downloads disabled.

The wheel build hook normalizes ZIP platform/permission metadata, ordering and timestamps, using uncompressed entries to avoid compressor-version differences. Package contents and RECORD hashes are preserved. This corrects an observed Windows/Linux archive difference and allows the same wheel hash to be verified from both systems.

## CLI contract

```text
k8s-triage INPUT [--json] [--config PATH] [--count-mode auto|occurrence|cumulative]
k8s-triage --version
```

Run the installed command or `python -m k8s_event_triage`. `--config config.example.toml` demonstrates all frozen defaults. Precedence: defaults, explicit TOML, explicit CLI count mode. JSON contains complete incident members, representative bodies, source line/byte offsets and raw/canonical hashes. Text and JSON use the same immutable report; IDs, order and UTF-8/LF output are deterministic. Successful analysis exits **0**, including incidents. Errors use stderr: usage/config **2**, invalid input/admission **3**, internal/output **1**, interruption **130**. Complete analysis precedes report output; a broken output sink can still interrupt emission.

Input must contain JSON objects with `timestamp`, string `body`, `attributes` and `resource`; object kind/name and event reason are required. UTC offsets and up to six fractional timestamp digits are supported. Duplicate JSON keys, nonfinite numbers, malformed UTF-8, invalid counts and unsupported timestamps fail explicitly. BOM at byte zero, CRLF and counted blank lines are accepted. Missing count defaults to one with disclosure; missing optional identities constrain correlation. Limits default to 100,000 records, 128 MiB input and 64 KiB per physical line. Empty input makes no cluster-health claim.

## Design rationale

Python 3.12 keeps review and operation inexpensive: one modular process, typed immutable models and no runtime dependencies, database, infrastructure or AI service. Streaming admission bounds input before in-memory finalization. Expected worst-case work is O(N log N) with O(N + groups + signatures) state; limits fail instead of silently evicting evidence.

`parse.py` validates identity/timestamps/provenance; `group.py` resolves series counts and chronological episodes; `classify.py` retains diagnostic signatures and applies reason/body-specific rules; `correlate.py` builds direct typed associations and compatible workload incidents; `render.py` serializes one report; `cli.py` owns exit/error handling. Small pure caches and lazy canonicalization reduce lifecycle cost without skipping validation or dropping rows.

Affected objects, producer attribution, controller ownership, affected nodes and causal hypotheses remain separate. Nodes are cluster-scoped and identified by object name/UID. Explicit ownership evidence precedes labelled naming inference. Correlation requires compatible identity, mechanism, generation and time; shared names/nodes or transitive links alone do not establish causes. Workload synthesis preserves member identities, reason counts, signatures, episodes and confidence.

Ordinary Pulling/Pulled/Created/Started/Scheduled/Killing events cannot inflate failures or prove recovery. Body inspection retains OOM-bearing Killing, Normal image BackOff and required controller/scheduling context. Recurrence requires three independent observations spanning 120 seconds, with adjacent gaps at most 600 seconds; direct OOM/Node and terminal image evidence have reason-specific exceptions. Correlation defaults to 120 seconds. These are defensible offline heuristics, not proof of uninterrupted outage or ultimate root cause.

Counting modes preserve accepted multiplicity:

| Mode | Contract |
|---|---|
| `occurrence` | Every count-1 row counts, including identical rows. Counts above one fail. |
| `cumulative` | Resolve identifiable series counters; first value is a baseline. For 1,2,3, source total is 3 and observed growth is 2. Equal counters add no growth. |
| `auto` | Distinct count-1 identities are independent under the supplied dataset contract. A series with count >1 is cumulative. N repeated-identity count-1 rows remain ambiguous with bounds 1..N. |

Missing/conflicting chronology makes increments unavailable. A decrease preserves a lower-bound maximum without invented resets. Lifetime totals, observed growth and independent occurrences stay separate. Counts of OOM, Killing and BackOff do not establish independent crash totals.

## Genuine known-scenario output

The following is the complete first five lines captured from `01-healthy.jsonl`:

```text
KUBERNETES CLUSTER EVENT TRIAGE
Records ingested: 20,000 | Filtered as noise: 12,875 | Context: 7,120 | Issues: 0
Count mode: auto | Policy SHA-256: b4403ae5c7861b5a1d061c2de91f8176b91cd8467d9bfbd8f4eb755593968509
Input SHA-256: 60b6de17645a384c4efe69fc23659c0ffa9d7dfd80f3f229db240a0e23332d8c | Repeated-payload candidates: 0
no issues detected
```

Known-scenario tests also require one recommendation-service incident across four Pods, retaining 26 OOMKilling / 91 BackOff / 26 OOM-bearing Killing observations separately; and one payment-service image-pull incident across three Pods, retaining 24 Failed / 18 Normal BackOff observations, rare manifest errors and controller context. Memory leak versus limit sizing remains a hypothesis requiring metrics.

## Containers, verification and reproduction

```sh
make docker-build
make docker-run
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=bind,source="$PWD/test-cases",target=/data,readonly k8s-event-triage /data/03-image-pull-failure.jsonl --json
```

The multi-stage Dockerfile pins the official Python image digest, builds a wheel with hash-locked tools, installs only the project into the runtime stage, removes the base image's installer, and runs as UID/GID **65532**. The allowlisted build context excludes assessment files, outputs, tests, internal notes and environments. Input is supplied through a read-only mount; runtime networking is unnecessary. Never push private assessment artifacts to a public registry.

`make check` runs the complete known/synthetic regression suite, Ruff lint/format and strict mypy. Tests cover identity/generation isolation, all count modes, chronology boundaries, rare/contradictory evidence, lifecycle filtering, negative correlations, synthesis, deterministic outputs and late errors. CI performs Linux quality/build, a separate wheel installation, capture verification, dependency audit and container smoke checks with read-only repository permissions. A configured workflow is not evidence that GitHub-hosted CI has run.

```sh
make build
make verify-outputs
make bench BENCH_OUTPUT=build/benchmark
```

Capture verification checks all six raw 04–06 outputs against the installed wheel, committed source/configuration/tests, original inputs and manifest. It requires Git history containing the executable commit recorded in the manifest (use a full clone). For a new release, freeze and verify a clean source commit S, then run `make capture SOURCE_REVISION=<full-40-character-SHA>` from that clean checkout. Commit only the refreshed evidence afterward; the manifest continues to reference S. Preserve previous evidence before refreshing. [ANALYSIS.md](ANALYSIS.md) contains the three SRE reports; [outputs/manifest.json](outputs/manifest.json) records capture lineage. [VERIFICATION.md](VERIFICATION.md) distinguishes historical benchmarks from final release certification.

Benchmarking launches the complete CLI in both formats for every supplied input, records a first launch and five measured runs, captures raw stdout/stderr and hashes, and measures elapsed time plus observed process RSS. The acceptance threshold is **each measured 20K run <5 seconds**. Host power/load, filesystem caches and memory-sampling limits affect measurements; no cold-cache or hardware-independent guarantee is implied. Verification results must come from executed checks.

The unknown analyses highlight **410** observations: 222 checkout probe failures, 11 disk-pressure Node/eviction events, and 177 scheduling failures. Their JSON reports retain **425** signal rows overall. The remaining **15** are five unrelated nonreportable transient warnings per file: one memory eviction, one mount failure and three brief readiness failures. Two late disk-pressure evictions are included in the 11 highlighted events even though the tool retains them outside the main incident's correlation window. No signal is discarded to produce these summaries.
