# Release verification

## Phase 7 recovered Linux acceptance - 2026-11-08

Executable S: `95c2bb857e891f4e6127ced93b0f0c3ce3bc25f0`. Canonical wheel: `3e842b14ff6dae7dbba23c3c6f255dad5cdbd3a499f9fa66d5f822601c588595`. [Current source-bound evidence](verification/source-release.json) and [all 72 full-precision CPU/wall/RSS records](verification/linux-recovery-performance.csv) are authoritative for this local recovery. [Captures](outputs/manifest.json) bind to S; no executable content changed.

The historical Linux slowdown's underlying cause remains **unproven**. Its 5.499s wall/5.496s CPU was real and CPU-bound; persistence added only 0.013s. Six predeclared alternating retained-image runs now produce Phase 6 times 1.761605/1.712995/1.872021s and Phase 7 times 1.651721/1.645889/1.654811s. Both have identical Python binaries, flags, environments, runtime packages, module and input hashes; wheel differences are README-bearing METADATA and RECORD only. The original disposable Phase 6 development venv is unavailable; current production-image A/B is explicitly not an exact historical replay. Earlier 1700MHz and current host frequency samples are correlation, not proof of a power cause.

One complete subsequent acceptance batch passed: **72 launches, 12 first plus 60 measured; every mandatory run below five seconds**. Slowest measured 1.938863723s; maximum observed RSS 87.26MiB. Every exit is zero, stderr empty and stdout exactly matches the approved baseline. Native subprocess startup through complete pipe capture is timed; evidence writes/hash work are outside the boundary. Live VmHWM sampling may miss late peaks and excludes parent capture buffers. No cold-cache, exclusive-host or hardware-independent claim is made.

Current cgroup CPU quota is unlimited, effective CPUs 0-15, throttling delta zero, swap use zero and major page faults zero. Read-only Windows sampling recorded 131 points with reported MHz values [2900]; Balanced plan and existing workloads were preserved. No power, security, priority, affinity, quota or cache setting was changed. The full records document normal host load and environment limitations.

| Input | Format | First (s) | Measured 1-5 (s) | Peak RSS (MiB) |
|---|---|---:|---|---:|
| 01-healthy.jsonl | text | 1.678281 | 1.640816, 1.683686, 1.697608, 1.907018, 1.816500 | 86.63 |
| 01-healthy.jsonl | json | 1.727505 | 1.700384, 1.681032, 1.786420, 1.777009, 1.711492 | 86.70 |
| 02-memory-leak.jsonl | text | 1.707461 | 1.712180, 1.668751, 1.859220, 1.797657, 1.657633 | 86.97 |
| 02-memory-leak.jsonl | json | 1.650012 | 1.745639, 1.701998, 1.873525, 1.827325, 1.763251 | 87.04 |
| 03-image-pull-failure.jsonl | text | 1.666527 | 1.674272, 1.918845, 1.781235, 1.663800, 1.688137 | 86.94 |
| 03-image-pull-failure.jsonl | json | 1.667095 | 1.708332, 1.868552, 1.749560, 1.705308, 1.693856 | 87.01 |
| 04-test-a.jsonl | text | 1.688333 | 1.705067, 1.909785, 1.893042, 1.750199, 1.851549 | 86.98 |
| 04-test-a.jsonl | json | 1.693286 | 1.893454, 1.786440, 1.717508, 1.702228, 1.701497 | 86.96 |
| 05-test-b.jsonl | text | 1.724930 | 1.889890, 1.750941, 1.721462, 1.686151, 1.665799 | 86.59 |
| 05-test-b.jsonl | json | 1.838988 | 1.795061, 1.716420, 1.717557, 1.658642, 1.790077 | 86.77 |
| 06-test-c.jsonl | text | 1.900393 | 1.765059, 1.661708, 1.706062, 1.673238, 1.860610 | 87.24 |
| 06-test-c.jsonl | json | 1.747647 | 1.741132, 1.711284, 1.697805, 1.715869, 1.938864 | 87.26 |

The already successful **340 Windows / 340 Linux tests**, Ruff lint/format, strict mypy, locked installation/audit, Make/build and non-root read-only Docker correctness remain valid for unchanged S. Canonical wheel bytes match Windows, Linux and Docker; runtime has only the project distribution. Current independent source/analysis reconciliation passed all three 148/144/153-word analyses and **425 = 410 + 15** retained signal accounting. The six raw captures and analysis bodies remain unchanged; only revision-bound metadata is promoted.

Frozen policy: `b4403ae5c7861b5a1d061c2de91f8176b91cd8467d9bfbd8f4eb755593968509`. Source/configuration/test fingerprint: `53482535a87d3339d500b44ca7041b99b6e94d370c29e60c8879be9fd370dc37`. Lock: `0f2cd63f57e1e714d3d86aebcabe33a97917af34e1ffdd74ceda1fda35b4cc4a`.

This evidence intentionally embeds S, not its own evidence commit SHA. The exact descendant commit is externally verifiable from Git. Actual hosted CI and reviewer invitation/access state are separate external release gates; this local record makes no claim they have completed. [GitHub Actions](https://github.com/MithunKumar09/k8s-event-triage/actions) records the actual hosted result.

## Historical Phase 6 evidence (preserved)

The following pre-commit record, older wheel/fingerprint and then-pending Phase 7 status are historical. Use the Phase 7 source-bound evidence above for current acceptance.

Verified 2026-11-07. Phase 6 PASS; final committed-revision/submission gates remain pending.

Application source and frozen policy are unchanged. Release changes add build/documentation/CI tooling, normalize cross-platform wheel metadata, handle a Linux RSS observer exit race, and update only the development installer from pip 24.2 to 26.2.1. All other 50 pins/hash sets remain unchanged.

## Executed gates

- Windows Python 3.12.6: 331 tests, Ruff lint/format, strict mypy and clean wheel installation passed.
- Debian Linux Python 3.12.16: 331 tests, actual Make install/check/test/build/run/capture/verify/bench/audit and clean runtime installation passed from 63 intended submission files, without internal files or original environments.
- The canonical wheel hash matches native Windows, Docker build and fresh Linux build. Docker runs as UID/GID 65532 with read-only root, no capabilities/network, and only the project distribution installed. Twelve scenario outputs match native bytes; two invalid-input cases return exit 3 without successful stdout.
- The 51-package hash lock passed integrity/installed-version checks and a strict pip-audit query with no known vulnerabilities. The old installer findings were corrected without advisory suppression. This does not certify the OS image or Python interpreter against all vulnerabilities.
- Source archive inspection found no internal/agent/environment files or supplied input datasets; the intended submission source retains all six inputs. Wheel contains only ten application modules and four metadata entries.
- GitHub Actions is configured with verified action commit pins and read-only repository permissions. Hosted CI has not run. Linux executed the corresponding application/build/container verification; Docker Make wrappers were syntax/dry-run checked, with actual Docker commands tested independently.

## Performance evidence

Each environment executed 72 complete CLI subprocesses: first launch plus five measured runs per input/format. Every measured run is below five seconds. Startup through complete stdout/stderr pipe capture is timed; evidence hashing/persistence follows. Every exit is 0, stderr is empty and repeated outputs are byte-identical across both environments.

Full-precision records and input/output hashes: [Windows CSV](verification/windows-performance.csv), [Linux CSV](verification/linux-performance.csv). Environment and measurement limitations: [Windows](verification/windows-environment.json), [Linux](verification/linux-environment.json). Both use the same physical laptop through Windows/Docker Desktop; host load/frequency and caches vary. No settings were changed to manufacture a pass. RSS is observed high-water memory, not a worst-case bound, and excludes parent capture buffers.

### Windows

| Input | Format | First (s) | Measured 1–5 (s) | Peak observed RSS (MiB) |
|---|---|---:|---|---:|
| 01-healthy.jsonl | text | 1.493246 | 1.464393, 1.518160, 1.677818, 1.642206, 1.534510 | 88.00 |
| 01-healthy.jsonl | json | 1.543390 | 1.475901, 1.480846, 1.483345, 1.689722, 1.630414 | 88.01 |
| 02-memory-leak.jsonl | text | 1.617271 | 1.514645, 1.525628, 1.556666, 1.804079, 1.561485 | 88.25 |
| 02-memory-leak.jsonl | json | 1.591575 | 1.487874, 1.570603, 1.475379, 1.607078, 1.758964 | 88.18 |
| 03-image-pull-failure.jsonl | text | 1.601984 | 1.490392, 1.511757, 1.628570, 1.555638, 1.829043 | 88.23 |
| 03-image-pull-failure.jsonl | json | 1.754649 | 1.559632, 1.586471, 1.528798, 1.581428, 1.823581 | 88.07 |
| 04-test-a.jsonl | text | 1.539186 | 1.579873, 1.474141, 1.479397, 1.511267, 1.800117 | 88.09 |
| 04-test-a.jsonl | json | 1.556473 | 1.601819, 1.499507, 1.517968, 1.494588, 1.564980 | 88.32 |
| 05-test-b.jsonl | text | 1.721253 | 1.627735, 1.498219, 1.463107, 1.511767, 1.521418 | 87.91 |
| 05-test-b.jsonl | json | 1.774855 | 1.558194, 1.470946, 1.539104, 1.468967, 1.448875 | 87.79 |
| 06-test-c.jsonl | text | 1.773610 | 1.575294, 1.567824, 1.535283, 1.500891, 1.480361 | 88.47 |
| 06-test-c.jsonl | json | 1.540298 | 1.787040, 1.664601, 1.571807, 1.493663, 1.481143 | 88.47 |

### Linux

| Input | Format | First (s) | Measured 1–5 (s) | Peak observed RSS (MiB) |
|---|---|---:|---|---:|
| 01-healthy.jsonl | text | 1.497127 | 1.511740, 1.741262, 1.599200, 1.496188, 1.500098 | 86.35 |
| 01-healthy.jsonl | json | 1.501948 | 1.477004, 1.490532, 1.764421, 1.613211, 1.461229 | 86.37 |
| 02-memory-leak.jsonl | text | 1.458408 | 1.473206, 1.487867, 1.721513, 1.532303, 1.473128 | 86.84 |
| 02-memory-leak.jsonl | json | 1.495100 | 1.494481, 1.523872, 1.746818, 1.533441, 1.510271 | 87.11 |
| 03-image-pull-failure.jsonl | text | 1.494344 | 1.461411, 1.500985, 1.531507, 1.741560, 1.610007 | 86.73 |
| 03-image-pull-failure.jsonl | json | 1.495394 | 1.506822, 1.493635, 1.483329, 1.695795, 1.546530 | 86.73 |
| 04-test-a.jsonl | text | 1.496950 | 1.477618, 1.496544, 1.490587, 1.502030, 1.743488 | 86.94 |
| 04-test-a.jsonl | json | 1.538165 | 1.488079, 1.481391, 1.468194, 1.484229, 1.754108 | 87.09 |
| 05-test-b.jsonl | text | 1.587821 | 1.491342, 1.466473, 1.467588, 1.459116, 1.651882 | 86.55 |
| 05-test-b.jsonl | json | 1.533079 | 1.560876, 1.480561, 1.472191, 1.472364, 1.484173 | 86.55 |
| 06-test-c.jsonl | text | 1.723322 | 1.547563, 1.530113, 1.485856, 1.533859, 1.483844 | 86.98 |
| 06-test-c.jsonl | json | 1.664638 | 1.580208, 1.563823, 1.510439, 1.478932, 1.493634 | 86.98 |

## Evidence reconciliation and lineage

All six required unknown-scenario stdout captures and ANALYSIS.md remain byte-identical to the independently reviewed Phase 5 evidence. Their manifest is refreshed against the actual canonical wheel and current release-source fingerprint.

| Scenario | Retained signal rows | Highlighted in analysis | Other transient signal rows |
|---|---:|---:|---:|
| 04 | 227 | 222 | 5 |
| 05 | 16 | 11 | 5 |
| 06 | 182 | 177 | 5 |
| Total | 425 | 410 | 15 |

The 15 remaining rows comprise one isolated memory eviction, one isolated mount failure and three brief readiness failures per file; all are retained as nonreportable evidence. The 410 highlighted rows include two checkout timeouts and two later disk-pressure evictions outside the reportable incident totals. No signal was dropped, and event observations are not crash totals.

Wheel SHA-256: `46effd1d792c14ab532a10a532ac66fb21172bab3a1851eb12d576bb596ee073`. Effective policy SHA-256: `b4403ae5c7861b5a1d061c2de91f8176b91cd8467d9bfbd8f4eb755593968509`. Release executable/configuration fingerprint: `0e25150c6958d8429f82aa0aff4613067337108e73fbefaee10c278865447d85`. See [capture manifest](outputs/manifest.json) and [release record](verification/release.json).

Final clean Git revision, revision-bound release captures, repository privacy and actual reviewer access remain Phase 7. No submission, push or invitation occurred in Phase 6.
