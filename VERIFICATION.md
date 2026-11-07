# Release verification

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
