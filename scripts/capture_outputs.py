"""Capture or verify raw unknown-scenario output against a built wheel."""

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from zipfile import ZipFile

import k8s_event_triage
from k8s_event_triage.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
STEMS = ("04-test-a", "05-test-b", "06-test-c")


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def source_bindings() -> dict[str, str]:
    paths = [*ROOT.glob("src/**/*.py"), *ROOT.glob("scripts/*.py"), *ROOT.glob("tests/**/*.py")]
    paths.extend(
        ROOT / name
        for name in (
            "pyproject.toml",
            "README.md",
            "requirements-dev.in",
            "requirements-dev.lock",
            "Makefile",
            "Dockerfile",
            ".dockerignore",
            ".gitattributes",
            ".gitignore",
            "config.example.toml",
            ".github/workflows/ci.yml",
        )
    )
    return {path.relative_to(ROOT).as_posix(): sha(path.read_bytes()) for path in sorted(paths)}


def fingerprint(bindings: dict[str, str]) -> str:
    return sha(json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode())


def git(*arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments], capture_output=True, timeout=60, check=False
    )
    if result.returncode:
        raise ValueError(
            f"Git revision verification failed: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def verify_revision(revision: str, bindings: dict[str, str]) -> None:
    """Bind current executable/tests/inputs to an existing ancestor commit, never ambient HEAD."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision requires a full 40-character Git commit SHA")
    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != ROOT:
        raise ValueError("capture requires this repository's checkout")
    if git("rev-parse", revision + "^{commit}").decode().strip() != revision:
        raise ValueError("source revision is not an exact commit")
    git("merge-base", "--is-ancestor", revision, "HEAD")
    entries = {}
    for entry in git("ls-tree", "-rz", revision).split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            mode, kind, digest = metadata.split()
            entries[name.decode()] = (mode, kind, digest.decode())
    source_paths = {
        name
        for name in entries
        if name.startswith(("src/", "scripts/", "tests/")) and name.endswith(".py")
    }
    current_paths = {name for name in bindings if name.endswith(".py")}
    inputs = {p.relative_to(ROOT).as_posix() for p in ROOT.glob("test-cases/*.jsonl")}
    committed_inputs = {
        name for name in entries if name.startswith("test-cases/") and name.endswith(".jsonl")
    }
    if source_paths != current_paths or inputs != committed_inputs:
        raise ValueError("source/test/input inventory differs from executable revision")
    names = sorted(set(bindings) | inputs)
    actual = git("hash-object", "--no-filters", "--", *names).decode().splitlines()
    for name, digest in zip(names, actual, strict=True):
        if name not in entries or entries[name][0] not in {b"100644", b"100755"}:
            raise ValueError(f"missing or unsupported committed file: {name}")
        if entries[name][1:] != (b"blob", digest):
            raise ValueError(f"file differs from executable revision: {name}")


def verify_wheel(wheel: Path) -> str:
    installed = Path(k8s_event_triage.__file__).resolve().parent
    with ZipFile(wheel) as archive:
        for path in (ROOT / "src/k8s_event_triage").glob("*.py"):
            expected = path.read_bytes()
            if archive.read("k8s_event_triage/" + path.name) != expected:
                raise ValueError(f"wheel/source mismatch: {path.name}")
            if (installed / path.name).read_bytes() != expected:
                raise ValueError(f"installed/source mismatch: {path.name}")
    return sha(wheel.read_bytes())


def execute(stem: str, structured: bool) -> tuple[bytes, bytes, list[str]]:
    arguments = ["-m", "k8s_event_triage", f"test-cases/{stem}.jsonl"]
    if structured:
        arguments.append("--json")
    result = subprocess.run(
        [sys.executable, *arguments], cwd=ROOT, capture_output=True, timeout=60, check=False
    )
    if result.returncode or result.stderr:
        raise RuntimeError(
            f"{stem}: exit {result.returncode}, stderr={result.stderr!r}; captures not refreshed"
        )
    result.stdout.decode("utf-8", errors="strict")
    if b"\r" in result.stdout or not result.stdout.endswith(b"\n"):
        raise ValueError("report must use UTF-8/LF")
    return result.stdout, result.stderr, arguments


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-revision", help="full executable commit SHA; required to refresh")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    wheel_hash = verify_wheel(args.wheel)
    bindings = source_bindings()
    source_hash = fingerprint(bindings)
    manifest_path = ROOT / "outputs/manifest.json"
    previous = json.loads(manifest_path.read_bytes()) if manifest_path.exists() else None
    if previous and not (args.verify or args.refresh):
        parser.error("captures exist; use --verify or explicitly --refresh")
    revision = args.source_revision or (previous.get("source_revision") if args.verify else None)
    if not isinstance(revision, str):
        parser.error("provide --source-revision for refresh; verification needs a bound manifest")
    verify_revision(revision, bindings)
    if not args.verify and git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("refresh requires a clean executable checkout before capture")
    if args.verify:
        if previous is None:
            raise ValueError("capture manifest is missing")
        if previous.get("capture_status") != "PASS":
            raise ValueError("captures are not marked valid for the current release")
        if previous.get("source_revision") != revision:
            raise ValueError("manifest source revision differs from requested executable revision")
        if previous.get("source_configuration_sha256") != bindings:
            raise ValueError("source/configuration binding map differs")
        expected_paths = {
            f"outputs/{stem}{suffix}" for stem in STEMS for suffix in (".stdout.txt", ".json")
        }
        if (
            len(previous["artifacts"]) != 6
            or {item["stdout"] for item in previous["artifacts"]} != expected_paths
        ):
            raise ValueError("capture manifest must contain exactly the six required outputs")
        for key, expected in (
            ("executable_configuration_sha256", source_hash),
            ("wheel_sha256", wheel_hash),
            ("effective_policy_sha256", Policy().digest()),
        ):
            if previous.get(key) != expected:
                raise ValueError(f"stale capture lineage: {key}")
        if previous["analysis"]["sha256"] != sha((ROOT / "ANALYSIS.md").read_bytes()):
            raise ValueError("analysis has changed; recheck facts before refreshing")
    pending: dict[str, bytes] = {}
    artifacts = []
    for stem in STEMS:
        input_hash = sha((ROOT / f"test-cases/{stem}.jsonl").read_bytes())
        for structured in (False, True):
            output_format = "json" if structured else "text"
            stdout_name = f"outputs/{stem}.json" if structured else f"outputs/{stem}.stdout.txt"
            stderr_name = f"outputs/{stem}.{output_format}.stderr.txt"
            runs = []
            baseline = None
            for number in (1, 2):
                stdout, stderr, arguments = execute(stem, structured)
                if baseline is not None and stdout != baseline:
                    raise ValueError(f"nondeterministic output: {stem}/{output_format}")
                baseline = stdout
                runs.append(
                    {
                        "run": number,
                        "exit_code": 0,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "stdout_sha256": sha(stdout),
                        "stderr_sha256": sha(stderr),
                    }
                )
            assert baseline is not None
            if structured:
                report = json.loads(baseline)
                if report["input"]["input_sha256"] != input_hash:
                    raise ValueError("input digest mismatch")
                if report["effective_policy_sha256"] != Policy().digest():
                    raise ValueError("effective policy mismatch")
            pending[stdout_name], pending[stderr_name] = baseline, b""
            item = {
                "input": f"test-cases/{stem}.jsonl",
                "input_sha256": input_hash,
                "format": output_format,
                "python_arguments": arguments,
                "stdout": stdout_name,
                "stderr": stderr_name,
                "runs": runs,
                "byte_repeatable": True,
            }
            if args.verify:
                matches = [a for a in previous["artifacts"] if a["stdout"] == stdout_name]
                if len(matches) != 1 or matches[0]["input_sha256"] != input_hash:
                    raise ValueError(f"missing/stale manifest input: {stdout_name}")
                if matches[0] != item:
                    raise ValueError(
                        f"capture commands/statuses/quantities/hashes differ: {stdout_name}"
                    )
                for name in (stdout_name, stderr_name):
                    if (ROOT / name).read_bytes() != pending[name]:
                        raise ValueError(f"captured bytes differ: {name}")
            artifacts.append(item)
    if source_bindings() != bindings:
        raise ValueError("source/configuration changed during capture")
    verify_revision(revision, bindings)
    if args.verify:
        print("PASS: six captures match installed wheel/source, policy, analysis and repeated runs")
        return 0
    manifest = {
        "schema_version": "1",
        "phase": 7,
        "capture_status": "PASS",
        "source_revision": revision,
        "wheel_sha256": wheel_hash,
        "lineage": (
            "Installed executable verified against wheel and committed executable revision; "
            "source, configuration, tests and supplied inputs match that revision."
        ),
        "executable_configuration_sha256": source_hash,
        "source_configuration_sha256": bindings,
        "dependency_lock_sha256": sha((ROOT / "requirements-dev.lock").read_bytes()),
        "python_version": sys.version,
        "capture_environment": {"os": platform.platform(), "machine": platform.machine()},
        "configuration_file": None,
        "configuration_sha256": None,
        "effective_policy": asdict(Policy()),
        "effective_policy_sha256": Policy().digest(),
        "invocation": "python -m k8s_event_triage INPUT [--json], from repository root",
        "artifacts": artifacts,
        "analysis": {
            "path": "ANALYSIS.md",
            "sha256": sha((ROOT / "ANALYSIS.md").read_bytes()),
            "scenario_word_counts": previous["analysis"]["scenario_word_counts"]
            if previous
            else None,
            "fact_verification": "See ANALYSIS.md and release verification evidence",
        },
    }
    pending["outputs/manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    for name, payload in pending.items():
        path = ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(payload)
        temporary.replace(path)
    print(
        "PASS: six raw captures refreshed after 12 successful repeatable runs; "
        "manifest bound to wheel/source"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"capture error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
