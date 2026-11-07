"""Full-process CLI benchmark: first launch plus five measured runs per format."""

import argparse
import csv
import errno
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def linux_measure(command):
    started_utc = datetime.now(UTC).isoformat()
    started = time.perf_counter()
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stop = threading.Event()
    peaks = []
    failures = []

    def observe():
        while not stop.is_set():
            try:
                for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
                    if line.startswith("VmHWM:"):
                        peaks.append(int(line.split()[1]) * 1024)
            except FileNotFoundError:
                pass  # Process may have exited between reads; prior samples remain.
            except OSError as error:
                if error.errno != errno.ESRCH:
                    failures.append(str(error))
            stop.wait(0.001)

    monitor = threading.Thread(target=observe, daemon=True)
    monitor.start()
    try:
        stdout, stderr = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    finally:
        elapsed = time.perf_counter() - started
        stop.set()
        monitor.join(timeout=5)
    if not peaks or max(peaks) <= 0 or failures or monitor.is_alive():
        raise RuntimeError(f"RSS monitoring failed: {failures}")
    return (
        {
            "command": command,
            "cwd": str(ROOT),
            "started_utc": started_utc,
            "seconds": elapsed,
            "exit_code": process.returncode,
            "peak_rss_bytes": max(peaks),
            "rss_samples": len(peaks),
            "process_tree_peak_rss_bytes": None,
            "stdout_bytes": len(stdout),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_bytes": len(stderr),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        },
        stdout,
        stderr,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/benchmark")
    parser.add_argument("inputs", nargs="*", type=Path)
    args = parser.parse_args()
    if os.name == "nt":
        from _windows import environment, measure

        host = environment()
    elif sys.platform.startswith("linux"):
        measure = linux_measure
        host = {
            "python": sys.version,
            "python_executable": sys.executable,
            "os": platform.platform(),
            "machine": platform.machine(),
            "logical_processors": os.cpu_count(),
            "cpuinfo": Path("/proc/cpuinfo").read_text().split("\n\n", 1)[0],
            "memoryinfo": Path("/proc/meminfo").read_text(),
            "rss_method": (
                "Live /proc/PID/status VmHWM, requested 1ms samples; late peaks may be missed. "
                "CLI is one interpreter process; parent capture buffers excluded."
            ),
            "cache_limitations": "No cold-cache, exclusive-host or fixed-power claim.",
            "timing_method": (
                "Before Popen through communicate, including startup/analysis/render/pipe capture; "
                "evidence hashing/persistence afterward."
            ),
        }
    else:
        parser.error("RSS measurement is supported on Windows and Linux")
    inputs = args.inputs or sorted((ROOT / "test-cases").glob("*.jsonl"))
    if not inputs:
        parser.error("no JSONL inputs found")
    args.output.mkdir(parents=True, exist_ok=False)
    host["source_sha256"] = {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((ROOT / "src").rglob("*.py"))
    }
    host["dependency_lock_sha256"] = hashlib.sha256(
        (ROOT / "requirements-dev.lock").read_bytes()
    ).hexdigest()
    (args.output / "environment.json").write_text(
        json.dumps(host, indent=2) + "\n", encoding="utf-8"
    )
    results = []
    for path in inputs:
        path = path.resolve()
        input_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open("rb") as stream:
            rows = sum(bool(line.strip()) for line in stream)
        for output_format in ("text", "json"):
            command = [sys.executable, "-m", "k8s_event_triage", str(path)]
            if output_format == "json":
                command.append("--json")
            reference = None
            for number in range(6):
                result, stdout, stderr = measure(command)
                reference = stdout if reference is None else reference
                result.update(
                    input=path.name,
                    input_sha256=input_hash,
                    input_records=rows,
                    format=output_format,
                    run="first" if number == 0 else f"measured-{number}",
                    byte_deterministic=stdout == reference,
                    under_five_seconds=result["seconds"] < 5,
                )
                stem = f"{path.stem}.{output_format}.{number}"
                for suffix, payload in (("stdout", stdout), ("stderr", stderr)):
                    filename = stem + "." + suffix
                    (args.output / filename).write_bytes(payload)
                    result[suffix + "_file"] = filename
                results.append(result)
                (args.output / "results.json").write_text(
                    json.dumps(results, indent=2) + "\n", encoding="utf-8"
                )
                with (args.output / "results.csv").open(
                    "w", encoding="utf-8", newline=""
                ) as stream:
                    columns = (
                        "input",
                        "format",
                        "run",
                        "seconds",
                        "exit_code",
                        "peak_rss_bytes",
                        "process_tree_peak_rss_bytes",
                        "stderr_bytes",
                        "stdout_sha256",
                        "input_sha256",
                    )
                    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(results)
                print(
                    f"{path.name} {output_format} {result['run']}: {result['seconds']:.6f}s; "
                    f"RSS {result['peak_rss_bytes'] / 1048576:.2f} MiB; "
                    f"exit {result['exit_code']}",
                    flush=True,
                )
                if result["exit_code"] or stderr or not result["byte_deterministic"]:
                    raise RuntimeError(
                        "CLI status/stderr/byte-parity gate failed; raw evidence retained"
                    )
                if (
                    output_format == "json"
                    and json.loads(stdout)["input"]["input_record_count"] != rows
                ):
                    raise ValueError("accepted record count differs from supplied JSONL records")
            if any(not item["under_five_seconds"] for item in results[-5:]):
                print("FAIL: measured run >=5 seconds; stopping before next input/format")
                return 1
    print(f"PASS: {len(results)} complete launches; every measured run <5 seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
