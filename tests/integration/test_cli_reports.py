import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def known_cli(tmp_path_factory):
    evidence = tmp_path_factory.mktemp("known-cli")
    results = {}
    commands = []
    for name in ("01-healthy.jsonl", "02-memory-leak.jsonl", "03-image-pull-failure.jsonl"):
        formats = {}
        for output_format in ("text", "json"):
            command = [sys.executable, "-m", "k8s_event_triage", str(_ROOT / "test-cases" / name)]
            if output_format == "json":
                command.append("--json")
            result = subprocess.run(command, capture_output=True, timeout=60)
            stem = f"{Path(name).stem}.{output_format}"
            path = evidence / (stem + ".stdout")
            path.write_bytes(result.stdout)
            (evidence / (stem + ".stderr")).write_bytes(result.stderr)
            commands.append(
                {
                    "command": command,
                    "exit_code": result.returncode,
                    "stdout_file": path.name,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_file": stem + ".stderr",
                    "format": output_format,
                    "input": name,
                }
            )
            formats[output_format] = result
        results[name] = formats
    (evidence / "commands.json").write_text(json.dumps(commands, indent=2) + "\n", encoding="utf-8")
    return results


@pytest.mark.parametrize(
    "name", ["01-healthy.jsonl", "02-memory-leak.jsonl", "03-image-pull-failure.jsonl"]
)
def test_known_cli_both_formats_complete_with_lf_and_no_stderr(name, known_cli):
    values = known_cli[name]
    for result in values.values():
        assert result.returncode == 0 and result.stderr == b""
        assert result.stdout.endswith(b"\n") and b"\r" not in result.stdout
        assert str(_ROOT).encode() not in result.stdout
    report = json.loads(values["json"].stdout)
    assert report["input"]["input_record_count"] == 20_000
    assert f"Issues: {len(report['incidents'])}".encode() in values["text"].stdout


def test_healthy_known_cli_has_no_incidents(known_cli):
    values = known_cli["01-healthy.jsonl"]
    assert b"no issues detected" in values["text"].stdout
    report = json.loads(values["json"].stdout)
    assert report["incidents"] == [] and len(report["observations"]) == 3
    assert all(not value["diagnosis"]["reportable"] for value in report["observations"])


def test_known_oom_cli_synthesizes_one_workload_without_losing_pods_or_counts(known_cli):
    values = known_cli["02-memory-leak.jsonl"]
    report = json.loads(values["json"].stdout)
    (incident,) = report["incidents"]
    assert incident["name"] == "recommendation-service" and incident["scope"] == "workload"
    assert incident["severity"] == "critical" and incident["recurrent"]
    assert len(incident["affected_objects"]) == 4 and len(incident["members"]) == 12
    counts = {
        item["reason"]: item["counts"]["observed_occurrences"] for item in incident["reason_counts"]
    }
    assert counts == {"OOMKilling": 26, "BackOff": 91, "Killing": 26}
    assert all(item["attribution"]["basis"] == "inferred" for item in incident["members"])
    assert len({member["id"] for member in incident["members"]}) == len(incident["members"])
    assert "leak" in incident["hypothesis"] and "hypotheses" in incident["hypothesis"]
    for reason, count in counts.items():
        assert (
            f"{reason}: rows={count}; mode=occurrence; observed occurrences={count}".encode()
            in values["text"].stdout
        )


def test_known_image_cli_preserves_terminal_cause_and_rollout_chain(known_cli):
    values = known_cli["03-image-pull-failure.jsonl"]
    report = json.loads(values["json"].stdout)
    (incident,) = report["incidents"]
    assert incident["name"] == "payment-service" and incident["scope"] == "workload"
    assert len(incident["affected_objects"]) == 3
    assert {
        item["reason"]: item["counts"]["observed_occurrences"] for item in incident["reason_counts"]
    } == {"Failed": 24, "BackOff": 18}
    assert all(item["attribution"]["basis"] == "confirmed" for item in incident["members"])
    manifests = [
        item
        for item in incident["members"]
        if item["evidence"]["signature"]["subtype"] == "manifest-not-found"
    ]
    assert sum(item["evidence"]["counts"]["observed_occurrences"] for item in manifests) == 3
    assert all("manifest" in item["evidence"]["first"]["body"] for item in manifests)
    assert any(link["kind"] == "rollout" for link in incident["associations"])
    assert any(event["reason"] == "ScalingReplicaSet" for event in report["context_evidence"])
    assert b"manifest" in values["text"].stdout and b"not found" in values["text"].stdout
    assert all(
        item["evidence"]["first"]["severity_text"] == "Normal"
        for item in incident["members"]
        if item["evidence"]["first"]["reason"] == "BackOff"
    )


@pytest.mark.parametrize("mode", ["occurrence", "cumulative", "auto"])
def test_cli_identical_count_one_contract_text_and_json(mode, record_factory, tmp_path):
    row = record_factory()
    path = tmp_path / "repeated.jsonl"
    path.write_text((json.dumps(row) + "\n") * 3, encoding="utf-8")
    command = [sys.executable, "-m", "k8s_event_triage", str(path), "--count-mode", mode]
    text = subprocess.run(command, capture_output=True, timeout=30)
    structured = subprocess.run([*command, "--json"], capture_output=True, timeout=30)
    assert text.returncode == structured.returncode == 0
    assert text.stderr == structured.stderr == b""
    report = json.loads(structured.stdout)
    count = report["observations"][0]["evidence"]["counts"]
    assert count["input_record_count"] == 3
    if mode == "occurrence":
        assert count["observed_occurrences"] == 3 and b"observed occurrences=3" in text.stdout
    elif mode == "cumulative":
        assert (count["source_reported_total"], count["observed_increments"]) == (1, 0)
        assert b"source-reported total=1" in text.stdout and b"observed increments=0" in text.stdout
    else:
        assert count["observed_occurrences"] is None
        assert (count["occurrence_lower_bound"], count["occurrence_upper_bound"]) == (1, 3)
        assert b"possible 1..3" in text.stdout


@pytest.mark.parametrize("json_output", [False, True])
def test_cli_repeated_execution_is_byte_deterministic(json_output, record_factory, tmp_path):
    path = tmp_path / "events.jsonl"
    row = record_factory(reason="OOMKilling", body="Container app was OOMKilled")
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    command = [
        sys.executable,
        "-m",
        "k8s_event_triage",
        str(path),
        *(["--json"] if json_output else []),
    ]
    first = subprocess.run(command, capture_output=True, timeout=30)
    second = subprocess.run(command, capture_output=True, timeout=30)
    assert first.returncode == second.returncode == 0 and first.stderr == second.stderr == b""
    assert first.stdout == second.stdout


@pytest.mark.parametrize(
    "failure", ["late-json", "duplicate-key", "count", "limit", "missing-input", "bad-enrichment"]
)
def test_cli_input_errors_have_exit_three_and_no_partial_report(failure, record_factory, tmp_path):
    row = record_factory()
    path = tmp_path / "events.jsonl"
    arguments = []
    if failure == "count":
        row["attributes"]["k8s.event.count"] = 2
        arguments = ["--count-mode", "occurrence"]
    if failure == "bad-enrichment":
        row["resource"]["k8s.deployment.uid"] = 123
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    if failure == "late-json":
        with path.open("a", encoding="utf-8") as stream:
            stream.write("{bad json}\n")
    elif failure == "duplicate-key":
        path.write_text('{"body":"one","body":"two"}\n', encoding="utf-8")
    elif failure == "limit":
        config = tmp_path / "limits.toml"
        config.write_text("max_input_bytes = 10\n", encoding="utf-8")
        arguments = ["--config", str(config)]
    elif failure == "missing-input":
        path = tmp_path / "missing.jsonl"
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", str(path), *arguments],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 3 and result.stdout == b""
    assert b"input error:" in result.stderr and b"Traceback" not in result.stderr


def test_cli_usage_error_escapes_terminal_controls():
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", "input.jsonl", "--bad\x1b[31m"],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2 and result.stdout == b""
    assert b"\x1b" not in result.stderr and b"\\u001b" in result.stderr


def test_closed_output_pipe_preserves_exit_one_without_shutdown_flush_error(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    process = subprocess.Popen(
        [sys.executable, "-m", "k8s_event_triage", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stderr is not None
    process.stdout.close()
    code = process.wait(timeout=30)
    error = process.stderr.read()
    process.stderr.close()
    assert code == 1
    assert b"output error" in error and b"Exception ignored" not in error
