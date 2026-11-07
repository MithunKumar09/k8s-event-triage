import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from k8s_event_triage.policy import Policy, load_policy


def test_installed_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", "--version"], capture_output=True
    )
    assert result.returncode == 0
    assert result.stdout == b"k8s-triage 0.1.0\n" or result.stdout == b"k8s-triage 0.1.0\r\n"
    assert result.stderr == b""


def test_config_precedence_and_validation(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text('count_mode = "cumulative"\nrecurrence_count = 4\n', encoding="utf-8")
    assert load_policy(path, "occurrence").count_mode == "occurrence"
    assert load_policy(path, None).recurrence_count == 4
    path.write_text("unknown = 1", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown"):
        load_policy(path, None)
    with pytest.raises(ValueError, match="positive integer"):
        Policy(recurrence_count=True).validate()


def test_policy_defaults_and_digest() -> None:
    policy = load_policy(None, None)
    assert policy.count_mode == "auto"
    assert policy.episode_gap_seconds == 600
    assert policy.recurrence_count == 3
    assert policy.recurrence_span_seconds == policy.correlation_seconds == 120
    assert policy.max_records == 100_000
    assert policy.max_input_bytes == 128 * 1024 * 1024
    assert policy.max_line_bytes == 64 * 1024
    assert policy.digest() == Policy().digest()
    assert len(policy.digest()) == 64
    assert policy.digest() != replace(policy, count_mode="occurrence").digest()


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "3"])
def test_config_rejects_invalid_thresholds(tmp_path: Path, value: object) -> None:
    path = tmp_path / "policy.toml"
    literal = '"3"' if isinstance(value, str) else str(value).lower()
    path.write_text(f"recurrence_count = {literal}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="positive integer"):
        load_policy(path, None)


@pytest.mark.parametrize("arguments", [[], ["input.jsonl", "--count-mode", "invalid"]])
def test_usage_errors_have_no_success_stdout(arguments: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", *arguments], capture_output=True
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"usage:" in result.stderr


def test_help_lists_approved_interface() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", "--help"], capture_output=True
    )
    assert result.returncode == 0
    assert result.stderr == b""
    for option in (b"--json", b"--config", b"--count-mode", b"--version"):
        assert option in result.stdout


@pytest.mark.parametrize("configuration", ["unknown = 1", "recurrence_count = [", None])
def test_cli_configuration_errors(tmp_path: Path, configuration: str | None) -> None:
    path = tmp_path / "policy.toml"
    if configuration is not None:
        path.write_text(configuration, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", "input.jsonl", "--config", str(path)],
        capture_output=True,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"configuration error:" in result.stderr


@pytest.mark.parametrize("mode", ["auto", "occurrence", "cumulative"])
def test_empty_input_completes_without_claiming_cluster_health(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "k8s_event_triage", str(path), "--count-mode", mode, "--json"],
        capture_output=True,
    )
    assert result.returncode == 0
    assert b'"input_record_count": 0' in result.stdout
    assert b"empty input; no conclusion about cluster health" in result.stdout
    assert result.stderr == b""
