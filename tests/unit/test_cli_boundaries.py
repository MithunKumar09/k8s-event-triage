import pytest

from k8s_event_triage import cli
from k8s_event_triage.render import render


@pytest.mark.parametrize(
    "stage,exception,expected",
    [
        ("read_events", KeyboardInterrupt(), 130),
        ("load_policy", KeyboardInterrupt(), 130),
        ("build_report", RuntimeError("analysis failed\x1b[31m"), 1),
        ("render", RuntimeError("serialization failed\x1b[31m"), 1),
    ],
)
def test_processing_failures_emit_no_successful_partial_stdout(
    stage, exception, expected, monkeypatch, tmp_path, capsys
):
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"")

    def fail(*args, **kwargs):
        raise exception

    monkeypatch.setattr(cli, stage, fail)
    assert cli.main([str(path)]) == expected
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err
    assert "\x1b" not in captured.err


def test_output_error_returns_one(monkeypatch, tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"")

    class BrokenBuffer:
        def write(self, payload):
            raise OSError("output unavailable")

    class BrokenOutput:
        buffer = BrokenBuffer()

    with monkeypatch.context() as scoped:
        scoped.setattr(cli.sys, "stdout", BrokenOutput())
        result = cli.main([str(path)])
    assert result == 1 and "output unavailable" in capsys.readouterr().err


def test_rendered_evidence_escapes_controls_without_losing_full_json_body(record_factory, triage):
    body = "Container app was OOMKilled\x1b[31m\nverification detail at body end"
    report = triage([record_factory(reason="Killing", body=body)])
    text = render(report)
    assert b"\x1b" not in text and b"\\u001b" in text
    assert b"verification detail at body end" in text
    import json

    structured = json.loads(render(report, json_output=True))
    assert structured["incidents"][0]["members"][0]["evidence"]["first"]["body"] == body
