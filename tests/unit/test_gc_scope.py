import gc

import pytest

from k8s_event_triage import cli
from k8s_event_triage.parse import InputError


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize(
    "failure,code", [(None, 0), ("input", 3), ("interrupt", 130), ("internal", 1)]
)
def test_cli_restores_gc_state_on_every_analysis_exit(
    enabled, failure, code, tmp_path, monkeypatch, capsys
):
    original = gc.isenabled()
    (gc.enable if enabled else gc.disable)()
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    if failure:

        def fail(*args, **kwargs):
            assert not gc.isenabled()
            if failure == "input":
                raise InputError("invalid", source="test")
            if failure == "interrupt":
                raise KeyboardInterrupt
            raise RuntimeError("test internal failure")

        monkeypatch.setattr(cli, "read_events", fail)
    try:
        assert cli.main([str(path)]) == code
        assert gc.isenabled() is enabled
        captured = capsys.readouterr()
        assert not captured.out if failure else captured.out
    finally:
        (gc.enable if original else gc.disable)()
