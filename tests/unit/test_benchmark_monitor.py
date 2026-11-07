"""Synthetic Linux /proc exit races must not hide real RSS sampling failures."""

import errno
import importlib.util
import time
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "benchmark", Path(__file__).resolve().parents[2] / "scripts/benchmark.py"
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


@pytest.mark.parametrize(
    "failure,passes", [(errno.ESRCH, True), (errno.EACCES, False), (None, False)]
)
def test_proc_exit_race_requires_positive_samples_and_rejects_other_errors(
    failure, passes, monkeypatch
):
    class Process:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            time.sleep(0.04)  # Allow multiple synthetic observer reads before process exit.
            return b"completed", b""

    calls = 0

    def status(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            return "VmHWM:\t98304 kB\n" if failure else "VmHWM:\t0 kB\n"
        if failure:
            raise OSError(failure, "synthetic process status race")
        return "VmHWM:\t0 kB\n"

    monkeypatch.setattr(_MODULE.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(Path, "read_text", status)
    if passes:
        result, stdout, stderr = _MODULE.linux_measure(["synthetic-command"])
        assert result["peak_rss_bytes"] == 96 * 1024 * 1024
        assert stdout == b"completed" and stderr == b""
    else:
        with pytest.raises(RuntimeError, match="RSS monitoring failed"):
            _MODULE.linux_measure(["synthetic-command"])
