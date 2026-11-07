"""Release evidence cannot claim a different, dirty or absent executable commit."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "capture_outputs", Path(__file__).resolve().parents[2] / "scripts/capture_outputs.py"
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(_MODULE, "ROOT", tmp_path)
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(tmp_path)], check=True, capture_output=True
    )
    for name, value in (("user.name", "Release test"), ("user.email", "release@example.invalid")):
        _MODULE.git("config", name, value)
    for name in ("src/app.py", "tests/test_app.py", "test-cases/sample.jsonl"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original\n")
    _MODULE.git("add", "--", "src", "tests", "test-cases")
    _MODULE.git("commit", "-m", "Executable source")
    revision = _MODULE.git("rev-parse", "HEAD").decode().strip()
    bindings = {
        name: _MODULE.sha((tmp_path / name).read_bytes())
        for name in ("src/app.py", "tests/test_app.py")
    }
    return tmp_path, revision, bindings


def test_evidence_commit_keeps_executable_ancestor_binding(checkout):
    root, revision, bindings = checkout
    _MODULE.verify_revision(revision, bindings)
    (root / "ANALYSIS.md").write_bytes(b"Evidence only\n")
    _MODULE.git("add", "ANALYSIS.md")
    _MODULE.git("commit", "-m", "Evidence")
    assert _MODULE.git("rev-parse", "HEAD").decode().strip() != revision
    _MODULE.verify_revision(revision, bindings)


@pytest.mark.parametrize("name", ["src/app.py", "tests/test_app.py", "test-cases/sample.jsonl"])
def test_dirty_source_test_or_input_rejected(checkout, name):
    root, revision, bindings = checkout
    (root / name).write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="differs from executable revision"):
        _MODULE.verify_revision(revision, bindings)


@pytest.mark.parametrize("change", ["add", "delete"])
def test_python_inventory_change_rejected(checkout, change):
    root, revision, bindings = checkout
    if change == "add":
        (root / "src/new.py").write_bytes(b"new\n")
        bindings["src/new.py"] = _MODULE.sha(b"new\n")
    else:
        del bindings["src/app.py"]
    with pytest.raises(ValueError, match="inventory differs"):
        _MODULE.verify_revision(revision, bindings)


@pytest.mark.parametrize("revision", ["HEAD", "bad", "0" * 40])
def test_missing_or_nonliteral_revision_rejected(checkout, revision):
    with pytest.raises(ValueError):
        _MODULE.verify_revision(revision, checkout[2])
