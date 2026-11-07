"""Regression for the observed cross-platform archive metadata difference."""

import importlib.util
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

_SPEC = importlib.util.spec_from_file_location(
    "wheel_metadata", Path(__file__).resolve().parents[2] / "scripts/wheel_metadata.py"
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_platform_permissions_order_and_compression_do_not_change_release_bytes(tmp_path):
    paths = []
    contents = {"package/main.py": b"print('hello')\n", "package.dist-info/RECORD": b"record\n"}
    for platform, permissions, compression in (
        (0, 0o100644, ZIP_DEFLATED),
        (3, 0o100755, ZIP_STORED),
    ):
        path = tmp_path / f"platform-{platform}.whl"
        with ZipFile(path, "w") as wheel:
            names = list(contents) if platform == 0 else list(reversed(contents))
            for name in names:
                item = ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
                item.create_system = platform
                item.external_attr = permissions << 16
                item.compress_type = compression
                wheel.writestr(item, contents[name])
        paths.append(path)
    assert paths[0].read_bytes() != paths[1].read_bytes()
    for path in paths:
        _MODULE.normalize_wheel(path)
    assert paths[0].read_bytes() == paths[1].read_bytes()
    with ZipFile(paths[0]) as wheel:
        assert {name: wheel.read(name) for name in wheel.namelist()} == contents
        assert all(
            item.create_system == 3
            and item.external_attr == 0o100644 << 16
            and item.compress_type == ZIP_STORED
            for item in wheel.infolist()
        )


def test_normalization_is_idempotent(tmp_path):
    path = tmp_path / "sample.whl"
    with ZipFile(path, "w") as wheel:
        wheel.writestr("package/main.py", b"original bytes\n")
    _MODULE.normalize_wheel(path)
    first = path.read_bytes()
    _MODULE.normalize_wheel(path)
    assert path.read_bytes() == first
