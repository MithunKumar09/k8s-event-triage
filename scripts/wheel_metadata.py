"""Normalize pure-Python release wheel metadata across Windows and Linux."""

from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def normalize_wheel(path: Path) -> None:
    with ZipFile(path) as source:
        entries = [(name, source.read(name)) for name in sorted(source.namelist())]
    temporary = path.with_suffix(".reproducible.tmp")
    with ZipFile(temporary, "w", compression=ZIP_STORED) as target:
        for name, payload in entries:
            info = ZipInfo(name, date_time=(2020, 2, 2, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            target.writestr(info, payload)
    temporary.replace(path)


class CustomBuildHook(BuildHookInterface):
    def finalize(self, version: str, build_data: dict[str, object], artifact_path: str) -> None:
        if version == "standard":
            normalize_wheel(Path(artifact_path))
