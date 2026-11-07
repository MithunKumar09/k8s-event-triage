"""Explicit configuration with no ambient environment overrides."""

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass, replace
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Policy:
    count_mode: str = "auto"
    episode_gap_seconds: int = 600
    recurrence_count: int = 3
    recurrence_span_seconds: int = 120
    correlation_seconds: int = 120
    corroboration_objects: int = 2
    corroboration_observations: int = 3
    max_records: int = 100_000
    max_input_bytes: int = 128 * 1024 * 1024
    max_line_bytes: int = 64 * 1024

    def validate(self) -> None:
        if type(self.count_mode) is not str or self.count_mode not in {
            "auto",
            "occurrence",
            "cumulative",
        }:
            raise ValueError("count_mode must be auto, occurrence, or cumulative")
        for name, value in asdict(self).items():
            if name != "count_mode" and (type(value) is not int or value < 1):
                raise ValueError(f"{name} must be a positive integer")

    def digest(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


def load_policy(path: Path | None, count_mode: str | None) -> Policy:
    policy = Policy()
    if path is not None:
        with path.open("rb") as stream:
            values = tomllib.load(stream)
        unknown = set(values) - set(asdict(policy))
        if unknown:
            raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
        policy = replace(policy, **values)
    if count_mode is not None:
        policy = replace(policy, count_mode=count_mode)
    policy.validate()
    return policy
