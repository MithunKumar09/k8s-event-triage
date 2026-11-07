import json
import random
from dataclasses import asdict
from datetime import datetime

import pytest

from k8s_event_triage.render import _json_bytes, _timestamp, render


def legacy(value):
    assert isinstance(value, datetime)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


@pytest.mark.parametrize("mode", ["auto", "occurrence", "cumulative"])
def test_json_bytes_match_full_copy_serializer(mode, record_factory, triage):
    rows = [
        record_factory(
            reason="Killing", body='Container app was OOMKilled {[],:} "\\\n\U0001f680\u202e'
        )
    ]
    rows += [
        record_factory(
            uid="snapshot",
            count=1,
            observed=index * 60,
            reason="Unhealthy",
            body="Readiness probe failed: timeout",
        )
        for index in range(3)
    ]
    report = triage(rows, mode)
    before = asdict(report)
    expected = (
        json.dumps(
            before,
            default=legacy,
            sort_keys=True,
            separators=(",", ": "),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode()
    assert render(report, json_output=True) == expected
    assert asdict(report) == before


def test_compact_output_matches_stdlib_for_nested_and_escaped_values():
    randomizer = random.Random(42)
    atoms = [
        None,
        True,
        False,
        -1,
        0,
        1,
        -0.0,
        1.25e-20,
        1.25e20,
        "",
        '{}[],:"\\\n\r\t',
        "\U0001f680\u202e",
        "literal \\ud800",
    ]

    def value(depth):
        if depth == 0 or randomizer.randrange(3) == 0:
            return randomizer.choice(atoms)
        if randomizer.randrange(2):
            return [value(depth - 1) for _ in range(randomizer.randrange(5))]
        return {
            str(index) + randomizer.choice(("", '{}[],:\\"', "\U0001f680")): value(depth - 1)
            for index in range(randomizer.randrange(5))
        }

    for item in (
        atoms + [{}, [], {"empty": [], "nested": [{}, []]}] + [value(4) for _ in range(200)]
    ):
        expected = (
            json.dumps(
                item, sort_keys=True, ensure_ascii=True, separators=(",", ": "), allow_nan=False
            )
            + "\n"
        ).encode()
        assert _json_bytes(item) == expected
        assert json.loads(_json_bytes(item)) == item


def test_timestamp_cache_preserves_equal_instants_with_distinct_offsets():
    utc = datetime.fromisoformat("2024-06-01T00:00:00+00:00")
    offset = datetime.fromisoformat("2024-06-01T01:00:00+01:00")
    assert utc == offset
    assert _timestamp(utc) == "2024-06-01T00:00:00.000000Z"
    assert _timestamp(offset) == "2024-06-01T01:00:00.000000+01:00"
