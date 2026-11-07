"""Command-line boundary; diagnostics never share successful report stdout."""

import argparse
import gc
import os
import sys
from pathlib import Path
from typing import NoReturn

from . import __version__
from .correlate import build_report
from .group import aggregate
from .parse import InputError, read_events
from .policy import load_policy
from .render import escape_text, render


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        super().error(escape_text(message))


def _discard_failed_output() -> None:
    """Prevent a second failing flush from replacing exit 1/130 with Python's 120.

    Windows closed pipes may surface as EINVAL rather than BrokenPipeError.
    Stream substitutes without a descriptor have no interpreter buffer to drain.
    """
    try:
        descriptor = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        return
    null_descriptor = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null_descriptor, descriptor)
    finally:
        os.close(null_descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="k8s-triage", description="Diagnose OTel-shaped Kubernetes JSONL events")
    parser.add_argument("input", type=Path)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--count-mode", choices=["auto", "occurrence", "cumulative"])
    parser.add_argument("--version", action="version", version=f"k8s-triage {__version__}")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.config, args.count_mode)
    except (OSError, ValueError) as error:
        print(f"configuration error: {escape_text(str(error))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("configuration interrupted", file=sys.stderr)
        return 130
    emitting = False
    collect_cycles = gc.isenabled()
    if collect_cycles:
        # JSON trees and immutable model links are acyclic; reference counting
        # still reclaims them. Restore caller state on every return/error path.
        gc.disable()
    try:
        events, stats = read_events(args.input, policy)
        grouped = aggregate(events, policy, include_noise_groups=False)
        report = build_report(grouped, events, stats, policy)
        payload = render(report, json_output=args.json_output)
        emitting = True
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    except InputError as error:
        print(f"input error: {escape_text(str(error))}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        if emitting:
            _discard_failed_output()
        print("analysis interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        _discard_failed_output()
        print("output error: broken pipe", file=sys.stderr)
        return 1
    except Exception as error:
        if emitting:
            _discard_failed_output()
        print(
            f"internal/output error: {type(error).__name__}: {escape_text(str(error))}",
            file=sys.stderr,
        )
        return 1
    finally:
        if collect_cycles:
            gc.enable()
