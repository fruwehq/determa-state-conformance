#!/usr/bin/env python3
"""Non-normative black-box runner for a future Determa State CLI profile.

This driver is preserved because it is language-agnostic and useful for future
cross-language profile cases. Format 1 currently defines no CLI commands, exit codes,
JSON shapes, queue inspection, or manual stepping contract, so no cases ship with it.

Usage:
    python conformance/profiles/cli/run_cli.py \
        [--cmd "determa-state"] [--conformance-dir DIR] [CASE ...]
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream) or {}


def _resolve_argument(case_directory: Path, argument: str) -> str:
    """Resolve a bare filename when it exists inside the profile case directory."""
    if "/" not in argument and (case_directory / argument).exists():
        return str(case_directory / argument)
    return argument


class Mismatch(Exception):
    """A structural comparison failed."""


def _assert_subset(actual: Any, expected: Any, path: str = "") -> None:
    """Require expected to be a structural subset of actual."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise Mismatch(
                f"{path or '<root>'}: expected object, got {type(actual).__name__}"
            )
        for key, value in expected.items():
            if key not in actual:
                raise Mismatch(f"{path}.{key}: missing key")
            _assert_subset(actual[key], value, f"{path}.{key}")
    elif isinstance(expected, list):
        if not isinstance(actual, list):
            raise Mismatch(f"{path}: expected list, got {type(actual).__name__}")
        if len(actual) != len(expected):
            raise Mismatch(f"{path}: list length {len(actual)} != {len(expected)}")
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected, strict=False)
        ):
            _assert_subset(actual_item, expected_item, f"{path}[{index}]")
    elif actual != expected:
        raise Mismatch(f"{path or '<root>'}: {actual!r} != {expected!r}")


def _run(
    command: list[str],
    store: str,
    arguments: list[str],
    standard_input: str | None,
) -> tuple[int, str]:
    process = subprocess.run(
        [*command, "--store", store, *arguments],
        input=standard_input,
        capture_output=True,
        text=True,
    )
    return process.returncode, process.stdout


def _check_step(
    command: list[str],
    store: str,
    case_directory: Path,
    step: dict[str, Any],
) -> None:
    expected = step.get("expect") or {}
    arguments = [
        _resolve_argument(case_directory, argument) for argument in step["run"]
    ]

    if "stdin" in step:
        lines = [
            json.dumps(
                [
                    _resolve_argument(case_directory, argument)
                    for argument in command_line
                ]
            )
            for command_line in step["stdin"]
        ]
        return_code, output = _run(
            command, store, arguments, standard_input="\n".join(lines) + "\n"
        )
        if "exit" in expected and return_code != expected["exit"]:
            raise Mismatch(f"process exit {return_code} != {expected['exit']}")
        if "stream" in expected:
            actual = [json.loads(line) for line in output.splitlines() if line.strip()]
            if len(actual) != len(expected["stream"]):
                raise Mismatch(
                    f"stream length {len(actual)} != {len(expected['stream'])}"
                )
            for index, (actual_item, expected_item) in enumerate(
                zip(actual, expected["stream"], strict=False)
            ):
                _assert_subset(actual_item, expected_item, f"stream[{index}]")
        return

    return_code, output = _run(command, store, arguments, standard_input=None)
    if "exit" in expected and return_code != expected["exit"]:
        raise Mismatch(f"exit {return_code} != {expected['exit']}")
    if "json" in expected:
        actual = json.loads(output) if output.strip() else None
        _assert_subset(actual, expected["json"])
    elif "stdout" in expected and output != expected["stdout"]:
        raise Mismatch("stdout mismatch")


def _run_case(command: list[str], case_directory: Path) -> str | None:
    """Run one future profile case; return None on pass or a failure reason."""
    profile_case = _load_yaml(case_directory / "cli.yaml")
    with tempfile.TemporaryDirectory(prefix="determa-cli-") as store:
        for index, step in enumerate(profile_case.get("steps", [])):
            try:
                _check_step(command, store, case_directory, step)
            except Mismatch as error:
                return (
                    f"step {index} ({' '.join(map(str, step['run']))}): {error}"
                )
    return None


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Black-box runner for the optional Determa State CLI profile"
    )
    parser.add_argument(
        "--cmd",
        default="determa-state",
        help='invoke the implementation CLI (default "determa-state")',
    )
    parser.add_argument(
        "--conformance-dir",
        default=str(Path(__file__).resolve().parent / "cases"),
        help="directory containing future CLI profile cases",
    )
    parser.add_argument("cases", nargs="*", help="restrict to these case names")
    parsed = parser.parse_args(arguments)

    command = shlex.split(parsed.cmd)
    profile_directory = Path(parsed.conformance_dir)
    if not profile_directory.is_dir():
        print("no CLI profile cases are defined", file=sys.stderr)
        return 2

    selected = sorted(path for path in profile_directory.iterdir() if path.is_dir())
    if parsed.cases:
        wanted = set(parsed.cases)
        selected = [path for path in selected if path.name in wanted]
    if not selected:
        print("no CLI profile cases selected", file=sys.stderr)
        return 2

    failures = 0
    for case_directory in selected:
        reason = _run_case(command, case_directory)
        if reason is None:
            print(f"PASS  profile/cli/{case_directory.name}")
        else:
            failures += 1
            print(f"FAIL  profile/cli/{case_directory.name}: {reason}")
    print(f"\n{len(selected) - failures}/{len(selected)} CLI profile cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
