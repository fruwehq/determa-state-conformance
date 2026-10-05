#!/usr/bin/env python3
"""Execute reviewed engine-native tests and enforce the complete gate mapping.

The mapping and commands are trusted, reviewed implementation harness code, not
provider input. Completion comes from fresh test reports of actual executions.
This does not turn CI results into production instance verification.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from adapter_evidence import OPERATIONAL_GATES, AdapterEvidenceError
from validate_extension_negotiation import _unique_members


def relative_file(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise AdapterEvidenceError("gate paths must be repository-relative files")
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()) or path == root.resolve():
        raise AdapterEvidenceError("gate path escapes implementation root")
    return path


def validate_mapping(mapping: object, root: Path) -> set[str]:
    if not isinstance(mapping, dict) or set(mapping) != {"gates", "runs"}:
        raise AdapterEvidenceError("closed operational gate mapping required")
    gates = mapping["gates"]
    if not isinstance(gates, dict) or set(gates) != set(OPERATIONAL_GATES):
        raise AdapterEvidenceError("missing or unknown operational gate mapping")
    selectors: set[str] = set()
    for entries in gates.values():
        if (not isinstance(entries, list) or not entries
                or any(not isinstance(item, str) or "::" not in item for item in entries)
                or len(entries) != len(set(entries))):
            raise AdapterEvidenceError("gate requires distinct exact classname::name test selectors")
        selectors.update(entries)
    runs = mapping["runs"]
    if not isinstance(runs, list) or not runs:
        raise AdapterEvidenceError("operational gate runs are required")
    reports: set[Path] = set()
    for run in runs:
        if not isinstance(run, dict) or set(run) != {"command", "report", "required_environment"}:
            raise AdapterEvidenceError("closed native test run required")
        if (not isinstance(run["command"], list) or not run["command"]
                or any(not isinstance(arg, str) or not arg for arg in run["command"])):
            raise AdapterEvidenceError("native test command argument array required")
        if not any("{report}" in arg for arg in run["command"]):
            raise AdapterEvidenceError("native test command must receive its fresh {report} path")
        required = run["required_environment"]
        if (not isinstance(required, list)
                or any(not isinstance(key, str) or not key.isidentifier() for key in required)
                or len(required) != len(set(required))):
            raise AdapterEvidenceError("distinct required environment names required")
        report = relative_file(root, run["report"])
        if report in reports:
            raise AdapterEvidenceError("duplicate operational gate report")
        reports.add(report)
    return selectors


def read_report(path: Path) -> set[str]:
    if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
        raise AdapterEvidenceError("missing or oversized fresh native test report")
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise AdapterEvidenceError("test report declarations are unsupported")
    report = ET.fromstring(raw)
    if report.tag not in {"testsuite", "testsuites"}:
        raise AdapterEvidenceError("JUnit test report required")
    for suite in report.iter("testsuite"):
        for key in ("failures", "errors", "skipped", "disabled"):
            if suite.get(key, "0") != "0":
                raise AdapterEvidenceError("failed or skipped native gate is unmet")
    observed: set[str] = set()
    for case in report.iter("testcase"):
        if any(case.find(tag) is not None for tag in ("failure", "error", "skipped")):
            raise AdapterEvidenceError("failed or skipped native gate is unmet")
        if case.get("status", "run") not in {"run", "passed"}:
            raise AdapterEvidenceError("unexecuted native gate is unmet")
        classname, name = case.get("classname"), case.get("name")
        if not classname or not name:
            raise AdapterEvidenceError("test report lacks exact test identity")
        selector = f"{classname}::{name}"
        if selector in observed:
            raise AdapterEvidenceError("duplicate executed native test identity")
        observed.add(selector)
    if not observed:
        raise AdapterEvidenceError("empty native test execution is unmet")
    return observed


def run_mapping(mapping: dict, root: Path) -> int:
    required = validate_mapping(mapping, root)
    observed: set[str] = set()
    # A private fresh directory per run prevents stale files or earlier commands
    # from filling a missing report, without deleting implementation files.
    for run in mapping["runs"]:
        for key in run["required_environment"]:
            if not os.environ.get(key):
                raise AdapterEvidenceError(f"required native service configuration {key} is absent")
        with tempfile.TemporaryDirectory(prefix="determa-native-gate-") as temporary:
            report = relative_file(Path(temporary), run["report"])
            report.parent.mkdir(parents=True, exist_ok=True)
            command = [arg.replace("{report}", str(report)) for arg in run["command"]]
            result = subprocess.run(command, cwd=root, check=False)
            if result.returncode:
                raise AdapterEvidenceError("native gate command failed")
            executed = read_report(report)
        if observed & executed:
            raise AdapterEvidenceError("duplicate native test across gate runs")
        observed.update(executed)
    if required - observed:
        raise AdapterEvidenceError(f"unexecuted mapped native tests: {sorted(required - observed)}")
    return len(OPERATIONAL_GATES)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--implementation-root", type=Path)
    parser.add_argument("--mapping", type=Path)
    args = parser.parse_args()
    if args.inventory:
        print(json.dumps(OPERATIONAL_GATES, indent=2))
        return
    if args.implementation_root is None or args.mapping is None:
        parser.error("--implementation-root and --mapping are required")
    mapping = json.loads(args.mapping.read_text(), object_pairs_hook=_unique_members)
    count = run_mapping(mapping, args.implementation_root.resolve())
    print(f"passed {count} required execution-store gates through fresh native tests")


if __name__ == "__main__":
    main()
