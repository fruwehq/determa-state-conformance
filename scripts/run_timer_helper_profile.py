#!/usr/bin/env python3
"""Run timer vectors through a configured production helper child process.

The child receives one JSON line per invocation and must return one JSON object. The
operation input contains no vector ID, coverage label, expected result or after state.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from validate_extension_negotiation import exact_json_equal
from timer_helper_validator import validate_profile


def strict_json(payload: bytes):
    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError(f"duplicate member {name}")
            value[name] = item
        return value
    def invalid(value):
        raise ValueError(f"non-JSON constant {value}")
    return json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=invalid)


def call(command, body, label):
    completed = subprocess.run(command, input=(json.dumps(body, separators=(",", ":")) + "\n").encode(),
                               capture_output=True, check=False)
    if completed.returncode:
        raise ValueError(f"{label}: child exited {completed.returncode}: {completed.stderr.decode(errors='replace')}")
    return strict_json(completed.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", nargs="+", required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    validate_profile(args.spec_root, repository)
    document = strict_json((repository / "conformance/profiles/timer-helper/timer-01-external-helper/vectors.generated.json").read_bytes())
    machine = (repository / "conformance/profiles/timer-helper/timer-01-external-helper/machine.yaml").read_text()
    setup = (repository / "conformance/profiles/timer-helper/timer-01-external-helper/test.yaml").read_text()
    for row in document["cases"]:
        body = {"kind": "timer_operation", "machine_source": machine,
                "setup_scenario": setup, "before": row["before"], "request": row["request"],
                "trusted_now": row["trusted_now"], "claim_expires_at": row["claim_expires_at"],
                "previous_attempt_fate": row["previous_attempt_fate"],
                "admission_disposition": row["admission_disposition"]}
        observed = call(args.adapter, body, row["id"])
        expected = {"result": row["expected_result"], "after": row["after"],
                    "calls": row["expected_calls"]}
        if not exact_json_equal(observed, expected):
            raise ValueError(f"{row['id']}: result, full storage or call counts differ")
    print(f"{len(document['cases'])} timer helper operations passed")


if __name__ == "__main__":
    main()
