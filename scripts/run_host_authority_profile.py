#!/usr/bin/env python3
"""Compare direct production adapter results and independent storage observations."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from validate_host_authority import PROFILE, compact, load, validate_profile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=Path("../determa-state-spec"))
    parser.add_argument("--adapter", nargs="+", required=True,
                        help="production test harness executable; receives one closed JSON input per invocation")
    args = parser.parse_args()
    validate_profile(args.spec_root)
    manifest = load(PROFILE / "vectors.generated.json")
    checked = 0
    for vector in manifest["operations"]:
        # The adapter cannot see the ID, source classification, expected result, or after-state.
        setup = {"ledger_before": vector["ledger_before"], "configuration": vector["configuration"]}
        call = {"request_bytes": vector["request_bytes"], "invocation": vector["invocation"],
                "native_mutation_bytes": vector["native_mutation_bytes"], "fault": vector["fault"]}
        completed = subprocess.run(args.adapter, input=compact({"kind": "operation", "setup": setup,
                                    "call": call}) + "\n", text=True, capture_output=True)
        if completed.returncode:
            raise SystemExit(f"adapter failed on {vector['id']}: {completed.stderr}")
        observed = json.loads(completed.stdout)
        if set(observed) != {"response_bytes", "ledger_after"}:
            raise SystemExit(f"{vector['id']}: adapter must return direct response bytes and independently observed ledger")
        if observed["response_bytes"] != vector["expected_response_bytes"] or observed["ledger_after"] != vector["ledger_after"]:
            raise SystemExit(f"{vector['id']}: production result or storage observation differs")
        checked += 1
    for vector in manifest["profiles"]:
        completed = subprocess.run(args.adapter, input=compact({"kind": "profile", "configured_facts":
                                    vector["configured_facts"]}) + "\n", text=True, capture_output=True)
        if completed.returncode:
            raise SystemExit(f"adapter failed on profile {vector['id']}: {completed.stderr}")
        observed = json.loads(completed.stdout)
        if observed != vector["expected_outcome"]:
            raise SystemExit(f"{vector['id']}: configured report differs")
        checked += 1
    for vector in manifest["clocks"]:
        completed = subprocess.run(args.adapter, input=compact({"kind": "clock_parse", "value": vector["value"]}) + "\n",
                                   text=True, capture_output=True)
        if completed.returncode or json.loads(completed.stdout) != {"accepted": vector["source_disposition"] == "valid"}:
            raise SystemExit(f"{vector['id']}: canonical signed clock mismatch")
        checked += 1
    for vector in manifest["worker_checks"]:
        completed = subprocess.run(args.adapter, input=compact({"kind": "worker_claim_check", "input": vector["input"]}) + "\n",
                                   text=True, capture_output=True)
        if completed.returncode or json.loads(completed.stdout) != vector["expected"]:
            raise SystemExit(f"{vector['id']}: production dispatch/result claim check mismatch")
        checked += 1
    for vector in manifest["native_traces"]:
        calls = [step["call"] for step in vector["steps"]]
        completed = subprocess.run(args.adapter, input=compact({"kind": "native_trace", "setup": vector["setup"],
            "schedule": vector["schedule"], "calls": calls}) + "\n", text=True, capture_output=True)
        if completed.returncode:
            raise SystemExit(f"{vector['id']}: native production trace failed: {completed.stderr}")
        observed = json.loads(completed.stdout)
        expected = {"responses": [step["expected_response_bytes"] for step in vector["steps"]],
                    "ledgers": [step["expected_ledger_after"] for step in vector["steps"]]}
        if observed != expected:
            raise SystemExit(f"{vector['id']}: native response or storage trace differs")
        checked += 1
    print(f"checked {checked} direct production responses and observations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
