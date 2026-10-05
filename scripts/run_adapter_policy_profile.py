#!/usr/bin/env python3
"""Run the conditional probes through shared production decision functions.

The implementation adapter must not create operational handles from these
hypothetical inputs. This runner never certifies a configured store.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from adapter_evidence import POLICY_INVENTORY, POLICY_LAYER, validate_policy_case
from validate_conformance import load_fixture_document, resolve_artifact_pointer
from validate_extension_negotiation import (
    _invalid_constant, _unique_members, exact_json_equal,
)


PROFILE = Path(__file__).resolve().parents[1] / "conformance/profiles/execution-checkpoint"


def check_observation(observed: object, expected: object) -> None:
    if not isinstance(observed, dict) or set(observed) != {
        "raw_response", "root_accesses", "operational_handles_created",
    }:
        raise ValueError("conditional adapter observation fields mismatch")
    for key in ("root_accesses", "operational_handles_created"):
        if type(observed[key]) is not int or observed[key] != 0:
            raise ValueError("conditional adapter policy performed operational work")
    if not exact_json_equal(observed["raw_response"], expected):
        raise ValueError("actual production policy return mismatch")


def run(adapter: list[str], profile: Path = PROFILE) -> int:
    total = 0
    for case_name, names in POLICY_INVENTORY.items():
        case = profile / case_name
        manifest = load_fixture_document(case / "test.yaml")
        validate_policy_case(case, manifest["durable_host_vectors"])
        for vector in manifest["durable_host_vectors"]:
            if vector["name"] not in names:
                continue
            reference = vector["request"]
            request = resolve_artifact_pointer(
                json.loads((case / reference["file"]).read_text()), reference["pointer"], case_name,
            )
            reference = vector["raw_response"]
            expected = resolve_artifact_pointer(
                json.loads((case / reference["file"]).read_text()), reference["pointer"], case_name,
            )
            # No case name, coverage label, fixture path or golden reaches the adapter.
            execution = {"evidence_layer": POLICY_LAYER, "request": request}
            completed = subprocess.run(adapter, input=json.dumps(execution).encode(),
                                       capture_output=True, check=False)
            if completed.returncode:
                raise ValueError(f"{case_name}/{vector['name']}: policy adapter failed")
            observed = json.loads(completed.stdout.decode("utf-8"),
                                  object_pairs_hook=_unique_members,
                                  parse_constant=_invalid_constant)
            check_observation(observed, expected)
            total += 1
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", nargs="+", required=True)
    args = parser.parse_args()
    print(f"passed {run(args.adapter)} conditional adapter policy probes; no operational claims")


if __name__ == "__main__":
    main()
