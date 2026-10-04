#!/usr/bin/env python3
"""Compare a production implementation adapter's actual §11.5 calls with the profile.

The adapter receives no case name or expected result. It starts a fresh registry for
one input, invokes actual production code, and returns its complete observation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from validate_extension_negotiation import PROFILE, load_manifest, validate_profile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", nargs="+", required=True,
                        help="Implementation harness command and arguments")
    args = parser.parse_args()
    validate_profile(args.spec_root)
    manifest = load_manifest(PROFILE / "vectors.generated.json")
    total = 0
    for mode, vectors in (("common_rule", manifest["vectors"]),
                          ("public_api", manifest["public_vectors"])):
        for vector in vectors:
            if mode == "common_rule":
                keys = ("registrations", "registration_bytes", "configurations",
                        "requirements", "lookup_uri", "operation", "hypothetical_verification")
            else:
                keys = ("installation", "registration", "registration_bytes",
                        "configuration", "requirement", "untrusted_candidate_report", "lookup_uri")
            request = {"mode": mode, "provider_closure": manifest["provider_closure"],
                       "profile_path": str(PROFILE),
                       "input": {key: vector[key] for key in keys}}
            completed = subprocess.run(args.adapter, input=json.dumps(request), text=True,
                                       capture_output=True, check=False)
            if completed.returncode:
                raise SystemExit(f"{vector['id']}: adapter failed: {completed.stderr.strip()}")
            try:
                observed = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise SystemExit(f"{vector['id']}: adapter returned invalid JSON: {error}") from error
            expected_keys = {"decision", "core_mutations"} if mode == "common_rule" else {
                "decision", "core_mutations", "stages", "loaded_source", "loaded_closure_digest"}
            if not isinstance(observed, dict) or set(observed) != expected_keys:
                raise SystemExit(f"{vector['id']}: adapter observation fields mismatch")
            if observed["decision"] != vector["expected"] or observed["core_mutations"] != 0:
                raise SystemExit(f"{vector['id']}: observed decision or core mutation mismatch")
            if mode == "public_api":
                if observed["stages"] != vector["expected_stages"]:
                    raise SystemExit(f"{vector['id']}: public API stage trace mismatch")
                if observed["loaded_source"] not in manifest["provider_closure"]["closure_files"] or \
                   observed["loaded_closure_digest"] != manifest["provider_closure"]["content_digest"]:
                    raise SystemExit(f"{vector['id']}: loaded provider identity mismatch")
            total += 1
    print(f"passed {total} extension negotiation runtime vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
