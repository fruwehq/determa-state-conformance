#!/usr/bin/env python3
"""Compare direct production adapter results and independent storage observations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

from validate_extension_negotiation import exact_json_equal
from validate_host_authority import PROFILE, compact, hash_value, load, schema_validators, validate_profile


class AdapterOutputError(ValueError):
    pass


def parse_adapter_output(payload: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise AdapterOutputError(f"duplicate adapter member {key!r}")
            result[key] = value
        return result
    def nonfinite(value: str) -> None:
        raise AdapterOutputError(f"non-JSON adapter constant {value}")
    try:
        return json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=unique,
                          parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AdapterOutputError(f"invalid UTF-8 JSON adapter output: {error}") from error


def adapter_run(command: list[str], input_value: dict, location: str) -> object:
    completed = subprocess.run(command, input=(compact(input_value) + "\n").encode(), capture_output=True)
    if completed.returncode:
        raise AdapterOutputError(f"{location}: adapter exited {completed.returncode}: "
                                 f"{completed.stderr.decode('utf-8', 'replace')}")
    return parse_adapter_output(completed.stdout)


def adapter_call(command: list[str], input_value: dict, expected: object, location: str) -> None:
    observed = adapter_run(command, input_value, location)
    if not exact_json_equal(observed, expected):
        raise AdapterOutputError(f"{location}: direct production result or independently observed state differs")


def verify_configured_profile(observed: object, spec_root: Path, proved_ids: set[str],
                              *, require_native_proof: bool = True) -> dict:
    if type(observed) is not dict or set(observed) != {"report_bytes", "installation_evidence"} or \
            type(observed["report_bytes"]) is not str:
        raise AdapterOutputError("configured profile must return exact report bytes and installation evidence")
    report = parse_adapter_output(observed["report_bytes"].encode())
    _, profile_schema = schema_validators(spec_root)
    if type(report) is not dict or list(profile_schema.iter_errors(report)):
        raise AdapterOutputError("configured profile fails normative schema")
    if report["scope_identity"] != "scope-42":
        raise AdapterOutputError("configured profile is not bound to fixture scope")
    if report["guarantees"]["safe_relocation"]:
        raise AdapterOutputError("safe_relocation requires separate I2 native transfer suite proof")
    extension = report["extension_report"]
    if extension is not None and (report["authority_epoch"], report["scope_generation"]) != ("2", "4"):
        raise AdapterOutputError("configured profile must expose fixture epoch and generation")
    installation = observed["installation_evidence"]
    if extension is None:
        if installation is not None or any(report["guarantees"].values()):
            raise AdapterOutputError("unconfigured authority asserted a guarantee")
        return report
    if type(installation) is not dict or set(installation) != {
            "closure_bytes_base64", "configuration_bytes_base64", "observed_health", "native_proof_ids"}:
        raise AdapterOutputError("incomplete installed provider evidence")
    try:
        closure = base64.b64decode(installation["closure_bytes_base64"], validate=True)
        configuration = base64.b64decode(installation["configuration_bytes_base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise AdapterOutputError("invalid installed closure/configuration bytes") from error
    digest = lambda payload: "sha256:" + hashlib.sha256(payload).hexdigest()
    if not closure or not configuration or \
            digest(closure) != extension["provider_reference"]["content_digest"] or \
            digest(configuration) != report["topology"]["configuration_digest"] or \
            installation["observed_health"] != extension["health"] or \
            type(installation["native_proof_ids"]) is not list or \
            not all(type(item) is str for item in installation["native_proof_ids"]):
        raise AdapterOutputError("installed closure, configuration or health differs from report")
    proofs = set(installation["native_proof_ids"])
    if not require_native_proof:
        return report
    if len(proofs) != len(installation["native_proof_ids"]) or not proofs <= proved_ids:
        raise AdapterOutputError("profile names absent native proof")
    required = {
        "guarded_local_writes": {"precommit_rollback", "postcommit_lost_response_replay",
                                 "race_second_writer", "freeze_waits_for_writer"},
        "worker_fencing": {"fence_worker_allocates_new_claim", "dispatch_at_expiry",
                           "result_at_expiry", "clock_unavailable", "old_epoch", "old_attempt",
                           "principal_mismatch"},
        "complete_scope_inventory": {"freeze_after_drain", "incomplete_frozen_inventory_refuses_freeze"},
    }
    for guarantee, needed in required.items():
        if report["guarantees"][guarantee] and not needed <= proofs:
            raise AdapterOutputError(f"{guarantee} lacks applicable native proof")
    return report


def report_binding(report: dict) -> str:
    return hash_value(["determa-conformance-configured-authority-binding-1",
        report["scope_identity"], report["authority_storage_boundary"],
        report["topology"], report["source_binding_digest"],
        report["destination_binding_digest"], report["extension_report"]])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=Path("../determa-state-spec"))
    parser.add_argument("--adapter", nargs="+", required=True,
                        help="production test harness executable; receives one closed JSON input per invocation")
    args = parser.parse_args()
    validate_profile(args.spec_root)
    manifest = load(PROFILE / "vectors.generated.json")
    checked = 0
    proved_ids = set()
    initial_profile = adapter_run(args.adapter, {"kind": "configured_profile"}, "configured profile")
    actual_report = verify_configured_profile(initial_profile, args.spec_root, set(), require_native_proof=False)
    binding = report_binding(actual_report)
    guarantees = actual_report["guarantees"]
    for vector in manifest["operations"]:
        if vector["execution_tier"] == "i2_conditional":
            continue  # Conditional source rules; public relocation belongs to the I2 suite.
        if actual_report["extension_report"] is None or \
                vector["request"]["operation"] == "fence_worker" and not guarantees["worker_fencing"] or \
                vector["request"]["operation"] in {"guarded_commit", "freeze_scope"} and not guarantees["guarded_local_writes"]:
            continue
        # The adapter cannot see the ID, source classification, expected result, or after-state.
        setup = {"ledger_before": vector["ledger_before"], "binding": binding}
        call = {"request_bytes": vector["request_bytes"], "invocation": vector["invocation"],
                "native_mutation_bytes": vector["native_mutation_bytes"], "fault": vector["fault"]}
        adapter_call(args.adapter, {"kind": "operation", "setup": setup, "call": call},
                     {"binding": binding, "response_bytes": vector["expected_response_bytes"],
                      "ledger_after": vector["ledger_after"]}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    no_authority = next(item for item in manifest["profiles"] if item["id"] == "application_owned_transaction")
    adapter_call(args.adapter, {"kind": "profile", "configured_facts": no_authority["configured_facts"]},
                 no_authority["expected_outcome"], no_authority["id"])
    checked += 1
    for vector in manifest["clocks"]:
        adapter_call(args.adapter, {"kind": "clock_parse", "value": vector["value"]},
                     {"accepted": vector["source_disposition"] == "valid"}, vector["id"])
        checked += 1
    for vector in manifest["worker_checks"]:
        if not guarantees["worker_fencing"]:
            continue
        adapter_call(args.adapter, {"kind": "worker_claim_check", "binding": binding, "input": vector["input"]},
                     {**vector["expected"], "binding": binding}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    for vector in manifest["native_traces"]:
        if vector["required_guarantee"] == "safe_relocation":
            continue  # Its positive proof is bound to the future I2 transfer suite.
        if actual_report["extension_report"] is None or \
                vector["required_guarantee"] != "none" and not guarantees[vector["required_guarantee"]]:
            continue
        calls = [step["call"] for step in vector["steps"]]
        adapter_call(args.adapter, {"kind": "native_trace", "setup": vector["setup"], "binding": binding,
            "control_plan": vector["control_plan"], "calls": calls},
            {"binding": binding, "events": vector["expected_events"]}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    for vector in manifest["allocation_checks"]:
        if not guarantees["guarded_local_writes"]:
            continue
        adapter_call(args.adapter, {"kind": "scope_allocation_check", "binding": binding, "input": vector["input"]},
                     {**vector["expected"], "binding": binding}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    for vector in manifest["base_core_checks"]:
        adapter_call(args.adapter, {"kind": "base_core_refusal", "input": vector["input"]},
                     vector["expected"], vector["id"])
        checked += 1
    configured = adapter_run(args.adapter, {"kind": "configured_profile"}, "configured profile")
    final_report = verify_configured_profile(configured, args.spec_root, proved_ids)
    if not exact_json_equal(final_report, actual_report) or report_binding(final_report) != binding:
        raise AdapterOutputError("configured authority changed during native proof")
    checked += 1
    print(f"checked {checked} direct production responses and observations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
