#!/usr/bin/env python3
"""Compare direct production adapter results and independent storage observations."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import subprocess
from pathlib import Path

from validate_conformance import canonical_json_bytes
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
            "closure_bytes_base64", "configuration_bytes_base64", "observed_health",
            "participant_installations", "native_proof_ids"}:
        raise AdapterOutputError("incomplete installed provider evidence")
    try:
        closure = base64.b64decode(installation["closure_bytes_base64"], validate=True)
        configuration = base64.b64decode(installation["configuration_bytes_base64"], validate=True)
    except (ValueError, TypeError, binascii.Error) as error:
        raise AdapterOutputError("invalid installed closure/configuration bytes") from error
    digest = lambda payload: "sha256:" + hashlib.sha256(payload).hexdigest()
    if not closure or not configuration or \
            digest(closure) != extension["provider_reference"]["content_digest"] or \
            digest(configuration) != report["topology"]["configuration_digest"] or \
            installation["observed_health"] != extension["health"] or \
            type(installation["native_proof_ids"]) is not list or \
            not all(type(item) is str for item in installation["native_proof_ids"]):
        raise AdapterOutputError("installed closure, configuration or health differs from report")
    participants = installation["participant_installations"]
    if type(participants) is not list or len(participants) != len(report["required_participants"]):
        raise AdapterOutputError("installed participant inventory differs from report")
    for installed, required in zip(participants, report["required_participants"]):
        if type(installed) is not dict or set(installed) != {
                "participant", "closure_bytes_base64", "observed_health"} or \
                not exact_json_equal(installed["participant"], required) or \
                installed["observed_health"] != "healthy":
            raise AdapterOutputError("installed participant differs from report")
        try:
            participant_closure = base64.b64decode(installed["closure_bytes_base64"], validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise AdapterOutputError("invalid installed participant closure bytes") from None
        if not participant_closure or digest(participant_closure) != required["provider_reference"]["content_digest"]:
            raise AdapterOutputError("installed participant closure digest differs from report")
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


def select_production_scenario(manifest: dict, report: dict) -> dict | None:
    applicability = {"topology_identifier": report["topology"]["identifier"],
                     "required_participants": [{"role": item["role"], "instance_id": item["instance_id"]}
                         for item in report["required_participants"]]}
    matching = [row for row in manifest["production_scenarios"] if
                exact_json_equal(row["applicability"], applicability)]
    guarantees = report["guarantees"]
    if guarantees["guarded_local_writes"] and len(matching) != 1:
        raise AdapterOutputError("claimed native topology has no exact configured production scenario")
    if guarantees["worker_fencing"] and (len(matching) != 1 or matching[0]["id"] != "worker_sqlite"):
        raise AdapterOutputError("worker fencing lacks exact configured journal/worker scenario")
    if guarantees["complete_scope_inventory"] and len(matching) != 1:
        raise AdapterOutputError("scope inventory lacks exact configured production scenario")
    return matching[0] if guarantees["guarded_local_writes"] else None


def common_rule_input(vector: dict) -> dict:
    return {"kind": "common_rule_profile", "submitted_report": vector["submitted_report"],
            "configured_facts": vector["configured_facts"],
            "hypothetical_verification": vector["hypothetical_verification"]}


def configured_unclaimed_probe(vector: dict, binding: str, report: dict) -> tuple[dict, dict]:
    before = copy.deepcopy(vector["ledger_before"])
    before["required_participant_records"] = [item["role"] + ":" + item["instance_id"]
        for item in report["required_participants"]]
    after = copy.deepcopy(before)
    setup = {"ledger_before": before, "binding": binding,
             "observed_effects_before": vector["effects_before"]}
    call = {"request_bytes": vector["request_bytes"], "invocation": vector["invocation"],
            "native_mutation_bytes": vector["native_mutation_bytes"], "fault": vector["fault"]}
    expected = {"binding": binding, "response_bytes": vector["expected_response_bytes"],
                "ledger_after": after, "observed_effects_after": vector["effects_after"]}
    return {"kind": "operation", "setup": setup, "call": call}, expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=Path("../determa-state-spec"))
    parser.add_argument("--adapter", nargs="+", required=True,
                        help="production test harness executable; receives one closed JSON input per invocation")
    parser.add_argument("--proof-summary-output", type=Path,
                        help="write the verified same-run authority proof receipt")
    args = parser.parse_args()
    validate_profile(args.spec_root)
    manifest = load(PROFILE / "vectors.generated.json")
    checked = 0
    proved_ids = set()
    initial_profile = adapter_run(args.adapter, {"kind": "configured_profile"}, "configured profile")
    actual_report = verify_configured_profile(initial_profile, args.spec_root, set(), require_native_proof=False)
    binding = report_binding(actual_report)
    guarantees = actual_report["guarantees"]
    scenario = select_production_scenario(manifest, actual_report)
    if actual_report["extension_report"] is not None:
        for vector in manifest["unclaimed_guarantee_checks"]:
            if guarantees[vector["required_guarantee"]]:
                continue
            probe, expected = configured_unclaimed_probe(vector, binding, actual_report)
            adapter_call(args.adapter, probe, expected, vector["id"])
            checked += 1
    for vector in (scenario["operations"] if scenario else []):
        # The adapter cannot see the ID, source classification, expected result, or after-state.
        setup = {"ledger_before": vector["ledger_before"], "binding": binding}
        call = {"request_bytes": vector["request_bytes"], "invocation": vector["invocation"],
                "native_mutation_bytes": vector["native_mutation_bytes"], "fault": vector["fault"]}
        adapter_call(args.adapter, {"kind": "operation", "setup": setup, "call": call},
                     {"binding": binding, "response_bytes": vector["expected_response_bytes"],
                      "ledger_after": vector["ledger_after"]}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    # The six source examples exercise only the internal common-rule seam.
    # Hypothetical premises never enter configured_profile or the proof ledger.
    for vector in manifest["profiles"]:
        adapter_call(args.adapter, common_rule_input(vector),
            vector["expected_outcome"], vector["id"])
        checked += 1
    no_authority = next(item for item in manifest["profiles"] if item["id"] == "application_owned_transaction")
    adapter_call(args.adapter, {"kind": "profile", "configured_facts": no_authority["configured_facts"]},
                 no_authority["expected_outcome"], no_authority["id"])
    checked += 1
    for vector in manifest["clocks"]:
        adapter_call(args.adapter, {"kind": "clock_parse", "value": vector["value"]},
                     {"accepted": vector["source_disposition"] == "valid"}, vector["id"])
        checked += 1
    for vector in (scenario["worker_checks"] if scenario else []):
        adapter_call(args.adapter, {"kind": "worker_claim_check", "binding": binding, "input": vector["input"]},
                     {**vector["expected"], "binding": binding}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    for vector in (scenario["native_traces"] if scenario else []):
        calls = [step["call"] for step in vector["steps"]]
        adapter_call(args.adapter, {"kind": "native_trace", "setup": vector["setup"], "binding": binding,
            "control_plan": vector["control_plan"], "calls": calls},
            {"binding": binding, "events": vector["expected_events"]}, vector["id"])
        checked += 1
        proved_ids.add(vector["id"])
    for vector in ([scenario["allocation_check"]] if scenario else []):
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
    if args.proof_summary_output is not None:
        args.proof_summary_output.write_bytes(canonical_json_bytes({
            'format': 'determa.conformance.host_authority.proof_summary',
            'schema_version': 1,
            'adapter_command_digest': 'sha256:' + hashlib.sha256(
                canonical_json_bytes(args.adapter)).hexdigest(),
            'report_digest': 'sha256:' + hashlib.sha256(
                canonical_json_bytes(actual_report)).hexdigest(),
            'report_binding': binding,
            'scope_identity': actual_report['scope_identity'],
            'topology': actual_report['topology'],
            'source_binding_digest': actual_report['source_binding_digest'],
            'destination_binding_digest': actual_report['destination_binding_digest'],
            'native_proof_ids': sorted(proved_ids),
            'checked_count': checked}))
    print(f"checked {checked} direct production responses and observations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
