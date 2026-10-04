#!/usr/bin/env python3
"""Run timer vectors through a configured production helper child process.

The child receives one JSON line per invocation and must return one JSON object. The
operation input contains no vector ID, coverage label, expected result or after state.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator
from validate_extension_negotiation import exact_json_equal
from timer_helper_validator import validate_profile
from run_portable_archive_profile import run_case as run_archive_case


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


def operation_input(row, target_machine):
    return {"kind": "timer_operation", "machine_source": target_machine,
            "before": row["before"], "request": row["request"],
            "trusted_now": row["trusted_now"], "claim_expires_at": row["claim_expires_at"],
            "previous_attempt_fate": row["previous_attempt_fate"],
            "admission_disposition": row["admission_disposition"]}


def loaded_closure_digest(files, module_paths):
    if type(files) is not list or not files or type(module_paths) is not list or \
            not all(type(path) is str for path in module_paths):
        raise ValueError("loaded timer source closure is incomplete")
    inventory = []
    actual_paths = []
    for item in files:
        if type(item) is not dict or set(item) != {
                "logical_path", "absolute_path", "bytes_base64"} or \
                type(item["logical_path"]) is not str or not item["logical_path"] or \
                item["logical_path"].startswith("/") or ".." in item["logical_path"].split("/"):
            raise ValueError("loaded timer source file identity invalid")
        try:
            body = base64.b64decode(item["bytes_base64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise ValueError("loaded timer source bytes are not canonical base64") from error
        path = Path(item["absolute_path"])
        if not path.is_absolute() or not path.is_file() or not body or path.read_bytes() != body:
            raise ValueError("loaded timer source bytes differ from installed file")
        actual_paths.append(str(path))
        inventory.append([item["logical_path"], "sha256:" + hashlib.sha256(body).hexdigest()])
    if inventory != sorted(inventory, key=lambda item: item[0].encode("utf-8")) or \
            len({item[0] for item in inventory}) != len(inventory) or \
            len(set(actual_paths)) != len(actual_paths) or \
            set(module_paths) != set(actual_paths) or len(module_paths) != len(actual_paths):
        raise ValueError("loaded timer module inventory differs from closure")
    return "sha256:" + hashlib.sha256(rfc8785.dumps([
        "determa-test-timer-provider-closure-1", inventory])).hexdigest()


def verify_configured(observed, spec_root, completed_request_digests):
    if type(observed) is not dict or set(observed) != {"report", "installation", "operational_proof"}:
        raise ValueError("configured helper omitted public report, installed closure or operational proof")
    report = observed["report"]
    schema = strict_json((spec_root / "schema/extension-capability-report-v1.schema.json").read_bytes())
    if list(Draft202012Validator(schema).iter_errors(report)) or report["category"] != "timer" or report["health"] != "healthy":
        raise ValueError("configured timer report invalid or unhealthy")
    claims = set(report["claims"])
    if len(claims & {"ephemeral_timer_helper", "durable_timer_helper"}) != 1 or \
            len(claims & {"independent_timer_delivery", "coordinated_timer_admission"}) != 1:
        raise ValueError("configured timer claim combination invalid")
    if "coordinated_timer_admission" in claims and "durable_timer_helper" not in claims:
        raise ValueError("coordinated timer admission requires durable helper storage")
    if "coordinated_timer_admission" not in claims or "durable_timer_helper" not in claims:
        raise ValueError("full timer lifecycle and archive runner requires durable coordinated helper claims")
    installation = observed["installation"]
    if type(installation) is not dict or set(installation) != {
            "loaded_closure_files", "loaded_module_paths", "configuration_bytes_base64",
            "configuration_digest", "scope_identity", "topology_identity", "storage_binding"}:
        raise ValueError("configured timer installation evidence incomplete")
    try:
        config = base64.b64decode(installation["configuration_bytes_base64"], validate=True)
    except (TypeError, ValueError, binascii.Error) as error:
        raise ValueError("configured timer closure or configuration is not canonical base64") from error
    if not config:
        raise ValueError("configured timer configuration is empty")
    hash_bytes = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
    if loaded_closure_digest(installation["loaded_closure_files"],
                             installation["loaded_module_paths"]) != report["provider_reference"]["content_digest"] or \
            hash_bytes(config) != installation["configuration_digest"] or \
            not all(type(installation[key]) is str and installation[key] for key in (
                "scope_identity", "topology_identity", "storage_binding")):
        raise ValueError("configured timer provider or topology binding differs")
    proof = observed["operational_proof"]
    if type(proof) is not dict or set(proof) != {"scope_identity", "topology_identity",
            "configuration_digest", "storage_binding",
            "provider_reference", "claims", "observed_request_digests", "authority", "delivery", "effects"} or \
            type(proof["claims"]) is not list or not all(type(item) is str for item in proof["claims"]) or \
            type(proof["observed_request_digests"]) is not list or \
            not all(type(item) is str and item.startswith("sha256:") and len(item) == 71
                    for item in proof["observed_request_digests"]) or \
            proof["scope_identity"] != installation["scope_identity"] or \
            proof["topology_identity"] != installation["topology_identity"] or \
            proof["configuration_digest"] != installation["configuration_digest"] or \
            proof["storage_binding"] != installation["storage_binding"] or \
            not exact_json_equal(proof["provider_reference"], report["provider_reference"]) or \
            set(proof["claims"]) != claims or \
            not completed_request_digests <= set(proof["observed_request_digests"]):
        raise ValueError("configured timer public operational proof differs from executed helper")
    if "coordinated_timer_admission" in claims:
        for category in ("authority", "delivery", "effects"):
            evidence = proof[category]
            if type(evidence) is not dict or set(evidence) != {
                    "scope_identity", "topology_identity", "storage_binding", "receipt_digests"} or \
                    evidence["scope_identity"] != installation["scope_identity"] or \
                    evidence["topology_identity"] != installation["topology_identity"] or \
                    evidence["storage_binding"] != installation["storage_binding"] or \
                    type(evidence["receipt_digests"]) is not list or not evidence["receipt_digests"] or \
                    not all(type(item) is str and item.startswith("sha256:") and len(item) == 71
                            for item in evidence["receipt_digests"]):
                raise ValueError(f"coordinated timer lacks configured {category} operational proof")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", nargs="+", required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    validate_profile(args.spec_root, repository)
    document = strict_json((repository / "conformance/profiles/timer-helper/timer-01-external-helper/vectors.generated.json").read_bytes())
    case_dir = repository / "conformance/profiles/timer-helper/timer-01-external-helper"
    machine = (repository / "conformance/profiles/timer-helper/timer-01-external-helper/machine.yaml").read_text()
    target_machine = (case_dir / "target-machine.yaml").read_text()
    lifecycle = strict_json((case_dir / "lifecycle.generated.json").read_bytes())
    lifecycle_input = {"kind": "timer_lifecycle", "intent_machine_source": machine,
                       "target_machine_source": target_machine,
                       "intent_inputs": lifecycle["intent_inputs"],
                       "cancel_intent_inputs": lifecycle["cancel_intent_inputs"],
                       "create_request": lifecycle["create_request"],
                       "intent_create_request": lifecycle["intent_create_request"],
                       "cancel_intent_create_request": lifecycle["cancel_intent_create_request"],
                       "schedule_request": lifecycle["schedule_request"],
                       "cancel_request": lifecycle["cancel_request"],
                       "claim_request": lifecycle["claim_request"],
                       "complete_request": lifecycle["complete_request"],
                       "step_request": lifecycle["step_request"],
                       "trusted_clock_sequence": lifecycle["trusted_clock_sequence"]}
    lifecycle_expected = {"create_checkpoint": lifecycle["expected_create_checkpoint"],
                          "intent_emissions": lifecycle["expected_intent_emissions"],
                          "cancel_intent_emissions": lifecycle["expected_cancel_intent_emissions"],
                          "helper_after_schedule": lifecycle["expected_helper_after_schedule"],
                          "helper_after_cancel": lifecycle["expected_helper_after_cancel"],
                          "helper_after_claim": lifecycle["expected_helper_after_claim"],
                          "helper_after_fire": lifecycle["expected_helper_after_fire"],
                          "admitted_checkpoint": lifecycle["expected_admitted_checkpoint"],
                          "after_step_checkpoint": lifecycle["expected_after_step_checkpoint"],
                          "results": lifecycle["expected_results"],
                          "fire_envelope": lifecycle["expected_fire_envelope"],
                          "calls": {"intent_create": 2, "intent_admission": 3,
                                    "intent_step": 3, "target_create": 1, "schedule": 2,
                                    "clock": 4, "cancel": 1, "claim": 1, "complete": 1,
                                    "target_admission": 1, "target_step": 1}}
    if not exact_json_equal(call(args.adapter, lifecycle_input, "timer_lifecycle"), lifecycle_expected):
        raise ValueError("timer_lifecycle: create/intent/schedule/claim/admit/step or complete state differs")
    for row in [*document["cases"], *document["clock_vectors"], *document["fence_vectors"]]:
        body = operation_input(row, target_machine)
        observed = call(args.adapter, body, row["id"])
        expected = {"result": row["expected_result"], "after": row["after"],
                    "calls": row["expected_calls"]}
        if not exact_json_equal(observed, expected):
            raise ValueError(f"{row['id']}: result, full storage or call counts differ")
    export = strict_json((case_dir / "archive-export.generated.json").read_bytes())
    run_archive_case(args.adapter, "export", {"case_id": "timer_archive_export",
                     "input_request": export["input_request"],
                     "source_capture": export["source_capture"],
                     "expected_result": export["expected_result"],
                     "expected_archive": export["expected_archive"]})
    stage = strict_json((case_dir / "archive-stage.generated.json").read_bytes())
    for row in stage["cases"]:
        run_archive_case(args.adapter, "stage", row)
    completed_request_digests = {row["request"]["request_digest"]
        for row in [*document["cases"], *document["clock_vectors"], *document["fence_vectors"]]
        if "request_digest" in row["request"]}
    verify_configured(call(args.adapter, {"kind": "configured_timer_helper"}, "configured_timer_helper"),
                      args.spec_root, completed_request_digests)
    print(f"{len(document['cases'])} normative timer operations, {len(document['clock_vectors'])} clock boundaries, {len(document['fence_vectors'])} claim fences, one lifecycle and 3 archive participant cases passed with configured proof")


if __name__ == "__main__":
    main()
