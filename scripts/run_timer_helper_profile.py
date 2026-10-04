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
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator
from validate_extension_negotiation import exact_json_equal
from timer_helper_validator import validate_profile
from run_portable_archive_profile import run_case as run_archive_case
from run_lossless_delivery_profile import (
    CASE as DELIVERY_CASE,
    run as run_delivery_case, verify_configured_delivery_profile,
    verify_delivery_proof_summary,
)


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
    completed = subprocess.run(command, input=rfc8785.dumps(body) + b"\n",
                               capture_output=True, check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f"{label}: child exited {completed.returncode}: {completed.stderr.decode(errors='replace')[:500]}")
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
                item["logical_path"].startswith("/") or "\\" in item["logical_path"] or \
                any(segment in ("", ".", "..") for segment in item["logical_path"].split("/")):
            raise ValueError("loaded timer source file identity invalid")
        try:
            body = base64.b64decode(item["bytes_base64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise ValueError("loaded timer source bytes are not canonical base64") from error
        path = Path(item["absolute_path"])
        if not path.is_absolute() or not path.is_file() or not body or path.read_bytes() != body or \
                base64.b64encode(body).decode() != item["bytes_base64"]:
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
    if not config or base64.b64encode(config).decode() != installation["configuration_bytes_base64"]:
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


def run_native_delivery_proof(command, authority_command, spec_root, case_dir, ownership):
    """Execute the full C/D/H chain, then timer ingress under that installation."""
    with tempfile.TemporaryDirectory(prefix="determa-timer-delivery-") as temporary:
        root = Path(temporary)
        summary_path = root / "delivery-proof.json"
        completed = subprocess.run([
            sys.executable, str(Path(__file__).with_name("run_lossless_delivery_profile.py")),
            "--spec-root", str(spec_root), "--adapter", shlex.join(command),
            "--authority-adapter", shlex.join(authority_command),
            "--proof-summary-output", str(summary_path)],
            capture_output=True, check=False, timeout=1800)
        if completed.returncode:
            raise ValueError("timer requires complete same-installation C/D/H native proof: " +
                             completed.stderr.decode(errors="replace")[-1000:])
        summary = strict_json(summary_path.read_bytes())
        verify_delivery_proof_summary(summary, command)
        report = summary["configured_delivery_profile"]
        if summary["authority_effect_summary"] is None or len(summary["effect_integrations"]) != 5:
            raise ValueError("timer coordinated claim lacks complete C/D/H proof")
        links = {name: report[name] for name in (
            "authority_report_digest", "effect_report_digest",
            "host_scope_identity", "host_topology_identifier")}
        if verify_configured_delivery_profile(command, summary["parent_run_id"], links) != report:
            raise ValueError("delivery installation changed before timer source run")
        timer_case = root / "timer-case"
        timer_case.mkdir()
        (timer_case / "delivery-vectors-v1.json").write_bytes(
            (case_dir / "timer-delivery.generated.json").read_bytes())
        (timer_case / "before-timer-checkpoint-v1.json").write_bytes(
            rfc8785.dumps(ownership["before_checkpoint"]))
        (timer_case / "after-timer-checkpoint-v1.json").write_bytes(
            rfc8785.dumps(ownership["after_checkpoint"]))
        (timer_case / "machine.yaml").write_bytes((case_dir / "target-machine.yaml").read_bytes())
        (timer_case / "outbox-machine.yaml").write_bytes((DELIVERY_CASE / "outbox-machine.yaml").read_bytes())
        native_operations = []
        if run_delivery_case(command, case=timer_case, run_id=summary["parent_run_id"],
                             profile_links=links, proof_summary=native_operations) != 3:
            raise ValueError("timer ingress native operations incomplete")
        if verify_configured_delivery_profile(command, summary["parent_run_id"], links) != report:
            raise ValueError("delivery installation changed after timer source run")
        if [item["name"] for item in native_operations] != [
                "timer_first_committed_admission", "timer_crash_after_commit_before_ack",
                "timer_replay_after_commit_crash"] or \
                [item["fate"] for item in native_operations] != ["committed", "committed", "committed"] or \
                native_operations[1]["crash_cut"] != {
                    "operation_id": native_operations[1]["operation_id"], "phase": "after_commit"} or \
                not all(item["host_store_proof_id"] for item in native_operations) or \
                native_operations[2]["source_acknowledgements"] != [ownership["acknowledge_after_commit"]]:
            raise ValueError("timer source native commit, crash, or replay proof differs")
        return summary, native_operations


def verify_native_composition(configured, delivery_summary, timer_operations, ownership):
    installation = configured["installation"]
    proof = configured["operational_proof"]
    delivery_report = delivery_summary["configured_delivery_profile"]
    effect = delivery_summary["authority_effect_summary"]
    authority = effect["authority_summary"]
    expected = {
        "authority": set(authority["native_proof_ids"]),
        "effects": set(effect["native_proof_ids"]),
        "delivery": {item["host_store_proof_id"] for item in
                     [*delivery_summary["delivery_operations"], *timer_operations]
                     if item["host_store_proof_id"] is not None} |
                    {item["host_store_proof_id"] for item in delivery_summary["effect_integrations"]},
    }
    if installation["scope_identity"] != ownership["request"]["source"]["source_scope"] or \
            installation["scope_identity"] != delivery_report["host_scope_identity"] or \
            installation["topology_identity"] != delivery_report["host_topology_identifier"] or \
            installation["storage_binding"] != delivery_report["host_storage_configuration_digest"] or \
            authority["scope_identity"] != installation["scope_identity"] or \
            effect["scope_identity"] != installation["scope_identity"] or \
            effect["topology_identifier"] != installation["topology_identity"] or \
            proof["scope_identity"] != installation["scope_identity"] or \
            proof["topology_identity"] != installation["topology_identity"] or \
            proof["storage_binding"] != installation["storage_binding"] or \
            any(set(proof[name]["receipt_digests"]) != ids or
                len(proof[name]["receipt_digests"]) != len(ids)
                for name, ids in expected.items()):
        raise ValueError("timer configured claim is not bound to actual same-run C/D/H proof")


def lifecycle_call(command, lifecycle, machine, target_machine, label):
    body = {"kind": "timer_lifecycle", "intent_machine_source": machine,
            "target_machine_source": target_machine}
    body.update({name: lifecycle[name] for name in (
        "intent_inputs", "cancel_intent_inputs", "create_request",
        "intent_create_request", "cancel_intent_create_request", "schedule_request",
        "cancel_request", "claim_request", "complete_request", "step_request",
        "trusted_clock_sequence")})
    observed = call(command, body, label)
    expected = {"create_checkpoint": lifecycle["expected_create_checkpoint"],
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
    if not exact_json_equal(observed, expected):
        raise ValueError(f"{label}: create/intent/schedule/claim/admit/step or complete state differs")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", nargs="+", required=True)
    parser.add_argument("--authority-adapter", nargs="+", required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    validate_profile(args.spec_root, repository)
    document = strict_json((repository / "conformance/profiles/timer-helper/timer-01-external-helper/vectors.generated.json").read_bytes())
    case_dir = repository / "conformance/profiles/timer-helper/timer-01-external-helper"
    machine = (repository / "conformance/profiles/timer-helper/timer-01-external-helper/machine.yaml").read_text()
    target_machine = (case_dir / "target-machine.yaml").read_text()
    lifecycle = strict_json((case_dir / "lifecycle.generated.json").read_bytes())
    installed_lifecycle = strict_json((case_dir / "configured-lifecycle.generated.json").read_bytes())
    lifecycle_call(args.adapter, lifecycle, machine, target_machine, "timer_lifecycle_normative")
    lifecycle_call(args.adapter, installed_lifecycle, machine, target_machine,
                   "timer_lifecycle_installed_scope")
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
    completed_request_digests.update(source[name]["request_digest"]
        for source in (lifecycle, installed_lifecycle)
        for name in ("schedule_request", "cancel_request", "claim_request", "complete_request"))
    ownership = strict_json((case_dir / "source-ownership.generated.json").read_bytes())
    delivery_summary, timer_operations = run_native_delivery_proof(
        args.adapter, args.authority_adapter, args.spec_root, case_dir, ownership)
    configured = call(args.adapter, {"kind": "configured_timer_helper"}, "configured_timer_helper")
    verify_configured(configured, args.spec_root, completed_request_digests)
    verify_native_composition(configured, delivery_summary, timer_operations, ownership)
    print(f"{len(document['cases'])} normative timer operations, {len(document['clock_vectors'])} clock boundaries, {len(document['fence_vectors'])} claim fences, two lifecycles, 3 archive participant and 3 native source ownership cases passed under one configured C/D/H installation")


if __name__ == "__main__":
    main()
