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
import uuid
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator
from validate_extension_negotiation import exact_json_equal
from timer_helper_validator import validate_profile
from generate_timer_helper_profile import artifact as timer_artifact
from generate_version1_vectors import typed_value
from run_portable_archive_profile import run_case as run_archive_case
from run_lossless_delivery_profile import (
    CASE as DELIVERY_CASE, STORE as DELIVERY_STORE,
    run as run_delivery_case, verify_configured_delivery_profile,
    verify_delivery_proof_summary, store_call as delivery_store_call,
    digest as delivery_digest, configuration_digests as delivery_configuration_digests,
)


def trusted_bridge_registration(command, registration):
    """Verify runner-selected reviewed source/build/install facts outside the child."""
    try:
        entry = strict_json(registration.read_bytes())
    except (OSError, UnicodeError) as error:
        raise ValueError("production timer execution unverified: bridge registration unavailable") from error
    required = {"format", "schema_version", "command", "language", "bridge_root",
        "bridge_source_path", "bridge_source_sha256", "installation_root",
        "installation_manifest_path", "installation_manifest_sha256",
        "production_factory", "public_timer_entrypoint", "public_archive_entrypoint",
        "native_observer_entrypoint", "effective_configuration_digest",
        "dependency_inventory_digest", "build_anchor_digest",
        "configured_provider_content_digest", "configured_scope_identity",
        "configured_topology_identifier", "configured_storage_binding"}
    if type(entry) is not dict or set(entry) != required or \
            entry["format"] != "determa.conformance.timer_helper.bridge_registration" or \
            type(entry["schema_version"]) is not int or entry["schema_version"] != 1 or \
            entry["language"] not in ("python", "rust") or \
            type(entry["command"]) is not list or entry["command"] != command or \
            any(type(part) is not str or not part for part in command) or \
            any(type(entry[key]) is not str or not entry[key]
                for key in required - {"format", "schema_version", "command", "language"}):
        raise ValueError("production timer execution unverified: closed bridge registration differs")
    def anchored(root_key, path_key, hash_key):
        root = Path(entry[root_key])
        relative = Path(entry[path_key])
        if not root.is_absolute() or not root.is_dir() or relative.is_absolute() or \
                ".." in relative.parts:
            raise ValueError("production timer execution unverified: source anchor invalid")
        source = (root.resolve() / relative).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file() or \
                "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest() != entry[hash_key]:
            raise ValueError("production timer execution unverified: source/build drift")
        return source
    bridge = anchored("bridge_root", "bridge_source_path", "bridge_source_sha256")
    manifest = anchored("installation_root", "installation_manifest_path",
                        "installation_manifest_sha256")
    if (entry["language"] == "python" and
            (len(command) != 4 or command[1:3] != ["-I", "-S"] or
             Path(command[0]).resolve() != Path(sys.executable).resolve() or
             Path(command[3]).resolve() != bridge)) or \
            (entry["language"] == "rust" and
             (len(command) != 1 or Path(command[0]).resolve() != bridge)):
        raise ValueError("production timer execution unverified: command is not reviewed bridge")
    installed = strict_json(manifest.read_bytes())
    manifest_keys = {"format", "schema_version", "language", "production_factory",
        "public_timer_entrypoint", "public_archive_entrypoint", "native_observer_entrypoint",
        "effective_configuration_digest", "dependency_inventory_digest", "build_anchor_digest",
        "source_closure", "dependency_files", "build_inputs", "features", "toolchain",
        "effective_configuration", "configured_provider_content_digest",
        "configured_scope_identity", "configured_topology_identifier",
        "configured_storage_binding"}
    shared = manifest_keys - {"format", "schema_version", "source_closure", "dependency_files",
                              "build_inputs", "features", "toolchain", "effective_configuration"}
    if type(installed) is not dict or set(installed) != manifest_keys or \
            installed["format"] != "determa.conformance.timer_helper.installation" or \
            type(installed["schema_version"]) is not int or installed["schema_version"] != 1 or \
            any(installed[key] != entry[key] for key in shared) or \
            type(installed["source_closure"]) is not list or not installed["source_closure"] or \
            type(installed["dependency_files"]) is not list or \
            type(installed["build_inputs"]) is not list or \
            type(installed["features"]) is not list or \
            any(type(feature) is not str or not feature for feature in installed["features"]) or \
            installed["features"] != sorted(set(installed["features"])) or \
            type(installed["toolchain"]) is not str or not installed["toolchain"] or \
            type(installed["effective_configuration"]) is not dict or \
            delivery_digest(rfc8785.dumps(installed["effective_configuration"])) != entry[
                "effective_configuration_digest"] or \
            delivery_digest(rfc8785.dumps(installed["dependency_files"])) != entry[
                "dependency_inventory_digest"] or \
            delivery_digest(rfc8785.dumps({key: installed[key] for key in (
                "build_inputs", "features", "toolchain")})) != entry["build_anchor_digest"]:
        raise ValueError("production timer execution unverified: installation manifest differs")
    files = []
    seen = set()
    for category in ("source_closure", "dependency_files", "build_inputs"):
        for item in installed[category]:
            if type(item) is not dict or set(item) != {"path", "sha256"} or \
                    type(item["path"]) is not str or type(item["sha256"]) is not str or \
                    not item["path"] or item["path"] in seen or Path(item["path"]).is_absolute() or \
                    ".." in Path(item["path"]).parts:
                raise ValueError("production timer execution unverified: source closure incomplete")
            seen.add(item["path"])
            source = (Path(entry["installation_root"]).resolve() / item["path"]).resolve()
            if not source.is_relative_to(Path(entry["installation_root"]).resolve()) or \
                    not source.is_file() or \
                    "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
                raise ValueError("production timer execution unverified: installed source drift")
            if category != "build_inputs":
                files.append(item)
    anchor = {"factory_identity": entry["production_factory"], "installed_files": files,
              "installation_root": entry["installation_root"],
              "provider_digest": entry["configured_provider_content_digest"],
              "scope_identity": entry["configured_scope_identity"],
              "topology_identity": entry["configured_topology_identifier"],
              "storage_binding": entry["configured_storage_binding"],
              "bridge_identity": delivery_digest(rfc8785.dumps(entry))}
    return anchor


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


def attach_invocation(body, database, run_id, factory_identity):
    """Give the reviewed bridge an observer journal owned by the test driver."""
    invocation_id = str(uuid.uuid4())
    request_digest = delivery_digest(rfc8785.dumps(body))
    body["trusted_timer_invocation"] = {
        "command": [sys.executable, str(DELIVERY_STORE)], "database_path": str(database),
        "run_id": run_id, "invocation_id": invocation_id,
        "request_digest": request_digest, "factory_identity": factory_identity,
        "public_request": strict_json(rfc8785.dumps(body))}
    return invocation_id, request_digest


def verify_invocation(database, run_id, invocation_id, request_digest, factory_identity,
                      raw_response, before, after, public_request):
    journal = delivery_store_call(database, "timer_invocation_snapshot", run_id=run_id)["invocations"]
    if journal != [{"invocation_id": invocation_id, "request_digest": request_digest,
                    "factory_identity": factory_identity, "public_request": public_request,
                    "start_state_digest": delivery_digest(rfc8785.dumps(before)),
                    "raw_return": raw_response, "native_transaction_id": None,
                    "return_digest": delivery_digest(rfc8785.dumps(raw_response)),
                    "return_state_digest": delivery_digest(rfc8785.dumps(after))}]:
        raise ValueError("reviewed timer bridge invocation/raw return was not independently journaled")


def operation_input(row, target_machine):
    return {"kind": "timer_operation", "machine_source": target_machine,
            "before": row["before"], "request": row["request"],
            "trusted_now": row["trusted_now"], "claim_expires_at": row["claim_expires_at"],
            "previous_attempt_fate": row["previous_attempt_fate"],
            "admission_disposition": row["admission_disposition"]}


def run_timer_operation(command, row, target_machine, factory_identity="test-unverified"):
    """Read helper and checkpoint fate from the driver-owned public store."""
    with tempfile.TemporaryDirectory(prefix="determa-timer-operation-") as temporary:
        database = Path(temporary) / "host.sqlite"
        run_id, operation_id = str(uuid.uuid4()), str(uuid.uuid4())
        before = {"timer_artifact": row["before"]["helper_artifact"],
                  "checkpoint": row["before"]["checkpoint"]}
        expected_after = {"timer_artifact": row["after"]["helper_artifact"],
                          "checkpoint": row["after"]["checkpoint"]}
        delivery_store_call(database, "seed", run_id=run_id, before=before)
        prior = delivery_store_call(database, "snapshot", run_id=run_id)
        if not exact_json_equal(prior["after"], before) or prior["transactions"]:
            raise ValueError("timer operation test store did not start from the exact prior state")
        body = operation_input(row, target_machine)
        body["host_store_provider"] = {
            "command": [sys.executable, str(DELIVERY_STORE)],
            "database_path": str(database), "run_id": run_id, "operation_id": operation_id,
            "source_sha256": delivery_digest(DELIVERY_STORE.read_bytes()),
            "configuration_digest": delivery_configuration_digests(run_id)[
                "host_storage_configuration_digest"]}
        invocation_id, request_digest = attach_invocation(body, database, run_id, factory_identity)
        observed = call(command, body, row["id"])
        if type(observed) is not dict or set(observed) != {"result", "calls"} or \
                not exact_json_equal(observed["result"], row["expected_result"]) or \
                not exact_json_equal(observed["calls"], row["expected_calls"]):
            raise ValueError(f"{row['id']}: live helper result or call counts differ")
        persistent = delivery_store_call(database, "snapshot", run_id=run_id)
        verify_invocation(database, run_id, invocation_id, request_digest, factory_identity,
                          observed, before, persistent["after"],
                          {key: value for key, value in body.items()
                           if key != "trusted_timer_invocation"})
        if not exact_json_equal(persistent["after"], expected_after):
            raise ValueError(f"{row['id']}: trusted helper/checkpoint store differs")
        changed = not exact_json_equal(before, expected_after)
        transactions = persistent["transactions"]
        if len(transactions) != int(changed) or persistent["crash_cuts"]:
            raise ValueError(f"{row['id']}: native timer transaction fate differs")
        if changed:
            transaction = transactions[0]
            if transaction["operation_id"] != operation_id or \
                    transaction["before_digest"] != delivery_digest(rfc8785.dumps(before)) or \
                    transaction["after_digest"] != delivery_digest(rfc8785.dumps(expected_after)):
                raise ValueError(f"{row['id']}: native timer commit did not bind full prior and after state")
            return transaction["native_transaction_id"]
        return None


def verify_archive_capture(captured_state, export, archive):
    """Compare every selected root and retained timer byte with the native capture."""
    helper = captured_state["timer_artifact"]
    checkpoint = captured_state["checkpoint"]
    if helper != timer_artifact(helper["records"], helper["operation_receipts"]) or \
            checkpoint not in export["source_capture"]["checkpoints"] or \
            export["source_capture"]["inventory_evidence"]["selected_checkpoint_digests"] != [
                checkpoint["execution_checkpoint_digest"]] or \
            archive["checkpoints"] != [checkpoint]:
        raise ValueError("archive selected checkpoint or live helper inventory differs")
    capture = next((item for item in export["source_capture"]["participant_captures"]
                    if item["participant_id"] == "timer-state"), None)
    participant = next((item for item in archive["participants"]
                        if item["participant_id"] == "timer-state"), None)
    if capture is None or participant is None or not participant["required"] or \
            capture["payload"] != typed_value(helper) or \
            participant["payload"] != typed_value(helper) or \
            participant["payload_digest"] != capture["payload_digest"] or \
            export["input_request"]["required_participant_ids"] != ["timer-state"]:
        raise ValueError("archive omitted a live pending/terminal timer or retained replay receipt")


def run_live_timer_archive(command, schedule_row, target_machine, export,
                           factory_identity="test-unverified"):
    """Capture the complete participant from a separately observed schedule commit."""
    with tempfile.TemporaryDirectory(prefix="determa-timer-archive-") as temporary:
        database = Path(temporary) / "host.sqlite"
        run_id, operation_id = str(uuid.uuid4()), str(uuid.uuid4())
        checkpoint = export["source_capture"]["checkpoints"][0]
        before = {"timer_artifact": timer_artifact(), "checkpoint": checkpoint}
        delivery_store_call(database, "seed", run_id=run_id, before=before)
        body = operation_input(schedule_row, target_machine)
        body["before"] = {"helper_artifact": timer_artifact(), "checkpoint": checkpoint}
        body["host_store_provider"] = {
            "command": [sys.executable, str(DELIVERY_STORE)],
            "database_path": str(database), "run_id": run_id, "operation_id": operation_id,
            "source_sha256": delivery_digest(DELIVERY_STORE.read_bytes()),
            "configuration_digest": delivery_configuration_digests(run_id)[
                "host_storage_configuration_digest"]}
        invocation_id, request_digest = attach_invocation(body, database, run_id, factory_identity)
        observed = call(command, body, "timer_archive_schedule")
        if type(observed) is not dict or set(observed) != {"result", "calls"} or \
                not exact_json_equal(observed["result"], schedule_row["expected_result"]) or \
                not exact_json_equal(observed["calls"], schedule_row["expected_calls"]):
            raise ValueError("timer archive schedule did not invoke the installed helper")
        snapshot = delivery_store_call(database, "snapshot", run_id=run_id)
        verify_invocation(database, run_id, invocation_id, request_digest, factory_identity,
                          observed, before, snapshot["after"],
                          {key: value for key, value in body.items()
                           if key != "trusted_timer_invocation"})
        if len(snapshot["transactions"]) != 1 or \
                snapshot["transactions"][0]["operation_id"] != operation_id or \
                snapshot["crash_cuts"]:
            raise ValueError("timer archive capture lacks a single native helper commit")
        captured = delivery_store_call(database, "capture_at", run_id=run_id,
                                       operation_id=operation_id)
        if not exact_json_equal(snapshot["after"], captured["captured_state"]):
            raise ValueError("timer archive consistency point changed after capture")
        verify_archive_capture(captured["captured_state"], export, export["expected_archive"])
        capture_provider = {
            "command": [sys.executable, str(DELIVERY_STORE)],
            "database_path": str(database), "run_id": run_id,
            "operation_id": operation_id, "proof_id": captured["proof_id"],
            "source_sha256": delivery_digest(DELIVERY_STORE.read_bytes())}
        archive_body = {"operation": "export", "request": export["input_request"],
                        "source_capture": export["source_capture"],
                        "timer_capture_provider": capture_provider}
        export_invocation, export_request_digest = attach_invocation(
            archive_body, database, run_id, factory_identity)
        response = run_archive_case(command, "export", {
            "case_id": "timer_live_archive_export", "input_request": export["input_request"],
            "source_capture": export["source_capture"],
            "expected_result": export["expected_result"],
            "expected_archive": export["expected_archive"]},
            extra_input={"timer_capture_provider": capture_provider,
                         "trusted_timer_invocation": archive_body["trusted_timer_invocation"]})
        journal = delivery_store_call(database, "timer_invocation_snapshot", run_id=run_id)["invocations"]
        if len(journal) != 2 or journal[1] != {
                "invocation_id": export_invocation, "request_digest": export_request_digest,
                "factory_identity": factory_identity,
                "public_request": {key: value for key, value in archive_body.items()
                                   if key != "trusted_timer_invocation"},
                "start_state_digest": delivery_digest(rfc8785.dumps(snapshot["after"])),
                "raw_return": response, "native_transaction_id": None,
                "return_digest": delivery_digest(rfc8785.dumps(response)),
                "return_state_digest": delivery_digest(rfc8785.dumps(snapshot["after"]))}:
            raise ValueError("live timer archive export lacks actual reviewed bridge invocation")
        verify_archive_capture(captured["captured_state"], export, response["archive"])
        after = delivery_store_call(database, "snapshot", run_id=run_id)
        if not exact_json_equal(after, snapshot):
            raise ValueError("archive export mutated active timer helper or checkpoint storage")
        return snapshot["transactions"][0]["native_transaction_id"]


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


def verify_configured(observed, spec_root, completed_request_digests, bridge_attestation=None,
                      bridge_anchor=None, installed_root=None, timer_transactions=()):
    if bridge_attestation is None or bridge_anchor is None or installed_root is None:
        raise ValueError("configured timer claim requires a reviewed live provider bridge")
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
            report["provider_reference"]["content_digest"] != bridge_anchor["provider_digest"] or \
            hash_bytes(config) != installation["configuration_digest"] or \
            installation["scope_identity"] != bridge_anchor["scope_identity"] or \
            installation["topology_identity"] != bridge_anchor["topology_identity"] or \
            installation["storage_binding"] != bridge_anchor["storage_binding"] or \
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
    expected_paths = {(installed_root / item["path"]).resolve(): item["sha256"]
                      for item in bridge_anchor["installed_files"]}
    if type(bridge_attestation) is not dict or set(bridge_attestation) != {
            "factory_identity", "factory_path", "callable_path", "loaded_files",
            "observed_request_digests", "native_transaction_ids", "configuration_digest",
            "scope_identity", "topology_identity", "storage_binding", "provider_reference"} or \
            bridge_attestation["factory_identity"] != bridge_anchor["factory_identity"] or \
            {Path(path).resolve() for path in installation["loaded_module_paths"]} != set(expected_paths) or \
            type(bridge_attestation["loaded_files"]) is not list or \
            {Path(item["absolute_path"]).resolve(): item["sha256"]
             for item in bridge_attestation["loaded_files"]} != expected_paths or \
            Path(bridge_attestation["factory_path"]).resolve() not in expected_paths or \
            Path(bridge_attestation["callable_path"]).resolve() not in expected_paths or \
            not all(path.is_file() and "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == sha
                    for path, sha in expected_paths.items()) or \
            type(bridge_attestation["observed_request_digests"]) is not list or \
            not completed_request_digests <= set(bridge_attestation["observed_request_digests"]) or \
            type(bridge_attestation["native_transaction_ids"]) is not list or \
            not set(timer_transactions) <= set(bridge_attestation["native_transaction_ids"]) or \
            bridge_attestation["configuration_digest"] != installation["configuration_digest"] or \
            bridge_attestation["scope_identity"] != installation["scope_identity"] or \
            bridge_attestation["topology_identity"] != installation["topology_identity"] or \
            bridge_attestation["storage_binding"] != installation["storage_binding"] or \
            not exact_json_equal(bridge_attestation["provider_reference"], report["provider_reference"]):
        raise ValueError("live reviewed timer factory/callable or native invocation proof differs")
    return report


def run_native_delivery_proof(command, authority_command, spec_root, case_dir, ownership,
                              bridge_anchor):
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
                             profile_links=links, proof_summary=native_operations,
                             timer_bridge_anchor=bridge_anchor) != 3:
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
                any("timer_invocation" not in item for item in native_operations) or \
                any(item["timer_invocation"]["factory_identity"] != bridge_anchor["factory_identity"]
                    for item in native_operations) or \
                native_operations[0]["timer_invocation"]["native_transaction_id"] != \
                    native_operations[0]["native_transaction_id"] or \
                native_operations[1]["timer_invocation"]["native_transaction_id"] != \
                    native_operations[1]["native_transaction_id"] or \
                native_operations[2]["timer_invocation"] != native_operations[1]["timer_invocation"] or \
                native_operations[0]["timer_invocation"]["invocation_id"] == \
                    native_operations[1]["timer_invocation"]["invocation_id"] or \
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


def lifecycle_call(command, lifecycle, machine, target_machine, label,
                   factory_identity="test-unverified"):
    body = {"kind": "timer_lifecycle", "intent_machine_source": machine,
            "target_machine_source": target_machine}
    body.update({name: lifecycle[name] for name in (
        "intent_inputs", "cancel_intent_inputs", "create_request",
        "intent_create_request", "cancel_intent_create_request", "schedule_request",
        "cancel_request", "claim_request", "complete_request", "step_request",
        "trusted_clock_sequence")})
    stages = {
        "main": ["target_create", "schedule", "claim", "fire_and_admit", "target_step"],
        "cancel": ["schedule", "cancel"]}
    with tempfile.TemporaryDirectory(prefix="determa-timer-lifecycle-") as temporary:
        providers = {}
        stage_ids = {}
        for branch, names in stages.items():
            run_id = str(uuid.uuid4())
            database = Path(temporary) / (branch + ".sqlite")
            delivery_store_call(database, "seed", run_id=run_id,
                                before={"timer_artifact": timer_artifact(), "checkpoint": None})
            providers[branch] = {"command": [sys.executable, str(DELIVERY_STORE)],
                                 "database_path": str(database), "run_id": run_id,
                                 "source_sha256": delivery_digest(DELIVERY_STORE.read_bytes()),
                                 "configuration_digest": delivery_configuration_digests(run_id)[
                                     "host_storage_configuration_digest"]}
            stage_ids[branch] = {name: str(uuid.uuid4()) for name in names}
        body["host_store_providers"] = providers
        body["stage_operation_ids"] = stage_ids
        main_provider = providers["main"]
        invocation_id, request_digest = attach_invocation(
            body, Path(main_provider["database_path"]), main_provider["run_id"],
            factory_identity)
        observed = call(command, body, label)
        expected_states = {
            "main": [
                {"timer_artifact": timer_artifact(), "checkpoint": lifecycle["expected_create_checkpoint"]},
                {"timer_artifact": lifecycle["expected_helper_after_schedule"],
                 "checkpoint": lifecycle["expected_create_checkpoint"]},
                {"timer_artifact": lifecycle["expected_helper_after_claim"],
                 "checkpoint": lifecycle["expected_create_checkpoint"]},
                {"timer_artifact": lifecycle["expected_helper_after_fire"],
                 "checkpoint": lifecycle["expected_admitted_checkpoint"]},
                {"timer_artifact": lifecycle["expected_helper_after_fire"],
                 "checkpoint": lifecycle["expected_after_step_checkpoint"]}],
            "cancel": [
                {"timer_artifact": lifecycle["expected_helper_after_schedule"], "checkpoint": None},
                {"timer_artifact": lifecycle["expected_helper_after_cancel"], "checkpoint": None}]}
        for branch, names in stages.items():
            provider = providers[branch]
            database = Path(provider["database_path"])
            snapshot = delivery_store_call(database, "snapshot", run_id=provider["run_id"])
            expected_ids = [stage_ids[branch][name] for name in names]
            if [item["operation_id"] for item in snapshot["transactions"]] != expected_ids or \
                    snapshot["crash_cuts"] or \
                    not exact_json_equal(snapshot["after"], expected_states[branch][-1]):
                raise ValueError(f"{label}: {branch} durable lifecycle stages differ")
            for operation_id, state in zip(expected_ids, expected_states[branch]):
                captured = delivery_store_call(database, "capture_at",
                                               run_id=provider["run_id"], operation_id=operation_id)
                if not exact_json_equal(captured["captured_state"], state) or \
                        captured["after_digest"] != delivery_digest(rfc8785.dumps(state)):
                    raise ValueError(f"{label}: {branch} captured helper/checkpoint stage differs")
        verify_invocation(Path(main_provider["database_path"]), main_provider["run_id"],
                          invocation_id, request_digest, factory_identity, observed,
                          {"timer_artifact": timer_artifact(), "checkpoint": None},
                          expected_states["main"][-1],
                          {key: value for key, value in body.items()
                           if key != "trusted_timer_invocation"})
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
    parser.add_argument("--bridge-registration", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    validate_profile(args.spec_root, repository)
    bridge = args.adapter
    bridge_anchor = trusted_bridge_registration(bridge, args.bridge_registration)
    document = strict_json((repository / "conformance/profiles/timer-helper/timer-01-external-helper/vectors.generated.json").read_bytes())
    case_dir = repository / "conformance/profiles/timer-helper/timer-01-external-helper"
    machine = (repository / "conformance/profiles/timer-helper/timer-01-external-helper/machine.yaml").read_text()
    target_machine = (case_dir / "target-machine.yaml").read_text()
    lifecycle = strict_json((case_dir / "lifecycle.generated.json").read_bytes())
    installed_lifecycle = strict_json((case_dir / "configured-lifecycle.generated.json").read_bytes())
    lifecycle_call(bridge, lifecycle, machine, target_machine, "timer_lifecycle_normative",
                   bridge_anchor["factory_identity"])
    lifecycle_call(bridge, installed_lifecycle, machine, target_machine,
                   "timer_lifecycle_installed_scope", bridge_anchor["factory_identity"])
    timer_transactions = []
    for row in [*document["cases"], *document["clock_vectors"], *document["fence_vectors"]]:
        transaction = run_timer_operation(bridge, row, target_machine,
                                          bridge_anchor["factory_identity"])
        if transaction is not None:
            timer_transactions.append(transaction)
    export = strict_json((case_dir / "archive-operational.generated.json").read_bytes())
    archive_transaction = run_live_timer_archive(bridge, document["cases"][0],
                                                 target_machine, export,
                                                 bridge_anchor["factory_identity"])
    timer_transactions.append(archive_transaction)
    stage = strict_json((case_dir / "archive-stage.generated.json").read_bytes())
    for row in stage["cases"]:
        run_archive_case(bridge, "stage", row)
    completed_request_digests = {row["request"]["request_digest"]
        for row in [*document["cases"], *document["clock_vectors"], *document["fence_vectors"]]
        if "request_digest" in row["request"]}
    completed_request_digests.update(source[name]["request_digest"]
        for source in (lifecycle, installed_lifecycle)
        for name in ("schedule_request", "cancel_request", "claim_request", "complete_request"))
    ownership = strict_json((case_dir / "source-ownership.generated.json").read_bytes())
    delivery_summary, timer_operations = run_native_delivery_proof(
        bridge, args.authority_adapter, args.spec_root, case_dir, ownership, bridge_anchor)
    configured = call(bridge, {"kind": "configured_timer_helper"}, "configured_timer_helper")
    attestation = call(bridge, {"kind": "trusted_timer_bridge_attestation"},
                       "trusted_timer_bridge_attestation")
    verify_configured(configured, args.spec_root, completed_request_digests,
                      attestation, bridge_anchor, Path(bridge_anchor["installation_root"]),
                      timer_transactions + [item["native_transaction_id"] for item in timer_operations
                                            if item["native_transaction_id"] is not None])
    verify_native_composition(configured, delivery_summary, timer_operations, ownership)
    print(f"{len(document['cases'])} normative timer operations, {len(document['clock_vectors'])} clock boundaries, {len(document['fence_vectors'])} claim fences, two lifecycles, 4 archive participant and 3 native source ownership cases passed under one configured C/D/H installation")


if __name__ == "__main__":
    main()
