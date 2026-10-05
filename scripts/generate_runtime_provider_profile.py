#!/usr/bin/env python3
"""Materialize exact-source runtime and compiler provider conformance vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from io import StringIO

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import DoubleQuotedScalarString
from generate_version1_vectors import canonical, digest as value_digest, typed_value, bundle_fingerprint_document

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "conformance/profiles/runtime-provider/provider-01-exact-source"
SOURCES = ("provider/test_provider.py", "provider/test_provider.rs")
NORMATIVE = (
    "action-output.json", "compilation-manifest-v1.json", "compiled-machine.json",
    "guard-descriptor-v1.json", "invalid-action-output.json",
    "invalid-guard-output-type.json", "invalid-missing-correlation-action-output.json",
    "invalid-provider-digest.json",
    "language-source-v1.json", "mixed-cel-native.yaml",
    "multiple-send-action-output.json", "multiple-send-identities.json",
    "invalid-multiple-send-identities.json", "inert-provider-metadata.yaml",
)
DOMAIN = b"determa-test-runtime-provider-closure-1\0"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def closure_digest() -> str:
    hash_ = hashlib.sha256(DOMAIN)
    for name in SOURCES:
        path = name.encode("utf-8")
        body = (CASE / name).read_bytes()
        hash_.update(len(path).to_bytes(8, "big"))
        hash_.update(path)
        hash_.update(len(body).to_bytes(8, "big"))
        hash_.update(body)
    return "sha256:" + hash_.hexdigest()


def reference(identifier: str, digest: str) -> dict:
    return {"identifier": identifier, "version": "1.0.0", "content_digest": digest}


def binding(identifier: str, kind: str, digest: str, source_digest: str,
            dependency: dict, weak: bool) -> dict:
    return {
        "provider_reference": reference(identifier, digest),
        "source_media_type": "application/vnd.determa.runtime-fixture+json",
        "source_digest": source_digest,
        "dependencies": [dependency],
        "capabilities": {
            "deterministic": not weak, "pure": not weak, "portable": False,
            "semantically_introspectable": not weak,
            "process_contained": not weak, "external_io_capable": weak,
        },
        "input_types": {"event": "event_envelope", "variables": "typed_variables"},
        "output_type": "bool" if kind == "guard" else "structured_actions",
    }


def machine(guard: dict, actions: dict) -> dict:
    return {
        "format": 1, "namespace": "example.runtime_profile",
        "events": {
            "submit": {"direction": "input", "payload": {"approved": {"type": "bool", "required": True}}},
            "accepted": {"direction": "output"},
        },
        "machines": [{"machine_id": "order", "root": {
            "type": "composite", "variables": {"accepted": {"type": "bool", "init": False}},
            "initial": {"transition_to": "pending"},
            "states": {"pending": {"on_events": {"submit": [
                {"guard": "event.payload.approved == true", "action": [
                    {"assign": {"accepted": "true"}}]},
                {"guard": {"provider": copy.deepcopy(guard)}, "action": [
                    {"provider_actions": copy.deepcopy(actions)},
                    {"send": {"event": "accepted", "to": {"external": True},
                              "correlation_id": "'provider-correlation'"}}]},
            ]}}},
        }}],
    }


def observation(result: str, *, code=None, stages=(), guard=0, actions=0,
                inspection=0, external=0, effects=0, committed=False,
                guarantees=None, value=None) -> dict:
    return {
        "stages": list(stages), "result": result, "code": code, "value": value,
        "calls": {"guard": guard, "actions": actions, "inspect_guard": inspection,
                  "external": external},
        "irreversible_side_effects": effects,
        "external_effects": ([{"effect_id": "fixture-io-1", "kind": "external_write",
                              "phase": "before_commit"}] if effects else []),
        "determa_state_committed": committed,
        "effective_capabilities": guarantees,
        "state_before": None, "state_after": None,
    }


def render(spec_root: Path) -> dict[str, bytes]:
    closure = canonical({
        "format": "determa.test_runtime_provider_closure", "version": 1,
        "files": [{"path": name, "sha256": sha((CASE / name).read_bytes())} for name in SOURCES],
    })
    digest = closure_digest()
    source_digest = sha(closure)
    dependency = reference("example.native-common", digest)
    guard = binding("example.native-review", "guard", digest, source_digest, dependency, True)
    actions = binding("example.native-actions", "actions", digest, source_digest, dependency, True)
    safe_guard = binding("example.native-safe", "guard", digest, source_digest, dependency, False)
    safe_actions = binding("example.native-safe-actions", "actions", digest, source_digest, dependency, False)
    data = machine(guard, actions)
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    def dump_machine(document):
        yaml_data = copy.deepcopy(document)
        def quote_versions(value):
            if isinstance(value, dict):
                if value.get("version") == "1.0.0":
                    value["version"] = DoubleQuotedScalarString("1.0.0")
                for child in value.values():
                    quote_versions(child)
            elif isinstance(value, list):
                for child in value:
                    quote_versions(child)
        quote_versions(yaml_data)
        stream = StringIO()
        yaml.dump(yaml_data, stream)
        return stream.getvalue().replace(": \n", ":\n").encode()
    safe_data = machine(safe_guard, safe_actions)
    safe_data["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"] = (
        safe_data["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"][1])
    stream = dump_machine(data)
    outputs = {"machine.yaml": stream, "machine-safe.yaml": dump_machine(safe_data),
               "provider-closure.json": closure,
               "guard-descriptor.json": canonical({"kind": "guard", "binding": guard}),
               "actions-descriptor.json": canonical({"kind": "actions", "binding": actions}),
               "safe-guard-descriptor.json": canonical({"kind": "guard", "binding": safe_guard}),
               "safe-actions-descriptor.json": canonical({"kind": "actions", "binding": safe_actions})}
    for name in NORMATIVE:
        destination = "norm-" + (name[:-5] + ".source" if name.endswith(".yaml") else name)
        outputs[destination] = (spec_root / "examples/providers" / name).read_bytes()

    final_data = copy.deepcopy(data)
    final_root = final_data["machines"][0]["root"]
    final_root["states"]["pending"]["on_events"]["submit"][1]["transition_to"] = "done"
    final_root["states"]["done"] = {"type": "final"}
    final_root["exit"] = [{"send": {"event": "accepted", "to": {"external": True}, "correlation_id": "string(accepted)"}}]
    control_data = copy.deepcopy(final_data)
    control_branch = control_data["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"][1]
    control_branch["guard"] = "true"
    control_branch["action"][0] = {"assign": {"accepted": "true"}}
    local_data = copy.deepcopy(data)
    local_root = local_data["machines"][0]["root"]
    local_root["states"]["pending"]["variables"] = {"accepted": {"type": "bool", "init": False}}
    local_root["states"]["pending"]["on_events"]["submit"][1]["transition_to"] = "left"
    local_root["states"]["left"] = {"type": "simple"}
    choice_data = copy.deepcopy(local_data)
    choice_root = choice_data["machines"][0]["root"]
    choice_root["states"]["pending"]["on_events"]["submit"][1]["transition_to"] = "decision"
    choice_root["states"]["decision"] = {"choice": [{"guard": "true", "transition_to": "left"}, {"transition_to": "left"}]}
    initial_data = copy.deepcopy(data)
    initial_root = initial_data["machines"][0]["root"]
    initial_root["states"] = {"pending": {"type": "composite", "variables": {"accepted": {"type": "bool", "init": False}},
        "initial": {"transition_to": "done", "action": [{"provider_actions": copy.deepcopy(actions)}]},
        "states": {"done": {"type": "final"}}}}
    initial_control = copy.deepcopy(initial_data)
    initial_control["machines"][0]["root"]["states"]["pending"]["initial"]["action"] = [{"assign": {"accepted": "true"}}]
    bundles = {"machine.yaml": data, "machine-safe.yaml": safe_data, "machine-final.yaml": final_data,
               "machine-final-control.yaml": control_data, "machine-local-write.yaml": local_data,
               "machine-choice-write.yaml": choice_data, "machine-initial-write.yaml": initial_data,
               "machine-initial-control.yaml": initial_control}
    for filename, document in bundles.items():
        outputs[filename] = dump_machine(document)

    source = json.loads(outputs["norm-language-source-v1.json"])
    source["content"]["regions"][0]["provider_reference"] = reference("example.guard-compiler", digest)
    source["content"]["dependencies"] = [dependency]
    source["artifact_digest"] = value_digest([
        source["artifact_format"], "1", typed_value(source["content"]),
    ])
    compiled = json.loads(outputs["norm-compiled-machine.json"])
    manifest = json.loads(outputs["norm-compilation-manifest-v1.json"])
    manifest["content"]["source_artifact_digest"] = source["artifact_digest"]
    manifest["content"]["compiler_providers"] = [reference("example.guard-compiler", digest), dependency]
    manifest["content"]["generated_validated_bundle_fingerprint"] = bundle_fingerprint_document(compiled)
    manifest["artifact_digest"] = value_digest([
        manifest["artifact_format"], "1", typed_value(manifest["content"]),
    ])
    outputs["source-package.json"] = canonical(source)
    outputs["source-manifest.json"] = canonical(manifest)

    outputs["machine-inert.yaml"] = (spec_root / "examples/providers/inert-provider-metadata.yaml").read_bytes()
    installed = [dependency, guard["provider_reference"], actions["provider_reference"]]
    compiler_installed = [dependency, reference("example.guard-compiler", digest)]
    exact = {"mode": "exact", "providers": installed, "closure_digest": digest,
             "source_digest": source_digest, "trusted": True}
    compiler_exact = dict(exact, providers=compiler_installed)
    weak_profile = {"deterministic": False, "pure": False, "portable": False,
                    "semantically_introspectable": False, "process_contained": False,
                    "external_io_capable": True}
    safe_profile = dict(manifest["content"]["source_capabilities"])
    vectors = []

    def add(name, operation, installed_override=None, expected=None, bundle_file="machine.yaml", **arguments):
        setup = None
        if operation in {"step", "host_commit", "inspect", "create"}:
            bundle = bundles[bundle_file]
            fingerprint = bundle_fingerprint_document(bundle)
            runtime_id = value_digest([
                "determa-root-runtime-identity-1", "1", fingerprint,
                bundle["namespace"], "order", "1", "runtime-provider-root-1",
            ])
            approved = arguments["approved"] if "approved" in arguments else False
            payload = ["map", [["approved", ["boolean", approved]]]]
            envelope = {
                "event": "submit", "event_id": "runtime-provider-event-1",
                "cause_id": "runtime-provider-event-1", "source": {"host": True},
                "target": {"root": {"root_instance_id": "runtime-provider-root-1",
                                     "root_runtime_id": runtime_id}}, "payload": payload,
            }
            setup = {
                "create_request": {"machine_id": "order", "machine_version": "1",
                                   "root_instance_id": "runtime-provider-root-1",
                                   "creation_id": "runtime-provider-create-1",
                                   "bindings": {"input": {}, "external": {}}},
                "target_runtime_id": runtime_id, "envelope": envelope,
                "provider_snapshot": {"event": envelope,
                                      "variables": ["map", [["accepted", ["boolean", False]]]]},
            }
            expected["stages"] = [expected["stages"][0], "create"] + (
                ["admit"] if operation in {"step", "host_commit"} else []) + expected["stages"][1:]
            before = {"status": "running", "active_leaf": "/machines/0/root/states/pending",
                      "variables": {"accepted": ["boolean", False]},
                      "ready_mailbox_length": 0 if operation == "inspect" else 1,
                      "deferred_mailbox_length": 0, "output_count": 0}
            after = copy.deepcopy(before)
            if expected["determa_state_committed"]:
                after["ready_mailbox_length"] = 0
                if expected["value"] is not None:
                    if "accepted" in expected["value"]:
                        after["variables"]["accepted"] = expected["value"]["accepted"]
                    after["output_count"] = expected["value"]["emissions"]
            expected["state_before"] = before
            expected["state_after"] = after
            if operation == "create":
                setup["provider_snapshot"].pop("event")
                expected["state_before"] = None
                expected["state_after"] = {"status": "faulted", "active_leaf": None, "variables": {}, "ready_mailbox_length": 0, "deferred_mailbox_length": 0, "output_count": 0}
        if operation == "restore":
            selected = compiled if bundle_file == "norm-compiled-machine.json" else data
            arguments["definition_fingerprint"] = bundle_fingerprint_document(selected)
        vectors.append({"name": name, "request": {
            "operation": operation, "bundle": bundle_file,
            "installed": copy.deepcopy((compiler_exact if operation == "compile" else exact)
                                       if installed_override is None else installed_override),
            "setup": setup, "arguments": arguments,
        }, "expected": expected})

    reject = lambda code: observation("rejected", code=code, stages=["resolve_closure"])
    add("load_exact_weak_opt_in", "load", expected=observation(
        "accepted", stages=["resolve_closure", "verify_capabilities", "load"],
        guarantees=weak_profile), opt_in_weak=True)
    add("load_missing_dependency", "load", dict(exact, providers=installed[1:]),
        reject("runtime_provider_unavailable"), opt_in_weak=True)
    changed = copy.deepcopy(exact)
    changed["providers"][0]["content_digest"] = "sha256:" + "0" * 64
    add("load_changed_dependency", "load", changed,
        reject("runtime_provider_unavailable"), opt_in_weak=True)
    add("load_untrusted_closure", "load", dict(exact, trusted=False),
        reject("runtime_provider_unavailable"), opt_in_weak=True)
    add("load_changed_source_bytes", "load", dict(exact, closure_digest="sha256:" + "1" * 64),
        reject("runtime_provider_unavailable"), opt_in_weak=True)
    add("load_strong_host_refuses_weak", "load", expected=observation(
        "rejected", code="extension_capability_mismatch",
        stages=["resolve_closure", "verify_capabilities"]), opt_in_weak=False)
    add("cel_first_skips_native", "step", expected=observation(
        "handled_now", stages=["resolve_closure", "evaluate_cel", "commit"],
        committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", True], "emissions": 0}),
        approved=True, native_selected=False)
    add("native_false_no_actions", "step", expected=observation(
        "unhandled", stages=["resolve_closure", "evaluate_cel", "evaluate_guard", "commit"],
        guard=1, committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", False], "emissions": 0}),
        approved=False, native_selected=True, guard_override=False)
    add("native_action_proposals", "step", expected=observation(
        "handled_now", stages=["resolve_closure", "evaluate_cel", "evaluate_guard",
                               "evaluate_actions", "validate_output", "commit"],
        guard=1, actions=1, committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", True], "emissions": 2}),
        approved=False, native_selected=True, guard_override=True)
    slot = "/machines/0/root/states/pending/on_events/submit/1/action/0"
    runtime_id = value_digest(["determa-root-runtime-identity-1", "1", bundle_fingerprint_document(data),
                             data["namespace"], "order", "1", "runtime-provider-root-1"])
    identities = [{"effect_id": value_digest(["determa-effect-identity-1", "1", [data["namespace"], "order", "1"],
                   "runtime-provider-root-1", runtime_id, "runtime-provider-event-1", "1", pointer, str(index)]),
                   "emission_index": str(index), "sequence": str(sequence)}
                  for pointer, index, sequence in [(slot, 0, 0), (slot, 1, 1), (slot.replace("action/0", "action/1/send"), 0, 2)]]
    add("native_repeated_sends_have_distinct_ids", "step", expected=observation(
        "handled_now", stages=["resolve_closure", "evaluate_cel", "evaluate_guard",
                               "evaluate_actions", "validate_output", "commit"],
        guard=1, actions=1, committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", True], "emissions": 3, "emission_identities": identities}),
        approved=False, native_selected=True, guard_override=True, repeat_send=True)
    add("native_repeated_sends_commit_and_replay", "host_commit", expected=observation(
        "handled_now", stages=["resolve_closure", "evaluate_cel", "evaluate_guard",
                               "evaluate_actions", "validate_output", "compare_and_swap", "commit", "replay"],
        guard=1, actions=1, committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", True], "emissions": 3, "emission_identities": copy.deepcopy(identities),
               "checkpoint_revision": "2", "retained_effect_references": 3, "pending_outbox_entries": 3,
               "replay_receipt_equal": True, "replay_checkpoint_unchanged": True,
               "replay_provider_calls_unchanged": True}),
        approved=False, native_selected=True, guard_override=True, repeat_send=True,
        cas_conflict=False, maximum_attempts=1, replay=True)
    add("load_inert_provider_metadata", "load", bundle_file="machine-inert.yaml", expected=observation(
        "accepted", stages=["resolve_closure", "verify_capabilities", "load"],
        guarantees=dict.fromkeys(("deterministic", "pure", "portable", "semantically_introspectable", "process_contained"), True) | {"external_io_capable": False}),
        opt_in_weak=True)
    for filename, name, count, claims, native in (
        ("machine-final.yaml", "native_root_assignment_before_final", 3, weak_profile, True),
        ("machine-final-control.yaml", "ordinary_root_assignment_before_final", 2,
         dict.fromkeys(("deterministic", "pure", "portable", "semantically_introspectable", "process_contained"), True) | {"external_io_capable": False}, False),
    ):
        add(name, "step", bundle_file=filename, expected=observation(
            "handled_now", stages=["resolve_closure", "evaluate_cel"] + (["evaluate_guard", "evaluate_actions", "validate_output"] if native else []) + ["commit"],
            guard=int(native), actions=int(native), committed=True, guarantees=claims,
            value={"emissions": count, "exit_correlation": "true", "status": "completed"}),
            approved=False, native_selected=native, guard_override=True)
        vectors[-1]["expected"]["state_after"].update(status="completed", active_leaf=None, variables={})
    for filename, name in (("machine-local-write.yaml", "native_local_write_destroyed_by_event"),
                           ("machine-choice-write.yaml", "native_local_write_destroyed_after_choice")):
        add(name, "step", bundle_file=filename, expected=observation(
            "faulted", code="action_fault", stages=["resolve_closure", "evaluate_cel", "evaluate_guard", "evaluate_actions", "validate_output"],
            guard=1, actions=1, guarantees=weak_profile,
            value={"boundary_code": "runtime_provider_output_invalid", "source_locator": "/machines/0/root/states/pending/on_events/submit/1/action/0"}),
            approved=False, native_selected=True, guard_override=True, destroyed_write=True)
    add("native_snapshot_preserves_complete_queue_envelope", "step", expected=observation(
        "handled_now", stages=["resolve_closure", "evaluate_cel", "evaluate_guard", "evaluate_actions", "validate_output", "commit"],
        guard=1, actions=1, committed=True, guarantees=weak_profile,
        value={"accepted": ["boolean", True], "emissions": 2}),
        approved=False, native_selected=True, guard_override=True, capture_snapshot=True)
    vectors[-1]["request"]["setup"]["envelope"]["cause_id"] = "runtime-provider-distinct-cause-1"
    vectors[-1]["request"]["setup"]["provider_snapshot"]["event"]["cause_id"] = "runtime-provider-distinct-cause-1"
    for key in ("guard_snapshot", "action_snapshot"):
        vectors[-1]["expected"]["value"][key] = copy.deepcopy(vectors[-1]["request"]["setup"]["provider_snapshot"])
    add("native_initial_local_write_destroyed_by_final", "create", bundle_file="machine-initial-write.yaml", expected=observation(
        "faulted", code="action_fault", stages=["resolve_closure", "evaluate_actions", "validate_output"],
        actions=1, guarantees=weak_profile,
        value={"boundary_code": "runtime_provider_output_invalid", "source_locator": "/machines/0/root/states/pending/initial/action/0", "emissions": 0, "status": "faulted"}),
        approved=False, destroyed_write=True)
    add("ordinary_initial_destroyed_write_rejected_at_load", "load", bundle_file="machine-initial-control.yaml", expected=observation(
        "rejected", code="destroyed_variable_write", stages=["resolve_closure", "load"]), opt_in_weak=True)
    add("invalid_action_output_rolls_back", "step", expected=observation(
        "faulted", code="action_fault", stages=["resolve_closure", "evaluate_cel",
          "evaluate_guard", "evaluate_actions", "validate_output"], guard=1, actions=1,
        guarantees=weak_profile, value={"boundary_code": "runtime_provider_output_invalid"}),
        approved=False, native_selected=True, guard_override=True, invalid_output=True)
    add("native_io_then_action_failure", "step", expected=observation(
        "faulted", code="action_fault", stages=["resolve_closure", "evaluate_cel",
          "evaluate_guard", "evaluate_actions"], guard=1, actions=1, external=1,
        effects=1, guarantees=weak_profile), approved=False, native_selected=True,
        guard_override=True, action_fail=True, action_external_io=True)
    add("native_io_then_cas_conflict", "host_commit", expected=observation(
        "uncommitted", code="compare_and_swap_conflict", stages=["resolve_closure", "evaluate_cel",
          "evaluate_guard", "evaluate_actions", "validate_output", "compare_and_swap"],
        guard=1, actions=1, external=1, effects=1, guarantees=weak_profile),
        approved=False, native_selected=True, guard_override=True,
        action_external_io=True, cas_conflict=True, maximum_attempts=1)
    add("inspect_unsafe_refused", "inspect", expected=observation(
        "rejected", code="inspection_capability_unavailable",
        stages=["resolve_closure", "preflight_inspection"], guarantees=weak_profile),
        mode="semantic", maximum_guard_evaluations=1, maximum_evaluation_steps=2)
    add("inspect_structural_no_call", "inspect", expected=observation(
        "accepted", stages=["resolve_closure", "structural_inspection"],
        guarantees=weak_profile, value={"classification": "conditional"}), mode="structural")
    safe_installed = dict(exact, providers=installed + [safe_guard["provider_reference"],
                                                  safe_actions["provider_reference"]])
    native_safe_profile = dict(weak_profile, deterministic=True, pure=True,
                               semantically_introspectable=True, process_contained=True,
                               external_io_capable=False)
    add("inspect_safe_bounded", "inspect", safe_installed, observation(
        "accepted", stages=["resolve_closure", "preflight_inspection", "invoke_inspect_guard"],
        inspection=1, guarantees=native_safe_profile,
        value={"classification": "definitive", "disposition": "handled_now", "fuel": 2}),
        bundle_file="machine-safe.yaml", mode="semantic", approved=True,
        maximum_guard_evaluations=1, maximum_evaluation_steps=2)
    add("inspect_safe_fuel_exhausted", "inspect", safe_installed, observation(
        "rejected", code="inspection_limit_exceeded",
        stages=["resolve_closure", "preflight_inspection", "invoke_inspect_guard"],
        inspection=1, guarantees=native_safe_profile), bundle_file="machine-safe.yaml",
        mode="semantic", approved=True, maximum_guard_evaluations=1,
        maximum_evaluation_steps=1)
    add("inspect_mixed_refused_before_cel", "inspect", expected=observation(
        "rejected", code="inspection_capability_unavailable",
        stages=["resolve_closure", "preflight_inspection"], guarantees=weak_profile),
        mode="semantic", approved=True, maximum_guard_evaluations=1,
        maximum_evaluation_steps=2)
    add("restore_without_compiler", "restore", dict(exact, providers=[]),
        observation("accepted", stages=["resolve_runtime_closure", "restore"],
                    guarantees={"deterministic": True, "pure": True, "portable": True,
                                "semantically_introspectable": True,
                                "process_contained": True, "external_io_capable": False}),
        bundle_file="norm-compiled-machine.json", source_file="source-package.json",
        manifest_file="source-manifest.json")
    add("restore_runtime_without_compiler", "restore", expected=observation(
        "accepted", stages=["resolve_runtime_closure", "restore"],
        guarantees=weak_profile))
    add("restore_missing_runtime", "restore", compiler_exact,
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["resolve_runtime_closure"]))
    add("restore_changed_runtime", "restore", changed,
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["resolve_runtime_closure"]))
    add("restore_untrusted_runtime", "restore", dict(exact, trusted=False),
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["resolve_runtime_closure"]))
    add("compile_exact_source", "compile", expected=observation(
        "accepted", stages=["validate_source", "resolve_compiler_closure", "compile_region",
                            "strict_load", "verify_manifest"], guarantees=safe_profile,
        value={"generated_guard": "event.payload.approved"}),
        source_file="source-package.json", manifest_file="source-manifest.json",
        generated_bundle_file="norm-compiled-machine.json")
    add("compile_missing_compiler", "compile", dict(compiler_exact, providers=[]),
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["validate_source", "resolve_compiler_closure"]),
        source_file="source-package.json")
    compiler_changed = copy.deepcopy(compiler_exact)
    compiler_changed["providers"][-1]["content_digest"] = "sha256:" + "2" * 64
    add("compile_changed_compiler", "compile", compiler_changed,
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["validate_source", "resolve_compiler_closure"]),
        source_file="source-package.json")
    add("compile_untrusted_compiler", "compile", dict(compiler_exact, trusted=False),
        observation("rejected", code="runtime_provider_unavailable",
                    stages=["validate_source", "resolve_compiler_closure"]),
        source_file="source-package.json")
    add("compile_manifest_fingerprint_mismatch", "compile", expected=observation(
        "rejected", code="language_compilation_failed",
        stages=["validate_source", "resolve_compiler_closure", "compile_region",
                "strict_load", "verify_manifest"]),
        source_file="source-package.json", manifest_file="source-manifest.json",
        generated_bundle_file="norm-compiled-machine.json",
        manifest_fingerprint_override="sha256:" + "3" * 64)
    add("compile_source_digest_mismatch", "compile", expected=observation(
        "rejected", code="language_compilation_failed", stages=["validate_source"]),
        source_file="source-package.json", source_digest_override="sha256:" + "4" * 64)
    add("compile_limit_exceeded", "compile", expected=observation(
        "rejected", code="language_compilation_limit_exceeded",
        stages=["validate_source", "resolve_compiler_closure", "compile_region"]),
        source_file="source-package.json",
        maximum_compilation_steps=0)
    add("compile_bad_region_source", "compile", expected=observation(
        "rejected", code="language_compilation_failed",
        stages=["validate_source", "resolve_compiler_closure", "compile_region"]),
        source_file="source-package.json", source_override="invalid expression")
    outputs["vectors.generated.json"] = canonical({
        "format": "determa.runtime_provider_vectors", "version": 1,
        "source_files": list(SOURCES), "source_closure_file": "provider-closure.json",
        "normative_examples": ["norm-" + (name[:-5] + ".source" if name.endswith(".yaml") else name) for name in NORMATIVE],
        "vectors": vectors,
    })
    test = {"title": "Exact runtime provider and compiler source profile",
            "static": {"documents": [{"file": "machine.yaml", "valid": True},
                                      {"file": "machine-safe.yaml", "valid": True},
                                      {"file": "machine-inert.yaml", "valid": True},
                                      *[{"file": name, "valid": True} for name in bundles if name not in {"machine.yaml", "machine-safe.yaml"}]]},
            "artifacts": {"documents": [
                {"file": name, "kind": "json_value", "valid": True}
                for name in sorted(outputs) if name.endswith(".json")
            ]}}
    stream = StringIO()
    yaml.dump(test, stream)
    outputs["test.yaml"] = stream.getvalue().encode()
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = render(args.spec_root)
    for name, body in outputs.items():
        path = CASE / name
        if args.check:
            if not path.is_file() or path.read_bytes() != body:
                raise SystemExit(f"stale runtime provider fixture: {name}")
        else:
            path.write_bytes(body)
    print(f"{'checked' if args.check else 'wrote'} {len(outputs)} runtime provider files; "
          f"{len(json.loads(outputs['vectors.generated.json'])['vectors'])} vectors")


if __name__ == "__main__":
    main()
