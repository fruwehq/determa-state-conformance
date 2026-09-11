#!/usr/bin/env python3
"""Generate the execution-checkpoint profile from pure core results."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import determa.state as state_module
import rfc8785
from determa.state import (
    MemoryArtifactResolver,
    __version__ as python_core_version,
    aggregate_envelope,
    aggregate_shape_fingerprint,
    create,
    dispatch,
    load_bundle,
    migrate_aggregate,
)
from determa.state.wire import migration_descriptor_digest, typed_value


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance" / "profiles" / "execution-checkpoint"
SPEC_COMMIT = "7782671b56165a59caa61a65c29fefc63105ebf8"
PYTHON_CORE_COMMIT = "7b17d788b48049648e7e463aa3d35ba13dc1aa6e"
RUST_CORE_COMMIT = "d17480c8b281dcd17953f59afcf6b5d23ff44efd"


def hash_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def operation_input_digest(value: dict[str, Any]) -> str:
    return hash_value(
        ["determa-conformance-execution-checkpoint-operation-input-1", value]
    )


def bundle_binding(case: Path, bundle_file: str, bundle: Any) -> dict[str, str]:
    return {
        "bundle_file": bundle_file,
        "bundle_source_digest": hash_bytes((case / bundle_file).read_bytes()),
        "validated_bundle_fingerprint": bundle.fingerprint,
    }


def verify_imported_python_checkout() -> None:
    source = Path(state_module.__file__).resolve()
    checkout = next(
        (parent for parent in source.parents if (parent / ".git").exists()),
        None,
    )
    if checkout is None:
        raise SystemExit(
            f"--check requires an imported Python Git checkout, got {source}"
        )
    commit = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if commit != PYTHON_CORE_COMMIT:
        raise SystemExit(
            f"wrong imported Python core commit: {commit}; "
            f"expected {PYTHON_CORE_COMMIT}"
        )
    dirty = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=no"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if dirty:
        raise SystemExit(f"imported Python core checkout is dirty: {checkout}")


def write_json(path: Path, value: Any, *, canonical: bool = False) -> None:
    if canonical:
        path.write_bytes(rfc8785.dumps(value))
    else:
        path.write_text(
            json.dumps(value, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )


def checkpoint_digest(checkpoint: dict[str, Any]) -> str:
    value = copy.deepcopy(checkpoint)
    value.pop("execution_checkpoint_digest", None)
    return hash_value(["determa-execution-checkpoint-digest-1", value])


def seal(checkpoint: dict[str, Any]) -> dict[str, Any]:
    checkpoint["execution_checkpoint_digest"] = checkpoint_digest(checkpoint)
    return checkpoint


def creation_digest(
    bundle: Any,
    machine_id: str,
    machine_version: int,
    root_instance_id: str,
    creation_id: str,
    bindings: dict[str, Any],
) -> str:
    return hash_value(
        [
            "determa-creation-request-digest-1",
            "1",
            bundle.fingerprint,
            bundle.namespace,
            machine_id,
            str(machine_version),
            root_instance_id,
            creation_id,
            typed_value(bindings),
        ]
    )


def portable_envelope(
    event: str,
    event_id: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    correlation_id: str | None = None,
) -> dict[str, Any]:
    result = {
        "event": event,
        "event_id": event_id,
        "target": copy.deepcopy(target),
        "payload": typed_value(payload),
    }
    if correlation_id is not None:
        result["correlation_id"] = correlation_id
    return result


def native_target(target: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(target)
    spawned = result.get("spawned_instance")
    if spawned is not None:
        spawned["machine_version"] = int(spawned["machine_version"])
    return result


def delivery_request(
    *,
    case: Path,
    bundle: Any,
    bundle_file: str,
    root_instance_id: str,
    delivery_mode: str,
    origin: dict[str, Any],
    event: str,
    event_id: str,
    target: dict[str, Any],
    payload: dict[str, Any],
    supplied_envelope_digest: str | None = None,
) -> dict[str, Any]:
    envelope = portable_envelope(event, event_id, target, payload)
    digest = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            root_instance_id,
            delivery_mode,
            envelope,
        ]
    )
    request = {
        "operation": "delivery",
        "root_instance_id": root_instance_id,
        "delivery_mode": delivery_mode,
        "origin": copy.deepcopy(origin),
        "envelope": envelope,
        "envelope_digest": (
            digest if supplied_envelope_digest is None else supplied_envelope_digest
        ),
        "dispatch_input": {
            **bundle_binding(case, bundle_file, bundle),
            "delivery": {
                delivery_mode: {
                    "event": event,
                    "event_id": event_id,
                    "target": copy.deepcopy(target),
                    "payload": copy.deepcopy(payload),
                }
            },
        },
    }
    return request


def with_read(
    request: dict[str, Any], checkpoint: dict[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(request)
    result["expected_revision"] = checkpoint["revision"]
    result["expected_checkpoint_digest"] = checkpoint[
        "execution_checkpoint_digest"
    ]
    return result


def projected_fault(
    result: dict[str, Any], aggregate: dict[str, Any] | None
) -> dict[str, Any] | None:
    fault = result["fault"]
    if fault is None or aggregate is None:
        return None
    for runtime in aggregate["runtimes"]:
        candidate = runtime["fault"]
        if candidate is not None and candidate["runtime_id"] == fault["runtime_id"]:
            return copy.deepcopy(candidate)
    raise RuntimeError("core fault is absent from its aggregate projection")


def projected_emission(emission: dict[str, Any]) -> dict[str, Any]:
    if emission["target"] == "external":
        return {
            "kind": "external",
            "event": emission["event"],
            "effect_id": emission["effect_id"],
            "sequence": str(emission["sequence"]),
            "payload": typed_value(emission["payload"]),
            "correlation_id": emission["correlation_id"],
        }
    result = {
        "kind": "internal",
        "event": emission["event"],
        "event_id": emission["event_id"],
        "target": copy.deepcopy(emission["target"]),
        "payload": typed_value(emission["payload"]),
    }
    if "correlation_id" in emission:
        result["correlation_id"] = emission["correlation_id"]
    return result


def project_core_result(
    bundle: Any,
    result: dict[str, Any],
    prior_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    aggregate = (
        aggregate_envelope(bundle, result["state"])
        if result["state"] is not None
        else None
    )
    return {
        "prior_aggregate_state_digest": (
            aggregate_envelope(bundle, prior_state)["aggregate_state_digest"]
            if prior_state is not None
            else None
        ),
        "status": result["status"],
        "disposition": result["disposition"],
        "aggregate_state": aggregate,
        "emissions": [projected_emission(item) for item in result["emissions"]],
        "fault": projected_fault(result, aggregate),
        "rejection": copy.deepcopy(result["rejection"]),
    }


def empty_checkpoint(
    aggregate: dict[str, Any],
    request_digest: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    checkpoint = {
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 1,
        "root_instance_id": aggregate["root_instance_id"],
        "revision": "0",
        "root_record": {
            "status": "retained",
            "aggregate_state": copy.deepcopy(aggregate),
        },
        "replay_retention": {
            "mode": "permanent",
            "permanent_replay_eligible": True,
            "pruned_through_receipt_sequence": None,
            "policy_identifier": None,
        },
        "next_delivery_sequence": "0",
        "pending_deliveries": [],
        "next_operation_receipt_sequence": "1",
        "operation_receipts": [
            {
                "operation_kind": "creation",
                "receipt_sequence": "0",
                "creation_id": aggregate["creation_id"],
                "request_digest": request_digest,
                "committed_revision": "0",
                "resulting_aggregate_state_digest": aggregate[
                    "aggregate_state_digest"
                ],
                "status": result["status"],
                "fault": copy.deepcopy(result["fault"]),
                "emission_references": [],
            }
        ],
        "pending_outbox_intents": [],
        "next_outbox_terminal_sequence": "0",
        "terminal_outbox_records": [],
        "outbox_effect_tombstones": [],
        "migration_audit_records": [],
    }
    if result["emissions"]:
        append_emissions(checkpoint, checkpoint["operation_receipts"][0], result)
    return seal(checkpoint)


def mutate(checkpoint: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(checkpoint)
    result.pop("execution_checkpoint_digest", None)
    result["revision"] = str(int(result["revision"]) + 1)
    return result


def append_emissions(
    checkpoint: dict[str, Any],
    receipt: dict[str, Any],
    result: dict[str, Any],
) -> None:
    for index, emission in enumerate(result["emissions"]):
        if emission["kind"] == "internal":
            sequence = checkpoint["next_delivery_sequence"]
            checkpoint["next_delivery_sequence"] = str(int(sequence) + 1)
            origin = {
                "kind": "internal_emission",
                "producing_receipt_sequence": receipt["receipt_sequence"],
                "emission_index": str(index),
            }
            envelope = {
                key: copy.deepcopy(emission[key])
                for key in ("event", "event_id", "target", "payload")
            }
            if "correlation_id" in emission:
                envelope["correlation_id"] = emission["correlation_id"]
            digest = hash_value(
                [
                    "determa-inbox-envelope-digest-1",
                    "1",
                    checkpoint["root_instance_id"],
                    "internal",
                    envelope,
                ]
            )
            checkpoint["pending_deliveries"].append(
                {
                    "delivery_sequence": sequence,
                    "accepted_revision": checkpoint["revision"],
                    "delivery_mode": "internal",
                    "origin": origin,
                    "envelope": envelope,
                    "envelope_digest": digest,
                }
            )
            receipt["emission_references"].append(
                {
                    "kind": "internal_delivery",
                    "emission_index": str(index),
                    "event_id": emission["event_id"],
                    "delivery_sequence": sequence,
                }
            )
        else:
            checkpoint["pending_outbox_intents"].append(
                {
                    "intent": {
                        "effect_id": emission["effect_id"],
                        "sequence": emission["sequence"],
                        "event": emission["event"],
                        "payload": copy.deepcopy(emission["payload"]),
                        "correlation_id": emission["correlation_id"],
                    },
                    "state_revision": checkpoint["revision"],
                    "delivery_state": {"status": "not_attempted"},
                }
            )
            receipt["emission_references"].append(
                {
                    "kind": "external_outbox",
                    "emission_index": str(index),
                    "effect_id": emission["effect_id"],
                }
            )


def accept_delivery(
    checkpoint: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    result = mutate(checkpoint)
    sequence = result["next_delivery_sequence"]
    result["next_delivery_sequence"] = str(int(sequence) + 1)
    result["pending_deliveries"].append(
        {
            "delivery_sequence": sequence,
            "accepted_revision": result["revision"],
            "delivery_mode": request["delivery_mode"],
            "origin": copy.deepcopy(request["origin"]),
            "envelope": copy.deepcopy(request["envelope"]),
            "envelope_digest": request["envelope_digest"],
        }
    )
    return seal(result)


def commit_delivery(
    checkpoint: dict[str, Any],
    request: dict[str, Any],
    core_result: dict[str, Any],
    *,
    foreground: bool,
) -> dict[str, Any]:
    result = mutate(checkpoint)
    if foreground:
        delivery_sequence = result["next_delivery_sequence"]
        result["next_delivery_sequence"] = str(int(delivery_sequence) + 1)
        accepted_revision = result["revision"]
    else:
        event_id = request["envelope"]["event_id"]
        pending = next(
            item
            for item in result["pending_deliveries"]
            if item["envelope"]["event_id"] == event_id
        )
        result["pending_deliveries"].remove(pending)
        delivery_sequence = pending["delivery_sequence"]
        accepted_revision = pending["accepted_revision"]
    receipt_sequence = result["next_operation_receipt_sequence"]
    result["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    aggregate = copy.deepcopy(core_result["aggregate_state"])
    result["root_record"]["aggregate_state"] = aggregate
    receipt = {
        "operation_kind": "delivery",
        "receipt_sequence": receipt_sequence,
        "event_id": request["envelope"]["event_id"],
        "request_digest": request["envelope_digest"],
        "accepted_delivery_sequence": delivery_sequence,
        "accepted_revision": accepted_revision,
        "delivery_mode": request["delivery_mode"],
        "origin": copy.deepcopy(request["origin"]),
        "committed_revision": result["revision"],
        "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
        "outcome": {
            "status": core_result["status"],
            "disposition": core_result["disposition"],
            "fault": copy.deepcopy(core_result["fault"]),
            "rejection": copy.deepcopy(core_result["rejection"]),
        },
        "emission_references": [],
    }
    result["operation_receipts"].append(receipt)
    append_emissions(result, receipt, core_result)
    return seal(result)


def outbox_pending_update(
    checkpoint: dict[str, Any],
    effect_id: str,
    desired: dict[str, Any],
) -> dict[str, Any]:
    result = mutate(checkpoint)
    item = next(
        item
        for item in result["pending_outbox_intents"]
        if item["intent"]["effect_id"] == effect_id
    )
    item["delivery_state"] = copy.deepcopy(desired)
    item["state_revision"] = result["revision"]
    return seal(result)


def outbox_terminal_update(
    checkpoint: dict[str, Any],
    effect_id: str,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    result = mutate(checkpoint)
    item = next(
        item
        for item in result["pending_outbox_intents"]
        if item["intent"]["effect_id"] == effect_id
    )
    result["pending_outbox_intents"].remove(item)
    terminal_sequence = result["next_outbox_terminal_sequence"]
    result["next_outbox_terminal_sequence"] = str(int(terminal_sequence) + 1)
    result["terminal_outbox_records"].append(
        {
            "terminal_sequence": terminal_sequence,
            "intent": item["intent"],
            "committed_revision": result["revision"],
            "outcome": copy.deepcopy(outcome),
        }
    )
    return seal(result)


def compact_outbox(
    checkpoint: dict[str, Any], effect_id: str
) -> dict[str, Any]:
    result = mutate(checkpoint)
    item = next(
        item
        for item in result["terminal_outbox_records"]
        if item["intent"]["effect_id"] == effect_id
    )
    result["terminal_outbox_records"].remove(item)
    result["outbox_effect_tombstones"].append(
        {
            "terminal_sequence": item["terminal_sequence"],
            "effect_id": effect_id,
            "intent_digest": hash_value(
                [
                    "determa-outbox-intent-digest-1",
                    "1",
                    result["root_instance_id"],
                    item["intent"],
                ]
            ),
            "committed_revision": item["committed_revision"],
            "outcome": item["outcome"],
        }
    )
    result["outbox_effect_tombstones"].sort(
        key=lambda value: int(value["terminal_sequence"])
    )
    return seal(result)


def operation_input(
    checkpoint: dict[str, Any],
    operation: str,
    **members: Any,
) -> dict[str, Any]:
    return {
        "operation": operation,
        **members,
        "expected_revision": checkpoint["revision"],
        "expected_checkpoint_digest": checkpoint["execution_checkpoint_digest"],
    }


def generation_record(
    calls: dict[str, Any],
    requests: dict[str, Any],
    call_inputs: dict[str, tuple[str, str]],
) -> dict[str, Any]:
    bound_calls = copy.deepcopy(calls)
    if set(bound_calls) != set(call_inputs):
        raise RuntimeError("every projected core result needs one exact input binding")
    for name, (core_operation, request_name) in call_inputs.items():
        bound_calls[name]["core_operation"] = core_operation
        bound_calls[name]["operation_input_file"] = "inputs.json"
        bound_calls[name]["operation_input_pointer"] = (
            f"/requests/{request_name}"
        )
        bound_calls[name]["operation_input_digest"] = operation_input_digest(
            requests[request_name]
        )
    return {
        "execution_checkpoint_core_evidence_format": (
            "determa.execution_checkpoint_profile.core_evidence"
        ),
        "execution_checkpoint_core_evidence_schema_version": 1,
        "provenance": {
            "spec_commit": SPEC_COMMIT,
            "python_core_commit": PYTHON_CORE_COMMIT,
            "python_core_version": python_core_version,
            "rust_cross_check_commit": RUST_CORE_COMMIT,
        },
        "calls": bound_calls,
    }


def generate_delivery() -> dict[str, Any]:
    case = PROFILE / "checkpoint-01-delivery-lifecycle"
    bundle_file = "machine.yaml"
    bundle = load_bundle((case / bundle_file).read_text(encoding="utf-8"))
    bindings = {"input": {}, "external": {}}
    create_args = {
        "operation": "create",
        **bundle_binding(case, bundle_file, bundle),
        "namespace": bundle.namespace,
        "machine_id": "counter",
        "machine_version": "1",
        "root_instance_id": "checkpoint-root",
        "creation_id": "checkpoint-create",
        "bindings": bindings,
    }
    created_raw = create(
        bundle,
        create_args["machine_id"],
        create_args["root_instance_id"],
        create_args["creation_id"],
        bindings,
    )
    created = project_core_result(bundle, created_raw)
    create_args["request_digest"] = creation_digest(
        bundle, "counter", 1, "checkpoint-root", "checkpoint-create", bindings
    )
    checkpoint_created = empty_checkpoint(
        created["aggregate_state"], create_args["request_digest"], created
    )
    target = {
        "root": {
            "root_instance_id": "checkpoint-root",
            "root_runtime_id": created["aggregate_state"]["root_runtime_id"],
        }
    }
    increment_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="checkpoint-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="increment",
        event_id="delivery-increment",
        target=target,
        payload={"amount": 1},
    )
    accept_increment = with_read(increment_base, checkpoint_created)
    accepted = accept_delivery(checkpoint_created, accept_increment)
    process_increment = with_read(increment_base, accepted)
    increment_raw = dispatch(
        bundle, created_raw["state"], process_increment["dispatch_input"]["delivery"]
    )
    increment_result = project_core_result(bundle, increment_raw, created_raw["state"])
    processed = commit_delivery(
        accepted, process_increment, increment_result, foreground=False
    )

    emit_internal_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="checkpoint-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="emit_internal",
        event_id="delivery-emit-internal",
        target=target,
        payload={"amount": 5},
    )
    emit_internal = with_read(emit_internal_base, processed)
    emit_raw = dispatch(
        bundle, increment_raw["state"], emit_internal["dispatch_input"]["delivery"]
    )
    emit_result = project_core_result(bundle, emit_raw, increment_raw["state"])
    internal_pending = commit_delivery(
        processed, emit_internal, emit_result, foreground=True
    )
    pending_internal = internal_pending["pending_deliveries"][0]
    internal_base = {
        "operation": "delivery",
        "root_instance_id": "checkpoint-root",
        "delivery_mode": "internal",
        "origin": copy.deepcopy(pending_internal["origin"]),
        "envelope": copy.deepcopy(pending_internal["envelope"]),
        "envelope_digest": pending_internal["envelope_digest"],
        "dispatch_input": {
            **bundle_binding(case, bundle_file, bundle),
            "delivery": {
                "internal": {
                    "event": pending_internal["envelope"]["event"],
                    "event_id": pending_internal["envelope"]["event_id"],
                    "target": copy.deepcopy(pending_internal["envelope"]["target"]),
                    "payload": {"amount": 5},
                }
            },
        },
    }
    internal = with_read(internal_base, internal_pending)
    internal_raw = dispatch(
        bundle, emit_raw["state"], internal["dispatch_input"]["delivery"]
    )
    internal_result = project_core_result(bundle, internal_raw, emit_raw["state"])
    internal_processed = commit_delivery(
        internal_pending, internal, internal_result, foreground=False
    )

    unhandled_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="checkpoint-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="unhandled",
        event_id="delivery-unhandled",
        target=target,
        payload={},
    )
    unhandled = with_read(unhandled_base, internal_processed)
    unhandled_raw = dispatch(
        bundle, internal_raw["state"], unhandled["dispatch_input"]["delivery"]
    )
    unhandled_result = project_core_result(bundle, unhandled_raw, internal_raw["state"])
    unhandled_checkpoint = commit_delivery(
        internal_processed, unhandled, unhandled_result, foreground=True
    )

    rejected_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="checkpoint-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="unknown_event",
        event_id="delivery-rejected",
        target=target,
        payload={},
    )
    rejected = with_read(rejected_base, unhandled_checkpoint)
    rejected_raw = dispatch(
        bundle, unhandled_raw["state"], rejected["dispatch_input"]["delivery"]
    )
    rejected_result = project_core_result(
        bundle, rejected_raw, unhandled_raw["state"]
    )
    rejected_checkpoint = commit_delivery(
        unhandled_checkpoint, rejected, rejected_result, foreground=True
    )

    fault_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="checkpoint-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="deliberate_fault",
        event_id="delivery-fault",
        target=target,
        payload={},
    )
    fault = with_read(fault_base, rejected_checkpoint)
    fault_raw = dispatch(
        bundle, rejected_raw["state"], fault["dispatch_input"]["delivery"]
    )
    fault_result = project_core_result(bundle, fault_raw, rejected_raw["state"])
    faulted_checkpoint = commit_delivery(
        rejected_checkpoint, fault, fault_result, foreground=True
    )

    rejected_create_args = {
        "operation": "create",
        **bundle_binding(case, bundle_file, bundle),
        "namespace": bundle.namespace,
        "machine_id": "missing_machine",
        "machine_version": "1",
        "root_instance_id": "rejected-root",
        "creation_id": "rejected-create",
        "bindings": bindings,
    }
    rejected_create_args["request_digest"] = creation_digest(
        bundle,
        "missing_machine",
        1,
        "rejected-root",
        "rejected-create",
        bindings,
    )
    rejected_create = project_core_result(
        bundle,
        create(
            bundle,
            "missing_machine",
            "rejected-root",
            "rejected-create",
            bindings,
        ),
    )
    conflicting_create = copy.deepcopy(create_args)
    conflicting_create["creation_id"] = "conflicting-create"
    conflicting_create["request_digest"] = creation_digest(
        bundle, "counter", 1, "checkpoint-root", "conflicting-create", bindings
    )

    wrong_root = copy.deepcopy(increment_base)
    wrong_root["root_instance_id"] = "another-root"
    wrong_root["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            "another-root",
            "input",
            wrong_root["envelope"],
        ]
    )
    wrong_root = with_read(wrong_root, faulted_checkpoint)
    invalid_mode = copy.deepcopy(increment_base)
    invalid_mode["delivery_mode"] = "invalid"
    invalid_mode["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            "checkpoint-root",
            "invalid",
            invalid_mode["envelope"],
        ]
    )
    invalid_mode.pop("dispatch_input", None)
    invalid_mode = with_read(invalid_mode, faulted_checkpoint)
    invalid_origin = copy.deepcopy(increment_base)
    invalid_origin["origin"] = {"kind": "invalid"}
    invalid_origin.pop("dispatch_input", None)
    invalid_origin = with_read(invalid_origin, faulted_checkpoint)
    fresh_invalid_mode = copy.deepcopy(invalid_mode)
    fresh_invalid_mode["envelope"]["event_id"] = "delivery-fresh-invalid-mode"
    fresh_invalid_mode["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            "checkpoint-root",
            "invalid",
            fresh_invalid_mode["envelope"],
        ]
    )
    fresh_invalid_origin = copy.deepcopy(invalid_origin)
    fresh_invalid_origin["envelope"]["event_id"] = "delivery-fresh-invalid-origin"
    fresh_invalid_origin["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            "checkpoint-root",
            "input",
            fresh_invalid_origin["envelope"],
        ]
    )
    digest_mismatch = copy.deepcopy(increment_base)
    digest_mismatch["envelope"]["event_id"] = "delivery-digest-mismatch"
    digest_mismatch["envelope_digest"] = "sha256:" + ("7" * 64)
    digest_mismatch.pop("dispatch_input", None)
    digest_mismatch = with_read(digest_mismatch, faulted_checkpoint)
    event_conflict = copy.deepcopy(fault_base)
    event_conflict["envelope"]["event"] = "increment"
    event_conflict["envelope"]["payload"] = typed_value({"amount": 99})
    event_conflict["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            "checkpoint-root",
            "input",
            event_conflict["envelope"],
        ]
    )
    event_conflict.pop("dispatch_input", None)
    event_conflict = with_read(event_conflict, faulted_checkpoint)
    process_increment_stale = copy.deepcopy(process_increment)
    process_increment_stale["expected_revision"] = checkpoint_created["revision"]
    process_increment_stale["expected_checkpoint_digest"] = checkpoint_created[
        "execution_checkpoint_digest"
    ]

    requests = {
        "create": create_args,
        "create_conflict": conflicting_create,
        "create_rejected": rejected_create_args,
        "accept_increment": accept_increment,
        "process_increment": process_increment,
        "process_increment_stale": process_increment_stale,
        "emit_internal": emit_internal,
        "internal_increment": internal,
        "unhandled": unhandled,
        "rejected": rejected,
        "fault": fault,
        "malformed": {
            "operation": "delivery",
            "candidate": None,
            "expected_revision": faulted_checkpoint["revision"],
            "expected_checkpoint_digest": faulted_checkpoint[
                "execution_checkpoint_digest"
            ],
        },
        "wrong_root": wrong_root,
        "invalid_mode": invalid_mode,
        "invalid_origin": invalid_origin,
        "fresh_invalid_mode": fresh_invalid_mode,
        "fresh_invalid_origin": fresh_invalid_origin,
        "digest_mismatch": digest_mismatch,
        "event_conflict": event_conflict,
    }
    inputs = {
        "execution_checkpoint_inputs_format": (
            "determa.execution_checkpoint_profile.inputs"
        ),
        "execution_checkpoint_inputs_schema_version": 1,
        "requests": requests,
    }
    calls = {
        "create": created,
        "create_rejected": rejected_create,
        "increment": increment_result,
        "emit_internal": emit_result,
        "internal_increment": internal_result,
        "unhandled": unhandled_result,
        "rejected": rejected_result,
        "fault": fault_result,
    }
    artifacts = {
        "created-checkpoint.json": checkpoint_created,
        "accepted-checkpoint.json": accepted,
        "processed-checkpoint.json": processed,
        "internal-pending-checkpoint.json": internal_pending,
        "internal-processed-checkpoint.json": internal_processed,
        "unhandled-checkpoint.json": unhandled_checkpoint,
        "rejected-checkpoint.json": rejected_checkpoint,
        "faulted-checkpoint.json": faulted_checkpoint,
    }
    for name, value in artifacts.items():
        write_json(case / name, value)
    write_json(case / "processed-checkpoint.canonical.json", processed, canonical=True)
    write_json(case / "inputs.json", inputs)
    write_json(
        case / "core-results.json",
        generation_record(
            calls,
            requests,
            {
                "create": ("create", "create"),
                "create_rejected": ("create", "create_rejected"),
                "increment": ("dispatch", "process_increment"),
                "emit_internal": ("dispatch", "emit_internal"),
                "internal_increment": ("dispatch", "internal_increment"),
                "unhandled": ("dispatch", "unhandled"),
                "rejected": ("dispatch", "rejected"),
                "fault": ("dispatch", "fault"),
            },
        ),
    )
    invalid_target = copy.deepcopy(accepted)
    invalid_target_envelope = invalid_target["pending_deliveries"][0]["envelope"]
    invalid_target_envelope["target"]["root"]["root_instance_id"] = "another-root"
    invalid_target["pending_deliveries"][0]["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-1",
            "1",
            invalid_target["root_instance_id"],
            invalid_target["pending_deliveries"][0]["delivery_mode"],
            invalid_target_envelope,
        ]
    )
    seal(invalid_target)
    write_json(
        case / "invalid-foreign-target-checkpoint.json",
        invalid_target,
    )
    invalid_gap = copy.deepcopy(faulted_checkpoint)
    invalid_gap["next_delivery_sequence"] = str(
        int(invalid_gap["next_delivery_sequence"]) + 1
    )
    seal(invalid_gap)
    write_json(
        case / "invalid-permanent-delivery-gap-checkpoint.json",
        invalid_gap,
    )
    return {
        "faulted": faulted_checkpoint,
        "inputs": inputs,
        "core_results": calls,
    }


def generate_spawned_checkpoint_trace() -> None:
    case = PROFILE / "checkpoint-05-spawned-host-trace"
    bundle_file = "spawn-machine.yaml"
    bundle = load_bundle((case / bundle_file).read_text(encoding="utf-8"))
    bindings = {"input": {}, "external": {}}
    create_request = {
        "operation": "create",
        **bundle_binding(case, bundle_file, bundle),
        "namespace": bundle.namespace,
        "machine_id": "order",
        "machine_version": "1",
        "root_instance_id": "owned-migration-root",
        "creation_id": "owned-migration-create",
        "bindings": bindings,
    }
    create_request["request_digest"] = creation_digest(
        bundle,
        "order",
        1,
        "owned-migration-root",
        "owned-migration-create",
        bindings,
    )
    created_raw = create(
        bundle,
        "order",
        "owned-migration-root",
        "owned-migration-create",
        bindings,
    )
    created = project_core_result(bundle, created_raw)
    created_checkpoint = empty_checkpoint(
        created["aggregate_state"], create_request["request_digest"], created
    )
    root_target = next(
        runtime["target_identity"]
        for runtime in created["aggregate_state"]["runtimes"]
        if runtime["relation"]["kind"] == "root"
    )
    start_request = with_read(
        delivery_request(
            case=case,
            bundle=bundle,
            bundle_file=bundle_file,
            root_instance_id="owned-migration-root",
            delivery_mode="input",
            origin={"kind": "host_input"},
            event="start",
            event_id="checkpoint-spawn-start",
            target=root_target,
            payload={},
        ),
        created_checkpoint,
    )
    started_raw = dispatch(
        bundle, created_raw["state"], start_request["dispatch_input"]["delivery"]
    )
    started = project_core_result(bundle, started_raw, created_raw["state"])
    started_checkpoint = commit_delivery(
        created_checkpoint, start_request, started, foreground=True
    )
    child_target = next(
        runtime["target_identity"]
        for runtime in started["aggregate_state"]["runtimes"]
        if runtime["relation"]["kind"] == "owned_spawned_instance"
    )
    child_request = with_read(
        delivery_request(
            case=case,
            bundle=bundle,
            bundle_file=bundle_file,
            root_instance_id="owned-migration-root",
            delivery_mode="input",
            origin={"kind": "host_input"},
            event="pay",
            event_id="python-host-spawned-child-pay",
            target=child_target,
            payload={"amount": 100},
        ),
        started_checkpoint,
    )
    child_accepted_checkpoint = accept_delivery(started_checkpoint, child_request)
    requests = {
        "create": create_request,
        "start": start_request,
        "accept_child": child_request,
    }
    write_json(
        case / "inputs.json",
        {
            "execution_checkpoint_inputs_format": (
                "determa.execution_checkpoint_profile.inputs"
            ),
            "execution_checkpoint_inputs_schema_version": 1,
            "requests": requests,
        },
    )
    write_json(
        case / "core-results.json",
        generation_record(
            {"create": created, "start": started},
            requests,
            {"create": ("create", "create"), "start": ("dispatch", "start")},
        ),
    )
    write_json(case / "spawned-created-checkpoint-v1.json", created_checkpoint)
    write_json(case / "spawned-started-checkpoint-v1.json", started_checkpoint)
    write_json(case / "spawned-child-checkpoint-v1.json", child_accepted_checkpoint)


def generate_terminal_spawned_checkpoint_trace() -> None:
    case = PROFILE / "checkpoint-06-terminal-spawned-host-trace"
    bundle_file = "machine.yaml"
    bundle = load_bundle((case / bundle_file).read_text(encoding="utf-8"))
    bindings = {"input": {}, "external": {}}
    create_request = {
        "operation": "create",
        **bundle_binding(case, bundle_file, bundle),
        "namespace": bundle.namespace,
        "machine_id": "order",
        "machine_version": "1",
        "root_instance_id": "terminal-spawn-root",
        "creation_id": "terminal-spawn-create",
        "bindings": bindings,
    }
    create_request["request_digest"] = creation_digest(
        bundle,
        "order",
        1,
        "terminal-spawn-root",
        "terminal-spawn-create",
        bindings,
    )
    created_raw = create(
        bundle,
        "order",
        "terminal-spawn-root",
        "terminal-spawn-create",
        bindings,
    )
    created = project_core_result(bundle, created_raw)
    created_checkpoint = empty_checkpoint(
        created["aggregate_state"], create_request["request_digest"], created
    )
    root_target = next(
        runtime["target_identity"]
        for runtime in created["aggregate_state"]["runtimes"]
        if runtime["relation"]["kind"] == "root"
    )
    start_request = with_read(
        delivery_request(
            case=case,
            bundle=bundle,
            bundle_file=bundle_file,
            root_instance_id="terminal-spawn-root",
            delivery_mode="input",
            origin={"kind": "host_input"},
            event="start",
            event_id="terminal-spawn-start",
            target=root_target,
            payload={},
        ),
        created_checkpoint,
    )
    started_raw = dispatch(
        bundle, created_raw["state"], start_request["dispatch_input"]["delivery"]
    )
    started = project_core_result(bundle, started_raw, created_raw["state"])
    started_checkpoint = commit_delivery(
        created_checkpoint, start_request, started, foreground=True
    )
    child_target = next(
        runtime["target_identity"]
        for runtime in started["aggregate_state"]["runtimes"]
        if runtime["relation"]["kind"] == "owned_spawned_instance"
    )
    child_request = with_read(
        delivery_request(
            case=case,
            bundle=bundle,
            bundle_file=bundle_file,
            root_instance_id="terminal-spawn-root",
            delivery_mode="input",
            origin={"kind": "host_input"},
            event="pay",
            event_id="terminal-spawn-child-pay",
            target=child_target,
            payload={"amount": 100},
        ),
        started_checkpoint,
    )
    child_accepted_checkpoint = accept_delivery(started_checkpoint, child_request)
    process_child_request = copy.deepcopy(child_request)
    process_child_request["expected_revision"] = child_accepted_checkpoint["revision"]
    process_child_request["expected_checkpoint_digest"] = child_accepted_checkpoint[
        "execution_checkpoint_digest"
    ]
    native_child_delivery = copy.deepcopy(
        process_child_request["dispatch_input"]["delivery"]
    )
    native_child_delivery["input"]["target"] = native_target(child_target)
    child_raw = dispatch(
        bundle, started_raw["state"], native_child_delivery
    )
    child = project_core_result(bundle, child_raw, started_raw["state"])
    child_terminal_checkpoint = commit_delivery(
        child_accepted_checkpoint, process_child_request, child, foreground=False
    )
    pending_completion = child_terminal_checkpoint["pending_deliveries"][0]
    completion_request = with_read(
        {
            "operation": "delivery",
            "root_instance_id": "terminal-spawn-root",
            "delivery_mode": "internal",
            "origin": copy.deepcopy(pending_completion["origin"]),
            "envelope": copy.deepcopy(pending_completion["envelope"]),
            "envelope_digest": pending_completion["envelope_digest"],
            "dispatch_input": {
                **bundle_binding(case, bundle_file, bundle),
                "delivery": {
                    "internal": {
                        "event": child_raw["emissions"][0]["event"],
                        "event_id": child_raw["emissions"][0]["event_id"],
                        "target": copy.deepcopy(child_raw["emissions"][0]["target"]),
                        "payload": copy.deepcopy(child_raw["emissions"][0]["payload"]),
                    }
                },
            },
        },
        child_terminal_checkpoint,
    )
    completion_raw = dispatch(
        bundle, child_raw["state"], completion_request["dispatch_input"]["delivery"]
    )
    completion = project_core_result(bundle, completion_raw, child_raw["state"])
    terminal_checkpoint = commit_delivery(
        child_terminal_checkpoint,
        completion_request,
        completion,
        foreground=False,
    )
    requests = {
        "create": create_request,
        "start": start_request,
        "accept_child": child_request,
        "process_child": process_child_request,
        "process_completion": completion_request,
    }
    write_json(
        case / "inputs.json",
        {
            "execution_checkpoint_inputs_format": (
                "determa.execution_checkpoint_profile.inputs"
            ),
            "execution_checkpoint_inputs_schema_version": 1,
            "requests": requests,
        },
    )
    write_json(
        case / "core-results.json",
        generation_record(
            {
                "create": created,
                "start": started,
                "process_child": child,
                "process_completion": completion,
            },
            requests,
            {
                "create": ("create", "create"),
                "start": ("dispatch", "start"),
                "process_child": ("dispatch", "process_child"),
                "process_completion": ("dispatch", "process_completion"),
            },
        ),
    )
    write_json(case / "created-checkpoint-v1.json", created_checkpoint)
    write_json(case / "started-checkpoint-v1.json", started_checkpoint)
    write_json(case / "child-pending-checkpoint-v1.json", child_accepted_checkpoint)
    write_json(
        case / "child-terminal-checkpoint-v1.json", child_terminal_checkpoint
    )
    write_json(case / "terminal-checkpoint-v1.json", terminal_checkpoint)


def generate_outbox() -> None:
    case = PROFILE / "checkpoint-02-outbox-lifecycle"
    bundle_file = "machine.yaml"
    bundle = load_bundle((case / bundle_file).read_text(encoding="utf-8"))
    bindings = {"input": {}, "external": {}}
    create_args = {
        "operation": "create",
        **bundle_binding(case, bundle_file, bundle),
        "namespace": bundle.namespace,
        "machine_id": "emitter",
        "machine_version": "1",
        "root_instance_id": "outbox-root",
        "creation_id": "outbox-create",
        "bindings": bindings,
    }
    create_args["request_digest"] = creation_digest(
        bundle, "emitter", 1, "outbox-root", "outbox-create", bindings
    )
    created_raw = create(
        bundle, "emitter", "outbox-root", "outbox-create", bindings
    )
    created = project_core_result(bundle, created_raw)
    base = empty_checkpoint(
        created["aggregate_state"], create_args["request_digest"], created
    )
    target = {
        "root": {
            "root_instance_id": "outbox-root",
            "root_runtime_id": created["aggregate_state"]["root_runtime_id"],
        }
    }
    emit_base = delivery_request(
        case=case,
        bundle=bundle,
        bundle_file=bundle_file,
        root_instance_id="outbox-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="emit_outputs",
        event_id="outbox-emit-eight",
        target=target,
        payload={"batch_id": "batch"},
    )
    emit = with_read(emit_base, base)
    emit_raw = dispatch(
        bundle, created_raw["state"], emit["dispatch_input"]["delivery"]
    )
    emit_result = project_core_result(bundle, emit_raw, created_raw["state"])
    created_outbox = commit_delivery(base, emit, emit_result, foreground=True)
    effect_ids = [
        item["intent"]["effect_id"]
        for item in created_outbox["pending_outbox_intents"]
    ]
    requests: dict[str, Any] = {
        "create": create_args,
        "emit_outputs": emit,
    }
    current = created_outbox
    retryable = {"status": "retryable_failure", "reason_code": "temporary_unavailable"}
    requests["retryable"] = operation_input(
        current,
        "update_pending_outbox",
        effect_id=effect_ids[0],
        desired_pending_state=retryable,
    )
    current = outbox_pending_update(current, effect_ids[0], retryable)
    retryable_checkpoint = current

    ambiguous = {"status": "ambiguous", "reason_code": "confirmation_unknown"}
    requests["ambiguous"] = operation_input(
        current,
        "update_pending_outbox",
        effect_id=effect_ids[1],
        desired_pending_state=ambiguous,
    )
    current = outbox_pending_update(current, effect_ids[1], ambiguous)
    ambiguous_checkpoint = current

    terminal_operations = [
        ("confirmed", {"status": "confirmed"}),
        (
            "permanently_rejected",
            {"status": "permanently_rejected", "reason_code": "destination_rejected"},
        ),
        (
            "operator_cancelled",
            {"status": "operator_cancelled", "reason_code": "operator_request"},
        ),
        ("discarded", {"status": "discarded", "reason_code": "declared_policy"}),
        ("dead_lettered", {"status": "dead_lettered", "reason_code": "dead_letter"}),
    ]
    intermediate: dict[str, dict[str, Any]] = {}
    for offset, (name, outcome) in enumerate(terminal_operations, start=2):
        requests[name] = operation_input(
            current,
            "terminalize_outbox",
            effect_id=effect_ids[offset],
            terminal_outcome=outcome,
        )
        current = outbox_terminal_update(current, effect_ids[offset], outcome)
        intermediate[name] = current

    total = current
    confirmed_effect = effect_ids[2]
    requests["compact_confirmed"] = operation_input(
        total, "compact_outbox", effect_id=confirmed_effect
    )
    compact = compact_outbox(total, confirmed_effect)
    requests["terminal_conflict"] = operation_input(
        total,
        "terminalize_outbox",
        effect_id=confirmed_effect,
        terminal_outcome={"status": "discarded", "reason_code": "changed_policy"},
    )
    requests["delete_referenced"] = operation_input(
        compact, "delete_outbox_record", effect_id=confirmed_effect
    )
    stale_retryable = copy.deepcopy(requests["retryable"])
    stale_retryable["desired_pending_state"] = {
        "status": "ambiguous",
        "reason_code": "stale_writer",
    }
    stale_retryable["expected_revision"] = base["revision"]
    stale_retryable["expected_checkpoint_digest"] = base[
        "execution_checkpoint_digest"
    ]
    requests["stale_outbox_update"] = stale_retryable
    inputs = {
        "execution_checkpoint_inputs_format": (
            "determa.execution_checkpoint_profile.inputs"
        ),
        "execution_checkpoint_inputs_schema_version": 1,
        "requests": requests,
    }
    calls = {"create": created, "emit_outputs": emit_result}

    write_json(case / "outbox-base-checkpoint.json", base)
    write_json(case / "outbox-created-checkpoint.json", created_outbox)
    write_json(case / "outbox-retryable-checkpoint.json", retryable_checkpoint)
    write_json(case / "outbox-ambiguous-checkpoint.json", ambiguous_checkpoint)
    for name, value in intermediate.items():
        write_json(case / f"outbox-{name}-checkpoint.json", value)
    write_json(case / "outbox-total-checkpoint.json", total)
    write_json(case / "outbox-compact-checkpoint.json", compact)
    write_json(case / "outbox-total-checkpoint.canonical.json", total, canonical=True)
    write_json(case / "inputs.json", inputs)
    write_json(
        case / "core-results.json",
        generation_record(
            calls,
            requests,
            {
                "create": ("create", "create"),
                "emit_outputs": ("dispatch", "emit_outputs"),
            },
        ),
    )

    invalid_dangling = copy.deepcopy(compact)
    invalid_dangling["outbox_effect_tombstones"] = []
    seal(invalid_dangling)
    write_json(case / "invalid-dangling-outbox-checkpoint.json", invalid_dangling)
    invalid_order = copy.deepcopy(total)
    invalid_order["pending_outbox_intents"].reverse()
    seal(invalid_order)
    write_json(case / "invalid-outbox-order-checkpoint.json", invalid_order)
    invalid_intent_digest = copy.deepcopy(compact)
    invalid_intent_digest["outbox_effect_tombstones"][0]["intent_digest"] = (
        "sha256:" + ("4" * 64)
    )
    seal(invalid_intent_digest)
    write_json(
        case / "invalid-compact-intent-digest-checkpoint.json",
        invalid_intent_digest,
    )
    invalid_state_revision = copy.deepcopy(created_outbox)
    invalid_state_revision["pending_outbox_intents"][0]["state_revision"] = "0"
    seal(invalid_state_revision)
    write_json(
        case / "invalid-pending-outbox-revision-checkpoint.json",
        invalid_state_revision,
    )


def generate_retention(delivery: dict[str, Any]) -> None:
    case = PROFILE / "checkpoint-03-retention-and-root-lifecycle"
    bindings = {"input": {}, "external": {}}
    source_bundle = load_bundle(
        (case / "migration-source.yaml").read_text(encoding="utf-8")
    )
    target_bundle = load_bundle(
        (case / "migration-target.yaml").read_text(encoding="utf-8")
    )
    descriptor = {
        "migration_descriptor_format": "determa.aggregate_migration",
        "migration_descriptor_schema_version": 1,
        "source_machine_format": 1,
        "target_machine_format": 1,
        "source_validated_bundle_fingerprint": source_bundle.fingerprint,
        "target_validated_bundle_fingerprint": target_bundle.fingerprint,
        "source_aggregate_shape_fingerprint": aggregate_shape_fingerprint(
            source_bundle
        ),
        "target_aggregate_shape_fingerprint": aggregate_shape_fingerprint(
            target_bundle
        ),
        "mode": "transform",
        "mappings": {
            "machines": [
                {
                    "source_definition_pointer": "/machines/0/root",
                    "target_definition_pointer": "/machines/0/root",
                }
            ],
            "active_states": [
                {
                    "source_leaf_state_definition_pointer": (
                        "/machines/0/root/states/old_state"
                    ),
                    "target_leaf_state_definition_pointers": [
                        "/machines/0/root/states/new_state"
                    ],
                }
            ],
            "variables": [
                {
                    "operation": "copy",
                    "source_declaration_pointer": (
                        "/machines/0/root/variables/old_count"
                    ),
                    "target_declaration_pointer": (
                        "/machines/0/root/variables/new_count"
                    ),
                },
                {
                    "operation": "drop",
                    "source_declaration_pointer": (
                        "/machines/0/root/variables/remove_me"
                    ),
                    "reason": "field removed by the next definition",
                },
                {
                    "operation": "transform",
                    "source_declaration_pointers": [
                        "/machines/0/root/states/old_state/variables/shadow"
                    ],
                    "target_declaration_pointer": (
                        "/machines/0/root/states/new_state/variables/renamed_shadow"
                    ),
                    "expression": "source_0 + 1",
                },
                {
                    "operation": "initialize",
                    "target_declaration_pointer": (
                        "/machines/0/root/variables/added"
                    ),
                    "expression": "true",
                },
            ],
            "history": [
                {
                    "operation": "map",
                    "source_history_declaration_pointer": "/machines/0/root/history",
                    "target_history_declaration_pointer": "/machines/0/root/history",
                    "recorded_state_mappings": [
                        {
                            "source_definition_pointer": (
                                "/machines/0/root/states/old_state"
                            ),
                            "target_definition_pointer": (
                                "/machines/0/root/states/new_state"
                            ),
                        }
                    ],
                }
            ],
            "components": [],
            "owned_runtimes": [],
            "lifetime_holders": [],
            "counters": [
                {
                    "operation": "map",
                    "source_definition_pointer": "/machines/0/root",
                    "target_definition_pointer": "/machines/0/root",
                },
                {
                    "operation": "map",
                    "source_definition_pointer": (
                        "/machines/0/root/states/old_state"
                    ),
                    "target_definition_pointer": (
                        "/machines/0/root/states/new_state"
                    ),
                },
            ],
        },
        "terminal_policy": {
            "completed": "preserve",
            "faulted": "preserve",
        },
        "resource_requirements": {
            "maximum_transformed_output_bytes": "64",
            "maximum_cel_expression_length": "32",
            "maximum_cel_ast_nodes": "32",
            "maximum_cel_evaluation_steps": "64",
        },
    }
    descriptor["migration_descriptor_digest"] = migration_descriptor_digest(
        descriptor
    )
    conflict_descriptor = copy.deepcopy(descriptor)
    conflict_descriptor["resource_requirements"][
        "maximum_cel_evaluation_steps"
    ] = "65"
    conflict_descriptor.pop("migration_descriptor_digest")
    conflict_descriptor["migration_descriptor_digest"] = (
        migration_descriptor_digest(conflict_descriptor)
    )
    create_args = {
        "operation": "create",
        **bundle_binding(case, "migration-source.yaml", source_bundle),
        "namespace": source_bundle.namespace,
        "machine_id": "workflow",
        "machine_version": "1",
        "root_instance_id": "maintenance-root",
        "creation_id": "maintenance-create",
        "bindings": bindings,
    }
    create_args["request_digest"] = creation_digest(
        source_bundle,
        "workflow",
        1,
        "maintenance-root",
        "maintenance-create",
        bindings,
    )
    created_raw = create(
        source_bundle,
        "workflow",
        "maintenance-root",
        "maintenance-create",
        bindings,
    )
    created = project_core_result(source_bundle, created_raw)
    maintenance_created = empty_checkpoint(
        created["aggregate_state"], create_args["request_digest"], created
    )
    resolver = MemoryArtifactResolver(
        definitions={
            source_bundle.fingerprint: source_bundle,
            target_bundle.fingerprint: target_bundle,
        },
        migration_descriptors={
            descriptor["migration_descriptor_digest"]: descriptor
        },
        trusted_definitions=[
            source_bundle.fingerprint,
            target_bundle.fingerprint,
        ],
        trusted_migration_descriptors=[
            descriptor["migration_descriptor_digest"]
        ],
    )
    migration = migrate_aggregate(
        rfc8785.dumps(created["aggregate_state"]),
        target_bundle.fingerprint,
        [descriptor["migration_descriptor_digest"]],
        resolver,
        maintenance_mode=True,
    )
    if not migration.succeeded or migration.aggregate_envelope is None:
        raise RuntimeError("maintenance migration failed")
    maintenance_input = {
        "operation": "maintenance_migration",
        "operation_id": "maintenance-transform",
        "source_aggregate_state_digest": created["aggregate_state"][
            "aggregate_state_digest"
        ],
        "target_bundle_file": "migration-target.yaml",
        "target_bundle_source_digest": hash_bytes(
            (case / "migration-target.yaml").read_bytes()
        ),
        "migration_descriptor_files": ["migration-descriptor.json"],
        "target_validated_bundle_fingerprint": target_bundle.fingerprint,
        "migration_descriptor_digest_route": [
            descriptor["migration_descriptor_digest"]
        ],
        "maintenance_mode": True,
    }
    maintenance_input["request_digest"] = hash_value(
        [
            "determa-maintenance-migration-request-digest-1",
            "1",
            "maintenance-root",
            maintenance_input["operation_id"],
            maintenance_input["source_aggregate_state_digest"],
            target_bundle.fingerprint,
            [descriptor["migration_descriptor_digest"]],
            True,
        ]
    )
    maintenance = mutate(maintenance_created)
    maintenance["next_operation_receipt_sequence"] = "2"
    maintenance["operation_receipts"].append(
        {
            "operation_kind": "maintenance_migration",
            "receipt_sequence": "1",
            "operation_id": maintenance_input["operation_id"],
            "request_digest": maintenance_input["request_digest"],
            "committed_revision": maintenance["revision"],
            "source_aggregate_state_digest": maintenance_input[
                "source_aggregate_state_digest"
            ],
            "resulting_aggregate_state_digest": migration.aggregate_envelope[
                "aggregate_state_digest"
            ],
            "migration_sequences": [
                item["migration_sequence"] for item in migration.audit_records
            ],
            "result_code": "migration_applied",
        }
    )
    maintenance["root_record"]["aggregate_state"] = copy.deepcopy(
        migration.aggregate_envelope
    )
    maintenance["migration_audit_records"] = [
        copy.deepcopy(item) for item in migration.audit_records
    ]
    maintenance = seal(maintenance)
    maintenance_input.update(
        {
            "expected_revision": maintenance_created["revision"],
            "expected_checkpoint_digest": maintenance_created[
                "execution_checkpoint_digest"
            ],
        }
    )
    maintenance_conflict = copy.deepcopy(maintenance_input)
    maintenance_conflict["migration_descriptor_files"] = [
        "migration-descriptor-conflict.json"
    ]
    maintenance_conflict["migration_descriptor_digest_route"] = [
        conflict_descriptor["migration_descriptor_digest"]
    ]
    maintenance_conflict["request_digest"] = hash_value(
        [
            "determa-maintenance-migration-request-digest-1",
            "1",
            "maintenance-root",
            maintenance_conflict["operation_id"],
            maintenance_conflict["source_aggregate_state_digest"],
            maintenance_conflict["target_validated_bundle_fingerprint"],
            maintenance_conflict["migration_descriptor_digest_route"],
            True,
        ]
    )

    dependency = copy.deepcopy(delivery["faulted"])
    bounded = mutate(dependency)
    bounded["replay_retention"] = {
        "mode": "bounded",
        "permanent_replay_eligible": False,
        "pruned_through_receipt_sequence": "1",
        "policy_identifier": "bounded-checkpoint-profile-v1",
    }
    bounded["operation_receipts"] = [
        receipt
        for receipt in bounded["operation_receipts"]
        if receipt["receipt_sequence"] == "0"
        or int(receipt["receipt_sequence"]) > 1
    ]
    bounded = seal(bounded)
    invalid_dependency = copy.deepcopy(bounded)
    invalid_dependency["replay_retention"][
        "pruned_through_receipt_sequence"
    ] = "2"
    invalid_dependency["operation_receipts"] = [
        receipt
        for receipt in invalid_dependency["operation_receipts"]
        if receipt["receipt_sequence"] != "2"
    ]
    seal(invalid_dependency)

    terminal_bundle = load_bundle((case / "terminal.yaml").read_text(encoding="utf-8"))
    terminal_args = {
        "operation": "create",
        **bundle_binding(case, "terminal.yaml", terminal_bundle),
        "namespace": terminal_bundle.namespace,
        "machine_id": "terminal",
        "machine_version": "1",
        "root_instance_id": "terminal-root",
        "creation_id": "terminal-create",
        "bindings": bindings,
    }
    terminal_args["request_digest"] = creation_digest(
        terminal_bundle,
        "terminal",
        1,
        "terminal-root",
        "terminal-create",
        bindings,
    )
    completed_raw = create(
        terminal_bundle,
        "terminal",
        "terminal-root",
        "terminal-create",
        bindings,
    )
    completed_result = project_core_result(terminal_bundle, completed_raw)
    completed = empty_checkpoint(
        completed_result["aggregate_state"],
        terminal_args["request_digest"],
        completed_result,
    )
    tombstone_input = operation_input(
        completed, "tombstone_root", operation_id="terminal-root-tombstone"
    )
    tombstone = mutate(completed)
    aggregate = completed["root_record"]["aggregate_state"]
    tombstone["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": aggregate["root_runtime_id"],
        "creation_id": aggregate["creation_id"],
        "terminal_status": aggregate["runtimes"][0]["status"],
        "final_aggregate_state_digest": aggregate["aggregate_state_digest"],
        "tombstone_operation_id": tombstone_input["operation_id"],
    }
    tombstone = seal(tombstone)
    terminal_target = {
        "root": {
            "root_instance_id": "terminal-root",
            "root_runtime_id": completed_result["aggregate_state"][
                "root_runtime_id"
            ],
        }
    }
    tombstoned_delivery = delivery_request(
        case=case,
        bundle=terminal_bundle,
        bundle_file="terminal.yaml",
        root_instance_id="terminal-root",
        delivery_mode="input",
        origin={"kind": "host_input"},
        event="after_tombstone",
        event_id="after-tombstone",
        target=terminal_target,
        payload={},
    )
    tombstoned_delivery.pop("dispatch_input")
    tombstoned_delivery = with_read(tombstoned_delivery, tombstone)
    recreate = copy.deepcopy(terminal_args)
    recreate["creation_id"] = "replacement-create"
    recreate["request_digest"] = creation_digest(
        terminal_bundle,
        "terminal",
        1,
        "terminal-root",
        "replacement-create",
        bindings,
    )
    recreate["expected_revision"] = tombstone["revision"]
    recreate["expected_checkpoint_digest"] = tombstone[
        "execution_checkpoint_digest"
    ]
    reverse_to_permanent = operation_input(
        bounded,
        "update_replay_retention",
        target_replay_retention={
            "mode": "permanent",
            "permanent_replay_eligible": True,
            "pruned_through_receipt_sequence": None,
            "policy_identifier": None,
        },
    )
    stale_prune = operation_input(
        dependency,
        "update_replay_retention",
        target_replay_retention={
            "mode": "bounded",
            "permanent_replay_eligible": False,
            "pruned_through_receipt_sequence": "1",
            "policy_identifier": "bounded-checkpoint-profile-v1",
        },
    )
    stale_prune["expected_revision"] = "0"
    stale_prune["expected_checkpoint_digest"] = maintenance_created[
        "execution_checkpoint_digest"
    ]
    stale_tombstone = copy.deepcopy(tombstone_input)
    stale_tombstone["operation_id"] = "stale-terminal-root-tombstone"
    stale_tombstone["expected_revision"] = "0"
    stale_tombstone["expected_checkpoint_digest"] = maintenance_created[
        "execution_checkpoint_digest"
    ]

    requests = {
            "create_maintenance": create_args,
            "maintenance": maintenance_input,
            "maintenance_conflict": maintenance_conflict,
            "prune_through_1": operation_input(
                dependency,
                "update_replay_retention",
                target_replay_retention={
                    "mode": "bounded",
                    "permanent_replay_eligible": False,
                    "pruned_through_receipt_sequence": "1",
                    "policy_identifier": "bounded-checkpoint-profile-v1",
                },
            ),
            "prune_through_2_dependency_conflict": operation_input(
                dependency,
                "update_replay_retention",
                target_replay_retention={
                    "mode": "bounded",
                    "permanent_replay_eligible": False,
                    "pruned_through_receipt_sequence": "2",
                    "policy_identifier": "bounded-checkpoint-profile-v1",
                },
            ),
            "stale_prune": stale_prune,
            "reverse_to_permanent": reverse_to_permanent,
            "create_terminal": terminal_args,
            "tombstone": tombstone_input,
            "stale_tombstone": stale_tombstone,
            "recreate_tombstoned": recreate,
            "tombstoned_delivery": tombstoned_delivery,
            "delete_checkpoint": operation_input(
                tombstone, "delete_checkpoint"
            ),
    }
    inputs = {
        "execution_checkpoint_inputs_format": (
            "determa.execution_checkpoint_profile.inputs"
        ),
        "execution_checkpoint_inputs_schema_version": 1,
        "requests": requests,
    }
    calls = {
        "create_maintenance": created,
        "maintenance_migration": {
            "prior_aggregate_state_digest": created["aggregate_state"][
                "aggregate_state_digest"
            ],
            "aggregate_state": migration.aggregate_envelope,
            "audit_records": list(migration.audit_records),
            "failure": None,
        },
        "create_terminal": completed_result,
    }
    write_json(case / "migration-descriptor.json", descriptor)
    write_json(
        case / "migration-descriptor-conflict.json",
        conflict_descriptor,
    )
    write_json(case / "maintenance-created-checkpoint.json", maintenance_created)
    write_json(case / "maintenance-checkpoint.json", maintenance)
    write_json(case / "dependency-checkpoint.json", dependency)
    write_json(case / "bounded-checkpoint.json", bounded)
    write_json(
        case / "invalid-bounded-dependency-checkpoint.json",
        invalid_dependency,
    )
    write_json(case / "completed-checkpoint.json", completed)
    write_json(case / "tombstone-checkpoint.json", tombstone)
    write_json(case / "tombstone-checkpoint.canonical.json", tombstone, canonical=True)
    write_json(case / "inputs.json", inputs)
    write_json(
        case / "core-results.json",
        generation_record(
            calls,
            requests,
            {
                "create_maintenance": ("create", "create_maintenance"),
                "maintenance_migration": ("migrate", "maintenance"),
                "create_terminal": ("create", "create_terminal"),
            },
        ),
    )

    invalid_schema = copy.deepcopy(maintenance_created)
    invalid_schema["unexpected"] = True
    seal(invalid_schema)
    write_json(case / "invalid-schema-checkpoint.json", invalid_schema)
    unsupported_format = copy.deepcopy(maintenance_created)
    unsupported_format["execution_checkpoint_format"] = "unknown"
    seal(unsupported_format)
    write_json(case / "unsupported-format-checkpoint.json", unsupported_format)
    unsupported_version = copy.deepcopy(maintenance_created)
    unsupported_version["execution_checkpoint_schema_version"] = 2
    seal(unsupported_version)
    write_json(case / "unsupported-version-checkpoint.json", unsupported_version)
    digest_mismatch = copy.deepcopy(maintenance_created)
    digest_mismatch["execution_checkpoint_digest"] = "sha256:" + ("0" * 64)
    write_json(case / "digest-mismatch-checkpoint.json", digest_mismatch)

    unrelated_tombstone = copy.deepcopy(tombstone)
    unrelated_tombstone["root_record"]["final_aggregate_state_digest"] = (
        "sha256:" + ("5" * 64)
    )
    seal(unrelated_tombstone)
    write_json(
        case / "invalid-unrelated-tombstone-digest-checkpoint.json",
        unrelated_tombstone,
    )


def generate_store_scope() -> None:
    case = PROFILE / "checkpoint-02-outbox-lifecycle"
    source_files = (
        "outbox-created-checkpoint.json",
        "outbox-retryable-checkpoint.json",
    )
    checkpoints: dict[str, dict[str, Any]] = {}
    outbox_records: dict[str, list[dict[str, Any]]] = {}
    for filename in source_files:
        source = case / filename
        document = json.loads(source.read_text(encoding="utf-8"))
        checkpoints[filename] = {
            "file": filename,
            "serialization_digest": hash_value(document),
            "execution_checkpoint_digest": document[
                "execution_checkpoint_digest"
            ],
        }
        records = [
            ("pending", item)
            for item in document["pending_outbox_intents"]
        ] + [
            ("terminal", item)
            for item in document["terminal_outbox_records"]
        ] + [
            ("tombstone", item)
            for item in document["outbox_effect_tombstones"]
        ]
        outbox_records[filename] = [
            {
                "effect_id": (
                    record["effect_id"]
                    if kind == "tombstone"
                    else record["intent"]["effect_id"]
                ),
                "record_kind": kind,
                "source_digest": hash_value(record),
            }
            for kind, record in records
        ]

    def scope(
        identifier: str,
        outbox_checkpoint: str,
    ) -> dict[str, Any]:
        return {
            "logical_scope_id": identifier,
            "physical_isolation_key": f"physical-isolation-{identifier}",
            "checkpoints": {
                "outbox-root": checkpoints[outbox_checkpoint]
            },
            "outbox_records": outbox_records[outbox_checkpoint],
        }

    def state(
        a_checkpoint: str,
        b_checkpoint: str,
    ) -> dict[str, Any]:
        return {
            "physical_backend_id": "shared-physical-backend",
            "scopes": [
                scope("scope-a", a_checkpoint),
                scope("scope-b", b_checkpoint),
            ],
        }

    snapshots = {
        "scope-base.json": state(
            "outbox-created-checkpoint.json", "outbox-created-checkpoint.json"
        ),
        "scope-updated-a.json": state(
            "outbox-retryable-checkpoint.json",
            "outbox-created-checkpoint.json",
        ),
        "scope-updated-b.json": state(
            "outbox-retryable-checkpoint.json",
            "outbox-retryable-checkpoint.json",
        ),
    }
    write_json(
        case / "scope-states.json",
        {
            "execution_store_scope_state_format": (
                "determa.execution_checkpoint_profile.store_scope_state"
            ),
            "execution_store_scope_state_schema_version": 1,
            "snapshots": {
                filename.removeprefix("scope-").removesuffix(".json"): document
                for filename, document in snapshots.items()
            },
        },
    )


def verify_creation_owned_work_host_traces() -> None:
    from generate_version2_vectors import upgrade_checkpoint

    case = PROFILE / "checkpoint-04-version2-mailboxes"
    bundle_file = "creation-owned-work-machine.yaml"
    bundle = load_bundle((case / bundle_file).read_text(encoding="utf-8"))
    bindings = {"input": {}, "external": {}}
    for machine_id, kind in (
        ("internal_creator", "internal"),
        ("external_creator", "external"),
    ):
        root_instance_id = f"{kind}-creation-root"
        creation_id = f"{kind}-creation"
        created_raw = create(
            bundle,
            machine_id,
            root_instance_id,
            creation_id,
            bindings,
        )
        created = project_core_result(bundle, created_raw)
        checkpoint = empty_checkpoint(
            created["aggregate_state"],
            creation_digest(
                bundle,
                machine_id,
                1,
                root_instance_id,
                creation_id,
                bindings,
            ),
            created,
        )
        checkpoint["replay_retention"] = {
            "mode": "bounded",
            "permanent_replay_eligible": False,
            "pruned_through_receipt_sequence": None,
            "policy_identifier": "bounded-test-v1",
        }
        checkpoint = seal(checkpoint)
        target = {
            "root": {
                "root_instance_id": root_instance_id,
                "root_runtime_id": created["aggregate_state"]["root_runtime_id"],
            }
        }
        request = delivery_request(
            case=case,
            bundle=bundle,
            bundle_file=bundle_file,
            root_instance_id=root_instance_id,
            delivery_mode="input",
            origin={"kind": "host_input"},
            event="increment",
            event_id="creation-unrelated",
            target=target,
            payload={},
        )
        dispatched_raw = dispatch(
            bundle,
            created_raw["state"],
            request["dispatch_input"]["delivery"],
        )
        dispatched = project_core_result(
            bundle, dispatched_raw, created_raw["state"]
        )
        checkpoint = commit_delivery(
            checkpoint, request, dispatched, foreground=True
        )
        source_path = (
            case / f"creation-{kind}-host-history-checkpoint-v1.json"
        )
        source = json.loads(source_path.read_text(encoding="utf-8"))
        if source != checkpoint:
            raise SystemExit(
                f"creation-owned {kind} version-1 host trace differs from "
                "pinned engine execution"
            )
        upgraded_path = case / f"creation-{kind}-before-prune-checkpoint-v2.json"
        upgraded = json.loads(upgraded_path.read_text(encoding="utf-8"))
        if upgraded != upgrade_checkpoint(source):
            raise SystemExit(
                f"creation-owned {kind} version-2 checkpoint is not the exact "
                "upgrade of the pinned engine trace"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generation changes checked artifacts",
    )
    args = parser.parse_args()
    if args.check:
        verify_imported_python_checkout()
    before = {
        path: path.read_bytes()
        for path in PROFILE.rglob("*.json")
        if path.is_file()
    }
    delivery = generate_delivery()
    generate_spawned_checkpoint_trace()
    generate_terminal_spawned_checkpoint_trace()
    generate_outbox()
    generate_retention(delivery)
    generate_store_scope()
    if args.check:
        verify_creation_owned_work_host_traces()
        changed = [
            str(path.relative_to(ROOT))
            for path in sorted(before)
            if path.read_bytes() != before[path]
        ]
        created = [
            str(path.relative_to(ROOT))
            for path in sorted(PROFILE.rglob("*.json"))
            if path not in before
        ]
        if changed or created:
            raise SystemExit(
                "generated artifacts differ: " + ", ".join(changed + created)
            )


if __name__ == "__main__":
    main()
