#!/usr/bin/env python3
"""Generate deterministic schema-v2 durable host profile artifacts."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import rfc8785

from generate_version2_vectors import (
    bundle_binding,
    bytes_digest,
    digest,
    native_v2_checkpoint,
    seal_aggregate,
    seal_checkpoint,
    typed_value,
)


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance" / "profiles"


def write_json(path: Path, value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def request_document(requests: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "durable_host_inputs_format": "determa.durable_host.inputs",
        "durable_host_inputs_schema_version": 2,
        "requests": requests,
    }


def result_document(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "durable_host_results_format": "determa.durable_host.results",
        "durable_host_results_schema_version": 2,
        "results": results,
    }


def request(
    operation: str,
    request_id: str,
    *,
    checkpoint: dict[str, Any] | None = None,
    parameters: dict[str, Any] | None = None,
    target_fingerprint: str | None = None,
    descriptor_route: list[str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "operation": operation,
        "request_id": request_id,
        "parameters": parameters or {},
    }
    if checkpoint is not None:
        value["expected_revision"] = checkpoint["revision"]
        value["expected_checkpoint_digest"] = checkpoint[
            "execution_checkpoint_digest"
        ]
    if target_fingerprint is not None:
        value["target_validated_bundle_fingerprint"] = target_fingerprint
    if descriptor_route is not None:
        value["migration_descriptor_digest_route"] = descriptor_route
    return value


def result(
    outcome: str,
    mutation: str,
    core_calls: int,
    *,
    acknowledged: bool = False,
    code: str | None = None,
) -> dict[str, Any]:
    value = {
        "result": outcome,
        "mutation": mutation,
        "core_calls": core_calls,
        "broker_acknowledged": acknowledged,
    }
    if code is not None:
        value["code"] = code
    return value


def create_checkpoint(case: Path, root_id: str, creation_id: str) -> dict[str, Any]:
    machine = case / "machine.yaml"
    return native_v2_checkpoint(
        machine,
        {
            "operation": "create_v2",
            "bundle": bundle_binding(machine),
            "machine_id": "counter",
            "machine_version": "1",
            "root_instance_id": root_id,
            "creation_id": creation_id,
            "bindings": {"input": {}, "external": {}},
        },
    )


def root_runtime(checkpoint: dict[str, Any]) -> dict[str, Any]:
    aggregate = checkpoint["root_record"]["aggregate_state"]
    return next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["relation"]["kind"] == "root"
    )


def envelope_for(
    checkpoint: dict[str, Any], event: str, event_id: str, payload: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    aggregate = checkpoint["root_record"]["aggregate_state"]
    runtime = root_runtime(checkpoint)
    envelope = {
        "event": event,
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": True},
        "target": copy.deepcopy(runtime["target_identity"]),
        "payload": typed_value(payload),
    }
    request_digest = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            aggregate["root_instance_id"],
            "input",
            envelope,
        ]
    )
    return envelope, request_digest


def admit(
    checkpoint: dict[str, Any], event: str, event_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    runtime = root_runtime(value)
    envelope, request_digest = envelope_for(value, event, event_id, payload)
    acceptance_sequence = aggregate["next_acceptance_sequence"]
    queue_sequence = aggregate["next_queue_sequence"]
    aggregate["next_acceptance_sequence"] = str(int(acceptance_sequence) + 1)
    aggregate["next_queue_sequence"] = str(int(queue_sequence) + 1)
    runtime["ready_mailbox"].append(
        {
            "envelope": envelope,
            "envelope_digest": request_digest,
            "delivery_mode": "input",
            "acceptance_sequence": acceptance_sequence,
            "queue_sequence": queue_sequence,
            "deferral_count": "0",
        }
    )
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    value["operation_receipts"].append(
        {
            "operation_kind": "acceptance",
            "receipt_sequence": receipt_sequence,
            "event_id": event_id,
            "request_digest": request_digest,
            "acceptance_sequence": acceptance_sequence,
            "accepted_revision": value["revision"],
            "delivery_mode": "input",
        }
    )
    value["root_record"]["aggregate_state"] = seal_aggregate(aggregate)
    return seal_checkpoint(value)


def process(
    checkpoint: dict[str, Any], *, output_count: int = 0
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    runtime = root_runtime(value)
    entry = runtime["ready_mailbox"].pop(0)
    aggregate["next_logical_step_sequence"] = str(
        int(aggregate["next_logical_step_sequence"]) + 1
    )
    if entry["envelope"]["event"] == "increment":
        amount = dict(entry["envelope"]["payload"][1])["amount"][1]
        count = next(
            item
            for item in runtime["variables"]
            if item["variable_declaration_pointer"].endswith("/count")
        )
        count["value"] = ["integer", str(int(count["value"][1]) + int(amount))]
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    references = []
    for index in range(output_count):
        sequence = aggregate["next_output_sequence"]
        aggregate["next_output_sequence"] = str(int(sequence) + 1)
        intent = {
            "effect_id": digest(
                [
                    "determa-effect-identity-2",
                    aggregate["root_instance_id"],
                    receipt_sequence,
                    str(index),
                ]
            ),
            "sequence": sequence,
            "event": "output_record",
            "payload": typed_value({"index": index}),
            "correlation_id": f"batch-{index}",
        }
        value["pending_outbox_intents"].append(
            {
                "intent": intent,
                "state_revision": value["revision"],
                "delivery_state": {"status": "not_attempted"},
            }
        )
        references.append(
            {
                "kind": "external_outbox",
                "emission_index": str(index),
                "effect_id": intent["effect_id"],
            }
        )
    aggregate = seal_aggregate(aggregate)
    value["root_record"]["aggregate_state"] = aggregate
    value["operation_receipts"].append(
        {
            "operation_kind": "event_terminal",
            "receipt_sequence": receipt_sequence,
            "event_id": entry["envelope"]["event_id"],
            "request_digest": entry["envelope_digest"],
            "acceptance_sequence": entry["acceptance_sequence"],
            "final_queue_sequence": entry["queue_sequence"],
            "committed_revision": value["revision"],
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "outcome": {
                "disposition": "handled",
                "status": runtime["status"],
                "fault": None,
                "rejection": None,
            },
            "emission_references": references,
        }
    )
    return seal_checkpoint(value)


def update_pending(
    checkpoint: dict[str, Any], index: int, status: str
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    value["revision"] = str(int(value["revision"]) + 1)
    record = value["pending_outbox_intents"][index]
    record["state_revision"] = value["revision"]
    record["delivery_state"] = {
        "status": status,
        "reason_code": f"{status}_reported",
    }
    return seal_checkpoint(value)


def terminalize(
    checkpoint: dict[str, Any], index: int, status: str
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    value["revision"] = str(int(value["revision"]) + 1)
    pending = value["pending_outbox_intents"].pop(index)
    terminal_sequence = value["next_outbox_terminal_sequence"]
    value["next_outbox_terminal_sequence"] = str(int(terminal_sequence) + 1)
    outcome: dict[str, Any] = {"status": status}
    if status != "confirmed":
        outcome["reason_code"] = f"{status}_policy"
    value["terminal_outbox_records"].append(
        {
            "terminal_sequence": terminal_sequence,
            "intent": pending["intent"],
            "committed_revision": value["revision"],
            "outcome": outcome,
        }
    )
    return seal_checkpoint(value)


def compact(checkpoint: dict[str, Any], index: int) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    value["revision"] = str(int(value["revision"]) + 1)
    record = value["terminal_outbox_records"].pop(index)
    value["outbox_effect_tombstones"].append(
        {
            "terminal_sequence": record["terminal_sequence"],
            "effect_id": record["intent"]["effect_id"],
            "intent_digest": digest(
                [
                    "determa-outbox-intent-digest-2",
                    "2",
                    value["root_instance_id"],
                    record["intent"],
                ]
            ),
            "committed_revision": record["committed_revision"],
            "outcome": record["outcome"],
        }
    )
    return seal_checkpoint(value)


def prune(checkpoint: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    acceptance = value["operation_receipts"][1]
    terminal = value["operation_receipts"][2]
    value["operation_receipts"] = [value["operation_receipts"][0]]
    value["event_identity_tombstones"] = [
        {
            "event_id": terminal["event_id"],
            "request_digest": terminal["request_digest"],
            "request_digest_domain": "determa-inbox-envelope-digest-2",
            "acceptance_sequence": acceptance["acceptance_sequence"],
            "terminal_receipt_sequence": terminal["receipt_sequence"],
            "terminal_disposition": terminal["outcome"]["disposition"],
        }
    ]
    value["replay_retention"] = {
        "mode": "bounded",
        "permanent_replay_eligible": False,
        "pruned_through_receipt_sequence": terminal["receipt_sequence"],
        "policy_identifier": "bounded-native-v2",
    }
    value["revision"] = str(int(value["revision"]) + 1)
    return seal_checkpoint(value)


def tombstone(checkpoint: dict[str, Any], operation_id: str) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    runtime = root_runtime(value)
    runtime["status"] = "completed"
    runtime["active_leaf_state_definition_pointers"] = []
    runtime["active_state_activations"] = []
    aggregate = seal_aggregate(aggregate)
    value["revision"] = str(int(value["revision"]) + 1)
    value["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": aggregate["root_runtime_id"],
        "creation_id": aggregate["creation_id"],
        "terminal_status": "completed",
        "final_aggregate_state_digest": aggregate["aggregate_state_digest"],
        "tombstone_operation_id": operation_id,
    }
    return seal_checkpoint(value)


def generate_delivery() -> dict[Path, bytes]:
    case = PROFILE / "execution-checkpoint" / "checkpoint-01-native-lifecycle"
    created = create_checkpoint(case, "checkpoint-lifecycle-root", "checkpoint-lifecycle-create")
    accepted = admit(created, "increment", "delivery-increment", {"amount": 2})
    processed = process(accepted)
    inputs = request_document(
        {
            "create": request("checkpoint_create_v2", "create"),
            "create_replay": request("checkpoint_replay_v2", "create", checkpoint=created),
            "create_conflict": request("checkpoint_create_v2", "different-create", checkpoint=created),
            "accept": request("checkpoint_admit_v2", "delivery-increment", checkpoint=created),
            "accept_replay": request("checkpoint_replay_v2", "delivery-increment", checkpoint=processed),
            "process": request("checkpoint_step_v2", "process-delivery", checkpoint=accepted),
            "process_crash": request("checkpoint_step_v2", "process-crash", checkpoint=accepted),
            "stale_process": request("checkpoint_step_v2", "stale-process", checkpoint=created),
            "malformed": request("checkpoint_admit_v2", "malformed", checkpoint=processed),
            "wrong_root": request("checkpoint_admit_v2", "wrong-root", checkpoint=processed),
            "event_conflict": request("checkpoint_admit_v2", "delivery-increment", checkpoint=processed, parameters={"payload": {"amount": 9}}),
        }
    )
    results = result_document(
        {
            "committed": result("committed", "atomic", 1, acknowledged=True),
            "replayed": result("replayed", "none", 0, acknowledged=True),
            "creation_conflict": result("rejected", "none", 0, code="creation_id_conflict"),
            "crash": result("crashed", "none", 1, code="injected_pre_commit_failure"),
            "stale": result("rejected", "none", 0, code="checkpoint_revision_conflict"),
            "malformed": result("rejected", "none", 0, code="malformed_delivery"),
            "wrong_root": result("rejected", "none", 0, code="wrong_root"),
            "event_conflict": result("rejected", "none", 0, code="event_id_conflict"),
        }
    )
    return {
        case / "created-checkpoint-v2.json": write_json(case / "x", created),
        case / "accepted-checkpoint-v2.json": write_json(case / "x", accepted),
        case / "processed-checkpoint-v2.json": write_json(case / "x", processed),
        case / "inputs-v2.json": write_json(case / "x", inputs),
        case / "results-v2.json": write_json(case / "x", results),
    }


def generate_outbox() -> dict[Path, bytes]:
    case = PROFILE / "execution-checkpoint" / "checkpoint-02-native-outbox"
    created = create_checkpoint(case, "checkpoint-outbox-root", "checkpoint-outbox-create")
    admitted = admit(created, "emit_outputs", "delivery-outputs", {"batch_id": "batch"})
    pending = process(admitted, output_count=5)
    retryable = update_pending(pending, 0, "retryable_failure")
    ambiguous = update_pending(retryable, 1, "ambiguous")
    statuses = ["confirmed", "permanently_rejected", "operator_cancelled", "discarded", "dead_lettered"]
    terminal = ambiguous
    for status in statuses:
        terminal = terminalize(terminal, 0, status)
    compacted = compact(terminal, 0)
    inputs = request_document(
        {
            "pending": request("checkpoint_step_v2", "emit-outputs", checkpoint=admitted),
            "retryable": request("checkpoint_update_outbox_v2", "retryable", checkpoint=pending),
            "retryable_replay": request("checkpoint_replay_v2", "retryable", checkpoint=retryable),
            "ambiguous": request("checkpoint_update_outbox_v2", "ambiguous", checkpoint=retryable),
            "terminal": request("checkpoint_terminalize_outbox_v2", "terminalize", checkpoint=ambiguous),
            "terminal_replay": request("checkpoint_replay_v2", "terminalize", checkpoint=terminal),
            "conflict": request("checkpoint_terminalize_outbox_v2", "terminalize-conflict", checkpoint=terminal),
            "compact": request("checkpoint_compact_outbox_v2", "compact", checkpoint=terminal),
            "delete": request("checkpoint_compact_outbox_v2", "delete", checkpoint=compacted),
        }
    )
    results = result_document(
        {
            "committed": result("committed", "atomic", 0),
            "replayed": result("replayed", "none", 0),
            "conflict": result("rejected", "none", 0, code="effect_id_conflict"),
            "deletion_rejected": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
        }
    )
    return {
        case / "pending-checkpoint-v2.json": write_json(case / "x", pending),
        case / "retryable-checkpoint-v2.json": write_json(case / "x", retryable),
        case / "ambiguous-checkpoint-v2.json": write_json(case / "x", ambiguous),
        case / "terminal-checkpoint-v2.json": write_json(case / "x", terminal),
        case / "effect-tombstone-checkpoint-v2.json": write_json(case / "x", compacted),
        case / "inputs-v2.json": write_json(case / "x", inputs),
        case / "results-v2.json": write_json(case / "x", results),
    }


def generate_retention() -> dict[Path, bytes]:
    case = PROFILE / "execution-checkpoint" / "checkpoint-03-native-retention"
    created = create_checkpoint(case, "checkpoint-retention-root", "checkpoint-retention-create")
    accepted = admit(created, "increment", "retention-event", {"amount": 1})
    processed = process(accepted)
    bounded = prune(processed)
    tombstoned = tombstone(bounded, "root-tombstone")
    operations = {
        "prune": request("checkpoint_prune_v2", "prune", checkpoint=processed),
        "prune_replay": request("checkpoint_replay_v2", "prune", checkpoint=bounded),
        "prune_lower": request("checkpoint_prune_v2", "prune-lower", checkpoint=bounded),
        "prune_stale": request("checkpoint_prune_v2", "prune-stale", checkpoint=processed),
        "tombstone": request("checkpoint_tombstone_v2", "root-tombstone", checkpoint=bounded),
        "tombstone_replay": request("checkpoint_replay_v2", "root-tombstone", checkpoint=tombstoned),
        "reuse": request("checkpoint_create_v2", "reuse", checkpoint=tombstoned),
        "delete": request("checkpoint_tombstone_v2", "delete", checkpoint=tombstoned),
        "resolve_adapter": request("checkpoint_resolve_adapter_v2", "resolve-adapter", parameters={"adapter": "sqlite"}),
        "validate_capabilities": request("checkpoint_validate_capabilities_v2", "validate-capabilities", parameters={"profile": "durable_embedded"}),
        "scope": request("checkpoint_scope_operation_v2", "scope", checkpoint=created, parameters={"scope": "scope-a"}),
    }
    results = result_document(
        {
            "committed": result("committed", "atomic", 0),
            "replayed": result("replayed", "none", 0),
            "invalid_cutoff": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
            "stale": result("rejected", "none", 0, code="checkpoint_revision_conflict"),
            "no_reuse": result("rejected", "none", 0, code="creation_id_conflict"),
            "deletion_unsupported": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
            "validated": result("validated", "none", 0),
            "scope_rejected": result("rejected", "none", 0, code="invalid_store_scope"),
        }
    )
    return {
        case / "processed-checkpoint-v2.json": write_json(case / "x", processed),
        case / "bounded-checkpoint-v2.json": write_json(case / "x", bounded),
        case / "root-tombstone-checkpoint-v2.json": write_json(case / "x", tombstoned),
        case / "created-checkpoint-v2.json": write_json(case / "x", created),
        case / "inputs-v2.json": write_json(case / "x", request_document(operations)),
        case / "results-v2.json": write_json(case / "x", results),
    }


def checkpoint_from_aggregate(
    aggregate: dict[str, Any], *, creation_digest: str
) -> dict[str, Any]:
    root = next(item for item in aggregate["runtimes"] if item["relation"]["kind"] == "root")
    return seal_checkpoint(
        {
            "execution_checkpoint_format": "determa.execution_checkpoint",
            "execution_checkpoint_schema_version": 2,
            "root_instance_id": aggregate["root_instance_id"],
            "revision": "0",
            "root_record": {"status": "retained", "aggregate_state": aggregate},
            "replay_retention": {"mode": "permanent", "permanent_replay_eligible": True, "pruned_through_receipt_sequence": None, "policy_identifier": None},
            "next_operation_receipt_sequence": "1",
            "operation_receipts": [{"operation_kind": "creation", "receipt_sequence": "0", "creation_id": aggregate["creation_id"], "request_digest": creation_digest, "committed_revision": "0", "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"], "status": root["status"], "fault": root["fault"], "emission_references": []}],
            "event_identity_tombstones": [],
            "pending_outbox_intents": [],
            "next_outbox_terminal_sequence": "0",
            "terminal_outbox_records": [],
            "outbox_effect_tombstones": [],
            "migration_audit_records": [],
        }
    )


def add_existing_acceptance(
    checkpoint: dict[str, Any], entry: dict[str, Any]
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    event_id = entry["envelope"]["event_id"]
    target_runtime = next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["target_identity"] == entry["envelope"]["target"]
    )
    target_runtime["ready_mailbox"].append(copy.deepcopy(entry))
    aggregate["next_acceptance_sequence"] = str(
        max(int(aggregate["next_acceptance_sequence"]), int(entry["acceptance_sequence"]) + 1)
    )
    aggregate["next_queue_sequence"] = str(
        max(int(aggregate["next_queue_sequence"]), int(entry["queue_sequence"]) + 1)
    )
    value["root_record"]["aggregate_state"] = seal_aggregate(aggregate)
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    value["operation_receipts"].append({"operation_kind": "acceptance", "receipt_sequence": receipt_sequence, "event_id": event_id, "request_digest": entry["envelope_digest"], "acceptance_sequence": entry["acceptance_sequence"], "accepted_revision": value["revision"], "delivery_mode": "input"})
    return seal_checkpoint(value)


def host_mailbox_entry(
    checkpoint: dict[str, Any],
    *,
    target: dict[str, Any],
    event: str,
    event_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    aggregate = checkpoint["root_record"]["aggregate_state"]
    acceptance_sequence = aggregate["next_acceptance_sequence"]
    queue_sequence = aggregate["next_queue_sequence"]
    envelope = {
        "event": event,
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": True},
        "target": copy.deepcopy(target),
        "payload": typed_value(payload),
    }
    return {
        "envelope": envelope,
        "envelope_digest": digest(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                aggregate["root_instance_id"],
                "input",
                envelope,
            ]
        ),
        "delivery_mode": "input",
        "acceptance_sequence": acceptance_sequence,
        "queue_sequence": queue_sequence,
        "deferral_count": "0",
    }


def finish_spawned_event(
    checkpoint: dict[str, Any], event_id: str, *, complete_target: bool
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    target_runtime = None
    entry = None
    for runtime in aggregate["runtimes"]:
        for candidate in runtime["ready_mailbox"]:
            if candidate["envelope"]["event_id"] == event_id:
                target_runtime = runtime
                entry = candidate
                break
    if target_runtime is None or entry is None:
        raise RuntimeError(f"missing spawned trace event {event_id}")
    target_runtime["ready_mailbox"].remove(entry)
    if complete_target:
        target_runtime["status"] = "completed"
        target_runtime["active_leaf_state_definition_pointers"] = []
        target_runtime["active_state_activations"] = []
    aggregate["next_logical_step_sequence"] = str(
        int(aggregate["next_logical_step_sequence"]) + 1
    )
    aggregate = seal_aggregate(aggregate)
    value["root_record"]["aggregate_state"] = aggregate
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    value["operation_receipts"].append(
        {
            "operation_kind": "event_terminal",
            "receipt_sequence": receipt_sequence,
            "event_id": event_id,
            "request_digest": entry["envelope_digest"],
            "acceptance_sequence": entry["acceptance_sequence"],
            "final_queue_sequence": entry["queue_sequence"],
            "committed_revision": value["revision"],
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "outcome": {
                "disposition": "handled",
                "status": target_runtime["status"],
                "fault": None,
                "rejection": None,
            },
            "emission_references": [],
        }
    )
    return seal_checkpoint(value)


def generate_spawned(terminal: bool) -> dict[Path, bytes]:
    name = "checkpoint-06-terminal-spawned-host-trace" if terminal else "checkpoint-05-spawned-host-trace"
    case = PROFILE / "execution-checkpoint" / name
    source = ROOT / "conformance" / "core" / "117-version2-mailboxes" / "spawn-isolation-aggregate.json"
    spawned_aggregate = json.loads(source.read_text(encoding="utf-8"))
    for runtime in spawned_aggregate["runtimes"]:
        runtime["ready_mailbox"] = []
        runtime["deferred_mailbox"] = []
    spawned_aggregate["next_acceptance_sequence"] = "1"
    spawned_aggregate["next_queue_sequence"] = "1"
    spawned_aggregate = seal_aggregate(spawned_aggregate)
    machine = case / "machine.yaml"
    base = native_v2_checkpoint(
        machine,
        {
            "operation": "create_v2",
            "bundle": bundle_binding(machine),
            "machine_id": "order",
            "machine_version": "1",
            "root_instance_id": "owned-migration-root",
            "creation_id": "owned-migration-create",
            "bindings": {"input": {}, "external": {}},
        },
    )
    start_pending = admit(base, "start", "spawn-start", {})
    started = copy.deepcopy(start_pending)
    start_entry = root_runtime(started)["ready_mailbox"][0]
    started["root_record"]["aggregate_state"] = spawned_aggregate
    started["revision"] = str(int(started["revision"]) + 1)
    receipt_sequence = started["next_operation_receipt_sequence"]
    started["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    started["operation_receipts"].append(
        {
            "operation_kind": "event_terminal",
            "receipt_sequence": receipt_sequence,
            "event_id": start_entry["envelope"]["event_id"],
            "request_digest": start_entry["envelope_digest"],
            "acceptance_sequence": start_entry["acceptance_sequence"],
            "final_queue_sequence": start_entry["queue_sequence"],
            "committed_revision": started["revision"],
            "resulting_aggregate_state_digest": spawned_aggregate["aggregate_state_digest"],
            "outcome": {"disposition": "handled", "status": "running", "fault": None, "rejection": None},
            "emission_references": [],
        }
    )
    started = seal_checkpoint(started)
    spawned_runtime = next(
        runtime
        for runtime in spawned_aggregate["runtimes"]
        if runtime["relation"]["kind"] == "owned_spawned_instance"
    )
    child_entry = host_mailbox_entry(
        started,
        target=spawned_runtime["target_identity"],
        event="pay",
        event_id="spawned-pay",
        payload={"amount": 100},
    )
    child_pending = add_existing_acceptance(started, child_entry)
    root_entry = host_mailbox_entry(
        child_pending,
        target=root_runtime(child_pending)["target_identity"],
        event="start",
        event_id="spawned-root-followup",
        payload={},
    )
    root_pending = add_existing_acceptance(child_pending, root_entry)
    child_terminal = finish_spawned_event(
        root_pending, "spawned-pay", complete_target=True
    )
    final = finish_spawned_event(
        child_terminal, "spawned-root-followup", complete_target=terminal
    )
    if terminal:
        final_root = root_runtime(final)
        if final_root["status"] != "completed":
            raise RuntimeError("terminal spawned trace did not complete the root")
    inputs = request_document(
        {
            "create": request("checkpoint_create_v2", f"{name}-create"),
            "start_accept": request("checkpoint_admit_v2", "spawn-start", checkpoint=base),
            "start_process": request("checkpoint_step_v2", f"{name}-start", checkpoint=start_pending),
            "child_accept": request("checkpoint_admit_v2", "spawned-pay", checkpoint=started),
            "root_accept": request("checkpoint_admit_v2", "spawned-root-followup", checkpoint=child_pending),
            "child_process": request("checkpoint_step_v2", f"{name}-child-process", checkpoint=root_pending),
            "root_process": request("checkpoint_step_v2", f"{name}-root-process", checkpoint=child_terminal),
        }
    )
    results = result_document({"committed": result("committed", "atomic", 1)})
    output = {
        case / "spawned-base-checkpoint-v2.json": write_json(case / "x", base),
        case / "spawned-start-pending-checkpoint-v2.json": write_json(case / "x", start_pending),
        case / "spawned-started-checkpoint-v2.json": write_json(case / "x", started),
        case / "spawned-child-pending-checkpoint-v2.json": write_json(case / "x", child_pending),
        case / "spawned-root-pending-checkpoint-v2.json": write_json(case / "x", root_pending),
        case / "spawned-child-terminal-checkpoint-v2.json": write_json(case / "x", child_terminal),
        case / "inputs-v2.json": write_json(case / "x", inputs),
        case / "results-v2.json": write_json(case / "x", results),
    }
    if terminal:
        output[case / "spawned-terminal-checkpoint-v2.json"] = write_json(case / "x", final)
    return output


def store(checkpoint: dict[str, Any], *, inbox: list[dict[str, Any]] | None = None, application_rows: dict[str, Any] | None = None, quarantine: dict[str, Any] | None = None, acknowledged: bool = False) -> dict[str, Any]:
    return {
        "durable_host_store_format": "determa.durable_host.store",
        "durable_host_store_schema_version": 2,
        "checkpoint": checkpoint,
        "inbox": inbox or [],
        "application_rows": application_rows or {},
        "quarantine": quarantine,
        "broker_acknowledged": acknowledged,
    }


def call_log(calls: list[str]) -> dict[str, Any]:
    return {"durable_host_call_log_format": "determa.durable_host.call_log", "durable_host_call_log_schema_version": 2, "calls": calls}


def generate_persistence_case(index: int, slug: str) -> dict[Path, bytes]:
    case = PROFILE / "persistence" / f"persistence-{index:02d}-{slug}"
    created = create_checkpoint(case, f"persistence-{index}-root", f"persistence-{index}-create")
    if index == 2:
        maintenance_case = (
            PROFILE
            / "execution-checkpoint"
            / "checkpoint-04-version2-mailboxes"
        )
        created = json.loads(
            (maintenance_case / "maintenance-one-hop-checkpoint-v2.json").read_text(
                encoding="utf-8"
            )
        )
    event = "host_commit" if index == 2 else "increment"
    payload = {} if index == 2 else {"amount": 1}
    accepted = admit(created, event, f"persistence-{index}-event", payload)
    committed_checkpoint = process(accepted, output_count=1 if index == 2 else 0)
    terminal = next(receipt for receipt in committed_checkpoint["operation_receipts"] if receipt["operation_kind"] == "event_terminal")
    inbox = [{"event_id": terminal["event_id"], "request_digest": terminal["request_digest"], "disposition": "committed"}]
    initial = store(created)
    committed = store(committed_checkpoint, inbox=inbox, application_rows={"aggregate_version": 1}, acknowledged=True)
    quarantined = store(created, inbox=[{"event_id": f"persistence-{index}-event", "request_digest": envelope_for(accepted, event, f"persistence-{index}-event", payload)[1], "disposition": "quarantined"}], quarantine={"event_id": f"persistence-{index}-event", "reason_code": "permanent_processing_failure", "released": False})
    released = copy.deepcopy(quarantined)
    released["quarantine"]["released"] = True
    common = ["select_scope", "resolve_artifacts", "validate_capabilities", "begin_transaction", "read_checkpoint", "check_replay"]
    logs = {
        "commit": call_log(common + ["call_core", "stage_checkpoint", "stage_inbox", "stage_outbox", "stage_audit", "stage_application_rows", "commit", "acknowledge"]),
        "replay": call_log(common + ["acknowledge"]),
        "rollback": call_log(common + ["call_core", "stage_checkpoint", "stage_inbox", "stage_outbox", "stage_audit", "rollback"]),
        "quarantine": call_log(["select_scope", "resolve_artifacts", "validate_capabilities", "quarantine"]),
        "release": call_log(["select_scope", "resolve_artifacts", "validate_capabilities", "release_quarantine"]),
    }
    if index == 4:
        logs["transient"] = call_log(common + ["rollback"])
    return {
        case / "initial-store-v2.json": write_json(case / "x", initial),
        case / "committed-store-v2.json": write_json(case / "x", committed),
        case / "quarantined-store-v2.json": write_json(case / "x", quarantined),
        case / "released-store-v2.json": write_json(case / "x", released),
        case / "inputs-v2.json": write_json(case / "x", request_document({
            "process": request("persistence_process_v2", f"persistence-{index}-process", checkpoint=created, target_fingerprint=created["root_record"]["aggregate_state"]["validated_bundle_fingerprint"], descriptor_route=[]),
            "replay": request("persistence_process_v2", f"persistence-{index}-process", checkpoint=committed_checkpoint, target_fingerprint=created["root_record"]["aggregate_state"]["validated_bundle_fingerprint"], descriptor_route=[]),
            "release": request("persistence_release_quarantine_v2", f"persistence-{index}-release", checkpoint=created, target_fingerprint=created["root_record"]["aggregate_state"]["validated_bundle_fingerprint"], descriptor_route=[]),
        })),
        case / "results-v2.json": write_json(case / "x", result_document({
            "committed": result("committed", "atomic", 1, acknowledged=True),
            "replayed": result("replayed", "none", 0, acknowledged=True),
            "crashed": result("crashed", "none", 1, code="injected_pre_commit_failure"),
            "postcommit_crash": result("crashed", "atomic", 1, code="response_lost_after_commit"),
            "transient": result("rejected", "none", 0, code="transient_processing_failure"),
            "quarantined": result("quarantined", "atomic", 0, code="permanent_processing_failure"),
            "released": result("released", "atomic", 0),
        })),
        **{case / f"{name}-call-log-v2.json": write_json(case / "x", value) for name, value in logs.items()},
    }


def outputs() -> dict[Path, bytes]:
    result_map: dict[Path, bytes] = {}
    for generated in (
        generate_delivery(),
        generate_outbox(),
        generate_retention(),
        generate_spawned(False),
        generate_spawned(True),
    ):
        result_map.update(generated)
    for index, slug in enumerate(
        (
            "inbox-idempotency",
            "atomic-aggregate-inbox-outbox-audit",
            "crash-boundaries",
            "transient-retry",
            "permanent-quarantine-release",
            "resolve-before-transaction-cache-boundary",
        ),
        start=1,
    ):
        result_map.update(generate_persistence_case(index, slug))
    return result_map


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = outputs()
    existing = {
        path
        for path in PROFILE.rglob("*.json")
        if "checkpoint-04-version2-mailboxes" not in path.parts
    }
    expected = set(generated)
    if args.check:
        differences = [
            str(path.relative_to(ROOT))
            for path, content in sorted(generated.items())
            if not path.is_file() or path.read_bytes() != content
        ]
        differences.extend(
            str(path.relative_to(ROOT)) for path in sorted(existing - expected)
        )
        if differences:
            raise SystemExit("generated durable profile artifacts differ: " + ", ".join(differences))
        return 0
    for path in sorted(existing - expected):
        path.unlink()
    for path, content in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
