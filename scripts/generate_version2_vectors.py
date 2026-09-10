#!/usr/bin/env python3
"""Generate deterministic queue-bearing conformance artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import rfc8785


ROOT = Path(__file__).resolve().parents[1]
MAILBOX = ROOT / "conformance" / "core" / "117-version2-mailboxes"
PERSISTENCE = ROOT / "conformance" / "core" / "118-version2-persistence"
CHECKPOINT = (
    ROOT
    / "conformance"
    / "profiles"
    / "execution-checkpoint"
    / "checkpoint-04-version2-mailboxes"
)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def seal_aggregate(value: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(value)
    value.pop("aggregate_state_digest", None)
    value["aggregate_state_digest"] = digest(
        ["determa-aggregate-state-digest-2", value]
    )
    return value


def seal_checkpoint(value: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(value)
    value.pop("execution_checkpoint_digest", None)
    value["execution_checkpoint_digest"] = digest(
        ["determa-execution-checkpoint-digest-2", value]
    )
    return value


def rebind_single_root(
    value: dict[str, Any], validated_bundle_fingerprint: str
) -> dict[str, Any]:
    result = copy.deepcopy(value)
    old_runtime_id = result["root_runtime_id"]
    runtime_id = digest(
        [
            "determa-root-runtime-identity-2",
            "1",
            validated_bundle_fingerprint,
            result["namespace"],
            result["root_machine_id"],
            result["root_machine_version"],
            result["root_instance_id"],
        ]
    )
    result["validated_bundle_fingerprint"] = validated_bundle_fingerprint
    result["root_runtime_id"] = runtime_id
    for runtime in result["runtimes"]:
        runtime["runtime_id"] = runtime_id
        runtime["identity_origin"]["definition"][
            "validated_bundle_fingerprint"
        ] = validated_bundle_fingerprint
        runtime["current_definition"][
            "validated_bundle_fingerprint"
        ] = validated_bundle_fingerprint
        root_target = runtime["target_identity"].get("root")
        if root_target is not None and root_target["root_runtime_id"] == old_runtime_id:
            root_target["root_runtime_id"] = runtime_id
        for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"]):
            for entry in mailbox:
                target = entry["envelope"]["target"].get("root")
                if target is not None and target["root_runtime_id"] == old_runtime_id:
                    target["root_runtime_id"] = runtime_id
                entry["envelope_digest"] = digest(
                    [
                        "determa-inbox-envelope-digest-2",
                        "2",
                        result["root_instance_id"],
                        entry["delivery_mode"],
                        entry["envelope"],
                    ]
                )
    return seal_aggregate(result)


def upgrade_aggregate(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result["aggregate_state_schema_version"] = 2
    result["next_acceptance_sequence"] = "0"
    result["next_queue_sequence"] = "0"
    for runtime in result["runtimes"]:
        runtime["ready_mailbox"] = []
        runtime["deferred_mailbox"] = []
    return seal_aggregate(result)


def envelope_entry(
    aggregate: dict[str, Any],
    runtime: dict[str, Any],
    *,
    event: str,
    event_id: str,
    acceptance_sequence: int,
    queue_sequence: int,
    delivery_mode: str = "input",
    source: dict[str, Any] | None = None,
    payload: list[Any] | None = None,
    deferral_count: int = 0,
) -> dict[str, Any]:
    envelope = {
        "event": event,
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": True} if source is None else source,
        "target": copy.deepcopy(runtime["target_identity"]),
        "payload": ["map", []] if payload is None else payload,
    }
    envelope_digest = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            aggregate["root_instance_id"],
            delivery_mode,
            envelope,
        ]
    )
    return {
        "acceptance_sequence": str(acceptance_sequence),
        "queue_sequence": str(queue_sequence),
        "delivery_mode": delivery_mode,
        "envelope": envelope,
        "envelope_digest": envelope_digest,
        "deferral_count": str(deferral_count),
    }


def step_result(
    state: dict[str, Any],
    disposition: str,
    *,
    status: str | None = None,
    fault: dict[str, Any] | None = None,
    rejection: str | None = None,
    emissions: list[Any] | None = None,
    lifecycle_dispositions: list[Any] | None = None,
) -> dict[str, Any]:
    return {
        "core_step_result_format": "determa.core_step_result",
        "core_step_result_schema_version": 2,
        "status": state["runtimes"][-1]["status"] if status is None else status,
        "disposition": disposition,
        "state": state,
        "emissions": [] if emissions is None else emissions,
        "lifecycle_dispositions": (
            [] if lifecycle_dispositions is None else lifecycle_dispositions
        ),
        "fault": fault,
        "rejection": None if rejection is None else {"code": rejection},
    }


def lifecycle_disposition(
    entry: dict[str, Any], target_runtime_id: str, reason: str
) -> dict[str, Any]:
    return {
        "event_id": entry["envelope"]["event_id"],
        "request_digest": entry["envelope_digest"],
        "acceptance_sequence": entry["acceptance_sequence"],
        "final_queue_sequence": entry["queue_sequence"],
        "target_runtime_id": target_runtime_id,
        "reason": reason,
    }


def internal_disposed_emission(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "internal_disposed",
        "emission_index": "0",
        "event_id": entry["envelope"]["event_id"],
        "acceptance_sequence": entry["acceptance_sequence"],
        "lifecycle_disposition_index": "0",
    }


def produce_mailbox() -> dict[str, bytes]:
    base = load(MAILBOX / "base-aggregate.json")
    outputs: dict[str, Any] = {
        "base-aggregate.canonical.json": base,
    }

    empty = copy.deepcopy(base)
    root = empty["runtimes"][0]
    root["ready_mailbox"] = []
    root["deferred_mailbox"] = []
    empty["next_acceptance_sequence"] = "0"
    empty["next_queue_sequence"] = "0"
    empty = seal_aggregate(empty)
    outputs["empty-aggregate-v2.json"] = empty
    outputs["not-runnable-result.json"] = step_result(empty, "not_runnable")

    handled = copy.deepcopy(base)
    handled_root = handled["runtimes"][0]
    recalled = handled_root["deferred_mailbox"].pop(0)
    recalled["queue_sequence"] = "4"
    handled_root["ready_mailbox"] = [recalled]
    handled_root["active_leaf_state_definition_pointers"] = [
        "/machines/0/root/states/busy/states/authorizing"
    ]
    handled_root["active_state_activations"][-1] = {
        "state_definition_pointer": "/machines/0/root/states/busy/states/authorizing",
        "activation_sequence": "0",
    }
    handled_root["next_state_activation_sequences"].append(
        {
            "definition_pointer": "/machines/0/root/states/busy/states/authorizing",
            "next_sequence": "1",
        }
    )
    handled["next_logical_step_sequence"] = "2"
    handled["next_queue_sequence"] = "5"
    handled = seal_aggregate(handled)
    outputs["handled-recall-result.json"] = step_result(handled, "handled")

    repeated_before = copy.deepcopy(empty)
    repeated_root = repeated_before["runtimes"][0]
    repeated = envelope_entry(
        repeated_before,
        repeated_root,
        event="new_request",
        event_id="request-repeated",
        acceptance_sequence=0,
        queue_sequence=0,
        payload=["map", [["transaction_id", ["string", "transaction-r"]]]],
        deferral_count=1,
    )
    repeated_root["ready_mailbox"] = [repeated]
    repeated_before["next_acceptance_sequence"] = "1"
    repeated_before["next_queue_sequence"] = "1"
    repeated_before = seal_aggregate(repeated_before)
    outputs["repeated-before.json"] = repeated_before
    repeated_after = copy.deepcopy(repeated_before)
    repeated_entry = repeated_after["runtimes"][0]["ready_mailbox"].pop(0)
    repeated_entry["queue_sequence"] = "1"
    repeated_entry["deferral_count"] = "2"
    repeated_after["runtimes"][0]["deferred_mailbox"] = [repeated_entry]
    repeated_after["next_logical_step_sequence"] = "2"
    repeated_after["next_queue_sequence"] = "2"
    repeated_after = seal_aggregate(repeated_after)
    outputs["repeated-deferral-result.json"] = step_result(
        repeated_after, "deferred"
    )

    component_v1 = load(
        ROOT
        / "conformance/core/94-aggregate-wire-round-trip/component-target-aggregate-state.json"
    )
    component = upgrade_aggregate(component_v1)
    for index, runtime in enumerate(component["runtimes"]):
        runtime["ready_mailbox"] = [
            envelope_entry(
                component,
                runtime,
                event="component_work" if runtime["relation"]["kind"] == "component" else "fanout",
                event_id=f"isolated-component-{index}",
                acceptance_sequence=index,
                queue_sequence=index,
                delivery_mode=(
                    "internal" if runtime["relation"]["kind"] == "component" else "input"
                ),
                source=(
                    {"runtime": copy.deepcopy(component["runtimes"][-1]["target_identity"])}
                    if runtime["relation"]["kind"] == "component"
                    else {"host": True}
                ),
            )
        ]
    component["next_acceptance_sequence"] = "3"
    component["next_queue_sequence"] = "3"
    component = seal_aggregate(component)
    outputs["component-isolation-aggregate.json"] = component
    component_after = copy.deepcopy(component)
    left = component_after["runtimes"][0]
    left["ready_mailbox"].pop(0)
    left["variables"][0]["value"] = ["list", [["string", "left"]]]
    component_after["next_logical_step_sequence"] = str(
        int(component_after["next_logical_step_sequence"]) + 1
    )
    component_after = seal_aggregate(component_after)
    outputs["component-isolation-result.json"] = step_result(
        component_after, "handled"
    )

    inactive = copy.deepcopy(component)
    inactive["runtimes"][0]["status"] = "completed"
    inactive["runtimes"][0]["active_leaf_state_definition_pointers"] = []
    inactive["runtimes"][0]["active_state_activations"] = []
    inactive["runtimes"][0]["variables"] = []
    inactive["runtimes"][0]["ready_mailbox"] = []
    inactive["runtimes"][0]["deferred_mailbox"] = []
    inactive = seal_aggregate(inactive)
    outputs["inactive-component-aggregate.json"] = inactive
    outputs["inactive-component-result.json"] = step_result(
        inactive, "rejected", rejection="inactive_component_target"
    )

    spawned_v1 = load(
        ROOT
        / "conformance/core/94-aggregate-wire-round-trip/spawned_instance-target-aggregate-state.json"
    )
    spawned = upgrade_aggregate(spawned_v1)
    for index, runtime in enumerate(spawned["runtimes"]):
        runtime["ready_mailbox"] = [
            envelope_entry(
                spawned,
                runtime,
                event="pay" if runtime["relation"]["kind"] == "owned_spawned_instance" else "start",
                event_id=f"isolated-spawn-{index}",
                acceptance_sequence=index,
                queue_sequence=index,
                payload=(
                    ["map", [["amount", ["integer", "50"]]]]
                    if runtime["relation"]["kind"] == "owned_spawned_instance"
                    else ["map", []]
                ),
            )
        ]
    spawned["next_acceptance_sequence"] = "2"
    spawned["next_queue_sequence"] = "2"
    spawned = seal_aggregate(spawned)
    outputs["spawn-isolation-aggregate.json"] = spawned
    spawned_after = copy.deepcopy(spawned)
    spawned_after["runtimes"][0]["ready_mailbox"].pop(0)
    spawned_after["next_logical_step_sequence"] = str(
        int(spawned_after["next_logical_step_sequence"]) + 1
    )
    spawned_after = seal_aggregate(spawned_after)
    outputs["spawn-isolation-result.json"] = step_result(
        spawned_after, "unhandled"
    )

    outputs["invalid-target-result.json"] = step_result(
        empty, "rejected", rejection="invalid_instance_target"
    )

    zero_before = copy.deepcopy(empty)
    zero_before = rebind_single_root(
        zero_before,
        "sha256:c54ded7abd3ba8f4849ee242aabc8f03c98d64d1856f2f7f011d760117fb7754",
    )
    zero_root = zero_before["runtimes"][0]
    zero_entry = envelope_entry(
        zero_before,
        zero_root,
        event="new_request",
        event_id="zero-capacity-request",
        acceptance_sequence=0,
        queue_sequence=0,
        payload=["map", [["transaction_id", ["string", "transaction-zero"]]]],
    )
    zero_root["ready_mailbox"] = [zero_entry]
    zero_before["next_acceptance_sequence"] = "1"
    zero_before["next_queue_sequence"] = "1"
    zero_before = seal_aggregate(zero_before)
    outputs["zero-capacity-before.json"] = zero_before
    overflow = copy.deepcopy(zero_before)
    overflow_root = overflow["runtimes"][0]
    causal = overflow_root["ready_mailbox"].pop(0)
    fault = {
        "definition_fingerprint": overflow["validated_bundle_fingerprint"],
        "runtime_id": overflow_root["runtime_id"],
        "cause_id": causal["envelope"]["cause_id"],
        "code": "deferred_event_capacity_exceeded",
        "step_sequence": overflow["next_logical_step_sequence"],
        "source_locator": "system:deferred_event_capacity",
    }
    overflow_root["status"] = "faulted"
    overflow_root["fault"] = fault
    overflow["next_logical_step_sequence"] = str(
        int(overflow["next_logical_step_sequence"]) + 1
    )
    overflow = seal_aggregate(overflow)
    outputs["overflow-result.json"] = step_result(
        overflow, "faulted", status="faulted", fault=fault
    )

    lifecycle_before = copy.deepcopy(component)
    for runtime in lifecycle_before["runtimes"][:-1]:
        runtime["ready_mailbox"] = []
        runtime["deferred_mailbox"] = []
    lifecycle_before = seal_aggregate(lifecycle_before)
    outputs["lifecycle-before.json"] = lifecycle_before

    source_runtime = lifecycle_before["runtimes"][-1]
    target_runtime = lifecycle_before["runtimes"][0]
    source_entry = source_runtime["ready_mailbox"][0]
    internal_event_id = digest(
        [
            "determa-event-identity-1",
            "1",
            lifecycle_before["root_instance_id"],
            source_runtime["runtime_id"],
            target_runtime["runtime_id"],
            source_entry["envelope"]["cause_id"],
            lifecycle_before["next_logical_step_sequence"],
            "/machines/0/root/states/processing/on_events/fanout/action/0/send/targets/0",
            "0",
        ]
    )
    emitted_entry = envelope_entry(
        lifecycle_before,
        target_runtime,
        event="component_work",
        event_id=internal_event_id,
        acceptance_sequence=int(lifecycle_before["next_acceptance_sequence"]),
        queue_sequence=int(lifecycle_before["next_queue_sequence"]),
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(source_runtime["target_identity"])},
    )
    active = copy.deepcopy(lifecycle_before)
    active["runtimes"][-1]["ready_mailbox"] = []
    active["runtimes"][0]["ready_mailbox"] = [emitted_entry]
    active["next_acceptance_sequence"] = str(
        int(active["next_acceptance_sequence"]) + 1
    )
    active["next_queue_sequence"] = str(int(active["next_queue_sequence"]) + 1)
    active["next_logical_step_sequence"] = str(
        int(active["next_logical_step_sequence"]) + 1
    )
    active = seal_aggregate(active)
    mailbox_emission = {
        "kind": "internal_mailbox",
        "emission_index": "0",
        "event_id": internal_event_id,
        "acceptance_sequence": emitted_entry["acceptance_sequence"],
        "queue_sequence": emitted_entry["queue_sequence"],
    }
    outputs["internal-emission-active-result.json"] = step_result(
        active, "handled", emissions=[mailbox_emission]
    )

    retained_faulted = copy.deepcopy(active)
    retained_target = retained_faulted["runtimes"][0]
    retained_fault = {
        "definition_fingerprint": retained_faulted["validated_bundle_fingerprint"],
        "runtime_id": retained_target["runtime_id"],
        "cause_id": internal_event_id,
        "code": "action_evaluation_failed",
        "step_sequence": retained_faulted["next_logical_step_sequence"],
        "source_locator": "system:contained_runtime_fault",
    }
    retained_target["status"] = "faulted"
    retained_target["fault"] = retained_fault
    retained_faulted = seal_aggregate(retained_faulted)
    outputs["internal-emission-retained-faulted-result.json"] = step_result(
        retained_faulted, "handled", emissions=[mailbox_emission]
    )

    def disposed_lifecycle_result(reason: str) -> dict[str, Any]:
        disposed = copy.deepcopy(active)
        target_id = disposed["runtimes"][0]["runtime_id"]
        disposed["runtimes"] = [disposed["runtimes"][-1]]
        if reason == "aggregate_completed":
            root_runtime = disposed["runtimes"][0]
            root_runtime["status"] = "completed"
            root_runtime["active_leaf_state_definition_pointers"] = []
            root_runtime["active_state_activations"] = []
            root_runtime["variables"] = []
        disposed = seal_aggregate(disposed)
        disposition = lifecycle_disposition(emitted_entry, target_id, reason)
        return step_result(
            disposed,
            "handled",
            status="completed" if reason == "aggregate_completed" else "running",
            emissions=[internal_disposed_emission(emitted_entry)],
            lifecycle_dispositions=[disposition],
        )

    outputs["internal-emission-cancelled-result.json"] = disposed_lifecycle_result(
        "runtime_cancelled"
    )
    outputs["internal-emission-runtime-completed-result.json"] = (
        disposed_lifecycle_result("runtime_completed")
    )
    outputs["internal-emission-aggregate-completed-result.json"] = (
        disposed_lifecycle_result("aggregate_completed")
    )

    rollback = copy.deepcopy(lifecycle_before)
    rollback_root = rollback["runtimes"][-1]
    rollback_root["ready_mailbox"] = []
    rollback_fault = {
        "definition_fingerprint": rollback["validated_bundle_fingerprint"],
        "runtime_id": rollback_root["runtime_id"],
        "cause_id": source_entry["envelope"]["cause_id"],
        "code": "action_evaluation_failed",
        "step_sequence": rollback["next_logical_step_sequence"],
        "source_locator": "/machines/0/root/states/processing/on_events/fanout/action/1",
    }
    rollback_root["status"] = "faulted"
    rollback_root["fault"] = rollback_fault
    rollback["next_logical_step_sequence"] = str(
        int(rollback["next_logical_step_sequence"]) + 1
    )
    rollback = seal_aggregate(rollback)
    outputs["internal-emission-rollback-result.json"] = step_result(
        rollback,
        "faulted",
        status="faulted",
        fault=rollback_fault,
    )

    invalid_aggregate = copy.deepcopy(base)
    del invalid_aggregate["runtimes"][0]["deferred_mailbox"]
    outputs["invalid-aggregate-v2.json"] = invalid_aggregate
    invalid_result = step_result(empty, "not_runnable")
    invalid_result["language_specific"] = True
    outputs["invalid-core-step-result-v2.json"] = invalid_result

    requests = {
        "admit_two": [
            {
                "delivery_mode": "input",
                "event": "received",
                "event_id": "batch-a",
                "target_runtime_id": base["root_runtime_id"],
                "payload": {},
            },
            {
                "delivery_mode": "input",
                "event": "authorized",
                "event_id": "batch-b",
                "target_runtime_id": base["root_runtime_id"],
                "payload": {},
            },
        ],
        "duplicate_batch": [
            {"event": "received", "event_id": "duplicate"},
            {"event": "received", "event_id": "duplicate"},
        ],
        "equal_replay": {"event_id": "request-2", "digest": base["runtimes"][0]["deferred_mailbox"][0]["envelope_digest"]},
        "conflicting_replay": {"event_id": "request-2", "payload": {"transaction_id": "different"}},
    }
    outputs["requests.json"] = requests
    outputs["admission-success.json"] = {
        "result": "accepted",
        "accepted": [
            {"event_id": "batch-a", "acceptance_sequence": "2", "queue_sequence": "4"},
            {"event_id": "batch-b", "acceptance_sequence": "3", "queue_sequence": "5"},
        ],
    }
    outputs["replay-success.json"] = {
        "result": "replay",
        "event_id": "request-2",
        "acceptance_sequence": "0",
        "location": "deferred",
    }
    outputs["invalid-version2-operation-result.json"] = {
        "result": "replay",
        "event_id": "request-2",
        "acceptance_sequence": "0",
        "location": "deferred",
        "language_specific": True,
    }
    return {name: canonical(value) for name, value in outputs.items()}


def produce_persistence() -> dict[str, bytes]:
    aggregate_v1 = load(PERSISTENCE / "base-aggregate-v1.json")
    upgraded_aggregate_v2 = upgrade_aggregate(aggregate_v1)
    aggregate_v2 = load(PERSISTENCE / "base-aggregate-v2.json")
    descriptor_v1 = load(PERSISTENCE / "base-descriptor-v1.json")
    descriptor_v2 = {
        "migration_descriptor_format": "determa.aggregate_migration",
        "migration_descriptor_schema_version": 2,
        "base_descriptor": descriptor_v1,
        "queued_event_default": "preserve_if_compatible",
        "queued_event_rules": [
            {
                "machine_id": aggregate_v2["root_machine_id"],
                "event": "retired_event",
                "delivery_mode": "input",
                "action": "dispose",
                "reason": "event removed by version migration",
            }
        ],
    }
    descriptor_v2["migration_descriptor_digest"] = digest(
        ["determa-migration-descriptor-2", descriptor_v2]
    )
    package_v2 = {
        "aggregate_state_package_format": "determa.aggregate_state_package",
        "aggregate_state_package_schema_version": 2,
        "aggregate_state": aggregate_v2,
        "normalized_definitions": [],
        "migration_descriptors": [descriptor_v2],
        "migration_route": [descriptor_v2["migration_descriptor_digest"]],
    }
    invalid_descriptor = copy.deepcopy(descriptor_v2)
    invalid_descriptor["queued_event_default"] = "drop"
    invalid_package = copy.deepcopy(package_v2)
    invalid_package["aggregate_state_package_schema_version"] = 1
    invalid_aggregate = copy.deepcopy(aggregate_v2)
    invalid_aggregate["next_queue_sequence"] = -1

    disposal_before = copy.deepcopy(aggregate_v2)
    disposal_entry = disposal_before["runtimes"][0]["deferred_mailbox"][0]
    disposal_entry["envelope"]["event"] = "retired_event"
    disposal_entry["envelope"]["event_id"] = "retired-1"
    disposal_entry["envelope"]["cause_id"] = "retired-1"
    disposal_entry["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            disposal_before["root_instance_id"],
            disposal_entry["delivery_mode"],
            disposal_entry["envelope"],
        ]
    )
    disposal_before = seal_aggregate(disposal_before)
    disposal_after = copy.deepcopy(disposal_before)
    disposal_after["runtimes"][0]["deferred_mailbox"] = []
    disposal_after = seal_aggregate(disposal_after)

    fault_frozen = copy.deepcopy(aggregate_v2)
    fault_runtime = fault_frozen["runtimes"][0]
    fault_record = {
        "definition_fingerprint": fault_frozen["validated_bundle_fingerprint"],
        "runtime_id": fault_runtime["runtime_id"],
        "cause_id": fault_runtime["ready_mailbox"][0]["envelope"]["cause_id"],
        "code": "action_evaluation_failed",
        "step_sequence": fault_frozen["next_logical_step_sequence"],
        "source_locator": "/machines/0/root/states/busy/on_events/received/action/0",
    }
    fault_runtime["status"] = "faulted"
    fault_runtime["fault"] = fault_record
    fault_frozen = seal_aggregate(fault_frozen)
    return {
        "upgraded-aggregate-v2.json": canonical(upgraded_aggregate_v2),
        "descriptor-v2.json": canonical(descriptor_v2),
        "package-v2.json": canonical(package_v2),
        "invalid-descriptor-v2.json": canonical(invalid_descriptor),
        "invalid-package-v2.json": canonical(invalid_package),
        "invalid-counter-aggregate-v2.json": canonical(invalid_aggregate),
        "disposal-before.json": canonical(disposal_before),
        "fault-frozen-aggregate-v2.json": canonical(fault_frozen),
        "migration-preserve-result.json": canonical(
            {"result": "success", "aggregate_state": aggregate_v2, "dispositions": []}
        ),
        "migration-fault-frozen-preserve-result.json": canonical(
            {"result": "success", "aggregate_state": fault_frozen, "dispositions": []}
        ),
        "migration-dispose-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": disposal_after,
                "dispositions": [
                    {
                        "disposition": "migration_disposed",
                        "reason": "event removed by version migration",
                        "migration_descriptor_digest": descriptor_v2["migration_descriptor_digest"],
                    }
                ],
            }
        ),
        "downgrade-result.json": canonical(
            {"result": "success", "aggregate_state": aggregate_v1}
        ),
        "migration-requests.json": canonical(
            {
                "preserve": {"descriptor": descriptor_v2["migration_descriptor_digest"]},
                "dispose": {"descriptor": descriptor_v2["migration_descriptor_digest"], "event_id": "retired-1"},
                "stale_target": {"target": "deleted-runtime"},
                "event_removed": {"event": "new_request", "target_contract": "removed"},
                "payload_incompatible": {"event": "retired_event", "payload": {"value": "wrong"}},
                "correlation_incompatible": {"event": "new_request", "correlation_id": "no-longer-accepted"},
                "lowered_capacity": {"deferred_capacity": 0},
            }
        ),
    }


def upgrade_checkpoint(value: dict[str, Any]) -> dict[str, Any]:
    source = copy.deepcopy(value)
    aggregate = upgrade_aggregate(source["root_record"]["aggregate_state"])
    receipts = []
    for receipt in source["operation_receipts"]:
        receipts.append(
            {
                "operation_kind": (
                    "legacy_v1_creation"
                    if receipt["operation_kind"] == "creation"
                    else "legacy_v1_operation"
                ),
                "receipt_sequence": receipt["receipt_sequence"],
                "legacy_receipt": receipt,
            }
        )
    result = {
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 2,
        "root_instance_id": source["root_instance_id"],
        "revision": str(int(source["revision"]) + 1),
        "root_record": {"status": "retained", "aggregate_state": aggregate},
        "replay_retention": source["replay_retention"],
        "next_operation_receipt_sequence": source["next_operation_receipt_sequence"],
        "operation_receipts": receipts,
        "event_identity_tombstones": [],
        "pending_outbox_intents": source["pending_outbox_intents"],
        "next_outbox_terminal_sequence": source["next_outbox_terminal_sequence"],
        "terminal_outbox_records": source["terminal_outbox_records"],
        "outbox_effect_tombstones": source["outbox_effect_tombstones"],
        "migration_audit_records": source["migration_audit_records"],
    }
    return seal_checkpoint(result)


def produce_checkpoint() -> dict[str, bytes]:
    v1 = load(CHECKPOINT / "base-checkpoint-v1.json")
    upgraded = upgrade_checkpoint(v1)
    admitted = copy.deepcopy(upgraded)
    aggregate = admitted["root_record"]["aggregate_state"]
    root = next(r for r in aggregate["runtimes"] if r["relation"]["kind"] == "root")
    entry = envelope_entry(
        aggregate,
        root,
        event="increment",
        event_id="checkpoint-v2-increment",
        acceptance_sequence=0,
        queue_sequence=0,
        payload=["map", [["amount", ["integer", "1"]]]],
    )
    root["ready_mailbox"] = [entry]
    aggregate["next_acceptance_sequence"] = "1"
    aggregate["next_queue_sequence"] = "1"
    aggregate = seal_aggregate(aggregate)
    admitted["root_record"]["aggregate_state"] = aggregate
    admitted["revision"] = str(int(upgraded["revision"]) + 1)
    receipt_sequence = admitted["next_operation_receipt_sequence"]
    admitted["operation_receipts"].append(
        {
            "operation_kind": "acceptance",
            "receipt_sequence": receipt_sequence,
            "event_id": entry["envelope"]["event_id"],
            "request_digest": entry["envelope_digest"],
            "acceptance_sequence": entry["acceptance_sequence"],
            "accepted_revision": admitted["revision"],
            "delivery_mode": "input",
        }
    )
    admitted["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    admitted = seal_checkpoint(admitted)

    terminal = copy.deepcopy(admitted)
    aggregate = terminal["root_record"]["aggregate_state"]
    root = next(r for r in aggregate["runtimes"] if r["relation"]["kind"] == "root")
    consumed = root["ready_mailbox"].pop(0)
    root["variables"][0]["value"] = ["integer", "1"]
    aggregate["next_logical_step_sequence"] = str(
        int(aggregate["next_logical_step_sequence"]) + 1
    )
    aggregate = seal_aggregate(aggregate)
    terminal["root_record"]["aggregate_state"] = aggregate
    terminal["revision"] = str(int(admitted["revision"]) + 1)
    terminal_sequence = terminal["next_operation_receipt_sequence"]
    terminal["operation_receipts"].append(
        {
            "operation_kind": "event_terminal",
            "receipt_sequence": terminal_sequence,
            "event_id": consumed["envelope"]["event_id"],
            "request_digest": consumed["envelope_digest"],
            "acceptance_sequence": consumed["acceptance_sequence"],
            "final_queue_sequence": consumed["queue_sequence"],
            "committed_revision": terminal["revision"],
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "outcome": {
                "status": "running",
                "disposition": "handled",
                "fault": None,
                "rejection": None,
            },
            "emission_references": [],
        }
    )
    terminal["next_operation_receipt_sequence"] = str(int(terminal_sequence) + 1)
    terminal = seal_checkpoint(terminal)

    compact = copy.deepcopy(terminal)
    acceptance = compact["operation_receipts"].pop(-2)
    event_terminal = compact["operation_receipts"].pop(-1)
    compact["event_identity_tombstones"] = [
        {
            "event_id": event_terminal["event_id"],
            "request_digest": event_terminal["request_digest"],
            "request_digest_domain": "determa-inbox-envelope-digest-2",
            "acceptance_sequence": acceptance["acceptance_sequence"],
            "terminal_receipt_sequence": event_terminal["receipt_sequence"],
            "terminal_disposition": "handled",
        }
    ]
    compact["revision"] = str(int(terminal["revision"]) + 1)
    compact = seal_checkpoint(compact)

    invalid = copy.deepcopy(admitted)
    invalid_aggregate = invalid["root_record"]["aggregate_state"]
    invalid_aggregate["runtimes"][0]["deferred_mailbox"] = copy.deepcopy(
        invalid_aggregate["runtimes"][0]["ready_mailbox"]
    )
    invalid["root_record"]["aggregate_state"] = seal_aggregate(invalid_aggregate)
    invalid = seal_checkpoint(invalid)
    return {
        "upgraded-checkpoint-v2.json": canonical(upgraded),
        "admitted-checkpoint-v2.json": canonical(admitted),
        "terminal-checkpoint-v2.json": canonical(terminal),
        "compact-checkpoint-v2.json": canonical(compact),
        "invalid-duplicate-location-checkpoint-v2.json": canonical(invalid),
        "checkpoint-requests.json": canonical(
            {
                "admit": {"event_id": "checkpoint-v2-increment", "event": "increment", "payload": {"amount": 1}},
                "duplicate_batch": [{"event_id": "same"}, {"event_id": "same"}],
                "terminal_equal_replay": {"event_id": "checkpoint-v2-increment", "request_digest": entry["envelope_digest"]},
                "terminal_conflict": {"event_id": "checkpoint-v2-increment", "payload": {"amount": 2}},
            }
        ),
        "terminal-replay-result.json": canonical(
            {"result": "replay", "acceptance_receipt_sequence": receipt_sequence, "terminal_receipt_sequence": terminal_sequence}
        ),
        "tombstone-replay-result.json": canonical(
            {"result": "replay", "terminal_receipt_sequence": terminal_sequence, "terminal_disposition": "handled"}
        ),
    }


def outputs() -> dict[Path, bytes]:
    result: dict[Path, bytes] = {}
    for directory, produced in (
        (MAILBOX, produce_mailbox()),
        (PERSISTENCE, produce_persistence()),
        (CHECKPOINT, produce_checkpoint()),
    ):
        for name, data in produced.items():
            result[directory / name] = data
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    generated = outputs()
    if arguments.check:
        stale = [path for path, data in generated.items() if not path.is_file() or path.read_bytes() != data]
        if stale:
            raise SystemExit("stale version-2 fixtures: " + ", ".join(str(path.relative_to(ROOT)) for path in stale))
        print(f"verified {len(generated)} deterministic version-2 artifacts")
        return 0
    for path, data in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"generated {len(generated)} deterministic version-2 artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
