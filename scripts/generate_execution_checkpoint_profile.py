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
    aggregate_shape_fingerprint_document,
    bundle_binding,
    bundle_fingerprint_document,
    bytes_digest,
    digest,
    load_yaml,
    migrate_compatible_aggregate,
    native_v2_checkpoint,
    normalize_bundle_document,
    seal_aggregate,
    seal_checkpoint,
    typed_value,
    v2_migration_audit_record,
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


def scope(
    scope_id: str = "primary",
    authorization: str = "authorized",
) -> dict[str, Any]:
    return {
        "scope_id": scope_id,
        "ownership_binding": f"owner:{scope_id}",
        "principal": "conformance-host",
        "authorization": authorization,
    }


def expected_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "root_instance_id": checkpoint["root_instance_id"],
        "revision": checkpoint["revision"],
        "digest": checkpoint["execution_checkpoint_digest"],
    }


def writer_checkpoint_context(
    presented_checkpoint: dict[str, Any], stored_checkpoint: dict[str, Any]
) -> dict[str, Any]:
    return {
        "presented_checkpoint": expected_checkpoint(presented_checkpoint),
        "stored_checkpoint": expected_checkpoint(stored_checkpoint),
    }


def aggregate_of(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return checkpoint["root_record"]["aggregate_state"]


def first_mailbox_entry(checkpoint: dict[str, Any]) -> dict[str, Any] | None:
    root_record = checkpoint["root_record"]
    if root_record["status"] != "retained":
        return None
    for runtime in root_record["aggregate_state"]["runtimes"]:
        for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"]):
            if mailbox:
                return mailbox[0]
    return None


def default_envelope(
    checkpoint: dict[str, Any],
    event_id: str,
    *,
    event: str = "increment",
    payload: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    delivery_mode: str = "input",
) -> tuple[dict[str, Any], str]:
    selected_target = target or root_runtime(checkpoint)["target_identity"]
    envelope = {
        "event": event,
        "event_id": event_id,
        "cause_id": event_id,
        "source": copy.deepcopy(source) if source is not None else {"host": True},
        "target": copy.deepcopy(selected_target),
        "payload": typed_value(payload if payload is not None else {"amount": 1}),
    }
    if correlation_id is not None:
        envelope["correlation_id"] = correlation_id
    envelope_digest = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            checkpoint["root_instance_id"],
            delivery_mode,
            envelope,
        ]
    )
    return envelope, envelope_digest


def creation_request(
    case: Path,
    checkpoint: dict[str, Any],
    request_id: str,
    *,
    existing: bool = False,
    creation_id: str | None = None,
) -> dict[str, Any]:
    aggregate = aggregate_of(checkpoint)
    definition = root_runtime(checkpoint)["current_definition"]["machine"]
    value = {
        "operation": "checkpoint_create_v2",
        "request_id": request_id,
        "scope": scope(),
        "bundle": {
            "file": "machine.yaml",
            "validated_bundle_fingerprint": aggregate[
                "validated_bundle_fingerprint"
            ],
        },
        "machine": copy.deepcopy(definition),
        "bindings": {"input": {}, "external": {}},
        "root_instance_id": aggregate["root_instance_id"],
        "creation_id": creation_id or aggregate["creation_id"],
        "retention_mode": checkpoint["replay_retention"]["mode"],
    }
    if existing:
        value["existing_checkpoint"] = expected_checkpoint(checkpoint)
    return value


def admission_request(
    checkpoint: dict[str, Any],
    request_id: str,
    *,
    event: str = "increment",
    payload: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    delivery_mode: str = "input",
    expected_from: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    envelope, envelope_digest = default_envelope(
        checkpoint,
        request_id,
        event=event,
        payload=payload,
        target=target,
        source=source,
        correlation_id=correlation_id,
        delivery_mode=delivery_mode,
    )
    return {
        "operation": "checkpoint_admit_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(expected_from or checkpoint),
        "envelopes": [
            {
                "delivery_mode": delivery_mode,
                "envelope": envelope,
                "envelope_digest": envelope_digest,
            }
        ],
    }


def admission_batch_request(
    checkpoint: dict[str, Any],
    request_id: str,
    members: list[dict[str, Any]],
) -> dict[str, Any]:
    envelopes = []
    for member in members:
        envelope, envelope_digest = default_envelope(
            checkpoint,
            member["event_id"],
            event=member.get("event", "increment"),
            payload=member.get("payload"),
            target=member.get("target"),
            source=member.get("source"),
            correlation_id=member.get("correlation_id"),
            delivery_mode=member.get("delivery_mode", "input"),
        )
        envelopes.append(
            {
                "delivery_mode": member.get("delivery_mode", "input"),
                "envelope": envelope,
                "envelope_digest": member.get("envelope_digest", envelope_digest),
            }
        )
    return {
        "operation": "checkpoint_admit_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(checkpoint),
        "envelopes": envelopes,
    }


def processing_request(
    checkpoint: dict[str, Any],
    request_id: str,
    *,
    mode: str = "delayed",
    expected_from: dict[str, Any] | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    entry = first_mailbox_entry(checkpoint)
    if event_id is not None:
        entry = next(
            (
                candidate
                for runtime in aggregate_of(checkpoint)["runtimes"]
                for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
                for candidate in mailbox
                if candidate["envelope"]["event_id"] == event_id
            ),
            None,
        )
        if entry is None:
            receipt = next(
                (
                    candidate
                    for candidate in checkpoint["operation_receipts"]
                    if candidate.get("event_id") == event_id
                    and candidate["operation_kind"] == "event_terminal"
                ),
                None,
            )
            if receipt is not None:
                entry = {
                    "envelope": {
                        "event_id": event_id,
                        "target": root_runtime(checkpoint)["target_identity"],
                    },
                    "envelope_digest": receipt["request_digest"],
                    "acceptance_sequence": receipt["acceptance_sequence"],
                    "queue_sequence": receipt["final_queue_sequence"],
                }
    if entry is None:
        envelope, envelope_digest = default_envelope(
            checkpoint, f"{request_id}-event"
        )
        entry = {
            "envelope": envelope,
            "envelope_digest": envelope_digest,
            "acceptance_sequence": "0",
            "queue_sequence": "0",
        }
    return {
        "operation": "checkpoint_step_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(expected_from or checkpoint),
        "event_id": entry["envelope"]["event_id"],
        "envelope_digest": entry["envelope_digest"],
        "target": copy.deepcopy(entry["envelope"]["target"]),
        "processing_mode": mode,
        "acceptance_sequence": entry["acceptance_sequence"],
        "queue_sequence": entry["queue_sequence"],
    }


def outbox_request(
    checkpoint: dict[str, Any],
    request_id: str,
    effect_id: str,
    disposition: str,
    *,
    terminal: bool,
    expected_from: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "operation": (
            "checkpoint_terminalize_outbox_v2"
            if terminal
            else "checkpoint_update_outbox_v2"
        ),
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(expected_from or checkpoint),
        "effect_id": effect_id,
        "target_disposition": disposition,
        "outcome": {
            "reason_code": (
                None
                if disposition == "confirmed"
                else f"{disposition}_{'policy' if terminal else 'reported'}"
            ),
            "durable_acceptance": disposition == "confirmed",
        },
    }


def compact_request(
    checkpoint: dict[str, Any], request_id: str, effect_id: str
) -> dict[str, Any]:
    record = next(
        item
        for item in checkpoint["terminal_outbox_records"]
        if item["intent"]["effect_id"] == effect_id
    )
    return {
        "operation": "checkpoint_compact_outbox_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(checkpoint),
        "effect_id": effect_id,
        "intent_digest": digest(
            [
                "determa-outbox-intent-digest-2",
                "2",
                checkpoint["root_instance_id"],
                record["intent"],
            ]
        ),
        "retention_mode": checkpoint["replay_retention"]["mode"],
    }


def prune_request(
    checkpoint: dict[str, Any],
    request_id: str,
    cutoff: str,
    target_mode: str,
    *,
    expected_from: dict[str, Any] | None = None,
    dependencies: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_prune_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(expected_from or checkpoint),
        "cutoff_receipt_sequence": cutoff,
        "target_mode": target_mode,
        "policy_identifier": "bounded-native-v2" if target_mode == "bounded" else None,
        "dependency_receipt_sequences": dependencies or [],
        "dependency_effect_ids": [],
    }


def tombstone_request(
    checkpoint: dict[str, Any],
    request_id: str,
    *,
    expected_from: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root_record = checkpoint["root_record"]
    terminal_status = (
        root_record["terminal_status"]
        if root_record["status"] == "tombstone"
        else "completed"
    )
    return {
        "operation": "checkpoint_tombstone_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(expected_from or checkpoint),
        "tombstone_operation_id": request_id,
        "terminal_status": terminal_status,
        "retention_mode": checkpoint["replay_retention"]["mode"],
    }


def deletion_probe_request(
    checkpoint: dict[str, Any],
    request_id: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_delete_retained_record_v2",
        "request_id": request_id,
        "deletion_operation_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(checkpoint),
        "target": target,
    }


STANDARD_REGISTRATIONS = [
    {
        "adapter_identifier": "memory",
        "uri_scheme": "memory",
        "source": "bundled",
        "configuration_schema": {"type": "object", "additionalProperties": False},
        "capabilities": ["ephemeral"],
    },
    {
        "adapter_identifier": "file",
        "uri_scheme": "file",
        "source": "bundled",
        "configuration_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "capabilities": ["restart_persistent"],
    },
    {
        "adapter_identifier": "sqlite",
        "uri_scheme": "sqlite",
        "source": "bundled",
        "configuration_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "capabilities": [
            "restart_persistent",
            "durable_single_writer",
            "root_identity_retention",
        ],
    },
    {
        "adapter_identifier": "postgresql",
        "uri_scheme": "postgresql",
        "source": "third_party",
        "configuration_schema": {
            "type": "object",
            "properties": {"dsn": {"type": "string"}},
            "required": ["dsn"],
            "additionalProperties": False,
        },
        "capabilities": [
            "restart_persistent",
            "durable_concurrent",
            "shared_application_transaction",
            "root_identity_retention",
        ],
    },
    {
        "adapter_identifier": "vendor-http",
        "uri_scheme": "vendor+https",
        "source": "third_party",
        "configuration_schema": {
            "type": "object",
            "additionalProperties": False,
        },
        "capabilities": ["restart_persistent"],
    },
]


def resolve_adapter_request(
    request_id: str,
    adapter: str,
    *,
    configuration: dict[str, Any] | None = None,
    capabilities: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_resolve_adapter_v2",
        "request_id": request_id,
        "adapter_identifier": adapter,
        "uri": f"{next((item['uri_scheme'] for item in STANDARD_REGISTRATIONS if item['adapter_identifier'] == adapter), adapter)}://conformance",
        "configuration": configuration or ({"path": "state.db"} if adapter == "sqlite" else {}),
        "requested_capabilities": capabilities or [],
        "registrations": copy.deepcopy(STANDARD_REGISTRATIONS),
    }


def capability_request(
    request_id: str,
    profile: str,
    store_capabilities: list[str],
    host_guarantees: list[str],
    *,
    adapter: str = "sqlite",
    retention_mode: str = "permanent",
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_validate_capabilities_v2",
        "request_id": request_id,
        "adapter_identifier": adapter,
        "store_capabilities": store_capabilities,
        "host_profile": profile,
        "host_guarantees": host_guarantees,
        "retention_mode": retention_mode,
    }


def registration_request(
    request_id: str,
    registration: dict[str, Any],
    existing: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_register_adapter_v2",
        "request_id": request_id,
        "registration": copy.deepcopy(registration),
        "existing_registrations": copy.deepcopy(existing),
    }


def backup_request(
    checkpoint: dict[str, Any],
    request_id: str,
    action: str,
    *,
    complete: bool,
) -> dict[str, Any]:
    return {
        "operation": "checkpoint_backup_restore_v2",
        "request_id": request_id,
        "scope": scope(),
        "action": action,
        "checkpoint_digests": [checkpoint["execution_checkpoint_digest"]],
        "trusted_artifact_digests": (
            [aggregate_of(checkpoint)["validated_bundle_fingerprint"]]
            if complete and checkpoint["root_record"]["status"] == "retained"
            else []
        ),
        "adapter_metadata_digest": digest(
            ["determa-backup-adapter-metadata-2", "primary"]
        ),
        "retention_mode": checkpoint["replay_retention"]["mode"],
    }


def inject_store_request(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation": "checkpoint_inject_store_v2",
        "request_id": "inject-store",
        "scope": scope(),
        "store_adapter_identifier": "injected-store",
        "store_uri": "object://injected-store",
        "configuration": {"instance": "provided"},
        "capabilities": [
            "durable_single_writer",
            "root_identity_retention",
        ],
    }


def scope_request(
    checkpoint: dict[str, Any],
    request_id: str,
    authorization: str,
    *,
    scope_id: str = "primary",
) -> dict[str, Any]:
    portable_identity = checkpoint["root_instance_id"]
    effect_id = digest(["determa-scope-effect-2", portable_identity])
    return {
        "operation": "checkpoint_scope_operation_v2",
        "request_id": request_id,
        "scope": scope(scope_id, authorization),
        "portable_identity": portable_identity,
        "effect_id": effect_id,
        "operation_context": "outbox",
        "store_records": (
            [
                {
                    "scope_id": scope_id,
                    "ownership_binding": f"owner:{scope_id}",
                    "portable_identity": portable_identity,
                    "effect_id": effect_id,
                }
            ]
            if authorization == "authorized"
            else []
        ),
    }


def persistence_request(
    checkpoint: dict[str, Any],
    request_id: str,
    envelope: dict[str, Any],
    envelope_digest: str,
    *,
    failure_policy: str = "commit",
    target_validated_bundle_fingerprint: str | None = None,
    migration_descriptor_digest_route: list[str] | None = None,
) -> dict[str, Any]:
    aggregate = aggregate_of(checkpoint)
    return {
        "operation": "persistence_process_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(checkpoint),
        "presented_envelope": copy.deepcopy(envelope),
        "envelope_digest": envelope_digest,
        "transaction_inputs": {
            "target_validated_bundle_fingerprint": aggregate[
                "validated_bundle_fingerprint"
            ]
            if target_validated_bundle_fingerprint is None
            else target_validated_bundle_fingerprint,
            "migration_descriptor_digest_route": migration_descriptor_digest_route
            or [],
            "application_writes": {"aggregate_version": 1},
            "failure_policy": failure_policy,
        },
        "store_adapter_identifier": "sqlite",
        "store_capabilities": [
            "restart_persistent",
            "durable_single_writer",
            "root_identity_retention",
            "shared_application_transaction",
        ],
        "host_profile": "shared_application_transaction",
        "host_guarantees": ["native_shared_transaction_used"],
        "retention_mode": checkpoint["replay_retention"]["mode"],
    }


def release_request(
    checkpoint: dict[str, Any],
    request_id: str,
    envelope: dict[str, Any],
    envelope_digest: str,
) -> dict[str, Any]:
    return {
        "operation": "persistence_release_quarantine_v2",
        "request_id": request_id,
        "scope": scope(),
        "expected_checkpoint": expected_checkpoint(checkpoint),
        "event_id": envelope["event_id"],
        "envelope_digest": envelope_digest,
        "quarantine_reason_code": "permanent_processing_failure",
        "release_authorization": "operator:conformance",
    }


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


def admit_batch(
    checkpoint: dict[str, Any], members: list[dict[str, Any]]
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    revision = str(int(value["revision"]) + 1)
    for member in members:
        envelope, request_digest = default_envelope(
            checkpoint,
            member["event_id"],
            event=member.get("event", "increment"),
            payload=member.get("payload"),
            target=member.get("target"),
            source=member.get("source"),
            correlation_id=member.get("correlation_id"),
            delivery_mode=member.get("delivery_mode", "input"),
        )
        target_runtime = next(
            runtime
            for runtime in aggregate["runtimes"]
            if runtime["target_identity"] == envelope["target"]
        )
        acceptance_sequence = aggregate["next_acceptance_sequence"]
        queue_sequence = aggregate["next_queue_sequence"]
        aggregate["next_acceptance_sequence"] = str(int(acceptance_sequence) + 1)
        aggregate["next_queue_sequence"] = str(int(queue_sequence) + 1)
        target_runtime["ready_mailbox"].append(
            {
                "envelope": envelope,
                "envelope_digest": request_digest,
                "delivery_mode": member.get("delivery_mode", "input"),
                "acceptance_sequence": acceptance_sequence,
                "queue_sequence": queue_sequence,
                "deferral_count": "0",
            }
        )
        receipt_sequence = value["next_operation_receipt_sequence"]
        value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
        value["operation_receipts"].append(
            {
                "operation_kind": "acceptance",
                "receipt_sequence": receipt_sequence,
                "event_id": envelope["event_id"],
                "request_digest": request_digest,
                "acceptance_sequence": acceptance_sequence,
                "accepted_revision": revision,
                "delivery_mode": member.get("delivery_mode", "input"),
            }
        )
    value["revision"] = revision
    value["root_record"]["aggregate_state"] = seal_aggregate(aggregate)
    return seal_checkpoint(value)


def process(
    checkpoint: dict[str, Any], *, bundle_path: Path | None = None
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
    elif entry["envelope"]["event"] == "complete":
        runtime["next_state_activation_sequences"].append(
            {
                "definition_pointer": "/machines/0/root/states/finished",
                "next_sequence": "1",
            }
        )
        runtime["status"] = "completed"
        runtime["active_leaf_state_definition_pointers"] = []
        runtime["active_state_activations"] = []
        runtime["variables"] = []
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    references = []
    external_actions: list[tuple[str, dict[str, Any]]] = []
    machine_identity = runtime["current_definition"]["machine"]
    if bundle_path is not None:
        bundle = normalize_bundle_document(load_yaml(bundle_path))
        machine_index, machine = next(
            (index, candidate)
            for index, candidate in enumerate(bundle["machines"])
            if candidate["machine_id"] == machine_identity["machine_id"]
            and str(candidate["version"]) == machine_identity["machine_version"]
        )
        handler = machine["root"].get("on_events", {}).get(
            entry["envelope"]["event"]
        )
        handler_candidates = handler if isinstance(handler, list) else [handler]
        has_external_send = any(
            isinstance(candidate, dict)
            and any(
                isinstance(action, dict)
                and isinstance(action.get("send"), dict)
                and action["send"].get("to") == {"external": True}
                for action in candidate.get("action", [])
            )
            for candidate in handler_candidates
        )
        if has_external_send and (
            isinstance(handler, list)
            or not isinstance(handler, dict)
            or "guard" in handler
        ):
            raise RuntimeError(
                "durable profile generator cannot select guarded or alternative "
                "external-output handlers"
            )
        transitions = handler_candidates
        for transition_index, transition in enumerate(transitions):
            if not isinstance(transition, dict):
                continue
            for action_index, action in enumerate(transition.get("action", [])):
                send = action.get("send") if isinstance(action, dict) else None
                if isinstance(send, dict) and send.get("to") == {"external": True}:
                    transition_suffix = (
                        f"/{transition_index}" if isinstance(handler, list) else ""
                    )
                    external_actions.append(
                        (
                            f"/machines/{machine_index}/root/on_events/"
                            f"{entry['envelope']['event']}{transition_suffix}/"
                            f"action/{action_index}/send",
                            send,
                        )
                    )
    input_payload = {
        name: value[1] for name, value in entry["envelope"]["payload"][1]
    }
    for action_pointer, send in external_actions:
        sequence = aggregate["next_output_sequence"]
        aggregate["next_output_sequence"] = str(int(sequence) + 1)
        output_payload = {
            name: int(expression)
            for name, expression in send.get("payload", {}).items()
        }
        correlation_expression = send["correlation_id"]
        correlation_id = input_payload[correlation_expression.rsplit(".", 1)[1]]
        intent = {
            "effect_id": digest(
                [
                    "determa-effect-identity-1",
                    "1",
                    [
                        machine_identity["namespace"],
                        machine_identity["machine_id"],
                        machine_identity["machine_version"],
                    ],
                    aggregate["root_instance_id"],
                    runtime["runtime_id"],
                    entry["envelope"]["cause_id"],
                    str(int(aggregate["next_logical_step_sequence"]) - 1),
                    action_pointer,
                    "0",
                ]
            ),
            "sequence": sequence,
            "event": send["event"],
            "payload": typed_value(output_payload),
            "correlation_id": correlation_id,
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
                "emission_index": "0",
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


def process_with_disposition(
    checkpoint: dict[str, Any], disposition: str
) -> dict[str, Any]:
    if disposition == "unhandled":
        value = copy.deepcopy(checkpoint)
        aggregate = value["root_record"]["aggregate_state"]
        runtime = root_runtime(value)
        entry = runtime["ready_mailbox"].pop(0)
        value["revision"] = str(int(value["revision"]) + 1)
        receipt_sequence = value["next_operation_receipt_sequence"]
        value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
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
                "resulting_aggregate_state_digest": aggregate[
                    "aggregate_state_digest"
                ],
                "outcome": {
                    "disposition": "unhandled",
                    "status": runtime["status"],
                    "fault": None,
                    "rejection": None,
                },
                "emission_references": [],
            }
        )
        return seal_checkpoint(value)

    value = process(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    runtime = root_runtime(value)
    receipt = value["operation_receipts"][-1]
    outcome = receipt["outcome"]
    outcome["disposition"] = disposition
    outcome["rejection"] = None
    outcome["fault"] = None
    if disposition == "rejected":
        outcome["rejection"] = {"code": "invalid_event"}
    elif disposition == "faulted":
        fault = {
            "definition_fingerprint": aggregate["validated_bundle_fingerprint"],
            "runtime_id": runtime["runtime_id"],
            "cause_id": receipt["event_id"],
            "code": "action_fault",
            "step_sequence": str(int(aggregate["next_logical_step_sequence"]) - 1),
            "source_locator": "/machines/0/root/on_events/fail/action/0/assign/count",
        }
        runtime["status"] = "faulted"
        runtime["fault"] = fault
        outcome["status"] = "faulted"
        outcome["fault"] = fault
        aggregate = seal_aggregate(aggregate)
        value["root_record"]["aggregate_state"] = aggregate
        receipt["resulting_aggregate_state_digest"] = aggregate[
            "aggregate_state_digest"
        ]
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
    cutoff = int(terminal["receipt_sequence"])
    value["operation_receipts"] = [
        receipt
        for receipt in value["operation_receipts"]
        if receipt["operation_kind"] == "creation"
        or int(receipt["receipt_sequence"]) > cutoff
    ]
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
    if runtime["status"] not in {"completed", "faulted"}:
        raise RuntimeError("root tombstones require a terminal aggregate")
    if any(
        runtime["ready_mailbox"] or runtime["deferred_mailbox"]
        for runtime in aggregate["runtimes"]
    ) or value["pending_outbox_intents"]:
        raise RuntimeError("root tombstones require no pending engine-owned work")
    value["revision"] = str(int(value["revision"]) + 1)
    value["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": aggregate["root_runtime_id"],
        "creation_id": aggregate["creation_id"],
        "terminal_status": runtime["status"],
        "final_aggregate_state_digest": aggregate["aggregate_state_digest"],
        "tombstone_operation_id": operation_id,
    }
    return seal_checkpoint(value)


def generate_delivery() -> dict[Path, bytes]:
    case = PROFILE / "execution-checkpoint" / "checkpoint-01-native-lifecycle"
    created = create_checkpoint(case, "checkpoint-lifecycle-root", "checkpoint-lifecycle-create")
    accepted = admit(created, "increment", "delivery-increment", {"amount": 2})
    processed = process(accepted)
    stale_process = processing_request(accepted, "stale-process")
    stale_process["writer_checkpoint_context"] = writer_checkpoint_context(
        accepted, processed
    )
    inputs = request_document(
        {
            "create": creation_request(case, created, "create"),
            "create_replay": creation_request(case, created, "create", existing=True),
            "create_conflict": creation_request(
                case,
                created,
                "different-create",
                existing=True,
                creation_id="different-create",
            ),
            "accept": admission_request(
                created,
                "delivery-increment",
                payload={"amount": 2},
            ),
            "accept_replay": admission_request(
                processed,
                "delivery-increment",
                payload={"amount": 2},
            ),
            "process": processing_request(accepted, "process-delivery"),
            "process_crash": processing_request(accepted, "process-crash"),
            "stale_process": stale_process,
            "wrong_root": admission_batch_request(
                processed,
                "wrong-root",
                [
                    {
                        "event_id": "wrong-root-duplicate",
                        "target": {
                            "root": {
                                "root_instance_id": "foreign-root",
                                "root_runtime_id": root_runtime(processed)["runtime_id"],
                            }
                        },
                    },
                    {
                        "event_id": "wrong-root-duplicate",
                        "target": {
                            "root": {
                                "root_instance_id": "foreign-root",
                                "root_runtime_id": root_runtime(processed)["runtime_id"],
                            }
                        },
                    },
                ],
            ),
            "event_conflict": admission_request(
                processed,
                "delivery-increment",
                payload={"amount": 9},
            ),
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
    pending = process(admitted, bundle_path=case / "machine.yaml")
    retryable = update_pending(pending, 0, "retryable_failure")
    ambiguous = update_pending(retryable, 1, "ambiguous")
    statuses = ["confirmed", "permanently_rejected", "operator_cancelled", "discarded", "dead_lettered"]
    terminal_states: list[dict[str, Any]] = []
    terminal = ambiguous
    terminal_requests: dict[str, dict[str, Any]] = {}
    for status in statuses:
        effect_id = terminal["pending_outbox_intents"][0]["intent"]["effect_id"]
        terminal_requests[f"terminal_{status}"] = outbox_request(
            terminal,
            f"terminalize-{status}",
            effect_id,
            status,
            terminal=True,
        )
        terminal = terminalize(terminal, 0, status)
        terminal_states.append(terminal)
    compacted = compact(terminal, 0)
    pending_effects = [item["intent"]["effect_id"] for item in pending["pending_outbox_intents"]]
    inputs = request_document(
        {
            "pending": processing_request(
                admitted, "emit-outputs", event_id="delivery-outputs"
            ),
            "retryable": outbox_request(
                pending, "retryable", pending_effects[0], "retryable_failure", terminal=False
            ),
            "retryable_replay": outbox_request(
                retryable, "retryable", pending_effects[0], "retryable_failure", terminal=False
            ),
            "ambiguous": outbox_request(
                retryable, "ambiguous", pending_effects[1], "ambiguous", terminal=False
            ),
            **terminal_requests,
            "terminal_replay": outbox_request(
                terminal,
                "terminalize-dead_lettered",
                pending_effects[4],
                "dead_lettered",
                terminal=True,
            ),
            "conflict": outbox_request(
                terminal,
                "terminalize-conflict",
                pending_effects[0],
                "discarded",
                terminal=True,
            ),
            "compact": compact_request(terminal, "compact", pending_effects[0]),
            "delete": deletion_probe_request(
                compacted,
                "delete-outbox-tombstone",
                {
                    "kind": "outbox_effect_tombstone",
                    "effect_id": pending_effects[0],
                },
            ),
            "prune_effect_dependency": {
                **prune_request(terminal, "prune-effect-dependency", "2", "bounded"),
                "dependency_effect_ids": [pending_effects[0]],
            },
            "prune_producer_dependency": prune_request(
                terminal,
                "prune-producer-dependency",
                "2",
                "bounded",
                dependencies=["2"],
            ),
        }
    )
    results = result_document(
        {
            "committed": result("committed", "atomic", 0),
            "processing_committed": result("committed", "atomic", 1),
            "replayed": result("replayed", "none", 0),
            "conflict": result("rejected", "none", 0, code="effect_id_conflict"),
            "deletion_rejected": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
        }
    )
    return {
        case / "accepted-checkpoint-v2.json": write_json(case / "x", admitted),
        case / "pending-checkpoint-v2.json": write_json(case / "x", pending),
        case / "retryable-checkpoint-v2.json": write_json(case / "x", retryable),
        case / "ambiguous-checkpoint-v2.json": write_json(case / "x", ambiguous),
        case / "terminal-confirmed-checkpoint-v2.json": write_json(case / "x", terminal_states[0]),
        case / "terminal-permanently-rejected-checkpoint-v2.json": write_json(case / "x", terminal_states[1]),
        case / "terminal-operator-cancelled-checkpoint-v2.json": write_json(case / "x", terminal_states[2]),
        case / "terminal-discarded-checkpoint-v2.json": write_json(case / "x", terminal_states[3]),
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
    completion_accepted = admit(bounded, "complete", "retention-complete", {})
    completed = process(completion_accepted)
    tombstoned = tombstone(completed, "root-tombstone")
    reuse = creation_request(
        case,
        created,
        "reuse",
        creation_id="reuse",
    )
    reuse["existing_checkpoint"] = expected_checkpoint(tombstoned)
    operations = {
        "complete_process": processing_request(
            completion_accepted,
            "complete-process",
            event_id="retention-complete",
        ),
        "prune": prune_request(processed, "prune", "2", "bounded"),
        "prune_replay": prune_request(bounded, "prune", "2", "bounded"),
        "prune_lower": prune_request(bounded, "prune-lower", "1", "bounded"),
        "prune_stale": prune_request(
            completed,
            "prune-stale",
            "4",
            "bounded",
            expected_from=bounded,
        ),
        "tombstone": tombstone_request(completed, "root-tombstone"),
        "tombstone_running": tombstone_request(bounded, "root-tombstone-running"),
        "tombstone_replay": tombstone_request(tombstoned, "root-tombstone"),
        "reuse": reuse,
        "delete": deletion_probe_request(
            tombstoned,
            "delete-root-identity",
            {
                "kind": "root_identity",
                "root_instance_id": tombstoned["root_instance_id"],
            },
        ),
        "resolve_adapter": resolve_adapter_request(
            "resolve-adapter", "sqlite", capabilities=["durable_single_writer"]
        ),
        "validate_capabilities": capability_request(
            "validate-capabilities",
            "durable_embedded_processing",
            ["restart_persistent", "durable_single_writer", "root_identity_retention"],
            ["atomic_accept_process"],
        ),
        "scope": scope_request(created, "scope", "mismatched", scope_id="scope-a"),
    }
    results = result_document(
        {
            "committed": result("committed", "atomic", 0),
            "processing_committed": result("committed", "atomic", 1),
            "replayed": result("replayed", "none", 0),
            "invalid_cutoff": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
            "stale": result("rejected", "none", 0, code="checkpoint_revision_conflict"),
            "running_root": result(
                "rejected", "none", 0, code="invalid_execution_checkpoint"
            ),
            "no_reuse": result("rejected", "none", 0, code="creation_id_conflict"),
            "deletion_unsupported": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
            "validated": result("validated", "none", 0),
            "scope_rejected": result("rejected", "none", 0, code="invalid_store_scope"),
        }
    )
    return {
        case / "processed-checkpoint-v2.json": write_json(case / "x", processed),
        case / "bounded-checkpoint-v2.json": write_json(case / "x", bounded),
        case / "completion-accepted-checkpoint-v2.json": write_json(
            case / "x", completion_accepted
        ),
        case / "completed-checkpoint-v2.json": write_json(case / "x", completed),
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


def start_spawned_runtime(checkpoint: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    owner = root_runtime(value)
    entry = owner["ready_mailbox"].pop(0)
    if entry["envelope"]["event"] != "start":
        raise RuntimeError("spawn trace must start with the declared start event")
    spawn_sequence = owner["next_spawn_sequence"]
    owner["next_spawn_sequence"] = str(int(spawn_sequence) + 1)
    action_pointer = "/machines/0/root/states/idle/on_events/start/action/0/spawn"
    child_runtime_id = digest(
        [
            "determa-spawned-runtime-identity-1",
            "1",
            aggregate["root_instance_id"],
            owner["runtime_id"],
            action_pointer,
            spawn_sequence,
            aggregate["namespace"],
            "payment",
            "1",
        ]
    )
    target_reference = {
        "root_instance_id": aggregate["root_instance_id"],
        "instance_id": child_runtime_id,
        "machine_id": "payment",
        "machine_version": "1",
    }
    logical_reference = copy.deepcopy(target_reference)
    logical_reference["machine_version"] = 1
    for variable in owner["variables"]:
        if variable["variable_declaration_pointer"].endswith("/payment_reference"):
            variable["value"] = typed_value(logical_reference)
    owner["active_leaf_state_definition_pointers"] = [
        "/machines/0/root/states/checkout"
    ]
    owner["active_state_activations"] = [
        item
        for item in owner["active_state_activations"]
        if item["state_definition_pointer"] == "/machines/0/root"
    ] + [
        {
            "state_definition_pointer": "/machines/0/root/states/checkout",
            "activation_sequence": "0",
        }
    ]
    owner["next_state_activation_sequences"].append(
        {
            "definition_pointer": "/machines/0/root/states/checkout",
            "next_sequence": "1",
        }
    )
    definition = {
        "validated_bundle_fingerprint": aggregate["validated_bundle_fingerprint"],
        "machine": {
            "namespace": aggregate["namespace"],
            "machine_id": "payment",
            "machine_version": "1",
            "root_definition_pointer": "/machines/1/root",
        },
    }
    aggregate["runtimes"].append(
        {
            "runtime_id": child_runtime_id,
            "identity_origin": {
                "kind": "owned_spawned_instance",
                "definition": copy.deepcopy(definition),
                "owner_runtime_id": owner["runtime_id"],
                "spawn_action_pointer": action_pointer,
                "spawn_sequence": spawn_sequence,
            },
            "target_identity": {"spawned_instance": target_reference},
            "current_definition": copy.deepcopy(definition),
            "relation": {
                "kind": "owned_spawned_instance",
                "owner_runtime_id": owner["runtime_id"],
                "current_spawn_action_pointer": action_pointer,
                "spawn_sequence": spawn_sequence,
                "lifetime_holder": {
                    "holder_runtime_id": owner["runtime_id"],
                    "variable_declaration_pointer": "/machines/0/root/variables/payment_reference",
                    "holder_state_activation_sequence": "0",
                },
            },
            "status": "running",
            "active_leaf_state_definition_pointers": [
                "/machines/1/root/states/awaiting"
            ],
            "active_state_activations": [
                {
                    "state_definition_pointer": "/machines/1/root",
                    "activation_sequence": "0",
                },
                {
                    "state_definition_pointer": "/machines/1/root/states/awaiting",
                    "activation_sequence": "0",
                },
            ],
            "variables": [
                {
                    "variable_declaration_pointer": "/machines/1/root/variables/due",
                    "declaring_state_activation_sequence": "0",
                    "value": ["integer", "100"],
                },
                {
                    "variable_declaration_pointer": "/machines/1/root/variables/paid",
                    "declaring_state_activation_sequence": "0",
                    "value": ["integer", "0"],
                },
            ],
            "history": [],
            "next_spawn_sequence": "0",
            "next_state_activation_sequences": [
                {"definition_pointer": "/machines/1/root", "next_sequence": "1"},
                {
                    "definition_pointer": "/machines/1/root/states/awaiting",
                    "next_sequence": "1",
                },
            ],
            "next_component_activation_sequences": [],
            "fault": None,
            "ready_mailbox": [],
            "deferred_mailbox": [],
        }
    )
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
            "event_id": entry["envelope"]["event_id"],
            "request_digest": entry["envelope_digest"],
            "acceptance_sequence": entry["acceptance_sequence"],
            "final_queue_sequence": entry["queue_sequence"],
            "committed_revision": value["revision"],
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "outcome": {
                "disposition": "handled",
                "status": owner["status"],
                "fault": None,
                "rejection": None,
            },
            "emission_references": [],
        }
    )
    return seal_checkpoint(value)


def complete_spawned_runtime(
    checkpoint: dict[str, Any], event_id: str
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    child = next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["relation"]["kind"] == "owned_spawned_instance"
    )
    owner = next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["runtime_id"] == child["relation"]["owner_runtime_id"]
    )
    entry = next(
        item for item in child["ready_mailbox"] if item["envelope"]["event_id"] == event_id
    )
    child["ready_mailbox"].remove(entry)
    step_sequence = aggregate["next_logical_step_sequence"]
    aggregate["next_logical_step_sequence"] = str(int(step_sequence) + 1)
    event_identity = digest(
        [
            "determa-event-identity-1",
            "1",
            aggregate["root_instance_id"],
            child["runtime_id"],
            owner["runtime_id"],
            entry["envelope"]["cause_id"],
            step_sequence,
            "system:spawned_completion",
            "0",
        ]
    )
    reference = copy.deepcopy(child["target_identity"]["spawned_instance"])
    payload_reference = copy.deepcopy(reference)
    payload_reference["machine_version"] = int(
        payload_reference["machine_version"]
    )
    completion_envelope = {
        "event": "done",
        "event_id": event_identity,
        "cause_id": entry["envelope"]["cause_id"],
        "source": {"system": "system:spawned_completion"},
        "target": copy.deepcopy(owner["target_identity"]),
        "payload": typed_value(
            {
                "relationship": "spawned_instance",
                "instance": payload_reference,
                "instance_id": reference["instance_id"],
                "machine_id": reference["machine_id"],
                "machine_version": payload_reference["machine_version"],
            }
        ),
    }
    acceptance_sequence = aggregate["next_acceptance_sequence"]
    queue_sequence = aggregate["next_queue_sequence"]
    aggregate["next_acceptance_sequence"] = str(int(acceptance_sequence) + 1)
    aggregate["next_queue_sequence"] = str(int(queue_sequence) + 1)
    completion_digest = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            aggregate["root_instance_id"],
            "internal",
            completion_envelope,
        ]
    )
    owner["ready_mailbox"].append(
        {
            "envelope": completion_envelope,
            "envelope_digest": completion_digest,
            "delivery_mode": "internal",
            "acceptance_sequence": acceptance_sequence,
            "queue_sequence": queue_sequence,
            "deferral_count": "0",
        }
    )
    aggregate["runtimes"].remove(child)
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
                "status": owner["status"],
                "fault": None,
                "rejection": None,
            },
            "emission_references": [
                {
                    "kind": "internal_mailbox",
                    "emission_index": "0",
                    "event_id": event_identity,
                    "acceptance_sequence": acceptance_sequence,
                    "queue_sequence": queue_sequence,
                }
            ],
        }
    )
    return seal_checkpoint(value)


def process_spawned_done(
    checkpoint: dict[str, Any], *, terminal: bool
) -> dict[str, Any]:
    value = copy.deepcopy(checkpoint)
    aggregate = value["root_record"]["aggregate_state"]
    owner = root_runtime(value)
    entry = owner["ready_mailbox"].pop(0)
    if entry["envelope"]["event"] != "done":
        raise RuntimeError("spawn completion must process the queued owner done event")
    aggregate["next_logical_step_sequence"] = str(
        int(aggregate["next_logical_step_sequence"]) + 1
    )
    if terminal:
        owner["status"] = "completed"
        owner["active_leaf_state_definition_pointers"] = []
        owner["active_state_activations"] = []
        owner["variables"] = []
    else:
        owner["active_leaf_state_definition_pointers"] = [
            "/machines/0/root/states/paid"
        ]
        owner["active_state_activations"] = [
            item
            for item in owner["active_state_activations"]
            if item["state_definition_pointer"] == "/machines/0/root"
        ] + [
            {
                "state_definition_pointer": "/machines/0/root/states/paid",
                "activation_sequence": "0",
            }
        ]
    owner["next_state_activation_sequences"].append(
        {
            "definition_pointer": "/machines/0/root/states/paid",
            "next_sequence": "1",
        }
    )
    aggregate = seal_aggregate(aggregate)
    value["root_record"]["aggregate_state"] = aggregate
    value["revision"] = str(int(value["revision"]) + 1)
    receipt_sequence = value["next_operation_receipt_sequence"]
    value["next_operation_receipt_sequence"] = str(int(receipt_sequence) + 1)
    producer_reference = next(
        reference
        for receipt in value["operation_receipts"]
        for reference in receipt.get("emission_references", [])
        if reference.get("kind") == "internal_mailbox"
        and reference["event_id"] == entry["envelope"]["event_id"]
    )
    producer_reference["kind"] = "internal_terminal"
    producer_reference.pop("queue_sequence")
    producer_reference["terminal_receipt_sequence"] = receipt_sequence
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
                "status": owner["status"],
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
    started = start_spawned_runtime(start_pending)
    spawned_aggregate = aggregate_of(started)
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
    child_terminal = complete_spawned_runtime(root_pending, "spawned-pay")
    owner_event_terminal = process_with_disposition(child_terminal, "unhandled")
    final = process_spawned_done(owner_event_terminal, terminal=terminal)
    if terminal:
        final_root = root_runtime(final)
        if final_root["status"] != "completed":
            raise RuntimeError("terminal spawned trace did not complete the root")
    inputs = request_document(
        {
            "create": creation_request(case, base, f"{name}-create"),
            "start_accept": admission_request(
                base, "spawn-start", event="start", payload={}
            ),
            "start_process": processing_request(start_pending, f"{name}-start"),
            "child_accept": admission_request(
                started,
                "spawned-pay",
                event="pay",
                payload={"amount": 100},
                target=spawned_runtime["target_identity"],
            ),
            "root_accept": admission_request(
                child_pending,
                "spawned-root-followup",
                event="start",
                payload={},
                target=root_runtime(child_pending)["target_identity"],
            ),
            "child_process": processing_request(
                root_pending, f"{name}-child-process", event_id="spawned-pay"
            ),
            "root_process": processing_request(
                child_terminal,
                f"{name}-root-process",
                event_id="spawned-root-followup",
            ),
            "done_process": processing_request(
                owner_event_terminal,
                f"{name}-done-process",
            ),
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
        case / "spawned-owner-event-terminal-checkpoint-v2.json": write_json(
            case / "x", owner_event_terminal
        ),
        case
        / (
            "spawned-terminal-checkpoint-v2.json"
            if terminal
            else "spawned-owner-done-checkpoint-v2.json"
        ): write_json(case / "x", final),
        case / "inputs-v2.json": write_json(case / "x", inputs),
        case / "results-v2.json": write_json(case / "x", results),
    }
    return output


def store(checkpoint: dict[str, Any], *, inbox: list[dict[str, Any]] | None = None, application_rows: dict[str, Any] | None = None, quarantine: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "durable_host_store_format": "determa.durable_host.store",
        "durable_host_store_schema_version": 2,
        "checkpoint": checkpoint,
        "inbox": inbox or [],
        "application_rows": application_rows or {},
        "quarantine": quarantine,
    }


def call_log(calls: list[str]) -> dict[str, Any]:
    return {"durable_host_call_log_format": "determa.durable_host.call_log", "durable_host_call_log_schema_version": 2, "calls": calls}


def compatible_descriptor(source_machine: Path, target_machine: Path) -> dict[str, Any]:
    source = normalize_bundle_document(load_yaml(source_machine))
    target = normalize_bundle_document(load_yaml(target_machine))
    descriptor = {
        "migration_descriptor_format": "determa.aggregate_migration",
        "migration_descriptor_schema_version": 2,
        "source_machine_format": 1,
        "target_machine_format": 1,
        "source_validated_bundle_fingerprint": bundle_fingerprint_document(source),
        "target_validated_bundle_fingerprint": bundle_fingerprint_document(target),
        "source_aggregate_shape_fingerprint": aggregate_shape_fingerprint_document(
            source
        ),
        "target_aggregate_shape_fingerprint": aggregate_shape_fingerprint_document(
            target
        ),
        "mode": "compatible",
        "mappings": {
            "machines": [],
            "active_states": [],
            "variables": [],
            "history": [],
            "components": [],
            "owned_runtimes": [],
            "lifetime_holders": [],
            "counters": [],
        },
        "terminal_policy": {"completed": "preserve", "faulted": "preserve"},
        "resource_requirements": {
            "maximum_transformed_output_bytes": "0",
            "maximum_cel_expression_length": "0",
            "maximum_cel_ast_nodes": "0",
            "maximum_cel_evaluation_steps": "0",
        },
        "queued_event_default": "preserve_if_compatible",
        "queued_event_rules": [],
    }
    if (
        descriptor["source_aggregate_shape_fingerprint"]
        != descriptor["target_aggregate_shape_fingerprint"]
    ):
        raise RuntimeError("compatible persistence migration changed aggregate shape")
    descriptor["migration_descriptor_digest"] = digest(
        ["determa-migration-descriptor-2", descriptor]
    )
    return descriptor


def combined_migrate_and_process(
    checkpoint: dict[str, Any], descriptor: dict[str, Any], event_id: str
) -> tuple[dict[str, Any], dict[str, Any], str]:
    value = copy.deepcopy(checkpoint)
    source_aggregate = aggregate_of(value)
    aggregate = migrate_compatible_aggregate(source_aggregate, descriptor)
    audit = v2_migration_audit_record(source_aggregate, aggregate, descriptor)
    value["migration_audit_records"].append(audit)
    runtime = next(
        item for item in aggregate["runtimes"] if item["relation"]["kind"] == "root"
    )
    envelope = {
        "event": "host_commit",
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": True},
        "target": copy.deepcopy(runtime["target_identity"]),
        "payload": typed_value({"correlation_id": event_id}),
    }
    envelope_digest = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            aggregate["root_instance_id"],
            "input",
            envelope,
        ]
    )
    acceptance_sequence = aggregate["next_acceptance_sequence"]
    queue_sequence = aggregate["next_queue_sequence"]
    step_sequence = aggregate["next_logical_step_sequence"]
    output_sequence = aggregate["next_output_sequence"]
    aggregate["next_acceptance_sequence"] = str(int(acceptance_sequence) + 1)
    aggregate["next_queue_sequence"] = str(int(queue_sequence) + 1)
    aggregate["next_logical_step_sequence"] = str(int(step_sequence) + 1)
    aggregate["next_output_sequence"] = str(int(output_sequence) + 1)
    action_pointer = "/machines/0/root/on_events/host_commit/action/0/send"
    effect_id = digest(
        [
            "determa-effect-identity-1",
            "1",
            [aggregate["namespace"], "counter", "1"],
            aggregate["root_instance_id"],
            runtime["runtime_id"],
            event_id,
            step_sequence,
            action_pointer,
            "0",
        ]
    )
    intent = {
        "effect_id": effect_id,
        "sequence": output_sequence,
        "event": "output_record",
        "payload": typed_value({"aggregate_version": 1}),
        "correlation_id": event_id,
    }
    aggregate = seal_aggregate(aggregate)
    value["root_record"]["aggregate_state"] = aggregate
    value["revision"] = str(int(value["revision"]) + 1)
    accepted_receipt_sequence = value["next_operation_receipt_sequence"]
    terminal_receipt_sequence = str(int(accepted_receipt_sequence) + 1)
    value["next_operation_receipt_sequence"] = str(
        int(terminal_receipt_sequence) + 1
    )
    value["operation_receipts"].extend(
        [
            {
                "operation_kind": "acceptance",
                "receipt_sequence": accepted_receipt_sequence,
                "event_id": event_id,
                "request_digest": envelope_digest,
                "acceptance_sequence": acceptance_sequence,
                "accepted_revision": value["revision"],
                "delivery_mode": "input",
            },
            {
                "operation_kind": "event_terminal",
                "receipt_sequence": terminal_receipt_sequence,
                "event_id": event_id,
                "request_digest": envelope_digest,
                "acceptance_sequence": acceptance_sequence,
                "final_queue_sequence": queue_sequence,
                "committed_revision": value["revision"],
                "resulting_aggregate_state_digest": aggregate[
                    "aggregate_state_digest"
                ],
                "outcome": {
                    "disposition": "handled",
                    "status": runtime["status"],
                    "fault": None,
                    "rejection": None,
                },
                "emission_references": [
                    {
                        "kind": "external_outbox",
                        "emission_index": "0",
                        "effect_id": effect_id,
                    }
                ],
            },
        ]
    )
    value["pending_outbox_intents"].append(
        {
            "intent": intent,
            "state_revision": value["revision"],
            "delivery_state": {"status": "not_attempted"},
        }
    )
    return seal_checkpoint(value), envelope, envelope_digest


def coalesce_persistence_revision(
    source: dict[str, Any], processed: dict[str, Any]
) -> dict[str, Any]:
    value = copy.deepcopy(processed)
    combined_revision = str(int(source["revision"]) + 1)
    first_new_receipt = int(source["next_operation_receipt_sequence"])
    for receipt in value["operation_receipts"]:
        if int(receipt["receipt_sequence"]) < first_new_receipt:
            continue
        if receipt["operation_kind"] == "acceptance":
            receipt["accepted_revision"] = combined_revision
        else:
            receipt["committed_revision"] = combined_revision
    for record in value["pending_outbox_intents"]:
        if int(record["state_revision"]) > int(source["revision"]):
            record["state_revision"] = combined_revision
    value["revision"] = combined_revision
    return seal_checkpoint(value)


def generate_persistence_case(index: int, slug: str) -> dict[Path, bytes]:
    case = PROFILE / "persistence" / f"persistence-{index:02d}-{slug}"
    created = create_checkpoint(case, f"persistence-{index}-root", f"persistence-{index}-create")
    descriptor = None
    if index == 2:
        descriptor = compatible_descriptor(
            case / "machine.yaml", case / "target-machine.yaml"
        )
    event = "host_commit" if index == 2 else "increment"
    payload = (
        {"correlation_id": f"persistence-{index}-event"}
        if index == 2
        else {"amount": 1}
    )
    if descriptor is not None:
        committed_checkpoint, presented_envelope, presented_digest = (
            combined_migrate_and_process(
                created, descriptor, f"persistence-{index}-event"
            )
        )
    else:
        presented_envelope, presented_digest = default_envelope(
            created,
            f"persistence-{index}-event",
            event=event,
            payload=payload,
        )
        accepted = admit(created, event, f"persistence-{index}-event", payload)
        committed_checkpoint = coalesce_persistence_revision(
            created, process(accepted)
        )
    terminal = next(receipt for receipt in committed_checkpoint["operation_receipts"] if receipt["operation_kind"] == "event_terminal")
    inbox = [{"event_id": terminal["event_id"], "request_digest": terminal["request_digest"], "disposition": "committed"}]
    initial = store(created)
    committed = store(
        committed_checkpoint,
        inbox=inbox,
        application_rows={"aggregate_version": 1},
    )
    quarantined = store(created, inbox=[{"event_id": f"persistence-{index}-event", "request_digest": presented_digest, "disposition": "quarantined"}], quarantine={"event_id": f"persistence-{index}-event", "reason_code": "permanent_processing_failure", "released": False})
    released = copy.deepcopy(quarantined)
    released["quarantine"]["released"] = True
    common = ["select_scope", "resolve_artifacts", "validate_capabilities", "begin_transaction", "read_checkpoint", "check_replay"]
    commit_calls = common + ["call_core", "stage_checkpoint", "stage_inbox", "stage_outbox", "stage_audit", "stage_application_rows", "commit"]
    if index != 3:
        commit_calls.append("acknowledge")
    logs = {
        "commit": call_log(commit_calls),
        "replay": call_log(common + ["acknowledge"]),
        "rollback": call_log(common + ["call_core", "stage_checkpoint", "stage_inbox", "stage_outbox", "stage_audit", "rollback"]),
        "quarantine": call_log(["select_scope", "resolve_artifacts", "validate_capabilities", "quarantine"]),
        "release": call_log(["select_scope", "resolve_artifacts", "validate_capabilities", "release_quarantine"]),
    }
    if index == 4:
        logs["transient"] = call_log(common + ["rollback"])
    request_options = (
        {
            "target_validated_bundle_fingerprint": descriptor[
                "target_validated_bundle_fingerprint"
            ],
            "migration_descriptor_digest_route": [
                descriptor["migration_descriptor_digest"]
            ],
        }
        if descriptor is not None
        else {}
    )
    output = {
        case / "initial-store-v2.json": write_json(case / "x", initial),
        case / "committed-store-v2.json": write_json(case / "x", committed),
        case / "quarantined-store-v2.json": write_json(case / "x", quarantined),
        case / "released-store-v2.json": write_json(case / "x", released),
        case / "inputs-v2.json": write_json(case / "x", request_document({
            "process": persistence_request(created, f"persistence-{index}-process", presented_envelope, presented_digest, **request_options),
            "process_precommit_failure": persistence_request(created, f"persistence-{index}-process", presented_envelope, presented_digest, failure_policy="inject_pre_commit", **request_options),
            "process_postcommit_response_loss": persistence_request(created, f"persistence-{index}-process", presented_envelope, presented_digest, failure_policy="inject_post_commit_response_loss", **request_options),
            "process_transient": persistence_request(created, f"persistence-{index}-process", presented_envelope, presented_digest, failure_policy="transient_retry", **request_options),
            "process_permanent": persistence_request(created, f"persistence-{index}-process", presented_envelope, presented_digest, failure_policy="permanent_quarantine", **request_options),
            "replay": persistence_request(committed_checkpoint, f"persistence-{index}-process", presented_envelope, presented_digest, **request_options),
            "release": release_request(created, f"persistence-{index}-release", presented_envelope, presented_digest),
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
    if descriptor is not None:
        output[case / "migration-descriptor-v2.json"] = write_json(
            case / "x", descriptor
        )
    return output


def generate_complete_host_contract() -> dict[Path, bytes]:
    case = PROFILE / "execution-checkpoint" / "checkpoint-07-complete-host-contract"
    created = create_checkpoint(case, "complete-host-root", "complete-host-create")
    accepted = admit(created, "increment", "complete-increment", {"amount": 1})
    handled = process_with_disposition(accepted, "handled")
    unhandled_accepted = admit(created, "ignored", "complete-unhandled", {})
    unhandled = process_with_disposition(unhandled_accepted, "unhandled")
    faulted_accepted = admit(created, "fail", "complete-faulted", {})
    faulted = process_with_disposition(faulted_accepted, "faulted")
    ordered_members = [
        {"event_id": "batch-first", "payload": {"amount": 1}},
        {"event_id": "batch-second", "payload": {"amount": 2}},
    ]
    ordered_batch = admit_batch(created, ordered_members)
    mixed_new_member = {"event_id": "mixed-new", "payload": {"amount": 3}}
    mixed_batch = admit_batch(accepted, [mixed_new_member])
    inactive_aggregate = json.loads(
        (
            ROOT
            / "conformance"
            / "core"
            / "117-version2-mailboxes"
            / "reserved-admission-before.json"
        ).read_text(encoding="utf-8")
    )
    inactive_checkpoint = checkpoint_from_aggregate(
        inactive_aggregate,
        creation_digest=digest(["determa-inactive-component-fixture-2"]),
    )
    inactive_target = next(
        runtime["target_identity"]
        for runtime in inactive_aggregate["runtimes"]
        if runtime["relation"]["kind"] == "component"
        and runtime["status"] == "completed"
    )
    bounded = prune(handled)
    terminal_after_handled = process_with_disposition(
        admit(handled, "fail", "complete-after-handled-fault", {}), "faulted"
    )
    permanent_tombstone = tombstone(
        terminal_after_handled, "permanent-tombstone"
    )
    bounded_tombstone = tombstone(
        prune(terminal_after_handled), "bounded-tombstone"
    )

    invalid_mode = admission_request(
        handled,
        "invalid-mode",
        delivery_mode="unsupported",
        source={"runtime": root_runtime(handled)["target_identity"]},
    )
    invalid_digest = admission_request(handled, "invalid-digest")
    invalid_digest["envelopes"][0]["envelope_digest"] = "sha256:" + "0" * 64
    replay_conflict = admission_request(
        faulted,
        "complete-faulted",
        event="fail",
        payload={"unexpected": 9},
        delivery_mode="unsupported",
    )
    replay_committed = admission_request(
        handled,
        "complete-increment",
        payload={"amount": 1},
        expected_from=created,
    )
    stale_replay_conflict = admission_request(
        handled,
        "complete-increment",
        payload={"amount": 2},
        expected_from=created,
    )
    global_batch_precedence = admission_batch_request(
        created,
        "global-batch-precedence",
        [
            {
                "event_id": "invalid-payload-before-mode",
                "event": "work_completed",
                "payload": {"unexpected": "field"},
            },
            {
                "event_id": "later-invalid-mode",
                "delivery_mode": "unsupported",
            },
        ],
    )
    creation_rejection = creation_request(case, created, "invalid-create")
    creation_rejection["bindings"] = {
        "input": {"undeclared": ["integer", "1"]},
        "external": {},
    }
    concurrent_loser = admission_request(
        created,
        "concurrent-loser",
    )
    concurrent_loser["writer_checkpoint_context"] = writer_checkpoint_context(
        created, accepted
    )
    stale_tombstone = tombstone_request(handled, "stale-tombstone")
    stale_tombstone["writer_checkpoint_context"] = writer_checkpoint_context(
        handled, bounded
    )
    tombstoned_ingress = admission_request(
        bounded_tombstone,
        "after-tombstone",
        target=root_runtime(created)["target_identity"],
    )
    tombstoned_ingress["envelopes"][0]["delivery_mode"] = "unsupported"
    invalid_correlation = admission_request(
        created,
        "invalid-correlation",
        event="work_completed",
        payload={},
    )
    invalid_correlation["envelopes"][0]["envelope_digest"] = "sha256:" + "0" * 64

    memory = STANDARD_REGISTRATIONS[0]
    postgresql = STANDARD_REGISTRATIONS[3]
    vendor_http = STANDARD_REGISTRATIONS[4]
    requests: dict[str, dict[str, Any]] = {
        "creation_rejection": creation_rejection,
        "pending_admission_replay": admission_request(
            accepted,
            "complete-increment",
            payload={"amount": 1},
        ),
        "handled_delayed": processing_request(
            accepted, "handled-delayed", mode="delayed"
        ),
        "handled_foreground": processing_request(
            accepted, "handled-foreground", mode="foreground"
        ),
        "unhandled": processing_request(unhandled_accepted, "unhandled"),
        "rejected": admission_request(
            created,
            "complete-rejected",
            event="undeclared",
            payload={},
        ),
        "faulted": processing_request(faulted_accepted, "faulted"),
        "invalid_mode": invalid_mode,
        "invalid_digest": invalid_digest,
        "replay_conflict": replay_conflict,
        "replay_committed": replay_committed,
        "stale_replay_conflict": stale_replay_conflict,
        "ordered_batch": admission_batch_request(
            created, "ordered-batch", ordered_members
        ),
        "all_replay_batch": admission_batch_request(
            ordered_batch, "all-replay-batch", ordered_members
        ),
        "mixed_replay_new_batch": admission_batch_request(
            accepted,
            "mixed-replay-new-batch",
            [
                {
                    "event_id": "complete-increment",
                    "payload": {"amount": 1},
                },
                mixed_new_member,
            ],
        ),
        "global_batch_precedence": global_batch_precedence,
        "duplicate_event_id_batch": admission_batch_request(
            handled,
            "duplicate-event-id-batch",
            [
                {"event_id": "complete-increment", "payload": {"amount": 1}},
                {"event_id": "complete-increment", "payload": {"amount": 2}},
            ],
        ),
        "terminal_root": admission_request(
            faulted,
            "terminal-root",
            event="increment",
            payload={"amount": 1},
            delivery_mode="unsupported",
        ),
        "terminal_root_replay": admission_request(
            faulted, "complete-faulted", event="fail", payload={}
        ),
        "invalid_source": admission_request(
            created,
            "invalid-source",
            source={"runtime": root_runtime(created)["target_identity"]},
            target={
                "root": {
                    "root_instance_id": created["root_instance_id"],
                    "root_runtime_id": "sha256:" + "0" * 64,
                }
            },
        ),
        "invalid_instance_target": admission_request(
            created,
            "invalid-instance-target",
            event="undeclared",
            target={
                "root": {
                    "root_instance_id": created["root_instance_id"],
                    "root_runtime_id": "sha256:" + "0" * 64,
                }
            },
        ),
        "inactive_component_target": admission_request(
            inactive_checkpoint,
            "inactive-component-target",
            target=inactive_target,
            event="reserved_failure",
            payload={},
        ),
        "invalid_payload": admission_request(
            created,
            "invalid-payload",
            event="work_completed",
            payload={"unexpected": "field"},
        ),
        "invalid_correlation": invalid_correlation,
        "concurrent_winner": admission_request(
            created, "complete-increment", payload={"amount": 1}
        ),
        "concurrent_loser": concurrent_loser,
        "dependency_live": prune_request(
            accepted, "dependency-live", "1", "bounded", dependencies=["1"]
        ),
        "dependency_terminal_pair": prune_request(
            handled, "dependency-terminal-pair", "1", "bounded", dependencies=["2"]
        ),
        "dependency_closed": prune_request(handled, "dependency-closed", "2", "bounded"),
        "bounded_to_permanent": prune_request(bounded, "bounded-to-permanent", "2", "permanent"),
        "stale_tombstone": stale_tombstone,
        "tombstoned_ingress": tombstoned_ingress,
        "tombstoned_replay": {
            **admission_request(
                handled,
                "complete-increment",
                payload={"amount": 1},
            ),
            "expected_checkpoint": expected_checkpoint(bounded_tombstone),
        },
        "backup_permanent": backup_request(permanent_tombstone, "backup-permanent", "backup", complete=True),
        "restore_permanent": backup_request(permanent_tombstone, "restore-permanent", "restore", complete=True),
        "backup_bounded": backup_request(bounded_tombstone, "backup-bounded", "backup", complete=True),
        "restore_bounded": backup_request(bounded_tombstone, "restore-bounded", "restore", complete=True),
        "restore_incomplete": backup_request(created, "restore-incomplete", "restore", complete=False),
        "inject_store": inject_store_request(created),
        "register_bundled": registration_request("register-bundled", memory, []),
        "register_third_party": registration_request("register-third-party", postgresql, [memory]),
        "register_vendor_http": registration_request(
            "register-vendor-http", vendor_http, [memory]
        ),
        "register_duplicate": registration_request("register-duplicate", memory, [memory]),
        "resolve_unknown": resolve_adapter_request("resolve-unknown", "unknown"),
        "resolve_invalid_config": resolve_adapter_request("resolve-invalid-config", "sqlite", configuration={"path": 7}),
        "resolve_capability_mismatch": resolve_adapter_request("resolve-capability-mismatch", "memory", capabilities=["durable_single_writer"]),
        "resolve_memory": resolve_adapter_request("resolve-memory", "memory"),
        "resolve_file": resolve_adapter_request("resolve-file", "file", configuration={"path": "state.json"}, capabilities=["restart_persistent"]),
        "resolve_sqlite": resolve_adapter_request("resolve-sqlite", "sqlite", capabilities=["durable_single_writer"]),
        "resolve_postgresql": resolve_adapter_request("resolve-postgresql", "postgresql", configuration={"dsn": "postgresql://db/state"}, capabilities=["durable_concurrent", "shared_application_transaction"]),
        "resolve_vendor_http": resolve_adapter_request(
            "resolve-vendor-http", "vendor-http"
        ),
        "scope_a": scope_request(created, "scope-a", "authorized", scope_id="scope-a"),
        "scope_b": scope_request(created, "scope-b", "authorized", scope_id="scope-b"),
        "scope_missing": scope_request(created, "scope-missing", "missing"),
        "scope_ambiguous": scope_request(created, "scope-ambiguous", "ambiguous"),
        "scope_mismatched": scope_request(created, "scope-mismatched", "mismatched"),
        "scope_unauthorized": scope_request(created, "scope-unauthorized", "unauthorized"),
    }

    profile_matrix = {
        "durable_embedded": (
            "durable_embedded_processing",
            ["durable_single_writer", "root_identity_retention"],
            ["atomic_accept_process"],
        ),
        "exactly_once": (
            "exactly_once_committed_processing",
            ["durable_single_writer", "root_identity_retention", "permanent_receipt_retention"],
            ["atomic_accept_process"],
        ),
        "broker": (
            "broker_integrated",
            ["durable_single_writer", "root_identity_retention"],
            ["atomic_accept_process", "ingress_ack_after_commit", "durable_redelivery", "outbox_worker"],
        ),
        "strict_outbox": (
            "strict_durable_outbox",
            ["durable_single_writer", "root_identity_retention", "permanent_outbox_terminal_retention"],
            ["total_outbox_lifecycle", "outbox_worker", "retain_unresolved_outbox"],
        ),
        "compact_outbox": (
            "compact_durable_outbox",
            ["durable_single_writer", "root_identity_retention", "compact_effect_identity_retention"],
            ["total_outbox_lifecycle", "outbox_worker", "retain_receipt_references"],
        ),
        "shared_transaction": (
            "shared_application_transaction",
            ["durable_concurrent", "shared_application_transaction", "root_identity_retention"],
            ["native_shared_transaction_used"],
        ),
    }
    for key, (profile, store_caps, guarantees) in profile_matrix.items():
        requests[f"profile_{key}_positive"] = capability_request(
            f"profile-{key}-positive", profile, store_caps, guarantees
        )
        requests[f"profile_{key}_negative"] = capability_request(
            f"profile-{key}-negative",
            profile,
            store_caps,
            guarantees if key == "exactly_once" else guarantees[:-1],
            retention_mode="bounded" if key == "exactly_once" else "permanent",
        )

    results = result_document(
        {
            "committed": result("committed", "atomic", 1),
            "committed_no_core": result("committed", "atomic", 0),
            "replayed": result("replayed", "none", 0),
            "validated": result("validated", "none", 0),
            "creation_rejected": result("rejected", "none", 1, code="creation_rejected"),
            "invalid_mode": result("rejected", "none", 0, code="invalid_delivery_mode"),
            "invalid_digest": result("rejected", "none", 0, code="delivery_digest_mismatch"),
            "invalid_event": result("rejected", "none", 0, code="invalid_event"),
            "malformed_delivery": result("rejected", "none", 0, code="malformed_delivery"),
            "duplicate_event_id_in_batch": result("rejected", "none", 0, code="duplicate_event_id_in_batch"),
            "terminal_root": result("rejected", "none", 0, code="terminal_root"),
            "invalid_delivery_source": result("rejected", "none", 0, code="invalid_delivery_source"),
            "invalid_instance_target": result("rejected", "none", 0, code="invalid_instance_target"),
            "inactive_component_target": result("rejected", "none", 0, code="inactive_component_target"),
            "invalid_payload": result("rejected", "none", 0, code="invalid_payload"),
            "invalid_correlation": result("rejected", "none", 0, code="invalid_correlation"),
            "event_conflict": result("rejected", "none", 0, code="event_id_conflict"),
            "stale": result("rejected", "none", 0, code="checkpoint_revision_conflict"),
            "invalid_checkpoint": result("rejected", "none", 0, code="invalid_execution_checkpoint"),
            "tombstoned_root": result("rejected", "none", 0, code="tombstoned_root"),
            "duplicate_registration": result("rejected", "none", 0, code="duplicate_adapter_registration"),
            "unknown_adapter": result("rejected", "none", 0, code="unknown_adapter"),
            "invalid_configuration": result("rejected", "none", 0, code="invalid_adapter_configuration"),
            "capability_mismatch": result("rejected", "none", 0, code="adapter_capability_mismatch"),
            "invalid_scope": result("rejected", "none", 0, code="invalid_store_scope"),
        }
    )
    return {
        case / "created-checkpoint-v2.json": write_json(case / "x", created),
        case / "accepted-checkpoint-v2.json": write_json(case / "x", accepted),
        case / "handled-checkpoint-v2.json": write_json(case / "x", handled),
        case / "unhandled-accepted-checkpoint-v2.json": write_json(case / "x", unhandled_accepted),
        case / "unhandled-checkpoint-v2.json": write_json(case / "x", unhandled),
        case / "faulted-accepted-checkpoint-v2.json": write_json(case / "x", faulted_accepted),
        case / "faulted-checkpoint-v2.json": write_json(case / "x", faulted),
        case / "ordered-batch-checkpoint-v2.json": write_json(case / "x", ordered_batch),
        case / "mixed-batch-checkpoint-v2.json": write_json(case / "x", mixed_batch),
        case / "inactive-component-checkpoint-v2.json": write_json(case / "x", inactive_checkpoint),
        case / "bounded-checkpoint-v2.json": write_json(case / "x", bounded),
        case / "permanent-tombstone-checkpoint-v2.json": write_json(case / "x", permanent_tombstone),
        case / "bounded-tombstone-checkpoint-v2.json": write_json(case / "x", bounded_tombstone),
        case / "inputs-v2.json": write_json(case / "x", request_document(requests)),
        case / "results-v2.json": write_json(case / "x", results),
        case / "invalid-adapter-identifier-v2.json": write_json(
            case / "x",
            request_document(
                {
                    "invalid_adapter_identifier": registration_request(
                        "invalid-adapter-identifier",
                        {**vendor_http, "adapter_identifier": "vendor_http"},
                        [],
                    )
                }
            ),
        ),
        case / "invalid-uri-scheme-v2.json": write_json(
            case / "x",
            request_document(
                {
                    "invalid_uri_scheme": registration_request(
                        "invalid-uri-scheme",
                        {**vendor_http, "uri_scheme": "vendor_https"},
                        [],
                    )
                }
            ),
        ),
    }


def outputs() -> dict[Path, bytes]:
    result_map: dict[Path, bytes] = {}
    for generated in (
        generate_delivery(),
        generate_outbox(),
        generate_retention(),
        generate_spawned(False),
        generate_spawned(True),
        generate_complete_host_contract(),
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
