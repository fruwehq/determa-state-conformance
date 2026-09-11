#!/usr/bin/env python3
"""Generate deterministic queue-bearing conformance artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import rfc8785
from ruamel.yaml import YAML


ROOT = Path(__file__).resolve().parents[1]
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


def load_yaml(path: Path) -> Any:
    loader = YAML(typ="safe")
    loader.version = (1, 2)
    return loader.load(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def typed_value(value: Any) -> list[Any]:
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", value]
    if isinstance(value, str):
        return ["string", value]
    if isinstance(value, int):
        return ["integer", str(value)]
    if isinstance(value, float):
        if value == 0.0:
            value = 0.0
        return ["float", struct.pack(">d", value).hex()]
    if isinstance(value, list):
        return ["list", [typed_value(item) for item in value]]
    if isinstance(value, dict):
        return [
            "map",
            [[key, typed_value(value[key])] for key in sorted(value, key=lambda item: item.encode("utf-8"))],
        ]
    raise TypeError(f"unsupported typed value {type(value)!r}")


def normalize_payload(payload: dict[str, Any]) -> None:
    for declaration in payload.values():
        declaration.setdefault("required", False)
        if declaration.get("type") == "float" and isinstance(
            declaration.get("default"), int
        ):
            declaration["default"] = float(declaration["default"])


def normalize_transition(transition: dict[str, Any], *, event_transition: bool) -> None:
    if event_transition:
        transition.setdefault("lang", "cel")
    actions = transition.get("action", [])
    for action in actions:
        send = action.get("send")
        if send is not None and "to" not in send and "targets" not in send:
            send["to"] = {"self": True}


def normalize_state(state: dict[str, Any]) -> None:
    state.setdefault("type", "simple")
    if state["type"] == "composite":
        state.setdefault("history", "none")
    for declaration in state.get("variables", {}).values():
        if declaration.get("type") != "instance_reference":
            declaration.setdefault("input", False)
            declaration.setdefault("external", False)
    for transition in state.get("on_events", {}).values():
        branches = transition if isinstance(transition, list) else [transition]
        for branch in branches:
            normalize_transition(branch, event_transition=True)
    for transition_name in ("initial",):
        transition = state.get(transition_name)
        if transition is not None:
            normalize_transition(transition, event_transition=False)
    for action_name in ("entry", "exit"):
        for action in state.get(action_name, []):
            send = action.get("send")
            if send is not None and "to" not in send and "targets" not in send:
                send["to"] = {"self": True}
    for child in state.get("states", {}).values():
        if child.get("type") != "choice":
            normalize_state(child)
    for component in state.get("components", []):
        if "root" in component:
            normalize_state(component["root"])


def normalize_bundle_document(document: dict[str, Any]) -> dict[str, Any]:
    bundle = copy.deepcopy(document)
    for declaration in bundle.get("events", {}).values():
        declaration.setdefault("direction", "internal")
        normalize_payload(declaration.get("payload", {}))
    for machine in bundle["machines"]:
        machine.setdefault("version", 1)
        languages = machine.setdefault("languages", {})
        languages.setdefault("guard", "cel")
        languages.setdefault("action", "determa")
        for declaration in machine.get("events", {}).values():
            declaration.setdefault("direction", "internal")
            normalize_payload(declaration.get("payload", {}))
        normalize_state(machine["root"])
    return bundle


def normalized_bundle(path: Path) -> dict[str, Any]:
    loader = YAML(typ="safe")
    loader.version = (1, 2)
    return normalize_bundle_document(loader.load(path.read_text(encoding="utf-8")))


def bundle_fingerprint_document(document: dict[str, Any]) -> str:
    return digest(
        ["determa-validated-bundle-fingerprint-1", typed_value(normalize_bundle_document(document))]
    )


def bundle_fingerprint(path: Path) -> str:
    return digest(
        ["determa-validated-bundle-fingerprint-1", typed_value(normalized_bundle(path))]
    )


def aggregate_shape_fingerprint_document(document: dict[str, Any]) -> str:
    bundle = normalize_bundle_document(document)

    def state_projection(state: dict[str, Any], pointer: str) -> dict[str, Any]:
        result: dict[str, Any] = {"definition_pointer": pointer, "type": state["type"]}
        if state["type"] == "composite":
            result["history"] = state.get("history", "none")
        variables = []
        for name, declaration in state.get("variables", {}).items():
            item = {
                "declaration_pointer": f"{pointer}/variables/{name}",
                "type": declaration["type"],
                "nullable": bool(declaration.get("nullable")) if declaration["type"] == "instance_reference" else False,
                "input": bool(declaration.get("input")),
                "external": bool(declaration.get("external")),
            }
            if declaration.get("machine_id") is not None:
                item["machine_id"] = declaration["machine_id"]
            variables.append(item)
        variables.sort(key=lambda item: item["declaration_pointer"].encode("utf-8"))
        if variables:
            result["variables"] = variables
        children = [
            state_projection(child, f"{pointer}/states/{name}")
            for name, child in sorted(state.get("states", {}).items(), key=lambda item: item[0].encode("utf-8"))
            if child.get("type") != "choice"
        ]
        if children:
            result["states"] = children
        components = []
        for index, placement in enumerate(state.get("components", [])):
            item = {
                "declaration_pointer": f"{pointer}/components/{index}",
                "declaration_index": index,
                "component_id": placement["component_id"],
            }
            if "machine_id" in placement:
                item["machine_id"] = placement["machine_id"]
            else:
                item["inline_root"] = state_projection(
                    placement["root"], f"{pointer}/components/{index}/root"
                )
            components.append(item)
        if components:
            result["components"] = components
        return result

    tree = {
        "format": 1,
        "namespace": bundle["namespace"],
        "machines": [
            {
                "machine_id": machine["machine_id"],
                "version": machine["version"],
                "root": state_projection(machine["root"], f"/machines/{index}/root"),
            }
            for index, machine in enumerate(bundle["machines"])
        ],
    }
    return digest(["determa-aggregate-shape-fingerprint-1", typed_value(tree)])


def bundle_binding(path: Path) -> dict[str, str]:
    return {
        "bundle_file": path.name,
        "bundle_source_digest": bytes_digest(path.read_bytes()),
        "validated_bundle_fingerprint": bundle_fingerprint(path),
    }


def generated_bundle_binding(name: str, document: dict[str, Any]) -> dict[str, str]:
    source = canonical(document)
    return {
        "bundle_file": name,
        "bundle_source_digest": bytes_digest(source),
        "validated_bundle_fingerprint": bundle_fingerprint_document(document),
    }


def create_v2_root(bundle_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    bundle = normalized_bundle(bundle_path)
    fingerprint = bundle_fingerprint(bundle_path)
    machine_index, machine = next(
        (index, item)
        for index, item in enumerate(bundle["machines"])
        if item["machine_id"] == request["machine_id"]
        and str(item["version"]) == request["machine_version"]
    )
    root_pointer = f"/machines/{machine_index}/root"
    root_instance_id = request["root_instance_id"]
    runtime_id = digest(
        [
            "determa-root-runtime-identity-2",
            "1",
            fingerprint,
            bundle["namespace"],
            machine["machine_id"],
            request["machine_version"],
            root_instance_id,
        ]
    )
    pointers = [root_pointer]
    states = [(root_pointer, machine["root"])]
    current = machine["root"]
    while current.get("type") == "composite" and "initial" in current:
        target = current["initial"]["transition_to"]
        segments = target.split(".")
        cursor = machine["root"]
        pointer = root_pointer
        for segment in segments:
            cursor = cursor["states"][segment]
            pointer += f"/states/{segment}"
        if pointer in pointers:
            break
        pointers.append(pointer)
        states.append((pointer, cursor))
        current = cursor
    variables = []
    for pointer, state in states:
        for name, declaration in state.get("variables", {}).items():
            source = request["bindings"]["input"] if declaration.get("input") else request["bindings"]["external"] if declaration.get("external") else {}
            value = source.get(name, declaration.get("init"))
            variables.append(
                {
                    "variable_declaration_pointer": f"{pointer}/variables/{name}",
                    "declaring_state_activation_sequence": "0",
                    "value": typed_value(value),
                }
            )
    definition = {
        "validated_bundle_fingerprint": fingerprint,
        "machine": {
            "namespace": bundle["namespace"],
            "machine_id": machine["machine_id"],
            "machine_version": request["machine_version"],
            "root_definition_pointer": root_pointer,
        },
    }
    runtime = {
        "runtime_id": runtime_id,
        "identity_origin": {
            "kind": "root",
            "definition": copy.deepcopy(definition),
            "root_instance_id": root_instance_id,
        },
        "target_identity": {
            "root": {
                "root_instance_id": root_instance_id,
                "root_runtime_id": runtime_id,
            }
        },
        "current_definition": copy.deepcopy(definition),
        "relation": {"kind": "root"},
        "status": "running",
        "active_leaf_state_definition_pointers": [pointers[-1]],
        "active_state_activations": [
            {"state_definition_pointer": pointer, "activation_sequence": "0"}
            for pointer in pointers
        ],
        "variables": variables,
        "history": [],
        "next_spawn_sequence": "0",
        "next_state_activation_sequences": [
            {"definition_pointer": pointer, "next_sequence": "1"}
            for pointer in pointers
        ],
        "next_component_activation_sequences": [],
        "fault": None,
        "ready_mailbox": [],
        "deferred_mailbox": [],
    }
    return seal_aggregate(
        {
            "aggregate_state_format": "determa.aggregate_state",
            "aggregate_state_schema_version": 2,
            "machine_format": 1,
            "validated_bundle_fingerprint": fingerprint,
            "namespace": bundle["namespace"],
            "root_machine_id": machine["machine_id"],
            "root_machine_version": request["machine_version"],
            "root_instance_id": root_instance_id,
            "creation_id": request["creation_id"],
            "root_runtime_id": runtime_id,
            "migration_sequence": "0",
            "next_logical_step_sequence": "1",
            "next_output_sequence": "0",
            "next_acceptance_sequence": "0",
            "next_queue_sequence": "0",
            "runtimes": [runtime],
        }
    )


def seal_aggregate(value: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(value)
    for runtime in value.get("runtimes", []):
        runtime["active_leaf_state_definition_pointers"] = sorted(
            runtime["active_leaf_state_definition_pointers"], key=lambda item: item.encode("utf-8")
        )
        runtime["active_state_activations"] = sorted(
            runtime["active_state_activations"],
            key=lambda item: (
                item["state_definition_pointer"].encode("utf-8"),
                int(item["activation_sequence"]),
            ),
        )
        runtime["variables"] = sorted(
            runtime["variables"],
            key=lambda item: (
                item["variable_declaration_pointer"].encode("utf-8"),
                int(item["declaring_state_activation_sequence"]),
            ),
        )
        runtime["history"] = sorted(
            runtime["history"], key=lambda item: item["history_declaration_pointer"].encode("utf-8")
        )
        for field in ("next_state_activation_sequences", "next_component_activation_sequences"):
            runtime[field] = sorted(
                runtime[field], key=lambda item: item["definition_pointer"].encode("utf-8")
            )
        for field in ("ready_mailbox", "deferred_mailbox"):
            runtime[field] = sorted(runtime[field], key=lambda item: int(item["queue_sequence"]))
    value["runtimes"] = sorted(
        value.get("runtimes", []), key=lambda item: item["runtime_id"].encode("utf-8")
    )
    value.pop("aggregate_state_digest", None)
    value["aggregate_state_digest"] = digest(
        ["determa-aggregate-state-digest-2", value]
    )
    return value






def reseal_aggregate_without_normalizing(value: dict[str, Any]) -> dict[str, Any]:
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


def maintenance_request_digest(
    root_instance_id: str,
    operation_id: str,
    source_aggregate_state_digest: str,
    target_validated_bundle_fingerprint: str,
    migration_descriptor_digest_route: list[str],
    maintenance_mode: bool,
) -> str:
    return digest(
        [
            "determa-maintenance-migration-request-digest-2",
            "2",
            root_instance_id,
            operation_id,
            source_aggregate_state_digest,
            target_validated_bundle_fingerprint,
            migration_descriptor_digest_route,
            maintenance_mode,
        ]
    )


def native_v2_checkpoint(
    bundle_path: Path,
    request: dict[str, Any],
) -> dict[str, Any]:
    aggregate = create_v2_root(bundle_path, request)
    creation_request_digest = digest(
        [
            "determa-creation-request-digest-2",
            "2",
            aggregate["validated_bundle_fingerprint"],
            aggregate["namespace"],
            aggregate["root_machine_id"],
            aggregate["root_machine_version"],
            aggregate["root_instance_id"],
            aggregate["creation_id"],
            typed_value(request["bindings"]),
        ]
    )
    root = root_runtime(aggregate)
    return seal_checkpoint(
        {
            "execution_checkpoint_format": "determa.execution_checkpoint",
            "execution_checkpoint_schema_version": 2,
            "root_instance_id": aggregate["root_instance_id"],
            "revision": "0",
            "root_record": {"status": "retained", "aggregate_state": aggregate},
            "operation_receipts": [
                {
                    "operation_kind": "creation",
                    "receipt_sequence": "0",
                    "creation_id": aggregate["creation_id"],
                    "request_digest": creation_request_digest,
                    "committed_revision": "0",
                    "resulting_aggregate_state_digest": aggregate[
                        "aggregate_state_digest"
                    ],
                    "status": root["status"],
                    "fault": root["fault"],
                    "emission_references": [],
                }
            ],
            "next_operation_receipt_sequence": "1",
            "replay_retention": {
                "mode": "permanent",
                "permanent_replay_eligible": True,
                "pruned_through_receipt_sequence": None,
                "policy_identifier": None,
            },
            "event_identity_tombstones": [],
            "pending_outbox_intents": [],
            "next_outbox_terminal_sequence": "0",
            "terminal_outbox_records": [],
            "outbox_effect_tombstones": [],
            "migration_audit_records": [],
        }
    )


def migrate_compatible_aggregate(
    source: dict[str, Any], descriptor: dict[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(source)
    target_fingerprint = descriptor["target_validated_bundle_fingerprint"]
    result["validated_bundle_fingerprint"] = target_fingerprint
    result["migration_sequence"] = str(int(result["migration_sequence"]) + 1)
    for runtime in result["runtimes"]:
        runtime["current_definition"][
            "validated_bundle_fingerprint"
        ] = target_fingerprint
    return seal_aggregate(result)


def v2_migration_audit_record(
    source: dict[str, Any],
    target: dict[str, Any],
    descriptor: dict[str, Any],
) -> dict[str, Any]:
    return {
        "migration_audit_record_schema_version": 2,
        "root_instance_id": source["root_instance_id"],
        "root_runtime_id": source["root_runtime_id"],
        "migration_sequence": target["migration_sequence"],
        "source_validated_bundle_fingerprint": source[
            "validated_bundle_fingerprint"
        ],
        "target_validated_bundle_fingerprint": target[
            "validated_bundle_fingerprint"
        ],
        "migration_descriptor_digest": descriptor[
            "migration_descriptor_digest"
        ],
        "source_aggregate_state_digest": source["aggregate_state_digest"],
        "target_aggregate_state_digest": target["aggregate_state_digest"],
        "result_code": "migration_applied",
    }


def commit_v2_maintenance_migration(
    checkpoint: dict[str, Any],
    operation: dict[str, Any],
    resulting_aggregate: dict[str, Any],
    audit_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(checkpoint)
    result["revision"] = str(int(result["revision"]) + 1)
    receipt_sequence = result["next_operation_receipt_sequence"]
    result["next_operation_receipt_sequence"] = str(
        int(receipt_sequence) + 1
    )
    receipt = {
        "operation_kind": "maintenance_migration",
        "receipt_sequence": receipt_sequence,
        "operation_id": operation["operation_id"],
        "request_digest": operation["request_digest"],
        "committed_revision": result["revision"],
        "source_aggregate_state_digest": checkpoint["root_record"][
            "aggregate_state"
        ]["aggregate_state_digest"],
        "target_validated_bundle_fingerprint": operation["target_bundle"][
            "validated_bundle_fingerprint"
        ],
        "resulting_aggregate_state_digest": resulting_aggregate[
            "aggregate_state_digest"
        ],
        "migration_sequences": [
            item["migration_sequence"] for item in audit_records
        ],
        "result_code": (
            "migration_applied" if audit_records else "migration_no_operation"
        ),
    }
    result["root_record"]["aggregate_state"] = copy.deepcopy(
        resulting_aggregate
    )
    result["migration_audit_records"].extend(copy.deepcopy(audit_records))
    result["operation_receipts"].append(receipt)
    return seal_checkpoint(result), receipt




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














def root_runtime(aggregate: dict[str, Any]) -> dict[str, Any]:
    return next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["relation"]["kind"] == "root"
    )






def produce_persistence() -> dict[str, bytes]:
    source_document = normalize_bundle_document(load_yaml(PERSISTENCE / "machine.yaml"))
    source_fingerprint = bundle_fingerprint_document(source_document)
    aggregate_v2 = rebind_single_root(
        load(PERSISTENCE / "base-aggregate-v2.json"), source_fingerprint
    )

    target_documents: dict[str, dict[str, Any]] = {}
    target_documents["target-compatible.yaml"] = copy.deepcopy(source_document)
    target_documents["target-compatible.yaml"]["machines"][0]["root"]["states"]["busy"]["states"]["authorizing"]["on_events"]["retry"]["guard"] = "false || false"
    target_documents["target-compatible-second.yaml"] = copy.deepcopy(
        target_documents["target-compatible.yaml"]
    )
    target_documents["target-compatible-second.yaml"]["machines"][0]["root"]["states"]["busy"]["states"]["authorizing"]["on_events"]["retry"]["guard"] = "false || false || false"
    removed_event = copy.deepcopy(source_document)
    del removed_event["events"]["new_request"]
    removed_event["events"]["replacement_request"] = {
        "direction": "input",
        "payload": {"transaction_id": {"type": "string", "required": True}},
    }
    removed_event["machines"][0]["root"]["states"]["idle"]["on_events"] = {
        "replacement_request": {"transition_to": "busy.receiving", "lang": "cel"}
    }
    removed_event["machines"][0]["root"]["states"]["busy"].pop("deferred_events")
    removed_event["machines"][0]["root"]["states"]["busy"]["states"]["authorizing"]["on_events"].pop("new_request")
    target_documents["target-removed-event.yaml"] = removed_event
    payload_incompatible = copy.deepcopy(source_document)
    payload_incompatible["events"]["new_request"]["payload"]["transaction_id"]["type"] = "int"
    target_documents["target-payload-incompatible.yaml"] = payload_incompatible
    correlation_incompatible = copy.deepcopy(source_document)
    correlation_incompatible["events"]["request_started"] = {"direction": "output"}
    correlation_incompatible["events"]["new_request"]["correlates_to"] = "request_started"
    target_documents["target-correlation-incompatible.yaml"] = correlation_incompatible
    capacity_incompatible = copy.deepcopy(source_document)
    capacity_incompatible["machines"][0]["root"]["deferred_event_capacity"] = 0
    target_documents["target-capacity-incompatible.yaml"] = capacity_incompatible
    stale_target = copy.deepcopy(source_document)
    stale_target["machines"][0]["root"]["states"]["busy"]["states"]["receiving_replacement"] = stale_target["machines"][0]["root"]["states"]["busy"]["states"].pop("receiving")
    stale_target["machines"][0]["root"]["states"]["busy"]["initial"]["transition_to"] = "busy.receiving_replacement"
    stale_target["machines"][0]["root"]["states"]["idle"]["on_events"]["new_request"]["transition_to"] = "busy.receiving_replacement"
    target_documents["target-stale-state.yaml"] = stale_target

    descriptor_template = {
        "migration_descriptor_format": "determa.aggregate_migration",
        "migration_descriptor_schema_version": 2,
        "source_machine_format": 1,
        "target_machine_format": 1,
        "source_validated_bundle_fingerprint": source_fingerprint,
        "target_validated_bundle_fingerprint": source_fingerprint,
        "source_aggregate_shape_fingerprint": aggregate_shape_fingerprint_document(source_document),
        "target_aggregate_shape_fingerprint": aggregate_shape_fingerprint_document(source_document),
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

    def make_descriptor(
        target_name: str,
        *,
        source_name: str | None = None,
        dispose_retired: bool = False,
    ) -> dict[str, Any]:
        descriptor_source = (
            source_document if source_name is None else target_documents[source_name]
        )
        descriptor = copy.deepcopy(descriptor_template)
        descriptor["source_validated_bundle_fingerprint"] = (
            bundle_fingerprint_document(descriptor_source)
        )
        descriptor["target_validated_bundle_fingerprint"] = bundle_fingerprint_document(target_documents[target_name])
        descriptor["source_aggregate_shape_fingerprint"] = aggregate_shape_fingerprint_document(descriptor_source)
        descriptor["target_aggregate_shape_fingerprint"] = aggregate_shape_fingerprint_document(target_documents[target_name])
        if descriptor["source_aggregate_shape_fingerprint"] != descriptor["target_aggregate_shape_fingerprint"]:
            descriptor["mode"] = "transform"
            descriptor["mappings"]["machines"] = [{
                "source_definition_pointer": "/machines/0/root",
                "target_definition_pointer": "/machines/0/root",
            }]
            descriptor["mappings"]["active_states"] = [{
                "source_leaf_state_definition_pointer": "/machines/0/root/states/busy/states/receiving",
                "target_leaf_state_definition_pointers": [
                    "/machines/0/root/states/busy/states/receiving_replacement"
                ],
            }]
            descriptor["mappings"]["counters"] = [
                {"operation": "map", "source_definition_pointer": "/machines/0/root", "target_definition_pointer": "/machines/0/root"},
                {"operation": "map", "source_definition_pointer": "/machines/0/root/states/busy", "target_definition_pointer": "/machines/0/root/states/busy"},
                {"operation": "map", "source_definition_pointer": "/machines/0/root/states/busy/states/receiving", "target_definition_pointer": "/machines/0/root/states/busy/states/receiving_replacement"},
            ]
        descriptor["queued_event_rules"] = ([{
                "machine_id": aggregate_v2["root_machine_id"],
                "event": "retired_event",
                "delivery_mode": "input",
                "action": "dispose",
                "reason": "event removed by version migration",
            }] if dispose_retired else [])
        descriptor["migration_descriptor_digest"] = digest(
            ["determa-migration-descriptor-2", descriptor]
        )
        return descriptor

    descriptors = {
        "descriptor-compatible-v2.json": make_descriptor("target-compatible.yaml"),
        "descriptor-compatible-second-v2.json": make_descriptor(
            "target-compatible-second.yaml", source_name="target-compatible.yaml"
        ),
        "descriptor-dispose-v2.json": make_descriptor("target-removed-event.yaml", dispose_retired=True),
        "descriptor-removed-event-v2.json": make_descriptor("target-removed-event.yaml"),
        "descriptor-payload-v2.json": make_descriptor("target-payload-incompatible.yaml"),
        "descriptor-correlation-v2.json": make_descriptor("target-correlation-incompatible.yaml"),
        "descriptor-capacity-v2.json": make_descriptor("target-capacity-incompatible.yaml"),
        "descriptor-stale-v2.json": make_descriptor("target-stale-state.yaml"),
    }
    descriptor_v2 = descriptors["descriptor-compatible-v2.json"]
    package_v2 = {
        "aggregate_state_package_format": "determa.aggregate_state_package",
        "aggregate_state_package_schema_version": 2,
        "aggregate_state": aggregate_v2,
        "normalized_definitions": [
            {
                "validated_bundle_fingerprint": source_fingerprint,
                "normalized_bundle": typed_value(source_document),
            },
            {
                "validated_bundle_fingerprint": descriptor_v2["target_validated_bundle_fingerprint"],
                "normalized_bundle": typed_value(target_documents["target-compatible.yaml"]),
            },
        ],
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
    disposal_entry["envelope"]["payload"] = ["map", []]
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
    disposal_after["validated_bundle_fingerprint"] = descriptors["descriptor-dispose-v2.json"]["target_validated_bundle_fingerprint"]
    disposal_after["runtimes"][0]["current_definition"]["validated_bundle_fingerprint"] = disposal_after["validated_bundle_fingerprint"]
    disposal_after["migration_sequence"] = str(int(disposal_after["migration_sequence"]) + 1)
    disposal_after = seal_aggregate(disposal_after)

    def migrated_to(source: dict[str, Any], descriptor: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(source)
        target_fingerprint = descriptor["target_validated_bundle_fingerprint"]
        result["validated_bundle_fingerprint"] = target_fingerprint
        result["migration_sequence"] = str(int(result["migration_sequence"]) + 1)
        for runtime in result["runtimes"]:
            runtime["current_definition"]["validated_bundle_fingerprint"] = target_fingerprint
        return seal_aggregate(result)

    def migration_audit_record(
        source: dict[str, Any],
        target: dict[str, Any],
        descriptor: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "migration_audit_record_schema_version": 2,
            "root_instance_id": source["root_instance_id"],
            "root_runtime_id": source["root_runtime_id"],
            "migration_sequence": target["migration_sequence"],
            "source_validated_bundle_fingerprint": source[
                "validated_bundle_fingerprint"
            ],
            "target_validated_bundle_fingerprint": target[
                "validated_bundle_fingerprint"
            ],
            "migration_descriptor_digest": descriptor[
                "migration_descriptor_digest"
            ],
            "source_aggregate_state_digest": source["aggregate_state_digest"],
            "target_aggregate_state_digest": target["aggregate_state_digest"],
            "result_code": "migration_applied",
        }

    preserved = migrated_to(aggregate_v2, descriptors["descriptor-compatible-v2.json"])
    two_hop_migrated = migrated_to(
        preserved, descriptors["descriptor-compatible-second-v2.json"]
    )

    stale_target_migrated = migrated_to(
        aggregate_v2, descriptors["descriptor-stale-v2.json"]
    )
    stale_source_pointer = "/machines/0/root/states/busy/states/receiving"
    stale_target_pointer = (
        "/machines/0/root/states/busy/states/receiving_replacement"
    )
    for runtime in stale_target_migrated["runtimes"]:
        runtime["active_leaf_state_definition_pointers"] = [
            stale_target_pointer if pointer == stale_source_pointer else pointer
            for pointer in runtime["active_leaf_state_definition_pointers"]
        ]
        for activation in runtime["active_state_activations"]:
            if activation["state_definition_pointer"] == stale_source_pointer:
                activation["state_definition_pointer"] = stale_target_pointer
        for counter in runtime["next_state_activation_sequences"]:
            if counter["definition_pointer"] == stale_source_pointer:
                counter["definition_pointer"] = stale_target_pointer
    stale_target_migrated = seal_aggregate(stale_target_migrated)

    fault_frozen = copy.deepcopy(aggregate_v2)
    fault_runtime = fault_frozen["runtimes"][0]
    fault_cause = fault_runtime["ready_mailbox"].pop(0)
    fault_record = {
        "definition_fingerprint": fault_frozen["validated_bundle_fingerprint"],
        "runtime_id": fault_runtime["runtime_id"],
        "cause_id": fault_cause["envelope"]["cause_id"],
        "code": "action_fault",
        "step_sequence": fault_frozen["next_logical_step_sequence"],
        "source_locator": (
            "/machines/0/root/states/busy/states/receiving/on_events/received/"
            "action/0/send/payload/amount"
        ),
    }
    fault_runtime["status"] = "faulted"
    fault_runtime["fault"] = fault_record
    fault_frozen["next_logical_step_sequence"] = str(
        int(fault_frozen["next_logical_step_sequence"]) + 1
    )
    fault_frozen = seal_aggregate(fault_frozen)
    preserved_fault_frozen = migrated_to(
        fault_frozen, descriptors["descriptor-compatible-v2.json"]
    )
    historical_fault_migrated = migrated_to(
        fault_frozen, descriptors["descriptor-stale-v2.json"]
    )
    for runtime in historical_fault_migrated["runtimes"]:
        runtime["active_leaf_state_definition_pointers"] = [
            stale_target_pointer if pointer == stale_source_pointer else pointer
            for pointer in runtime["active_leaf_state_definition_pointers"]
        ]
        for activation in runtime["active_state_activations"]:
            if activation["state_definition_pointer"] == stale_source_pointer:
                activation["state_definition_pointer"] = stale_target_pointer
        for counter in runtime["next_state_activation_sequences"]:
            if counter["definition_pointer"] == stale_source_pointer:
                counter["definition_pointer"] = stale_target_pointer
    historical_fault_migrated = seal_aggregate(historical_fault_migrated)
    outputs: dict[str, Any] = {
        "base-aggregate-v2.json": canonical(aggregate_v2),
        "package-v2.json": canonical(package_v2),
        "invalid-descriptor-v2.json": canonical(invalid_descriptor),
        "invalid-package-v2.json": canonical(invalid_package),
        "invalid-counter-aggregate-v2.json": canonical(invalid_aggregate),
        "disposal-before.json": canonical(disposal_before),
        "fault-frozen-aggregate-v2.json": canonical(fault_frozen),
        "migration-preserve-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": preserved,
                "dispositions": [],
                "audit_records": [
                    migration_audit_record(
                        aggregate_v2,
                        preserved,
                        descriptors["descriptor-compatible-v2.json"],
                    )
                ],
            }
        ),
        "migration-empty-route-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": aggregate_v2,
                "dispositions": [],
                "audit_records": [],
            }
        ),
        "migration-two-hop-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": two_hop_migrated,
                "dispositions": [],
                "audit_records": [
                    migration_audit_record(
                        aggregate_v2,
                        preserved,
                        descriptors["descriptor-compatible-v2.json"],
                    ),
                    migration_audit_record(
                        preserved,
                        two_hop_migrated,
                        descriptors["descriptor-compatible-second-v2.json"],
                    ),
                ],
            }
        ),
        "migration-stale-target-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": stale_target_migrated,
                "dispositions": [],
                "audit_records": [
                    migration_audit_record(
                        aggregate_v2,
                        stale_target_migrated,
                        descriptors["descriptor-stale-v2.json"],
                    )
                ],
            }
        ),
        "migration-fault-frozen-preserve-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": preserved_fault_frozen,
                "dispositions": [],
                "audit_records": [
                    migration_audit_record(
                        fault_frozen,
                        preserved_fault_frozen,
                        descriptors["descriptor-compatible-v2.json"],
                    )
                ],
            }
        ),
        "migration-historical-fault-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": historical_fault_migrated,
                "dispositions": [],
                "audit_records": [
                    migration_audit_record(
                        fault_frozen,
                        historical_fault_migrated,
                        descriptors["descriptor-stale-v2.json"],
                    )
                ],
            }
        ),
        "migration-dispose-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": disposal_after,
                "dispositions": [
                    {
                        "disposition": "migration_disposed",
                        "reason": "event removed by version migration",
                        "migration_descriptor_digest": descriptors["descriptor-dispose-v2.json"]["migration_descriptor_digest"],
                    }
                ],
                "audit_records": [
                    migration_audit_record(
                        disposal_before,
                        disposal_after,
                        descriptors["descriptor-dispose-v2.json"],
                    )
                ],
            }
        ),
        "operation-inputs.json": canonical({}),
    }
    for name, document in target_documents.items():
        outputs[name] = canonical(document)
    for name, descriptor in descriptors.items():
        outputs[name] = canonical(descriptor)
    operations: dict[str, Any] = {}
    migration_targets = {
        "preserve": ("target-compatible.yaml", "descriptor-compatible-v2.json"),
        "preserve_fault": ("target-compatible.yaml", "descriptor-compatible-v2.json"),
        "preserve_historical_fault": (
            "target-stale-state.yaml",
            "descriptor-stale-v2.json",
        ),
        "dispose": ("target-removed-event.yaml", "descriptor-dispose-v2.json"),
        "stale_target": ("target-stale-state.yaml", "descriptor-stale-v2.json"),
        "event_removed": ("target-removed-event.yaml", "descriptor-removed-event-v2.json"),
        "payload_incompatible": ("target-payload-incompatible.yaml", "descriptor-payload-v2.json"),
        "correlation_incompatible": ("target-correlation-incompatible.yaml", "descriptor-correlation-v2.json"),
        "lowered_capacity": ("target-capacity-incompatible.yaml", "descriptor-capacity-v2.json"),
    }
    for operation_name, (target_name, descriptor_name) in migration_targets.items():
        descriptor = descriptors[descriptor_name]
        operations[operation_name] = {
            "operation": "migrate_aggregate_v2",
            "maintenance_mode": True,
            "source_bundle": bundle_binding(PERSISTENCE / "machine.yaml"),
            "target_bundle": generated_bundle_binding(target_name, target_documents[target_name]),
            "migration_descriptor_file": descriptor_name,
            "migration_descriptor_digest_route": [descriptor["migration_descriptor_digest"]],
        }
    operations["empty_route"] = {
        "operation": "migrate_aggregate_v2",
        "maintenance_mode": True,
        "source_bundle": bundle_binding(PERSISTENCE / "machine.yaml"),
        "target_bundle": bundle_binding(PERSISTENCE / "machine.yaml"),
        "migration_descriptor_files": [],
        "migration_descriptor_digest_route": [],
    }
    operations["two_hop"] = {
        "operation": "migrate_aggregate_v2",
        "maintenance_mode": True,
        "source_bundle": bundle_binding(PERSISTENCE / "machine.yaml"),
        "target_bundle": generated_bundle_binding(
            "target-compatible-second.yaml",
            target_documents["target-compatible-second.yaml"],
        ),
        "migration_descriptor_files": [
            "descriptor-compatible-v2.json",
            "descriptor-compatible-second-v2.json",
        ],
        "migration_descriptor_digest_route": [
            descriptors["descriptor-compatible-v2.json"][
                "migration_descriptor_digest"
            ],
            descriptors["descriptor-compatible-second-v2.json"][
                "migration_descriptor_digest"
            ],
        ],
    }
    outputs["operation-inputs.json"] = canonical(operations)
    return {name: data if isinstance(data, bytes) else canonical(data) for name, data in outputs.items()}


def produce_checkpoint() -> dict[str, bytes]:
    persistence = produce_persistence()
    descriptor_one = json.loads(
        persistence["descriptor-compatible-v2.json"]
    )
    descriptor_two = json.loads(
        persistence["descriptor-compatible-second-v2.json"]
    )
    source_path = CHECKPOINT / "maintenance-source.yaml"
    target_one_path = CHECKPOINT / "maintenance-target-one.yaml"
    target_two_path = CHECKPOINT / "maintenance-target-two.yaml"

    source_binding = bundle_binding(source_path)
    target_one_binding = bundle_binding(target_one_path)
    target_two_binding = bundle_binding(target_two_path)
    creation_request = {
        "machine_id": "transaction_server",
        "machine_version": "1",
        "root_instance_id": "maintenance-v2-root",
        "creation_id": "maintenance-v2-create",
        "bindings": {"input": {}, "external": {}},
    }
    base = native_v2_checkpoint(source_path, creation_request)

    def operation(
        checkpoint: dict[str, Any],
        operation_id: str,
        target_binding: dict[str, str],
        descriptors: list[dict[str, Any]],
    ) -> dict[str, Any]:
        source_digest = checkpoint["root_record"]["aggregate_state"][
            "aggregate_state_digest"
        ]
        route = [item["migration_descriptor_digest"] for item in descriptors]
        result = {
            "operation": "checkpoint_migrate_v2",
            "source_bundle": source_binding,
            "target_bundle": target_binding,
            "migration_descriptor_files": [
                "maintenance-descriptor-one.json",
                "maintenance-descriptor-two.json",
            ][: len(descriptors)],
            "migration_descriptor_digest_route": route,
            "maintenance_mode": True,
            "operation_id": operation_id,
            "expected_revision": checkpoint["revision"],
            "expected_checkpoint_digest": checkpoint[
                "execution_checkpoint_digest"
            ],
        }
        result["request_digest"] = maintenance_request_digest(
            checkpoint["root_instance_id"],
            operation_id,
            source_digest,
            target_binding["validated_bundle_fingerprint"],
            route,
            True,
        )
        return result

    empty_operation = operation(
        base, "maintenance-v2-empty", source_binding, []
    )
    base_aggregate = base["root_record"]["aggregate_state"]
    empty_checkpoint, empty_receipt = commit_v2_maintenance_migration(
        base, empty_operation, base_aggregate, []
    )

    one_operation = operation(
        base,
        "maintenance-v2-one-hop",
        target_one_binding,
        [descriptor_one],
    )
    one_aggregate = migrate_compatible_aggregate(
        base_aggregate, descriptor_one
    )
    one_audit = v2_migration_audit_record(
        base_aggregate, one_aggregate, descriptor_one
    )
    one_checkpoint, one_receipt = commit_v2_maintenance_migration(
        base, one_operation, one_aggregate, [one_audit]
    )

    two_operation = operation(
        base,
        "maintenance-v2-two-hop",
        target_two_binding,
        [descriptor_one, descriptor_two],
    )
    two_first = migrate_compatible_aggregate(base_aggregate, descriptor_one)
    two_aggregate = migrate_compatible_aggregate(two_first, descriptor_two)
    two_audits = [
        v2_migration_audit_record(
            base_aggregate, two_first, descriptor_one
        ),
        v2_migration_audit_record(
            two_first, two_aggregate, descriptor_two
        ),
    ]
    two_checkpoint, two_receipt = commit_v2_maintenance_migration(
        base, two_operation, two_aggregate, two_audits
    )

    sequential_operation = operation(
        empty_checkpoint,
        "maintenance-v2-after-empty",
        target_one_binding,
        [descriptor_one],
    )
    sequential_checkpoint, sequential_receipt = (
        commit_v2_maintenance_migration(
            empty_checkpoint,
            sequential_operation,
            one_aggregate,
            [one_audit],
        )
    )

    completed_base = copy.deepcopy(base)
    completed_aggregate = completed_base["root_record"]["aggregate_state"]
    completed_root = root_runtime(completed_aggregate)
    completed_root["status"] = "completed"
    completed_aggregate = seal_aggregate(completed_aggregate)
    completed_base["root_record"]["aggregate_state"] = completed_aggregate
    completed_base["operation_receipts"][0]["status"] = "completed"
    completed_base["operation_receipts"][0][
        "resulting_aggregate_state_digest"
    ] = completed_aggregate["aggregate_state_digest"]
    completed_base = seal_checkpoint(completed_base)
    tombstone_operation = operation(
        completed_base,
        "maintenance-v2-tombstoned-empty",
        source_binding,
        [],
    )
    tombstone_retained, tombstone_receipt = (
        commit_v2_maintenance_migration(
            completed_base,
            tombstone_operation,
            completed_aggregate,
            [],
        )
    )
    tombstoned = copy.deepcopy(tombstone_retained)
    tombstoned["revision"] = str(int(tombstoned["revision"]) + 1)
    tombstoned["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": completed_aggregate["root_runtime_id"],
        "creation_id": completed_aggregate["creation_id"],
        "terminal_status": "completed",
        "final_aggregate_state_digest": completed_aggregate[
            "aggregate_state_digest"
        ],
        "tombstone_operation_id": "maintenance-v2-tombstone",
    }
    tombstoned = seal_checkpoint(tombstoned)

    missing_target = copy.deepcopy(tombstoned)
    missing_target["operation_receipts"][1].pop(
        "target_validated_bundle_fingerprint"
    )
    missing_target = seal_checkpoint(missing_target)
    altered_target = copy.deepcopy(tombstoned)
    altered_target["operation_receipts"][1][
        "target_validated_bundle_fingerprint"
    ] = "sha256:" + "f" * 64
    altered_target = seal_checkpoint(altered_target)
    historical_digest = copy.deepcopy(sequential_checkpoint)
    historical_digest["operation_receipts"][1]["request_digest"] = (
        "sha256:" + "e" * 64
    )
    historical_digest = seal_checkpoint(historical_digest)
    audit_order = copy.deepcopy(two_checkpoint)
    audit_order["migration_audit_records"].reverse()
    audit_order = seal_checkpoint(audit_order)
    next_gap = copy.deepcopy(sequential_checkpoint)
    next_gap["operation_receipts"] = next_gap["operation_receipts"][:2]
    next_gap = seal_checkpoint(next_gap)
    shifted_gap = copy.deepcopy(empty_checkpoint)
    shifted_gap["next_operation_receipt_sequence"] = "3"
    shifted_gap["operation_receipts"][1]["receipt_sequence"] = "2"
    shifted_gap = seal_checkpoint(shifted_gap)

    conflict_operation = operation(
        empty_checkpoint,
        "maintenance-v2-empty",
        target_one_binding,
        [descriptor_one],
    )
    stale_operation = operation(
        empty_checkpoint,
        "maintenance-v2-stale-writer",
        target_one_binding,
        [descriptor_one],
    )
    stale_operation["expected_revision"] = base["revision"]
    stale_operation["expected_checkpoint_digest"] = base[
        "execution_checkpoint_digest"
    ]

    operations = {
        "maintenance_empty": empty_operation,
        "maintenance_empty_replay": empty_operation,
        "maintenance_tombstoned_empty_replay": tombstone_operation,
        "maintenance_one_hop": one_operation,
        "maintenance_two_hop": two_operation,
        "maintenance_after_empty": sequential_operation,
        "maintenance_conflict": conflict_operation,
        "maintenance_stale_writer": stale_operation,
    }
    artifacts: dict[str, Any] = {
        "maintenance-descriptor-one.json": descriptor_one,
        "maintenance-descriptor-two.json": descriptor_two,
        "maintenance-base-checkpoint-v2.json": base,
        "maintenance-empty-checkpoint-v2.json": empty_checkpoint,
        "maintenance-one-hop-checkpoint-v2.json": one_checkpoint,
        "maintenance-two-hop-checkpoint-v2.json": two_checkpoint,
        "maintenance-sequential-checkpoint-v2.json": sequential_checkpoint,
        "maintenance-tombstoned-empty-checkpoint-v2.json": tombstoned,
        "maintenance-empty-result.json": {
            "result": "committed",
            "receipt": empty_receipt,
        },
        "maintenance-one-hop-result.json": {
            "result": "committed",
            "receipt": one_receipt,
        },
        "maintenance-two-hop-result.json": {
            "result": "committed",
            "receipt": two_receipt,
        },
        "maintenance-sequential-result.json": {
            "result": "committed",
            "receipt": sequential_receipt,
        },
        "maintenance-tombstoned-empty-result.json": {
            "result": "committed",
            "receipt": tombstone_receipt,
        },
        "invalid-maintenance-missing-target-checkpoint-v2.json": missing_target,
        "invalid-maintenance-target-digest-checkpoint-v2.json": altered_target,
        "invalid-maintenance-historical-digest-checkpoint-v2.json": historical_digest,
        "invalid-maintenance-audit-order-checkpoint-v2.json": audit_order,
        "invalid-maintenance-next-receipt-gap-checkpoint-v2.json": next_gap,
        "invalid-maintenance-shifted-receipt-gap-checkpoint-v2.json": shifted_gap,
        "operation-inputs.json": operations,
    }
    return {name: canonical(value) for name, value in artifacts.items()}


def outputs() -> dict[Path, bytes]:
    result: dict[Path, bytes] = {}
    for directory, produced in (
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
