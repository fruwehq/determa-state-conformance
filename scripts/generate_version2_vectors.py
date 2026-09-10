#!/usr/bin/env python3
"""Generate deterministic queue-bearing conformance artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import rfc8785
from ruamel.yaml import YAML


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


def rebind_component_aggregate(
    value: dict[str, Any], bundle_path: Path
) -> dict[str, Any]:
    result = copy.deepcopy(value)
    fingerprint = bundle_fingerprint(bundle_path)
    old_root_id = result["root_runtime_id"]
    root_id = digest(
        [
            "determa-root-runtime-identity-2",
            "1",
            fingerprint,
            result["namespace"],
            result["root_machine_id"],
            result["root_machine_version"],
            result["root_instance_id"],
        ]
    )
    replacements = {old_root_id: root_id}
    root_runtime = next(
        runtime for runtime in result["runtimes"] if runtime["relation"]["kind"] == "root"
    )
    for runtime in result["runtimes"]:
        relation = runtime["relation"]
        if relation["kind"] != "component":
            continue
        replacements[runtime["runtime_id"]] = digest(
            [
                "determa-component-runtime-identity-1",
                "1",
                result["root_instance_id"],
                root_id,
                relation["current_component_definition_pointer"],
                relation["activation_sequence"],
                result["namespace"],
                result["root_machine_id"],
                result["root_machine_version"],
            ]
        )

    def replace(value: Any) -> Any:
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    result = replace(result)
    result["validated_bundle_fingerprint"] = fingerprint
    result["root_runtime_id"] = root_id
    for runtime in result["runtimes"]:
        runtime["current_definition"]["validated_bundle_fingerprint"] = fingerprint
        runtime["identity_origin"]["definition"][
            "validated_bundle_fingerprint"
        ] = fingerprint
    root_runtime = next(
        runtime for runtime in result["runtimes"] if runtime["relation"]["kind"] == "root"
    )
    assert root_runtime["runtime_id"] == root_id
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
    machine_path = MAILBOX / "machine.yaml"
    create_input = {
        "operation": "create_v2",
        "bundle": bundle_binding(machine_path),
        "machine_id": "transaction_server",
        "machine_version": "1",
        "root_instance_id": "server-1",
        "creation_id": "create-server-1",
        "bindings": {"input": {}, "external": {}},
    }
    empty = create_v2_root(machine_path, create_input)
    outputs: dict[str, Any] = {}
    outputs["empty-aggregate-v2.json"] = empty
    root = empty["runtimes"][0]

    base = copy.deepcopy(empty)
    base_root = base["runtimes"][0]
    base_root["active_leaf_state_definition_pointers"] = [
        "/machines/0/root/states/busy/states/receiving"
    ]
    base_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/busy", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/busy/states/receiving", "activation_sequence": "0"},
    ]
    base_root["next_state_activation_sequences"] = [
        {"definition_pointer": "/machines/0/root", "next_sequence": "1"},
        {"definition_pointer": "/machines/0/root/states/idle", "next_sequence": "1"},
        {"definition_pointer": "/machines/0/root/states/busy", "next_sequence": "1"},
        {"definition_pointer": "/machines/0/root/states/busy/states/receiving", "next_sequence": "1"},
    ]
    base["next_logical_step_sequence"] = "2"
    received = envelope_entry(
        base,
        base_root,
        event="received",
        event_id="received-1",
        acceptance_sequence=0,
        queue_sequence=0,
    )
    authorized = envelope_entry(
        base,
        base_root,
        event="authorized",
        event_id="authorized-competitor",
        acceptance_sequence=1,
        queue_sequence=1,
    )
    deferred_request = envelope_entry(
        base,
        base_root,
        event="new_request",
        event_id="request-2",
        acceptance_sequence=2,
        queue_sequence=2,
        payload=["map", [["transaction_id", ["string", "transaction-2"]]]],
        deferral_count=1,
    )
    deferred_retry = envelope_entry(
        base,
        base_root,
        event="retry",
        event_id="retry-stays-deferred",
        acceptance_sequence=3,
        queue_sequence=3,
        deferral_count=1,
    )
    base_root["ready_mailbox"] = [received, authorized]
    base_root["deferred_mailbox"] = [deferred_request, deferred_retry]
    base["next_acceptance_sequence"] = "4"
    base["next_queue_sequence"] = "4"
    base = seal_aggregate(base)
    outputs["base-aggregate.json"] = base
    outputs["base-aggregate.canonical.json"] = base

    handled = copy.deepcopy(base)
    handled_root = handled["runtimes"][0]
    handled_root["ready_mailbox"].pop(0)
    recalled = handled_root["deferred_mailbox"].pop(0)
    recalled["queue_sequence"] = "4"
    handled_root["ready_mailbox"].append(recalled)
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
    handled["next_logical_step_sequence"] = "3"
    handled["next_queue_sequence"] = "5"
    handled = seal_aggregate(handled)
    outputs["handled-recall-result.json"] = step_result(handled, "handled")

    deferred_only = copy.deepcopy(base)
    deferred_only["runtimes"][0]["ready_mailbox"] = []
    deferred_only = seal_aggregate(deferred_only)
    outputs["deferred-only-aggregate-v2.json"] = deferred_only
    outputs["not-runnable-result.json"] = step_result(
        deferred_only, "not_runnable"
    )

    repeated_before = copy.deepcopy(base)
    repeated_root = repeated_before["runtimes"][0]
    repeated_root["ready_mailbox"] = []
    repeated_root["deferred_mailbox"] = []
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
    repeated_after["next_logical_step_sequence"] = str(
        int(repeated_before["next_logical_step_sequence"]) + 1
    )
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
    component = rebind_component_aggregate(
        component, MAILBOX / "component-machine.yaml"
    )
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

    completed_component = copy.deepcopy(component)
    completed_target = completed_component["runtimes"][0]
    completed_target["status"] = "completed"
    completed_target["active_leaf_state_definition_pointers"] = []
    completed_target["active_state_activations"] = []
    completed_target["variables"] = []
    completed_target["ready_mailbox"] = []
    completed_target["deferred_mailbox"] = []
    completed_component = seal_aggregate(completed_component)
    outputs["completed-component-aggregate.json"] = completed_component
    outputs["completed-component-step-result.json"] = step_result(
        completed_component, "rejected", rejection="inactive_component_target"
    )

    faulted_component = copy.deepcopy(component)
    faulted_target = faulted_component["runtimes"][0]
    faulted_target["ready_mailbox"] = []
    faulted_target["deferred_mailbox"] = []
    faulted_target["status"] = "faulted"
    faulted_target["fault"] = {
        "definition_fingerprint": faulted_component["validated_bundle_fingerprint"],
        "runtime_id": faulted_target["runtime_id"],
        "cause_id": "retained-fault-cause",
        "code": "action_evaluation_failed",
        "step_sequence": faulted_component["next_logical_step_sequence"],
        "source_locator": "/machines/0/root/states/processing/components/0/root/entry/0",
    }
    faulted_component = seal_aggregate(faulted_component)
    outputs["faulted-component-aggregate.json"] = faulted_component
    outputs["faulted-component-step-result.json"] = step_result(
        faulted_component, "rejected", rejection="inactive_component_target"
    )

    disposed_component = copy.deepcopy(component)
    disposed_target_id = disposed_component["runtimes"][0]["runtime_id"]
    disposed_component["runtimes"].pop(0)
    disposed_component = seal_aggregate(disposed_component)
    outputs["disposed-component-aggregate.json"] = disposed_component
    outputs["disposed-component-step-result.json"] = step_result(
        disposed_component, "rejected", rejection="invalid_instance_target"
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

    zero_before = copy.deepcopy(repeated_before)
    zero_before = rebind_single_root(
        zero_before,
        bundle_fingerprint(MAILBOX / "zero-capacity-machine.yaml"),
    )
    zero_root = zero_before["runtimes"][0]
    zero_entry = zero_root["ready_mailbox"][0]
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
    target_runtimes = lifecycle_before["runtimes"][:2]
    source_entry = source_runtime["ready_mailbox"][0]
    emitted_entries = []
    mailbox_emissions = []
    for ordinal, target_runtime in enumerate(target_runtimes):
        internal_event_id = digest(
            [
                "determa-event-identity-1",
                "1",
                lifecycle_before["root_instance_id"],
                source_runtime["runtime_id"],
                target_runtime["runtime_id"],
                source_entry["envelope"]["cause_id"],
                lifecycle_before["next_logical_step_sequence"],
                "/machines/0/root/states/processing/on_events/fanout/action/0/send",
                str(ordinal),
            ]
        )
        emitted_entry = envelope_entry(
            lifecycle_before,
            target_runtime,
            event="component_work",
            event_id=internal_event_id,
            acceptance_sequence=int(lifecycle_before["next_acceptance_sequence"]) + ordinal,
            queue_sequence=int(lifecycle_before["next_queue_sequence"]) + ordinal,
            delivery_mode="internal",
            source={"runtime": copy.deepcopy(source_runtime["target_identity"])},
        )
        emitted_entries.append(emitted_entry)
        mailbox_emissions.append(
            {
                "kind": "internal_mailbox",
                "emission_index": str(ordinal),
                "event_id": internal_event_id,
                "acceptance_sequence": emitted_entry["acceptance_sequence"],
                "queue_sequence": emitted_entry["queue_sequence"],
            }
        )
    active = copy.deepcopy(lifecycle_before)
    active["runtimes"][-1]["ready_mailbox"] = []
    for runtime, emitted_entry in zip(
        active["runtimes"][:2], emitted_entries, strict=True
    ):
        runtime["ready_mailbox"] = [emitted_entry]
    active["next_acceptance_sequence"] = str(
        int(active["next_acceptance_sequence"]) + len(emitted_entries)
    )
    active["next_queue_sequence"] = str(
        int(active["next_queue_sequence"]) + len(emitted_entries)
    )
    active["next_logical_step_sequence"] = str(
        int(active["next_logical_step_sequence"]) + 1
    )
    active = seal_aggregate(active)
    outputs["internal-emission-active-result.json"] = step_result(
        active, "handled", emissions=mailbox_emissions
    )

    def root_event_before(event: str, event_id: str) -> dict[str, Any]:
        before = copy.deepcopy(lifecycle_before)
        before_root = before["runtimes"][-1]
        entry = before_root["ready_mailbox"][0]
        entry["envelope"]["event"] = event
        entry["envelope"]["event_id"] = event_id
        entry["envelope"]["cause_id"] = event_id
        entry["envelope_digest"] = digest(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                before["root_instance_id"],
                entry["delivery_mode"],
                entry["envelope"],
            ]
        )
        return seal_aggregate(before)

    retained_before = root_event_before("enter_faulty", "enter-faulty-1")
    retained_root = retained_before["runtimes"][-1]
    retained_source = retained_root["ready_mailbox"][0]
    faulty_pointer = "/machines/0/root/states/faulty_processing/components/0"
    faulty_runtime_id = digest(
        [
            "determa-component-runtime-identity-1",
            "1",
            retained_before["root_instance_id"],
            retained_root["runtime_id"],
            faulty_pointer,
            "0",
            retained_before["namespace"],
            retained_before["root_machine_id"],
            retained_before["root_machine_version"],
        ]
    )
    faulty_target = {
        "component": {
            "root_instance_id": retained_before["root_instance_id"],
            "owner_runtime_id": retained_root["runtime_id"],
            "component_id": "faulty",
            "activation_sequence": "0",
            "component_runtime_id": faulty_runtime_id,
        }
    }
    entry_event_id = digest(
        [
            "determa-event-identity-1",
            "1",
            retained_before["root_instance_id"],
            retained_root["runtime_id"],
            faulty_runtime_id,
            retained_source["envelope"]["cause_id"],
            retained_before["next_logical_step_sequence"],
            "/machines/0/root/states/faulty_processing/entry/0/send",
            "0",
        ]
    )
    faulty_template = copy.deepcopy(retained_before["runtimes"][0])
    faulty_template["runtime_id"] = faulty_runtime_id
    faulty_template["identity_origin"] = {
        "kind": "component",
        "definition": {
            "validated_bundle_fingerprint": retained_before["validated_bundle_fingerprint"],
            "machine": {
                "namespace": retained_before["namespace"],
                "machine_id": retained_before["root_machine_id"],
                "machine_version": retained_before["root_machine_version"],
                "root_definition_pointer": f"{faulty_pointer}/root",
            },
        },
        "owner_runtime_id": retained_root["runtime_id"],
        "component_definition_pointer": faulty_pointer,
        "declaration_index": "0",
        "activation_sequence": "0",
    }
    faulty_template["target_identity"] = copy.deepcopy(faulty_target)
    faulty_template["current_definition"] = copy.deepcopy(
        faulty_template["identity_origin"]["definition"]
    )
    faulty_template["relation"] = {
        "kind": "component",
        "owner_runtime_id": retained_root["runtime_id"],
        "current_component_definition_pointer": faulty_pointer,
        "component_id": "faulty",
        "declaration_index": "0",
        "activation_sequence": "0",
    }
    initialization_cause = digest(
        [
            "determa-cause-identity-1",
            "1",
            "component_initialization",
            retained_before["root_instance_id"],
            retained_root["runtime_id"],
            faulty_runtime_id,
            retained_source["envelope"]["cause_id"],
            retained_before["next_logical_step_sequence"],
            faulty_pointer,
            "0",
        ]
    )
    faulty_fault = {
        "definition_fingerprint": retained_before["validated_bundle_fingerprint"],
        "runtime_id": faulty_runtime_id,
        "cause_id": initialization_cause,
        "code": "action_evaluation_failed",
        "step_sequence": retained_before["next_logical_step_sequence"],
        "source_locator": f"{faulty_pointer}/root/entry/0/assign/count",
    }
    faulty_template["status"] = "faulted"
    faulty_template["active_leaf_state_definition_pointers"] = []
    faulty_template["active_state_activations"] = []
    faulty_template["variables"] = []
    faulty_template["history"] = []
    faulty_template["next_spawn_sequence"] = "0"
    faulty_template["next_state_activation_sequences"] = []
    faulty_template["next_component_activation_sequences"] = []
    faulty_template["fault"] = faulty_fault
    pending_entry = envelope_entry(
        retained_before,
        faulty_template,
        event="component_work",
        event_id=entry_event_id,
        acceptance_sequence=int(retained_before["next_acceptance_sequence"]),
        queue_sequence=int(retained_before["next_queue_sequence"]),
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(retained_root["target_identity"])},
    )
    faulty_template["ready_mailbox"] = [pending_entry]
    faulty_template["deferred_mailbox"] = []
    pending_faulty = copy.deepcopy(faulty_template)
    pending_faulty["status"] = "running"
    pending_faulty["fault"] = None
    observer_pointer = "/machines/0/root/states/faulty_processing/components/1"
    observer_runtime_id = digest([
        "determa-component-runtime-identity-1", "1", retained_before["root_instance_id"],
        retained_root["runtime_id"], observer_pointer, "0", retained_before["namespace"],
        retained_before["root_machine_id"], retained_before["root_machine_version"],
    ])
    observer = copy.deepcopy(pending_faulty)
    observer_text = json.dumps(observer).replace(faulty_runtime_id, observer_runtime_id).replace(faulty_pointer, observer_pointer)
    observer = json.loads(observer_text)
    observer["identity_origin"]["declaration_index"] = "1"
    observer["relation"]["declaration_index"] = "1"
    observer["relation"]["component_id"] = "observer"
    observer["target_identity"]["component"]["component_id"] = "observer"
    observer["ready_mailbox"] = []
    pending_root = copy.deepcopy(retained_root)
    pending_root["ready_mailbox"] = []
    pending_root["active_leaf_state_definition_pointers"] = ["/machines/0/root/states/faulty_processing"]
    pending_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/faulty_processing", "activation_sequence": "0"},
    ]
    pending_root["next_state_activation_sequences"].append(
        {"definition_pointer": "/machines/0/root/states/faulty_processing", "next_sequence": "1"}
    )
    pending_root["next_component_activation_sequences"].extend([
        {"definition_pointer": faulty_pointer, "next_sequence": "1"},
        {"definition_pointer": observer_pointer, "next_sequence": "1"},
    ])
    retained_before["runtimes"] = [pending_faulty, observer, pending_root]
    retained_before["next_acceptance_sequence"] = str(int(retained_before["next_acceptance_sequence"]) + 1)
    retained_before["next_queue_sequence"] = str(int(retained_before["next_queue_sequence"]) + 1)
    retained_before["next_logical_step_sequence"] = str(int(retained_before["next_logical_step_sequence"]) + 1)
    retained_before = seal_aggregate(retained_before)
    outputs["retained-faulted-before.json"] = retained_before
    faulty_template["fault"]["step_sequence"] = retained_before["next_logical_step_sequence"]
    failure_event_id = digest(
        [
            "determa-event-identity-1",
            "1",
            retained_before["root_instance_id"],
            faulty_runtime_id,
            retained_root["runtime_id"],
            initialization_cause,
            retained_before["next_logical_step_sequence"],
            "system:component_failure",
            "0",
        ]
    )
    failure_entry = envelope_entry(
        retained_before,
        retained_root,
        event="determa.component_failed",
        event_id=failure_event_id,
        acceptance_sequence=int(retained_before["next_acceptance_sequence"]),
        queue_sequence=int(retained_before["next_queue_sequence"]),
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(faulty_target)},
        payload=typed_value(
            {
                "component_id": "faulty",
                "component_runtime_id": faulty_runtime_id,
                "fault": {
                    "runtime_id": faulty_runtime_id,
                    "cause_id": initialization_cause,
                    "code": "action_evaluation_failed",
                    "step_sequence": faulty_template["fault"]["step_sequence"],
                    "source_locator": faulty_fault["source_locator"],
                },
            }
        ),
    )
    retained_faulted = copy.deepcopy(retained_before)
    retained_result_root = retained_faulted["runtimes"][-1]
    retained_result_root["ready_mailbox"] = [failure_entry]
    retained_result_root["active_leaf_state_definition_pointers"] = [
        "/machines/0/root/states/faulty_processing"
    ]
    retained_result_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/faulty_processing", "activation_sequence": "0"},
    ]
    retained_result_root["next_state_activation_sequences"].append(
        {"definition_pointer": "/machines/0/root/states/faulty_processing", "next_sequence": "1"}
    )
    retained_result_root["next_component_activation_sequences"].append(
        {"definition_pointer": faulty_pointer, "next_sequence": "1"}
    )
    retained_faulted["runtimes"] = [faulty_template, observer, retained_result_root]
    retained_faulted["next_acceptance_sequence"] = str(
        int(retained_faulted["next_acceptance_sequence"]) + 1
    )
    retained_faulted["next_queue_sequence"] = str(
        int(retained_faulted["next_queue_sequence"]) + 1
    )
    retained_faulted["next_logical_step_sequence"] = str(
        int(retained_faulted["next_logical_step_sequence"]) + 1
    )
    retained_faulted = seal_aggregate(retained_faulted)
    outputs["internal-emission-retained-faulted-result.json"] = step_result(
        retained_faulted,
        "faulted",
        fault=faulty_template["fault"],
        emissions=[
            {
                "kind": "internal_mailbox",
                "emission_index": "0",
                "event_id": failure_event_id,
                "acceptance_sequence": failure_entry["acceptance_sequence"],
                "queue_sequence": failure_entry["queue_sequence"],
            },
        ],
    )

    cancellation_before = root_event_before(
        "cancel_after_send", "cancel-after-send-1"
    )
    outputs["cancellation-before.json"] = cancellation_before
    cancellation_root = cancellation_before["runtimes"][-1]
    cancellation_target = cancellation_before["runtimes"][0]
    cancellation_source = cancellation_root["ready_mailbox"][0]
    cancellation_event_id = digest(
        [
            "determa-event-identity-1", "1", cancellation_before["root_instance_id"],
            cancellation_root["runtime_id"], cancellation_target["runtime_id"],
            cancellation_source["envelope"]["cause_id"], cancellation_before["next_logical_step_sequence"],
            "/machines/0/root/states/processing/on_events/cancel_after_send/action/0/send", "0",
        ]
    )
    cancellation_entry = envelope_entry(
        cancellation_before, cancellation_target, event="component_work",
        event_id=cancellation_event_id,
        acceptance_sequence=int(cancellation_before["next_acceptance_sequence"]),
        queue_sequence=int(cancellation_before["next_queue_sequence"]),
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(cancellation_root["target_identity"])},
    )
    cancelled = copy.deepcopy(cancellation_before)
    cancelled_root = cancelled["runtimes"][-1]
    cancelled_root["ready_mailbox"] = []
    cancelled_root["status"] = "completed"
    cancelled_root["active_leaf_state_definition_pointers"] = []
    cancelled_root["active_state_activations"] = []
    cancelled_root["variables"] = []
    cancelled["runtimes"] = [cancelled_root]
    cancelled["next_acceptance_sequence"] = str(int(cancelled["next_acceptance_sequence"]) + 1)
    cancelled["next_queue_sequence"] = str(int(cancelled["next_queue_sequence"]) + 1)
    cancelled["next_logical_step_sequence"] = str(int(cancelled["next_logical_step_sequence"]) + 1)
    cancelled = seal_aggregate(cancelled)
    cancellation_disposition = lifecycle_disposition(
        cancellation_entry, cancellation_target["runtime_id"], "runtime_cancelled"
    )
    outputs["internal-emission-cancelled-result.json"] = step_result(
        cancelled, "handled", status="completed",
        emissions=[internal_disposed_emission(cancellation_entry)],
        lifecycle_dispositions=[cancellation_disposition],
    )

    natural_before = copy.deepcopy(lifecycle_before)
    natural_root = natural_before["runtimes"][-1]
    natural_target = natural_before["runtimes"][0]
    natural_root["ready_mailbox"] = []
    natural_cause = envelope_entry(
        natural_before, natural_target, event="component_finish",
        event_id="component-finish-1", acceptance_sequence=2, queue_sequence=2,
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(natural_root["target_identity"])},
    )
    natural_target["ready_mailbox"] = [natural_cause]
    natural_before = seal_aggregate(natural_before)
    outputs["natural-completion-before.json"] = natural_before
    self_event_id = digest(
        ["determa-event-identity-1", "1", natural_before["root_instance_id"],
         natural_target["runtime_id"], natural_target["runtime_id"],
         natural_cause["envelope"]["cause_id"], natural_before["next_logical_step_sequence"],
         "/machines/0/root/states/processing/components/0/root/states/running/on_events/component_finish/action/0/send", "0"]
    )
    self_entry = envelope_entry(
        natural_before, natural_target, event="component_work", event_id=self_event_id,
        acceptance_sequence=3, queue_sequence=3, delivery_mode="internal",
        source={"runtime": copy.deepcopy(natural_target["target_identity"])},
    )
    completion_event_id = digest(
        ["determa-event-identity-1", "1", natural_before["root_instance_id"],
         natural_target["runtime_id"], natural_root["runtime_id"],
         natural_cause["envelope"]["cause_id"], natural_before["next_logical_step_sequence"],
         "system:component_completion", "0"]
    )
    completion_entry = envelope_entry(
        natural_before, natural_root, event="determa.component_completed",
        event_id=completion_event_id, acceptance_sequence=4, queue_sequence=4,
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(natural_target["target_identity"])},
        payload=typed_value({"component_id": "left", "component_runtime_id": natural_target["runtime_id"]}),
    )
    naturally_completed = copy.deepcopy(natural_before)
    completed_target = naturally_completed["runtimes"][0]
    completed_target["status"] = "completed"
    completed_target["active_leaf_state_definition_pointers"] = []
    completed_target["active_state_activations"] = []
    completed_target["variables"] = []
    completed_target["ready_mailbox"] = []
    naturally_completed["runtimes"][-1]["ready_mailbox"] = [completion_entry]
    naturally_completed["next_acceptance_sequence"] = "5"
    naturally_completed["next_queue_sequence"] = "5"
    naturally_completed["next_logical_step_sequence"] = str(int(naturally_completed["next_logical_step_sequence"]) + 1)
    naturally_completed = seal_aggregate(naturally_completed)
    natural_disposition = lifecycle_disposition(self_entry, natural_target["runtime_id"], "runtime_completed")
    outputs["internal-emission-runtime-completed-result.json"] = step_result(
        naturally_completed, "handled",
        emissions=[
            internal_disposed_emission(self_entry),
            {"kind": "internal_mailbox", "emission_index": "1", "event_id": completion_event_id,
             "acceptance_sequence": completion_entry["acceptance_sequence"], "queue_sequence": completion_entry["queue_sequence"]},
        ],
        lifecycle_dispositions=[natural_disposition],
    )
    reserved_before = copy.deepcopy(naturally_completed)
    outputs["reserved-event-before.json"] = reserved_before
    reserved_after = copy.deepcopy(reserved_before)
    reserved_after["runtimes"][-1]["ready_mailbox"].pop(0)
    reserved_after["next_logical_step_sequence"] = str(
        int(reserved_after["next_logical_step_sequence"]) + 1
    )
    reserved_after = seal_aggregate(reserved_after)
    outputs["reserved-event-handled-result.json"] = step_result(
        reserved_after, "handled"
    )

    aggregate_before = root_event_before("aggregate_finish", "aggregate-finish-1")
    outputs["aggregate-completion-before.json"] = aggregate_before
    aggregate_root = aggregate_before["runtimes"][-1]
    aggregate_cause = aggregate_root["ready_mailbox"][0]
    aggregate_event_id = digest(
        ["determa-event-identity-1", "1", aggregate_before["root_instance_id"],
         aggregate_root["runtime_id"], aggregate_root["runtime_id"],
         aggregate_cause["envelope"]["cause_id"], aggregate_before["next_logical_step_sequence"],
         "/machines/0/root/on_events/aggregate_finish/action/0/send", "0"]
    )
    aggregate_entry = envelope_entry(
        aggregate_before, aggregate_root, event="component_work", event_id=aggregate_event_id,
        acceptance_sequence=3, queue_sequence=3, delivery_mode="internal",
        source={"runtime": copy.deepcopy(aggregate_root["target_identity"])},
    )
    aggregate_completed = copy.deepcopy(aggregate_before)
    result_root = aggregate_completed["runtimes"][-1]
    result_root["status"] = "completed"
    result_root["active_leaf_state_definition_pointers"] = []
    result_root["active_state_activations"] = []
    result_root["variables"] = []
    result_root["ready_mailbox"] = []
    aggregate_completed["runtimes"] = [result_root]
    aggregate_completed["next_acceptance_sequence"] = "4"
    aggregate_completed["next_queue_sequence"] = "4"
    aggregate_completed["next_logical_step_sequence"] = str(int(aggregate_completed["next_logical_step_sequence"]) + 1)
    aggregate_completed = seal_aggregate(aggregate_completed)
    aggregate_disposition = lifecycle_disposition(aggregate_entry, aggregate_root["runtime_id"], "aggregate_completed")
    outputs["internal-emission-aggregate-completed-result.json"] = step_result(
        aggregate_completed, "handled", status="completed",
        emissions=[internal_disposed_emission(aggregate_entry)],
        lifecycle_dispositions=[aggregate_disposition],
    )

    rollback_before = root_event_before("cleanup_rollback", "cleanup-rollback-1")
    rollback_root = rollback_before["runtimes"][-1]
    retained_component = rollback_before["runtimes"][0]
    cleanup_pointer = "/machines/0/root/states/cleanup_failed/components/0"
    cleanup_runtime_id = digest(
        ["determa-component-runtime-identity-1", "1", rollback_before["root_instance_id"],
         rollback_root["runtime_id"], cleanup_pointer, "0", rollback_before["namespace"],
         rollback_before["root_machine_id"], rollback_before["root_machine_version"]]
    )
    old_id = retained_component["runtime_id"]
    encoded = json.dumps(retained_component).replace(old_id, cleanup_runtime_id).replace(
        "/machines/0/root/states/processing/components/0", cleanup_pointer
    )
    retained_component = json.loads(encoded)
    retained_component["relation"]["component_id"] = "retained"
    retained_component["target_identity"]["component"]["component_id"] = "retained"
    peer_pointer = "/machines/0/root/states/cleanup_failed/components/1"
    peer_runtime_id = digest(
        ["determa-component-runtime-identity-1", "1", rollback_before["root_instance_id"],
         rollback_root["runtime_id"], peer_pointer, "0", rollback_before["namespace"],
         rollback_before["root_machine_id"], rollback_before["root_machine_version"]]
    )
    retained_peer = json.loads(
        json.dumps(retained_component).replace(cleanup_runtime_id, peer_runtime_id).replace(cleanup_pointer, peer_pointer)
    )
    retained_peer["identity_origin"]["declaration_index"] = "1"
    retained_peer["relation"]["declaration_index"] = "1"
    retained_peer["relation"]["component_id"] = "retained_peer"
    retained_peer["target_identity"]["component"]["component_id"] = "retained_peer"
    rollback_root["active_leaf_state_definition_pointers"] = ["/machines/0/root/states/cleanup_failed"]
    rollback_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/cleanup_failed", "activation_sequence": "0"},
    ]
    rollback_root["next_state_activation_sequences"].append(
        {"definition_pointer": "/machines/0/root/states/cleanup_failed", "next_sequence": "1"}
    )
    rollback_root["next_component_activation_sequences"].append(
        {"definition_pointer": cleanup_pointer, "next_sequence": "1"}
    )
    rollback_root["next_component_activation_sequences"].append(
        {"definition_pointer": peer_pointer, "next_sequence": "1"}
    )
    rollback_before["runtimes"] = [retained_component, retained_peer, rollback_root]
    rollback_before = seal_aggregate(rollback_before)
    outputs["cleanup-rollback-before.json"] = rollback_before
    rollback = copy.deepcopy(rollback_before)
    rollback_root = rollback["runtimes"][-1]
    rollback_source = rollback_root["ready_mailbox"].pop(0)
    rollback_fault = {
        "definition_fingerprint": rollback["validated_bundle_fingerprint"],
        "runtime_id": rollback_root["runtime_id"],
        "cause_id": rollback_source["envelope"]["cause_id"],
        "code": "action_evaluation_failed",
        "step_sequence": rollback["next_logical_step_sequence"],
        "source_locator": "/machines/0/root/states/cleanup_failed/exit/0/assign/cleanup_marker",
    }
    rollback_root["status"] = "faulted"
    rollback_root["fault"] = rollback_fault
    rollback["next_logical_step_sequence"] = str(int(rollback["next_logical_step_sequence"]) + 1)
    rollback = seal_aggregate(rollback)
    outputs["internal-emission-rollback-result.json"] = step_result(
        rollback, "faulted", status="faulted", fault=rollback_fault
    )

    invalid_aggregate = copy.deepcopy(base)
    del invalid_aggregate["runtimes"][0]["deferred_mailbox"]
    outputs["invalid-aggregate-v2.json"] = invalid_aggregate
    invalid_result = step_result(empty, "not_runnable")
    invalid_result["language_specific"] = True
    outputs["invalid-core-step-result-v2.json"] = invalid_result

    def delivery_input(
        aggregate: dict[str, Any],
        runtime: dict[str, Any],
        event: str,
        event_id: str,
        payload: list[Any] | None = None,
    ) -> dict[str, Any]:
        entry = envelope_entry(
            aggregate,
            runtime,
            event=event,
            event_id=event_id,
            acceptance_sequence=0,
            queue_sequence=0,
            payload=payload,
        )
        return {
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }

    base_root = base["runtimes"][0]
    duplicate_delivery = delivery_input(
        base, base_root, "received", "duplicate"
    )
    equal_replay = {
        "delivery_mode": deferred_request["delivery_mode"],
        "envelope": copy.deepcopy(deferred_request["envelope"]),
        "envelope_digest": deferred_request["envelope_digest"],
    }
    conflicting_replay = copy.deepcopy(equal_replay)
    conflicting_replay["envelope"]["payload"] = typed_value(
        {"transaction_id": "different"}
    )
    conflicting_replay["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            base["root_instance_id"],
            conflicting_replay["delivery_mode"],
            conflicting_replay["envelope"],
        ]
    )
    completed_identity = component["runtimes"][0]["target_identity"]
    disposed_delivery = delivery_input(
        component,
        component["runtimes"][0],
        "component_work",
        "disposed-component-admission",
    )
    disposed_delivery["envelope"]["target"] = copy.deepcopy(completed_identity)
    disposed_delivery["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            disposed_component["root_instance_id"],
            disposed_delivery["delivery_mode"],
            disposed_delivery["envelope"],
        ]
    )
    operation_inputs = {
        "create": create_input,
        "admit_two": {
            "operation": "admit_v2",
            "deliveries": [
                delivery_input(base, base_root, "received", "batch-a"),
                delivery_input(base, base_root, "authorized", "batch-b"),
            ],
        },
        "duplicate_batch": {
            "operation": "admit_v2",
            "deliveries": [duplicate_delivery, copy.deepcopy(duplicate_delivery)],
        },
        "equal_replay": {"operation": "admit_v2", "deliveries": [equal_replay]},
        "conflicting_replay": {
            "operation": "admit_v2",
            "deliveries": [conflicting_replay],
        },
        "recall_step": {"operation": "step_v2", "target_runtime_id": base["root_runtime_id"]},
        "repeated_step": {"operation": "step_v2", "target_runtime_id": repeated_before["root_runtime_id"]},
        "deferred_only_step": {"operation": "step_v2", "target_runtime_id": deferred_only["root_runtime_id"]},
        "component_step": {"operation": "step_v2", "target_runtime_id": component["runtimes"][0]["runtime_id"]},
        "spawn_step": {"operation": "step_v2", "target_runtime_id": spawned["runtimes"][0]["runtime_id"]},
        "completed_component_step": {"operation": "step_v2", "target_runtime_id": completed_component["runtimes"][0]["runtime_id"]},
        "faulted_component_step": {"operation": "step_v2", "target_runtime_id": faulted_component["runtimes"][0]["runtime_id"]},
        "disposed_component_step": {"operation": "step_v2", "target_runtime_id": disposed_target_id},
        "invalid_runtime_step": {"operation": "step_v2", "target_runtime_id": "sha256:" + "0" * 64},
        "overflow_step": {"operation": "step_v2", "target_runtime_id": zero_before["root_runtime_id"]},
        "fanout_step": {"operation": "step_v2", "target_runtime_id": lifecycle_before["root_runtime_id"]},
        "retained_faulted_step": {"operation": "step_v2", "target_runtime_id": faulty_runtime_id},
        "cancellation_step": {"operation": "step_v2", "target_runtime_id": cancellation_before["root_runtime_id"]},
        "natural_completion_step": {"operation": "step_v2", "target_runtime_id": natural_target["runtime_id"]},
        "aggregate_completion_step": {"operation": "step_v2", "target_runtime_id": aggregate_before["root_runtime_id"]},
        "cleanup_rollback_step": {"operation": "step_v2", "target_runtime_id": rollback_before["root_runtime_id"]},
        "reserved_event_step": {"operation": "step_v2", "target_runtime_id": reserved_before["root_runtime_id"]},
        "completed_component_admit": {"operation": "admit_v2", "deliveries": [delivery_input(completed_component, completed_component["runtimes"][0], "component_work", "completed-component-admission")]},
        "faulted_component_admit": {"operation": "admit_v2", "deliveries": [delivery_input(faulted_component, faulted_component["runtimes"][0], "component_work", "faulted-component-admission")]},
        "disposed_component_admit": {"operation": "admit_v2", "deliveries": [disposed_delivery]},
    }
    outputs["operation-inputs.json"] = operation_inputs
    outputs["admission-success.json"] = {
        "result": "accepted",
        "accepted": [
            {"event_id": "batch-a", "acceptance_sequence": "4", "queue_sequence": "4"},
            {"event_id": "batch-b", "acceptance_sequence": "5", "queue_sequence": "5"},
        ],
    }
    outputs["replay-success.json"] = {
        "result": "replay",
        "event_id": "request-2",
        "acceptance_sequence": "2",
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
    source_document = normalize_bundle_document(load_yaml(PERSISTENCE / "machine.yaml"))
    source_fingerprint = bundle_fingerprint_document(source_document)
    aggregate_v2 = rebind_single_root(
        load(PERSISTENCE / "base-aggregate-v2.json"), source_fingerprint
    )

    target_documents: dict[str, dict[str, Any]] = {}
    target_documents["target-compatible.yaml"] = copy.deepcopy(source_document)
    removed_event = copy.deepcopy(source_document)
    del removed_event["events"]["new_request"]
    removed_event["machines"][0]["root"]["states"]["idle"].pop("on_events")
    removed_event["machines"][0]["root"]["states"]["busy"]["deferred_events"] = ["retired_event"]
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

    base_descriptor_template = load(PERSISTENCE / "base-descriptor-v1.json")

    def make_descriptor(target_name: str, *, dispose_retired: bool = False) -> dict[str, Any]:
        descriptor_v1 = copy.deepcopy(base_descriptor_template)
        descriptor_v1["source_validated_bundle_fingerprint"] = source_fingerprint
        descriptor_v1["target_validated_bundle_fingerprint"] = bundle_fingerprint_document(target_documents[target_name])
        descriptor_v1.pop("migration_descriptor_digest", None)
        descriptor_v1["migration_descriptor_digest"] = digest(
            ["determa-migration-descriptor-1", descriptor_v1]
        )
        descriptor = {
            "migration_descriptor_format": "determa.aggregate_migration",
            "migration_descriptor_schema_version": 2,
            "base_descriptor": descriptor_v1,
            "queued_event_default": "preserve_if_compatible",
            "queued_event_rules": ([{
                "machine_id": aggregate_v2["root_machine_id"],
                "event": "retired_event",
                "delivery_mode": "input",
                "action": "dispose",
                "reason": "event removed by version migration",
            }] if dispose_retired else []),
        }
        descriptor["migration_descriptor_digest"] = digest(
            ["determa-migration-descriptor-2", descriptor]
        )
        return descriptor

    descriptors = {
        "descriptor-compatible-v2.json": make_descriptor("target-compatible.yaml"),
        "descriptor-dispose-v2.json": make_descriptor("target-compatible.yaml", dispose_retired=True),
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
        "normalized_definitions": [{
            "validated_bundle_fingerprint": source_fingerprint,
            "normalized_bundle": typed_value(source_document),
        }],
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
    disposal_after["validated_bundle_fingerprint"] = descriptors["descriptor-dispose-v2.json"]["base_descriptor"]["target_validated_bundle_fingerprint"]
    disposal_after["runtimes"][0]["current_definition"]["validated_bundle_fingerprint"] = disposal_after["validated_bundle_fingerprint"]
    disposal_after["migration_sequence"] = str(int(disposal_after["migration_sequence"]) + 1)
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
    outputs: dict[str, Any] = {
        "upgraded-aggregate-v2.json": canonical(upgraded_aggregate_v2),
        "base-aggregate-v2.json": canonical(aggregate_v2),
        "base-descriptor-v1.json": canonical(descriptors["descriptor-compatible-v2.json"]["base_descriptor"]),
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
                        "migration_descriptor_digest": descriptors["descriptor-dispose-v2.json"]["migration_descriptor_digest"],
                    }
                ],
            }
        ),
        "downgrade-result.json": canonical(
            {"result": "success", "aggregate_state": aggregate_v1}
        ),
        "operation-inputs.json": canonical({}),
    }
    for name, document in target_documents.items():
        outputs[name] = canonical(document)
    for name, descriptor in descriptors.items():
        outputs[name] = canonical(descriptor)
    operations: dict[str, Any] = {
        "upgrade": {"operation": "upgrade_aggregate_v1_to_v2"},
        "downgrade": {"operation": "downgrade_aggregate_v2_to_v1"},
        "downgrade_prohibited": {"operation": "downgrade_aggregate_v2_to_v1"},
    }
    migration_targets = {
        "preserve": ("target-compatible.yaml", "descriptor-compatible-v2.json"),
        "preserve_fault": ("target-compatible.yaml", "descriptor-compatible-v2.json"),
        "dispose": ("target-compatible.yaml", "descriptor-dispose-v2.json"),
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
            "source_bundle": bundle_binding(PERSISTENCE / "machine.yaml"),
            "target_bundle": generated_bundle_binding(target_name, target_documents[target_name]),
            "migration_descriptor_file": descriptor_name,
            "migration_descriptor_digest_route": [descriptor["migration_descriptor_digest"]],
        }
    outputs["operation-inputs.json"] = canonical(operations)
    return {name: data if isinstance(data, bytes) else canonical(data) for name, data in outputs.items()}


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
    next_receipt_sequence = int(source["next_operation_receipt_sequence"])
    next_queue_sequence = 0
    aggregate["next_acceptance_sequence"] = source["next_delivery_sequence"]
    runtime_by_id = {runtime["runtime_id"]: runtime for runtime in aggregate["runtimes"]}
    for pending in sorted(source["pending_deliveries"], key=lambda item: int(item["delivery_sequence"])):
        origin = pending["origin"]
        envelope = copy.deepcopy(pending["envelope"])
        envelope["cause_id"] = envelope["event_id"]
        envelope["source"] = (
            {"host": True}
            if origin["kind"] == "host_input"
            else {"legacy_v1_internal": {
                "producing_receipt_sequence": origin["producing_receipt_sequence"],
                "emission_index": origin["emission_index"],
            }}
        )
        entry = {
            "acceptance_sequence": pending["delivery_sequence"],
            "queue_sequence": str(next_queue_sequence),
            "delivery_mode": pending["delivery_mode"],
            "envelope": envelope,
            "envelope_digest": digest([
                "determa-inbox-envelope-digest-2", "2", source["root_instance_id"],
                pending["delivery_mode"], envelope,
            ]),
            "deferral_count": "0",
        }
        target_runtime_id = next(iter(envelope["target"].values()))
        if isinstance(target_runtime_id, dict):
            target_runtime_id = next(value for key, value in target_runtime_id.items() if key.endswith("runtime_id"))
        runtime_by_id[target_runtime_id]["ready_mailbox"].append(entry)
        receipt = {
            "operation_kind": "acceptance",
            "receipt_sequence": str(next_receipt_sequence),
            "event_id": envelope["event_id"],
            "request_digest": entry["envelope_digest"],
            "acceptance_sequence": pending["delivery_sequence"],
            "accepted_revision": pending["accepted_revision"],
            "delivery_mode": pending["delivery_mode"],
        }
        if pending["delivery_mode"] == "internal":
            receipt["legacy_v1_delivery"] = {
                "delivery_sequence": pending["delivery_sequence"],
                "envelope_digest": pending["envelope_digest"],
                "origin": origin,
            }
        receipts.append(receipt)
        next_receipt_sequence += 1
        next_queue_sequence += 1
    aggregate["next_queue_sequence"] = str(next_queue_sequence)
    aggregate = seal_aggregate(aggregate)
    result = {
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 2,
        "root_instance_id": source["root_instance_id"],
        "revision": str(int(source["revision"]) + 1),
        "root_record": {"status": "retained", "aggregate_state": aggregate},
        "replay_retention": source["replay_retention"],
        "next_operation_receipt_sequence": str(next_receipt_sequence),
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
    v1 = load(CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle" / "internal-pending-checkpoint.json")
    upgraded = upgrade_checkpoint(v1)
    operational_base = copy.deepcopy(upgraded)
    operational_aggregate = operational_base["root_record"]["aggregate_state"]
    for runtime in operational_aggregate["runtimes"]:
        runtime["ready_mailbox"] = []
        runtime["deferred_mailbox"] = []
    operational_aggregate["next_queue_sequence"] = "0"
    operational_base["root_record"]["aggregate_state"] = seal_aggregate(operational_aggregate)
    operational_base["operation_receipts"] = [
        receipt for receipt in operational_base["operation_receipts"]
        if receipt["operation_kind"] != "acceptance"
    ]
    operational_base["next_operation_receipt_sequence"] = v1["next_operation_receipt_sequence"]
    operational_base["replay_retention"] = {
        "mode": "bounded",
        "permanent_replay_eligible": False,
        "pruned_through_receipt_sequence": None,
        "policy_identifier": "bounded-test-v1",
    }
    operational_base = seal_checkpoint(operational_base)
    admitted = copy.deepcopy(operational_base)
    aggregate = admitted["root_record"]["aggregate_state"]
    root = next(r for r in aggregate["runtimes"] if r["relation"]["kind"] == "root")
    entry = envelope_entry(
        aggregate,
        root,
        event="increment",
        event_id="checkpoint-v2-increment",
        acceptance_sequence=int(aggregate["next_acceptance_sequence"]),
        queue_sequence=int(aggregate["next_queue_sequence"]),
        payload=["map", [["amount", ["integer", "1"]]]],
    )
    root["ready_mailbox"] = [entry]
    aggregate["next_acceptance_sequence"] = str(int(entry["acceptance_sequence"]) + 1)
    aggregate["next_queue_sequence"] = str(int(entry["queue_sequence"]) + 1)
    aggregate = seal_aggregate(aggregate)
    admitted["root_record"]["aggregate_state"] = aggregate
    admitted["revision"] = str(int(operational_base["revision"]) + 1)
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

    native_internal = copy.deepcopy(terminal)
    native_aggregate = native_internal["root_record"]["aggregate_state"]
    native_root = next(r for r in native_aggregate["runtimes"] if r["relation"]["kind"] == "root")
    native_event_id = digest([
        "determa-event-identity-1", "1", native_aggregate["root_instance_id"],
        native_root["runtime_id"], native_root["runtime_id"], consumed["envelope"]["cause_id"],
        str(int(native_aggregate["next_logical_step_sequence"]) - 1),
        "/machines/0/root/on_events/increment/action/0/send", "0",
    ])
    native_entry = envelope_entry(
        native_aggregate, native_root, event="internal_increment", event_id=native_event_id,
        acceptance_sequence=int(native_aggregate["next_acceptance_sequence"]),
        queue_sequence=int(native_aggregate["next_queue_sequence"]), delivery_mode="internal",
        source={"runtime": copy.deepcopy(native_root["target_identity"])},
        payload=typed_value({"amount": 5}),
    )
    native_root["ready_mailbox"] = [native_entry]
    native_aggregate["next_acceptance_sequence"] = str(int(native_entry["acceptance_sequence"]) + 1)
    native_aggregate["next_queue_sequence"] = str(int(native_entry["queue_sequence"]) + 1)
    native_internal["operation_receipts"][-1]["emission_references"] = [{
        "kind": "internal_mailbox", "emission_index": "0", "event_id": native_event_id,
        "acceptance_sequence": native_entry["acceptance_sequence"], "queue_sequence": native_entry["queue_sequence"],
    }]
    native_internal["root_record"]["aggregate_state"] = seal_aggregate(native_aggregate)
    native_internal["operation_receipts"][-1]["resulting_aggregate_state_digest"] = native_internal["root_record"]["aggregate_state"]["aggregate_state_digest"]
    native_internal = seal_checkpoint(native_internal)

    native_terminal = copy.deepcopy(native_internal)
    native_terminal_aggregate = native_terminal["root_record"]["aggregate_state"]
    native_terminal_root = next(r for r in native_terminal_aggregate["runtimes"] if r["relation"]["kind"] == "root")
    native_consumed = native_terminal_root["ready_mailbox"].pop(0)
    native_terminal_root["variables"][0]["value"] = ["integer", "6"]
    native_terminal_aggregate["next_logical_step_sequence"] = str(int(native_terminal_aggregate["next_logical_step_sequence"]) + 1)
    native_terminal_aggregate = seal_aggregate(native_terminal_aggregate)
    native_terminal["root_record"]["aggregate_state"] = native_terminal_aggregate
    native_terminal["revision"] = str(int(native_terminal["revision"]) + 1)
    native_terminal_sequence = native_terminal["next_operation_receipt_sequence"]
    native_terminal["operation_receipts"][-1]["emission_references"] = [{
        "kind": "internal_terminal",
        "emission_index": "0",
        "event_id": native_consumed["envelope"]["event_id"],
        "acceptance_sequence": native_consumed["acceptance_sequence"],
        "terminal_receipt_sequence": native_terminal_sequence,
    }]
    native_terminal["operation_receipts"].append({
        "operation_kind": "event_terminal", "receipt_sequence": native_terminal_sequence,
        "event_id": native_consumed["envelope"]["event_id"], "request_digest": native_consumed["envelope_digest"],
        "acceptance_sequence": native_consumed["acceptance_sequence"], "final_queue_sequence": native_consumed["queue_sequence"],
        "committed_revision": native_terminal["revision"],
        "resulting_aggregate_state_digest": native_terminal_aggregate["aggregate_state_digest"],
        "outcome": {"status": "running", "disposition": "handled", "fault": None, "rejection": None},
        "emission_references": [],
    })
    native_terminal["next_operation_receipt_sequence"] = str(int(native_terminal_sequence) + 1)
    native_terminal = seal_checkpoint(native_terminal)

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
    permanent = copy.deepcopy(terminal)
    permanent["replay_retention"] = {
        "mode": "permanent",
        "permanent_replay_eligible": True,
        "pruned_through_receipt_sequence": None,
        "policy_identifier": None,
    }
    permanent = seal_checkpoint(permanent)
    operations = {
        "upgrade": {"operation": "upgrade_checkpoint_v1_to_v2"},
        "admit": {"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]},
        "v1_admit": {"operation": "checkpoint_v1_accept", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]},
        "terminal_step": {"operation": "checkpoint_step_v2", "target_runtime_id": aggregate["root_runtime_id"]},
        "native_internal_step": {"operation": "checkpoint_step_v2", "target_runtime_id": native_aggregate["root_runtime_id"]},
        "terminal_equal_replay": {"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]},
        "terminal_conflict": {"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": {**entry["envelope"], "payload": typed_value({"amount": 2})},
            "envelope_digest": digest(["determa-inbox-envelope-digest-2", "2", aggregate["root_instance_id"], entry["delivery_mode"], {**entry["envelope"], "payload": typed_value({"amount": 2})}]),
        }]},
        "bounded_prune": {"operation": "checkpoint_prune_v2", "retention_mode": "bounded"},
        "permanent_prune": {"operation": "checkpoint_prune_v2", "retention_mode": "permanent"},
        "pending_prune": {"operation": "checkpoint_prune_v2", "retention_mode": "bounded"},
        "producer_prune": {"operation": "checkpoint_prune_v2", "retention_mode": "bounded"},
        "tombstone": {"operation": "checkpoint_tombstone_v2"},
        "downgrade": {"operation": "downgrade_checkpoint_v2_to_v1"},
    }
    return {
        "base-checkpoint-v1.json": canonical(v1),
        "base-checkpoint.json": canonical(operational_base),
        "upgraded-checkpoint-v2.json": canonical(upgraded),
        "admitted-checkpoint-v2.json": canonical(admitted),
        "terminal-checkpoint-v2.json": canonical(terminal),
        "native-internal-checkpoint-v2.json": canonical(native_internal),
        "native-internal-terminal-checkpoint-v2.json": canonical(native_terminal),
        "compact-checkpoint-v2.json": canonical(compact),
        "invalid-duplicate-location-checkpoint-v2.json": canonical(invalid),
        "permanent-checkpoint-v2.json": canonical(permanent),
        "operation-inputs.json": canonical(operations),
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
