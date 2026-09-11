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


def seal_checkpoint_v1(value: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(value)
    value.pop("execution_checkpoint_digest", None)
    value["execution_checkpoint_digest"] = digest(
        ["determa-execution-checkpoint-digest-1", value]
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
    root_runtime = next(
        runtime for runtime in state["runtimes"] if runtime["relation"]["kind"] == "root"
    )
    return {
        "core_step_result_format": "determa.core_step_result",
        "core_step_result_schema_version": 2,
        "status": root_runtime["status"] if status is None else status,
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


def root_runtime(aggregate: dict[str, Any]) -> dict[str, Any]:
    return next(
        runtime
        for runtime in aggregate["runtimes"]
        if runtime["relation"]["kind"] == "root"
    )


def component_runtimes(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        (
            runtime
            for runtime in aggregate["runtimes"]
            if runtime["relation"]["kind"] == "component"
        ),
        key=lambda runtime: int(runtime["relation"]["declaration_index"]),
    )


def spawned_runtimes(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        (
            runtime
            for runtime in aggregate["runtimes"]
            if runtime["relation"]["kind"] == "owned_spawned_instance"
        ),
        key=lambda runtime: int(runtime["relation"]["spawn_sequence"]),
    )


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
    deferred_retry = envelope_entry(
        base,
        base_root,
        event="retry",
        event_id="retry-guarded-recall",
        acceptance_sequence=2,
        queue_sequence=2,
        deferral_count=1,
    )
    deferred_held = envelope_entry(
        base,
        base_root,
        event="held_request",
        event_id="held-stays-deferred",
        acceptance_sequence=3,
        queue_sequence=3,
        deferral_count=1,
    )
    base_root["ready_mailbox"] = [received, authorized]
    base_root["deferred_mailbox"] = [deferred_retry, deferred_held]
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
    component_root = root_runtime(component)
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
                    {"runtime": copy.deepcopy(component_root["target_identity"])}
                    if runtime["relation"]["kind"] == "component"
                    else {"host": True}
                ),
            )
        ]
    component["next_acceptance_sequence"] = "3"
    component["next_queue_sequence"] = "3"
    component = seal_aggregate(component)
    outputs["component-isolation-aggregate.json"] = component
    invalid_runtime_order = copy.deepcopy(component)
    invalid_runtime_order["runtimes"].reverse()
    outputs["invalid-canonical-order-aggregate-v2.json"] = (
        reseal_aggregate_without_normalizing(invalid_runtime_order)
    )
    component_after = copy.deepcopy(component)
    left = component_runtimes(component_after)[0]
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
    completed_target = component_runtimes(completed_component)[0]
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
    faulted_target = component_runtimes(faulted_component)[0]
    faulted_target["ready_mailbox"] = []
    faulted_target["deferred_mailbox"] = []
    faulted_target["status"] = "faulted"
    faulted_target["fault"] = {
        "definition_fingerprint": faulted_component["validated_bundle_fingerprint"],
        "runtime_id": faulted_target["runtime_id"],
        "cause_id": "retained-fault-cause",
        "code": "action_fault",
        "step_sequence": faulted_component["next_logical_step_sequence"],
        "source_locator": "/machines/0/root/states/processing/components/0/root/states/running/on_events/component_work/action/0/assign/trace",
    }
    faulted_component = seal_aggregate(faulted_component)
    outputs["faulted-component-aggregate.json"] = faulted_component
    outputs["faulted-component-step-result.json"] = step_result(
        faulted_component, "rejected", rejection="inactive_component_target"
    )

    disposed_component = copy.deepcopy(component)
    disposed_target = component_runtimes(disposed_component)[0]
    disposed_target_id = disposed_target["runtime_id"]
    disposed_component["runtimes"] = [
        runtime for runtime in disposed_component["runtimes"] if runtime["runtime_id"] != disposed_target_id
    ]
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
    spawned_runtimes(spawned_after)[0]["ready_mailbox"].pop(0)
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
    for runtime in component_runtimes(lifecycle_before):
        runtime["ready_mailbox"] = []
        runtime["deferred_mailbox"] = []
    lifecycle_before = seal_aggregate(lifecycle_before)
    outputs["lifecycle-before.json"] = lifecycle_before

    source_runtime = root_runtime(lifecycle_before)
    target_runtimes = component_runtimes(lifecycle_before)
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
    root_runtime(active)["ready_mailbox"] = []
    for runtime, emitted_entry in zip(
        component_runtimes(active), emitted_entries, strict=True
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
        before_root = root_runtime(before)
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
    outputs["retained-faulted-before.json"] = retained_before
    retained_faulted = copy.deepcopy(retained_before)
    retained_root = root_runtime(retained_faulted)
    retained_source = retained_root["ready_mailbox"].pop(0)
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
    faulty_template = copy.deepcopy(component_runtimes(retained_faulted)[0])
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
    faulty_template["status"] = "running"
    faulty_template["active_leaf_state_definition_pointers"] = []
    faulty_template["active_state_activations"] = []
    faulty_template["variables"] = []
    faulty_template["history"] = []
    faulty_template["next_spawn_sequence"] = "0"
    faulty_template["next_state_activation_sequences"] = []
    faulty_template["next_component_activation_sequences"] = []
    initialization_cause_id = digest(
        [
            "determa-cause-identity-1",
            "1",
            "component_initialization",
            retained_faulted["root_instance_id"],
            retained_root["runtime_id"],
            faulty_runtime_id,
            retained_source["envelope"]["cause_id"],
            retained_faulted["next_logical_step_sequence"],
            faulty_pointer,
            "0",
        ]
    )
    faulty_fault = {
        "definition_fingerprint": retained_faulted["validated_bundle_fingerprint"],
        "runtime_id": faulty_runtime_id,
        "cause_id": initialization_cause_id,
        "code": "action_fault",
        "step_sequence": retained_faulted["next_logical_step_sequence"],
        "source_locator": f"{faulty_pointer}/root/entry/0/assign/count",
    }
    faulty_template["status"] = "faulted"
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
    observer_pointer = "/machines/0/root/states/faulty_processing/components/1"
    observer_runtime_id = digest([
        "determa-component-runtime-identity-1", "1", retained_before["root_instance_id"],
        retained_root["runtime_id"], observer_pointer, "0", retained_before["namespace"],
        retained_before["root_machine_id"], retained_before["root_machine_version"],
    ])
    observer = copy.deepcopy(faulty_template)
    observer_text = json.dumps(observer).replace(faulty_runtime_id, observer_runtime_id).replace(faulty_pointer, observer_pointer)
    observer = json.loads(observer_text)
    observer["identity_origin"]["declaration_index"] = "1"
    observer["relation"]["declaration_index"] = "1"
    observer["relation"]["component_id"] = "observer"
    observer["target_identity"]["component"]["component_id"] = "observer"
    observer["active_leaf_state_definition_pointers"] = [f"{observer_pointer}/root"]
    observer["active_state_activations"] = [
        {"state_definition_pointer": f"{observer_pointer}/root", "activation_sequence": "0"}
    ]
    observer["variables"] = []
    observer["next_state_activation_sequences"] = [
        {"definition_pointer": f"{observer_pointer}/root", "next_sequence": "1"}
    ]
    observer["ready_mailbox"] = []
    observer["status"] = "running"
    observer["fault"] = None
    retained_root["active_leaf_state_definition_pointers"] = ["/machines/0/root/states/faulty_processing"]
    retained_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/faulty_processing", "activation_sequence": "0"},
    ]
    retained_root["next_state_activation_sequences"].append(
        {"definition_pointer": "/machines/0/root/states/faulty_processing", "next_sequence": "1"}
    )
    retained_root["next_component_activation_sequences"].extend([
        {"definition_pointer": faulty_pointer, "next_sequence": "1"},
        {"definition_pointer": observer_pointer, "next_sequence": "1"},
    ])
    retained_faulted["runtimes"] = [faulty_template, observer, retained_root]
    failure_event_id = digest(
        [
            "determa-event-identity-1",
            "1",
            retained_before["root_instance_id"],
            faulty_runtime_id,
            retained_root["runtime_id"],
            initialization_cause_id,
            retained_faulted["next_logical_step_sequence"],
            "system:component_failure",
            "0",
        ]
    )
    failure_entry = envelope_entry(
        retained_faulted,
        root_runtime(retained_faulted),
        event="determa.component_failed",
        event_id=failure_event_id,
        acceptance_sequence=int(retained_faulted["next_acceptance_sequence"]) + 1,
        queue_sequence=int(retained_faulted["next_queue_sequence"]) + 1,
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(faulty_template["target_identity"])},
        payload=typed_value(
            {
                "component_id": "faulty",
                "component_runtime_id": faulty_runtime_id,
                "fault": {
                    "runtime_id": faulty_runtime_id,
                    "cause_id": initialization_cause_id,
                    "code": "action_fault",
                    "step_sequence": faulty_fault["step_sequence"],
                    "source_locator": faulty_fault["source_locator"],
                },
            }
        ),
    )
    retained_root["ready_mailbox"] = [failure_entry]
    retained_faulted["next_acceptance_sequence"] = str(
        int(retained_faulted["next_acceptance_sequence"]) + 2
    )
    retained_faulted["next_queue_sequence"] = str(
        int(retained_faulted["next_queue_sequence"]) + 2
    )
    retained_faulted["next_logical_step_sequence"] = str(
        int(retained_faulted["next_logical_step_sequence"]) + 1
    )
    retained_faulted = seal_aggregate(retained_faulted)
    outputs["internal-emission-retained-faulted-result.json"] = step_result(
        retained_faulted,
        "handled",
        emissions=[
            {
                "kind": "internal_mailbox",
                "emission_index": "0",
                "event_id": entry_event_id,
                "acceptance_sequence": pending_entry["acceptance_sequence"],
                "queue_sequence": pending_entry["queue_sequence"],
            },
            {
                "kind": "internal_mailbox",
                "emission_index": "1",
                "event_id": failure_event_id,
                "acceptance_sequence": failure_entry["acceptance_sequence"],
                "queue_sequence": failure_entry["queue_sequence"],
            },
        ],
    )
    faulted_component = copy.deepcopy(retained_faulted)
    outputs["faulted-component-aggregate.json"] = faulted_component
    outputs["faulted-component-step-result.json"] = step_result(
        faulted_component, "rejected", rejection="inactive_component_target"
    )

    cancellation_before = root_event_before(
        "cancel_after_send", "cancel-after-send-1"
    )
    outputs["cancellation-before.json"] = cancellation_before
    cancellation_root = root_runtime(cancellation_before)
    cancellation_target = component_runtimes(cancellation_before)[0]
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
    cancelled_root = root_runtime(cancelled)
    cancelled_root["ready_mailbox"] = []
    cancelled_root["status"] = "completed"
    cancelled_root["active_leaf_state_definition_pointers"] = []
    cancelled_root["active_state_activations"] = []
    cancelled_root["variables"] = []
    cancelled_root["next_state_activation_sequences"].append(
        {
            "definition_pointer": "/machines/0/root/states/finished",
            "next_sequence": "1",
        }
    )
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
    outputs["completed-root-aggregate.json"] = cancelled
    outputs["completed-root-step-result.json"] = step_result(
        cancelled, "rejected", status="completed", rejection="invalid_instance_target"
    )

    natural_before = copy.deepcopy(lifecycle_before)
    natural_root = root_runtime(natural_before)
    natural_target = component_runtimes(natural_before)[0]
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
    completed_target = next(
        runtime for runtime in component_runtimes(naturally_completed)
        if runtime["runtime_id"] == natural_target["runtime_id"]
    )
    completed_target["status"] = "completed"
    completed_target["active_leaf_state_definition_pointers"] = []
    completed_target["active_state_activations"] = []
    completed_target["variables"] = []
    completed_target["ready_mailbox"] = []
    completed_target["next_state_activation_sequences"].append(
        {
            "definition_pointer": (
                "/machines/0/root/states/processing/components/0/root/states/complete"
            ),
            "next_sequence": "1",
        }
    )
    root_runtime(naturally_completed)["ready_mailbox"] = [completion_entry]
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
    completed_component = copy.deepcopy(naturally_completed)
    outputs["completed-component-aggregate.json"] = completed_component
    outputs["completed-component-step-result.json"] = step_result(
        completed_component, "rejected", rejection="inactive_component_target"
    )
    reserved_before = copy.deepcopy(naturally_completed)
    outputs["reserved-event-before.json"] = reserved_before
    reserved_after = copy.deepcopy(reserved_before)
    root_runtime(reserved_after)["ready_mailbox"].pop(0)
    reserved_after["next_logical_step_sequence"] = str(
        int(reserved_after["next_logical_step_sequence"]) + 1
    )
    reserved_after = seal_aggregate(reserved_after)
    outputs["reserved-event-handled-result.json"] = step_result(
        reserved_after, "handled"
    )

    aggregate_before = root_event_before("aggregate_finish", "aggregate-finish-1")
    outputs["aggregate-completion-before.json"] = aggregate_before
    aggregate_root = root_runtime(aggregate_before)
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
    result_root = root_runtime(aggregate_completed)
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
    disposed_target_id = component_runtimes(component)[0]["runtime_id"]
    disposed_component = copy.deepcopy(aggregate_completed)
    outputs["disposed-component-aggregate.json"] = disposed_component
    outputs["disposed-component-step-result.json"] = step_result(
        disposed_component, "rejected", rejection="invalid_instance_target"
    )

    rollback_before = root_event_before("cleanup_rollback", "cleanup-rollback-1")
    rollback_root = root_runtime(rollback_before)
    retained_component = component_runtimes(rollback_before)[0]
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
    retained_component["active_leaf_state_definition_pointers"] = [f"{cleanup_pointer}/root"]
    retained_component["active_state_activations"] = [
        {"state_definition_pointer": f"{cleanup_pointer}/root", "activation_sequence": "0"}
    ]
    retained_component["variables"] = []
    retained_component["next_state_activation_sequences"] = [
        {"definition_pointer": f"{cleanup_pointer}/root", "next_sequence": "1"}
    ]
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
    retained_peer["active_leaf_state_definition_pointers"] = [f"{peer_pointer}/root"]
    retained_peer["active_state_activations"] = [
        {"state_definition_pointer": f"{peer_pointer}/root", "activation_sequence": "0"}
    ]
    retained_peer["next_state_activation_sequences"] = [
        {"definition_pointer": f"{peer_pointer}/root", "next_sequence": "1"}
    ]
    rollback_root["active_leaf_state_definition_pointers"] = ["/machines/0/root/states/cleanup_failed"]
    rollback_root["active_state_activations"] = [
        {"state_definition_pointer": "/machines/0/root", "activation_sequence": "0"},
        {"state_definition_pointer": "/machines/0/root/states/cleanup_failed", "activation_sequence": "0"},
    ]
    rollback_root["variables"] = [
        {
            "variable_declaration_pointer": "/machines/0/root/states/cleanup_failed/variables/cleanup_marker",
            "declaring_state_activation_sequence": "0",
            "value": ["integer", "0"],
        }
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
    rollback_before["next_logical_step_sequence"] = str(
        int(rollback_before["next_logical_step_sequence"]) + 1
    )
    rollback_before = seal_aggregate(rollback_before)
    outputs["cleanup-rollback-before.json"] = rollback_before
    rollback = copy.deepcopy(rollback_before)
    rollback_root = root_runtime(rollback)
    rollback_source = rollback_root["ready_mailbox"].pop(0)
    rollback_fault = {
        "definition_fingerprint": rollback["validated_bundle_fingerprint"],
        "runtime_id": rollback_root["runtime_id"],
        "cause_id": rollback_source["envelope"]["cause_id"],
        "code": "action_fault",
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
    outputs["faulted-root-retained-component-aggregate.json"] = rollback
    outputs["faulted-root-retained-component-step-result.json"] = step_result(
        rollback,
        "rejected",
        status="faulted",
        rejection="invalid_instance_target",
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

    def delivery_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "delivery_mode": entry["delivery_mode"],
            "envelope": copy.deepcopy(entry["envelope"]),
            "envelope_digest": entry["envelope_digest"],
        }

    base_root = base["runtimes"][0]
    duplicate_delivery = delivery_input(
        base, base_root, "received", "duplicate"
    )
    duplicate_delivery_with_bad_digest = copy.deepcopy(duplicate_delivery)
    duplicate_delivery_with_bad_digest["envelope_digest"] = "sha256:" + "0" * 64
    valid_contract_delivery = delivery_input(
        base, base_root, "received", "contract-valid-first"
    )
    undeclared_delivery = delivery_input(
        base, base_root, "not_declared", "contract-undeclared"
    )
    wrong_payload_delivery = delivery_input(
        base,
        base_root,
        "new_request",
        "contract-wrong-payload",
        typed_value({"transaction_id": 17}),
    )
    digest_mismatch_delivery = delivery_input(
        base, base_root, "authorized", "digest-mismatch"
    )
    digest_mismatch_delivery["envelope_digest"] = "sha256:" + "0" * 64
    unrelated_host_cause = delivery_input(
        base, base_root, "received", "host-cause-mismatch"
    )
    unrelated_host_cause["envelope"]["cause_id"] = "unrelated-cause"
    unrelated_host_cause["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            base["root_instance_id"],
            unrelated_host_cause["delivery_mode"],
            unrelated_host_cause["envelope"],
        ]
    )
    equal_replay = {
        "delivery_mode": deferred_retry["delivery_mode"],
        "envelope": copy.deepcopy(deferred_retry["envelope"]),
        "envelope_digest": deferred_retry["envelope_digest"],
    }
    conflicting_replay = copy.deepcopy(equal_replay)
    conflicting_replay["envelope"]["event"] = "held_request"
    conflicting_replay["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            base["root_instance_id"],
            conflicting_replay["delivery_mode"],
            conflicting_replay["envelope"],
        ]
    )
    pending_changed_payload_stale_digest = copy.deepcopy(equal_replay)
    pending_changed_payload_stale_digest["envelope"]["payload"] = typed_value(
        {"changed": "payload"}
    )
    pending_unchanged_bad_digest = copy.deepcopy(equal_replay)
    pending_unchanged_bad_digest["envelope_digest"] = "sha256:" + ("0" * 64)
    completed_identity = component_runtimes(component)[0]["target_identity"]
    disposed_delivery = delivery_input(
        component,
        component_runtimes(component)[0],
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
    faulted_root_component = component_runtimes(rollback)[0]
    faulted_root_descendant_entry = envelope_entry(
        rollback,
        faulted_root_component,
        event="component_work",
        event_id="faulted-root-descendant-admission",
        acceptance_sequence=0,
        queue_sequence=0,
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(root_runtime(rollback)["target_identity"])},
    )
    completed_root_delivery = delivery_input(
        cancelled,
        root_runtime(cancelled),
        "fanout",
        "completed-root-admission",
    )
    faulted_root_delivery = delivery_input(
        rollback,
        root_runtime(rollback),
        "fanout",
        "faulted-root-admission",
    )

    reserved_admission_before = copy.deepcopy(reserved_after)
    reserved_source = component_runtimes(reserved_admission_before)[0]
    reserved_target = root_runtime(reserved_admission_before)
    reserved_entry = envelope_entry(
        reserved_admission_before,
        reserved_target,
        event="determa.component_completed",
        event_id="reserved-component-completed-admission",
        acceptance_sequence=int(reserved_admission_before["next_acceptance_sequence"]),
        queue_sequence=int(reserved_admission_before["next_queue_sequence"]),
        delivery_mode="internal",
        source={"runtime": copy.deepcopy(reserved_source["target_identity"])},
        payload=typed_value(
            {
                "component_id": reserved_source["relation"]["component_id"],
                "component_runtime_id": reserved_source["runtime_id"],
            }
        ),
    )
    reserved_admitted = copy.deepcopy(reserved_admission_before)
    root_runtime(reserved_admitted)["ready_mailbox"].append(reserved_entry)
    reserved_admitted["next_acceptance_sequence"] = str(
        int(reserved_admitted["next_acceptance_sequence"]) + 1
    )
    reserved_admitted["next_queue_sequence"] = str(
        int(reserved_admitted["next_queue_sequence"]) + 1
    )
    reserved_admitted = seal_aggregate(reserved_admitted)
    reserved_dispatched = copy.deepcopy(reserved_admitted)
    root_runtime(reserved_dispatched)["ready_mailbox"].pop(0)
    reserved_dispatched["next_logical_step_sequence"] = str(
        int(reserved_dispatched["next_logical_step_sequence"]) + 1
    )
    reserved_dispatched = seal_aggregate(reserved_dispatched)
    outputs["reserved-admission-before.json"] = reserved_admission_before
    outputs["reserved-admitted-aggregate.json"] = reserved_admitted
    outputs["reserved-admission-result.json"] = {
        "result": "accepted",
        "status": "running",
        "accepted": [
            {
                "event_id": reserved_entry["envelope"]["event_id"],
                "acceptance_sequence": reserved_entry["acceptance_sequence"],
                "queue_sequence": reserved_entry["queue_sequence"],
            }
        ],
        "state": reserved_admitted,
        "rejection": None,
    }
    outputs["reserved-dispatch-result.json"] = step_result(
        reserved_dispatched, "handled"
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
            "deliveries": [duplicate_delivery, duplicate_delivery_with_bad_digest],
        },
        "digest_mismatch_batch": {
            "operation": "admit_v2",
            "deliveries": [valid_contract_delivery, digest_mismatch_delivery],
        },
        "host_cause_mismatch": {
            "operation": "admit_v2",
            "deliveries": [unrelated_host_cause],
        },
        "undeclared_event_batch": {
            "operation": "admit_v2",
            "deliveries": [valid_contract_delivery, undeclared_delivery],
        },
        "wrong_payload_batch": {
            "operation": "admit_v2",
            "deliveries": [valid_contract_delivery, wrong_payload_delivery],
        },
        "equal_replay": {"operation": "admit_v2", "deliveries": [equal_replay]},
        "conflicting_replay": {
            "operation": "admit_v2",
            "deliveries": [conflicting_replay],
        },
        "pending_changed_payload_stale_digest": {
            "operation": "admit_v2",
            "deliveries": [pending_changed_payload_stale_digest],
        },
        "pending_unchanged_bad_digest": {
            "operation": "admit_v2",
            "deliveries": [pending_unchanged_bad_digest],
        },
        "recall_step": {"operation": "step_v2", "target_runtime_id": base["root_runtime_id"]},
        "repeated_step": {"operation": "step_v2", "target_runtime_id": repeated_before["root_runtime_id"]},
        "deferred_only_step": {"operation": "step_v2", "target_runtime_id": deferred_only["root_runtime_id"]},
        "component_step": {"operation": "step_v2", "target_runtime_id": component_runtimes(component)[0]["runtime_id"]},
        "spawn_step": {"operation": "step_v2", "target_runtime_id": spawned_runtimes(spawned)[0]["runtime_id"]},
        "completed_component_step": {"operation": "step_v2", "target_runtime_id": component_runtimes(completed_component)[0]["runtime_id"]},
        "faulted_component_step": {"operation": "step_v2", "target_runtime_id": component_runtimes(faulted_component)[0]["runtime_id"]},
        "disposed_component_step": {"operation": "step_v2", "target_runtime_id": disposed_target_id},
        "invalid_runtime_step": {"operation": "step_v2", "target_runtime_id": "sha256:" + "0" * 64},
        "completed_root_step": {
            "operation": "step_v2",
            "target_runtime_id": cancelled["root_runtime_id"],
        },
        "overflow_step": {"operation": "step_v2", "target_runtime_id": zero_before["root_runtime_id"]},
        "fanout_step": {"operation": "step_v2", "target_runtime_id": lifecycle_before["root_runtime_id"]},
        "retained_faulted_step": {
            "operation": "step_v2",
            "target_runtime_id": root_runtime(retained_before)["runtime_id"],
        },
        "cancellation_step": {"operation": "step_v2", "target_runtime_id": cancellation_before["root_runtime_id"]},
        "natural_completion_step": {"operation": "step_v2", "target_runtime_id": natural_target["runtime_id"]},
        "aggregate_completion_step": {"operation": "step_v2", "target_runtime_id": aggregate_before["root_runtime_id"]},
        "cleanup_rollback_step": {"operation": "step_v2", "target_runtime_id": rollback_before["root_runtime_id"]},
        "reserved_event_step": {"operation": "step_v2", "target_runtime_id": reserved_before["root_runtime_id"]},
        "reserved_event_admit": {
            "operation": "admit_v2",
            "deliveries": [delivery_from_entry(reserved_entry)],
        },
        "reserved_admitted_step": {
            "operation": "step_v2",
            "target_runtime_id": reserved_admitted["root_runtime_id"],
        },
        "faulted_root_descendant_step": {
            "operation": "step_v2",
            "target_runtime_id": faulted_root_component["runtime_id"],
        },
        "faulted_root_descendant_admit": {
            "operation": "admit_v2",
            "deliveries": [delivery_from_entry(faulted_root_descendant_entry)],
        },
        "completed_root_admit": {
            "operation": "admit_v2",
            "deliveries": [completed_root_delivery],
        },
        "faulted_root_admit": {
            "operation": "admit_v2",
            "deliveries": [faulted_root_delivery],
        },
        "completed_component_admit": {"operation": "admit_v2", "deliveries": [delivery_input(completed_component, component_runtimes(completed_component)[0], "component_work", "completed-component-admission")]},
        "faulted_component_admit": {"operation": "admit_v2", "deliveries": [delivery_input(faulted_component, component_runtimes(faulted_component)[0], "component_work", "faulted-component-admission")]},
        "disposed_component_admit": {"operation": "admit_v2", "deliveries": [disposed_delivery]},
    }
    admitted_state = copy.deepcopy(base)
    admitted_root = root_runtime(admitted_state)
    admitted_entries = []
    for offset, delivery in enumerate(operation_inputs["admit_two"]["deliveries"]):
        entry = {
            "acceptance_sequence": str(4 + offset),
            "queue_sequence": str(4 + offset),
            "deferral_count": "0",
            "delivery_mode": delivery["delivery_mode"],
            "envelope": copy.deepcopy(delivery["envelope"]),
            "envelope_digest": delivery["envelope_digest"],
        }
        admitted_root["ready_mailbox"].append(entry)
        admitted_entries.append(entry)
    admitted_state["next_acceptance_sequence"] = "6"
    admitted_state["next_queue_sequence"] = "6"
    admitted_state = seal_aggregate(admitted_state)
    outputs["operation-inputs.json"] = operation_inputs
    outputs["admission-success.json"] = {
        "result": "accepted",
        "status": "running",
        "accepted": [
            {
                "event_id": entry["envelope"]["event_id"],
                "acceptance_sequence": entry["acceptance_sequence"],
                "queue_sequence": entry["queue_sequence"],
            }
            for entry in admitted_entries
        ],
        "state": admitted_state,
        "rejection": None,
    }
    outputs["replay-success.json"] = {
        "result": "replay",
        "status": "running",
        "event_id": "retry-guarded-recall",
        "acceptance_sequence": "2",
        "location": "deferred",
        "state": base,
        "rejection": None,
    }
    outputs["invalid-version2-operation-result.json"] = {
        "result": "replay",
        "event_id": "retry-guarded-recall",
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
    target_documents["target-compatible.yaml"]["machines"][0]["root"]["states"]["busy"]["states"]["authorizing"]["on_events"]["retry"]["guard"] = "false || false"
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

    base_descriptor_template = load(PERSISTENCE / "base-descriptor-v1.json")

    def make_descriptor(target_name: str, *, dispose_retired: bool = False) -> dict[str, Any]:
        descriptor_v1 = copy.deepcopy(base_descriptor_template)
        descriptor_v1["source_validated_bundle_fingerprint"] = source_fingerprint
        descriptor_v1["target_validated_bundle_fingerprint"] = bundle_fingerprint_document(target_documents[target_name])
        descriptor_v1["source_aggregate_shape_fingerprint"] = aggregate_shape_fingerprint_document(source_document)
        descriptor_v1["target_aggregate_shape_fingerprint"] = aggregate_shape_fingerprint_document(target_documents[target_name])
        if descriptor_v1["source_aggregate_shape_fingerprint"] != descriptor_v1["target_aggregate_shape_fingerprint"]:
            descriptor_v1["mode"] = "transform"
            descriptor_v1["mappings"]["machines"] = [{
                "source_definition_pointer": "/machines/0/root",
                "target_definition_pointer": "/machines/0/root",
            }]
            descriptor_v1["mappings"]["active_states"] = [{
                "source_leaf_state_definition_pointer": "/machines/0/root/states/busy/states/receiving",
                "target_leaf_state_definition_pointers": [
                    "/machines/0/root/states/busy/states/receiving_replacement"
                ],
            }]
            descriptor_v1["mappings"]["counters"] = [
                {"operation": "map", "source_definition_pointer": "/machines/0/root", "target_definition_pointer": "/machines/0/root"},
                {"operation": "map", "source_definition_pointer": "/machines/0/root/states/busy", "target_definition_pointer": "/machines/0/root/states/busy"},
                {"operation": "map", "source_definition_pointer": "/machines/0/root/states/busy/states/receiving", "target_definition_pointer": "/machines/0/root/states/busy/states/receiving_replacement"},
            ]
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
                "validated_bundle_fingerprint": descriptor_v2["base_descriptor"]["target_validated_bundle_fingerprint"],
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

    def migrated_to(source: dict[str, Any], descriptor: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(source)
        target_fingerprint = descriptor["base_descriptor"]["target_validated_bundle_fingerprint"]
        result["validated_bundle_fingerprint"] = target_fingerprint
        result["migration_sequence"] = str(int(result["migration_sequence"]) + 1)
        for runtime in result["runtimes"]:
            runtime["current_definition"]["validated_bundle_fingerprint"] = target_fingerprint
        return seal_aggregate(result)

    preserved = migrated_to(aggregate_v2, descriptors["descriptor-compatible-v2.json"])

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
            {"result": "success", "aggregate_state": preserved, "dispositions": []}
        ),
        "migration-stale-target-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": stale_target_migrated,
                "dispositions": [],
            }
        ),
        "migration-fault-frozen-preserve-result.json": canonical(
            {"result": "success", "aggregate_state": preserved_fault_frozen, "dispositions": []}
        ),
        "migration-historical-fault-result.json": canonical(
            {
                "result": "success",
                "aggregate_state": historical_fault_migrated,
                "dispositions": [],
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
    outputs["operation-inputs.json"] = canonical(operations)
    return {name: data if isinstance(data, bytes) else canonical(data) for name, data in outputs.items()}


def target_runtime_id(target: dict[str, Any]) -> str:
    if "root" in target:
        return target["root"]["root_runtime_id"]
    if "component" in target:
        return target["component"]["component_runtime_id"]
    if "spawned_instance" in target:
        return target["spawned_instance"]["instance_id"]
    raise ValueError(f"unsupported checkpoint target: {target!r}")


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
        target = envelope["target"]
        runtime_id = target_runtime_id(target)
        if runtime_id not in runtime_by_id:
            raise ValueError(
                f"checkpoint target does not resolve to a runtime: {target!r}"
            )
        runtime_by_id[runtime_id]["ready_mailbox"].append(entry)
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
    def with_checkpoint_cas(
        operation: dict[str, Any], checkpoint: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            **operation,
            "expected_revision": checkpoint["revision"],
            "expected_checkpoint_digest": checkpoint[
                "execution_checkpoint_digest"
            ],
        }

    v1 = load(CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle" / "internal-pending-checkpoint.json")
    upgraded = upgrade_checkpoint(v1)
    delivery_trace = CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle"
    created_v1 = load(delivery_trace / "created-checkpoint.json")
    delivery_inputs = load(delivery_trace / "inputs.json")["requests"]
    delivery_results = load(delivery_trace / "core-results.json")["calls"]
    multi_pending_v1 = copy.deepcopy(created_v1)
    for accepted_revision, request_name in (("1", "accept_increment"), ("2", "unhandled")):
        request = delivery_inputs[request_name]
        delivery_sequence = multi_pending_v1["next_delivery_sequence"]
        multi_pending_v1["next_delivery_sequence"] = str(int(delivery_sequence) + 1)
        multi_pending_v1["revision"] = accepted_revision
        multi_pending_v1["pending_deliveries"].append(
            {
                "delivery_sequence": delivery_sequence,
                "accepted_revision": accepted_revision,
                "delivery_mode": request["delivery_mode"],
                "origin": copy.deepcopy(request["origin"]),
                "envelope": copy.deepcopy(request["envelope"]),
                "envelope_digest": request["envelope_digest"],
            }
        )
        multi_pending_v1 = seal_checkpoint_v1(multi_pending_v1)
    process_request = delivery_inputs["process_increment"]
    process_result = delivery_results["increment"]
    processed_pending = multi_pending_v1["pending_deliveries"].pop(0)
    multi_pending_v1.pop("execution_checkpoint_digest", None)
    multi_pending_v1["revision"] = "3"
    multi_pending_v1["root_record"]["aggregate_state"] = copy.deepcopy(
        process_result["aggregate_state"]
    )
    receipt_sequence = multi_pending_v1["next_operation_receipt_sequence"]
    multi_pending_v1["next_operation_receipt_sequence"] = str(
        int(receipt_sequence) + 1
    )
    multi_pending_v1["operation_receipts"].append(
        {
            "operation_kind": "delivery",
            "receipt_sequence": receipt_sequence,
            "event_id": process_request["envelope"]["event_id"],
            "request_digest": process_request["envelope_digest"],
            "accepted_delivery_sequence": processed_pending["delivery_sequence"],
            "accepted_revision": processed_pending["accepted_revision"],
            "delivery_mode": process_request["delivery_mode"],
            "origin": copy.deepcopy(process_request["origin"]),
            "committed_revision": "3",
            "resulting_aggregate_state_digest": process_result["aggregate_state"][
                "aggregate_state_digest"
            ],
            "outcome": {
                "status": process_result["status"],
                "disposition": process_result["disposition"],
                "fault": copy.deepcopy(process_result["fault"]),
                "rejection": copy.deepcopy(process_result["rejection"]),
            },
            "emission_references": [],
        }
    )
    multi_pending_v1 = seal_checkpoint_v1(multi_pending_v1)
    multi_pending_upgraded = upgrade_checkpoint(multi_pending_v1)
    multi_pending_upgraded_with_metadata = copy.deepcopy(multi_pending_upgraded)
    multi_pending_acceptance = next(
        receipt
        for receipt in multi_pending_upgraded_with_metadata["operation_receipts"]
        if receipt["operation_kind"] == "acceptance"
    )
    multi_pending_acceptance["legacy_v1_delivery"] = {
        "delivery_sequence": multi_pending_v1["pending_deliveries"][0][
            "delivery_sequence"
        ],
        "envelope_digest": multi_pending_v1["pending_deliveries"][0][
            "envelope_digest"
        ],
        "origin": copy.deepcopy(multi_pending_v1["pending_deliveries"][0]["origin"]),
    }
    multi_pending_upgraded_with_metadata = seal_checkpoint(
        multi_pending_upgraded_with_metadata
    )
    outbox_v1 = load(
        CHECKPOINT.parent
        / "checkpoint-02-outbox-lifecycle"
        / "outbox-created-checkpoint.json"
    )
    upgraded_outbox = upgrade_checkpoint(outbox_v1)
    operational_v1 = load(
        CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle" / "created-checkpoint.json"
    )
    operational_base = upgrade_checkpoint(operational_v1)
    operational_base["replay_retention"] = {
        "mode": "bounded",
        "permanent_replay_eligible": False,
        "pruned_through_receipt_sequence": None,
        "policy_identifier": "bounded-test-v1",
    }
    operational_base = seal_checkpoint(operational_base)

    spawned_checkpoint_v1 = load(
        CHECKPOINT.parent
        / "checkpoint-05-spawned-host-trace"
        / "spawned-child-checkpoint-v1.json"
    )
    spawned_checkpoint_v2 = upgrade_checkpoint(spawned_checkpoint_v1)
    spawned_terminal_checkpoint_v1 = load(
        CHECKPOINT.parent
        / "checkpoint-06-terminal-spawned-host-trace"
        / "terminal-checkpoint-v1.json"
    )
    spawned_terminal_checkpoint_v2 = upgrade_checkpoint(
        spawned_terminal_checkpoint_v1
    )
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

    native_emit_admitted = copy.deepcopy(terminal)
    native_admitted_aggregate = native_emit_admitted["root_record"]["aggregate_state"]
    native_admitted_root = root_runtime(native_admitted_aggregate)
    native_host_entry = envelope_entry(
        native_admitted_aggregate,
        native_admitted_root,
        event="emit_internal",
        event_id="checkpoint-v2-emit-internal",
        acceptance_sequence=int(native_admitted_aggregate["next_acceptance_sequence"]),
        queue_sequence=int(native_admitted_aggregate["next_queue_sequence"]),
        payload=typed_value({"amount": 5}),
    )
    native_admitted_root["ready_mailbox"] = [native_host_entry]
    native_admitted_aggregate["next_acceptance_sequence"] = str(
        int(native_host_entry["acceptance_sequence"]) + 1
    )
    native_admitted_aggregate["next_queue_sequence"] = str(
        int(native_host_entry["queue_sequence"]) + 1
    )
    native_emit_admitted["root_record"]["aggregate_state"] = seal_aggregate(
        native_admitted_aggregate
    )
    native_emit_admitted["revision"] = str(int(terminal["revision"]) + 1)
    native_host_acceptance_receipt_sequence = native_emit_admitted[
        "next_operation_receipt_sequence"
    ]
    native_emit_admitted["operation_receipts"].append(
        {
            "operation_kind": "acceptance",
            "receipt_sequence": native_host_acceptance_receipt_sequence,
            "event_id": native_host_entry["envelope"]["event_id"],
            "request_digest": native_host_entry["envelope_digest"],
            "acceptance_sequence": native_host_entry["acceptance_sequence"],
            "accepted_revision": native_emit_admitted["revision"],
            "delivery_mode": "input",
        }
    )
    native_emit_admitted["next_operation_receipt_sequence"] = str(
        int(native_host_acceptance_receipt_sequence) + 1
    )
    native_emit_admitted = seal_checkpoint(native_emit_admitted)

    native_internal = copy.deepcopy(native_emit_admitted)
    native_aggregate = native_internal["root_record"]["aggregate_state"]
    native_root = root_runtime(native_aggregate)
    native_host_cause = native_root["ready_mailbox"].pop(0)
    native_event_id = digest([
        "determa-event-identity-1", "1", native_aggregate["root_instance_id"],
        native_root["runtime_id"], native_root["runtime_id"],
        native_host_cause["envelope"]["cause_id"],
        native_aggregate["next_logical_step_sequence"],
        "/machines/0/root/on_events/emit_internal/action/0/send", "0",
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
    native_aggregate["next_logical_step_sequence"] = str(
        int(native_aggregate["next_logical_step_sequence"]) + 1
    )
    native_internal["revision"] = str(int(native_emit_admitted["revision"]) + 1)
    native_host_terminal_receipt_sequence = native_internal[
        "next_operation_receipt_sequence"
    ]
    native_internal["operation_receipts"].append({
        "operation_kind": "event_terminal",
        "receipt_sequence": native_host_terminal_receipt_sequence,
        "event_id": native_host_cause["envelope"]["event_id"],
        "request_digest": native_host_cause["envelope_digest"],
        "acceptance_sequence": native_host_cause["acceptance_sequence"],
        "final_queue_sequence": native_host_cause["queue_sequence"],
        "committed_revision": native_internal["revision"],
        "resulting_aggregate_state_digest": "pending",
        "outcome": {
            "status": "running",
            "disposition": "handled",
            "fault": None,
            "rejection": None,
        },
        "emission_references": [{
        "kind": "internal_mailbox", "emission_index": "0", "event_id": native_event_id,
        "acceptance_sequence": native_entry["acceptance_sequence"], "queue_sequence": native_entry["queue_sequence"],
        }],
    })
    native_internal["next_operation_receipt_sequence"] = str(
        int(native_host_terminal_receipt_sequence) + 1
    )
    native_internal["root_record"]["aggregate_state"] = seal_aggregate(native_aggregate)
    native_internal["operation_receipts"][-1]["resulting_aggregate_state_digest"] = (
        native_internal["root_record"]["aggregate_state"]["aggregate_state_digest"]
    )
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
    compact["replay_retention"]["pruned_through_receipt_sequence"] = event_terminal["receipt_sequence"]
    compact["revision"] = str(int(terminal["revision"]) + 1)
    compact = seal_checkpoint(compact)

    compacted_legacy = copy.deepcopy(upgraded)
    compacted_legacy_receipt = next(
        receipt
        for receipt in compacted_legacy["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["legacy_receipt"].get("event_id") == "delivery-increment"
    )
    compacted_nested = compacted_legacy_receipt["legacy_receipt"]
    compacted_legacy["operation_receipts"].remove(compacted_legacy_receipt)
    compacted_legacy["event_identity_tombstones"] = [
        {
            "event_id": compacted_nested["event_id"],
            "request_digest": compacted_nested["request_digest"],
            "request_digest_domain": "determa-inbox-envelope-digest-1",
            "acceptance_sequence": compacted_nested[
                "accepted_delivery_sequence"
            ],
            "terminal_receipt_sequence": compacted_legacy_receipt[
                "receipt_sequence"
            ],
            "terminal_disposition": compacted_nested["outcome"]["disposition"],
        }
    ]
    compacted_legacy["replay_retention"] = {
        "mode": "bounded",
        "permanent_replay_eligible": False,
        "pruned_through_receipt_sequence": compacted_legacy_receipt[
            "receipt_sequence"
        ],
        "policy_identifier": "bounded-legacy-replay-v1",
    }
    compacted_legacy["revision"] = str(int(upgraded["revision"]) + 1)
    compacted_legacy = seal_checkpoint(compacted_legacy)

    faulted_v1 = load(
        CHECKPOINT.parent
        / "checkpoint-01-delivery-lifecycle"
        / "faulted-checkpoint.json"
    )
    faulted_upgraded = upgrade_checkpoint(faulted_v1)
    faulted_aggregate = faulted_upgraded["root_record"]["aggregate_state"]
    faulted_root = root_runtime(faulted_aggregate)
    terminal_mismatch_entry = envelope_entry(
        faulted_aggregate,
        faulted_root,
        event="increment",
        event_id="checkpoint-v2-terminal-fresh-mismatch",
        acceptance_sequence=int(faulted_aggregate["next_acceptance_sequence"]),
        queue_sequence=int(faulted_aggregate["next_queue_sequence"]),
        payload=typed_value({"amount": 1}),
    )
    terminal_mismatch_delivery = {
        "delivery_mode": terminal_mismatch_entry["delivery_mode"],
        "envelope": terminal_mismatch_entry["envelope"],
        "envelope_digest": "sha256:" + ("7" * 64),
    }
    tombstoned = copy.deepcopy(faulted_upgraded)
    terminal_aggregate = tombstoned["root_record"]["aggregate_state"]
    terminal_root = root_runtime(terminal_aggregate)
    tombstoned["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": terminal_root["runtime_id"],
        "creation_id": terminal_aggregate["creation_id"],
        "terminal_status": terminal_root["status"],
        "final_aggregate_state_digest": terminal_aggregate[
            "aggregate_state_digest"
        ],
        "tombstone_operation_id": "checkpoint-v2-faulted-root-tombstone",
    }
    tombstoned["revision"] = str(int(faulted_upgraded["revision"]) + 1)
    tombstoned = seal_checkpoint(tombstoned)
    tombstoned_fresh_delivery = copy.deepcopy(terminal_mismatch_delivery)
    tombstoned_fresh_delivery["envelope"]["event_id"] = (
        "checkpoint-v2-tombstoned-fresh"
    )
    tombstoned_fresh_delivery["envelope"]["cause_id"] = (
        "checkpoint-v2-tombstoned-fresh"
    )

    invalid_mode_delivery = copy.deepcopy(terminal_mismatch_entry)
    invalid_mode_delivery = {
        "delivery_mode": "invalid",
        "envelope": invalid_mode_delivery["envelope"],
        "envelope_digest": digest(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                operational_base["root_instance_id"],
                "invalid",
                invalid_mode_delivery["envelope"],
            ]
        ),
    }
    retained_native_delivery = {
        "delivery_mode": entry["delivery_mode"],
        "envelope": copy.deepcopy(entry["envelope"]),
        "envelope_digest": entry["envelope_digest"],
    }
    changed_payload_stale_digest = copy.deepcopy(retained_native_delivery)
    changed_payload_stale_digest["envelope"]["payload"] = typed_value(
        {"amount": 2}
    )
    unchanged_envelope_bad_digest = copy.deepcopy(retained_native_delivery)
    unchanged_envelope_bad_digest["envelope_digest"] = "sha256:" + ("0" * 64)

    spawned_tombstoned = copy.deepcopy(spawned_terminal_checkpoint_v2)
    spawned_terminal_aggregate = spawned_tombstoned["root_record"]["aggregate_state"]
    spawned_terminal_root = root_runtime(spawned_terminal_aggregate)
    spawned_tombstoned["root_record"] = {
        "status": "tombstone",
        "root_runtime_id": spawned_terminal_root["runtime_id"],
        "creation_id": spawned_terminal_aggregate["creation_id"],
        "terminal_status": spawned_terminal_root["status"],
        "final_aggregate_state_digest": spawned_terminal_aggregate[
            "aggregate_state_digest"
        ],
        "tombstone_operation_id": "checkpoint-v2-spawned-root-tombstone",
    }
    spawned_tombstoned["revision"] = str(
        int(spawned_terminal_checkpoint_v2["revision"]) + 1
    )
    spawned_tombstoned = seal_checkpoint(spawned_tombstoned)

    invalid_acceptance_tombstone_overlap = copy.deepcopy(compact)
    overlapping_acceptance = copy.deepcopy(acceptance)
    overlapping_acceptance["receipt_sequence"] = compact["next_operation_receipt_sequence"]
    invalid_acceptance_tombstone_overlap["operation_receipts"].append(overlapping_acceptance)
    invalid_acceptance_tombstone_overlap["next_operation_receipt_sequence"] = str(
        int(overlapping_acceptance["receipt_sequence"]) + 1
    )
    invalid_acceptance_tombstone_overlap = seal_checkpoint(
        invalid_acceptance_tombstone_overlap
    )

    invalid_tombstone_counter = copy.deepcopy(compact)
    invalid_tombstone_counter["event_identity_tombstones"][0][
        "terminal_receipt_sequence"
    ] = invalid_tombstone_counter["next_operation_receipt_sequence"]
    invalid_tombstone_counter = seal_checkpoint(invalid_tombstone_counter)

    invalid_pruning_claim = copy.deepcopy(terminal)
    invalid_pruning_claim["replay_retention"][
        "pruned_through_receipt_sequence"
    ] = "1"
    invalid_pruning_claim = seal_checkpoint(invalid_pruning_claim)

    invalid_creation_identity = copy.deepcopy(tombstoned)
    invalid_creation_identity["root_record"]["creation_id"] = (
        "different-creation"
    )
    invalid_creation_identity = seal_checkpoint(invalid_creation_identity)

    invalid_future_receipt_revision = copy.deepcopy(admitted)
    next(
        receipt
        for receipt in invalid_future_receipt_revision["operation_receipts"]
        if receipt["operation_kind"] == "acceptance"
    )["accepted_revision"] = "999"
    invalid_future_receipt_revision = seal_checkpoint(
        invalid_future_receipt_revision
    )

    invalid = copy.deepcopy(admitted)
    invalid_aggregate = invalid["root_record"]["aggregate_state"]
    invalid_aggregate["runtimes"][0]["deferred_mailbox"] = copy.deepcopy(
        invalid_aggregate["runtimes"][0]["ready_mailbox"]
    )
    invalid["root_record"]["aggregate_state"] = seal_aggregate(invalid_aggregate)
    invalid = seal_checkpoint(invalid)
    stale_writer_entry = envelope_entry(
        operational_base["root_record"]["aggregate_state"],
        next(
            runtime
            for runtime in operational_base["root_record"]["aggregate_state"][
                "runtimes"
            ]
            if runtime["relation"]["kind"] == "root"
        ),
        event="increment",
        event_id="checkpoint-v2-distinct-stale-writer",
        acceptance_sequence=0,
        queue_sequence=0,
        payload=typed_value({"amount": 1}),
    )
    mixed_new_entry = envelope_entry(
        admitted["root_record"]["aggregate_state"],
        root_runtime(admitted["root_record"]["aggregate_state"]),
        event="increment",
        event_id="checkpoint-v2-mixed-new",
        acceptance_sequence=int(
            admitted["root_record"]["aggregate_state"]["next_acceptance_sequence"]
        ),
        queue_sequence=int(
            admitted["root_record"]["aggregate_state"]["next_queue_sequence"]
        ),
        payload=typed_value({"amount": 2}),
    )
    mixed_checkpoint = copy.deepcopy(admitted)
    mixed_aggregate = mixed_checkpoint["root_record"]["aggregate_state"]
    root_runtime(mixed_aggregate)["ready_mailbox"].append(mixed_new_entry)
    mixed_aggregate["next_acceptance_sequence"] = str(
        int(mixed_new_entry["acceptance_sequence"]) + 1
    )
    mixed_aggregate["next_queue_sequence"] = str(
        int(mixed_new_entry["queue_sequence"]) + 1
    )
    mixed_checkpoint["revision"] = str(int(admitted["revision"]) + 1)
    mixed_receipt_sequence = mixed_checkpoint["next_operation_receipt_sequence"]
    mixed_checkpoint["operation_receipts"].append(
        {
            "operation_kind": "acceptance",
            "receipt_sequence": mixed_receipt_sequence,
            "event_id": mixed_new_entry["envelope"]["event_id"],
            "request_digest": mixed_new_entry["envelope_digest"],
            "acceptance_sequence": mixed_new_entry["acceptance_sequence"],
            "accepted_revision": mixed_checkpoint["revision"],
            "delivery_mode": mixed_new_entry["delivery_mode"],
        }
    )
    mixed_checkpoint["next_operation_receipt_sequence"] = str(
        int(mixed_receipt_sequence) + 1
    )
    mixed_checkpoint["root_record"]["aggregate_state"] = seal_aggregate(
        mixed_aggregate
    )
    mixed_checkpoint = seal_checkpoint(mixed_checkpoint)

    original_v1_input = load(
        CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle" / "inputs.json"
    )["requests"]["accept_increment"]
    original_v1_inputs = load(
        CHECKPOINT.parent / "checkpoint-01-delivery-lifecycle" / "inputs.json"
    )["requests"]
    legacy_replay_delivery = {
        "delivery_mode": original_v1_input["delivery_mode"],
        "envelope": original_v1_input["envelope"],
        "envelope_digest": original_v1_input["envelope_digest"],
        "request_digest_domain": "determa-inbox-envelope-digest-1",
    }

    def terminal_replay_evidence(
        checkpoint: dict[str, Any], event_id: str
    ) -> dict[str, Any]:
        acceptance = next(
            receipt
            for receipt in checkpoint["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("event_id") == event_id
        )
        terminal_receipt = next(
            receipt
            for receipt in checkpoint["operation_receipts"]
            if receipt.get("operation_kind") == "event_terminal"
            and receipt.get("event_id") == event_id
        )
        return {
            "result": "replay",
            "acceptance_receipt_sequence": acceptance["receipt_sequence"],
            "terminal_receipt_sequence": terminal_receipt["receipt_sequence"],
        }

    all_replay_deliveries = [
        {
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        },
        {
            "delivery_mode": native_host_entry["delivery_mode"],
            "envelope": native_host_entry["envelope"],
            "envelope_digest": native_host_entry["envelope_digest"],
        },
    ]
    all_replay_result = {
        "result": "batch",
        "members": [
            {
                "event_id": delivery["envelope"]["event_id"],
                "disposition": "replay",
                "evidence": terminal_replay_evidence(
                    native_terminal, delivery["envelope"]["event_id"]
                ),
            }
            for delivery in all_replay_deliveries
        ],
        "checkpoint": native_terminal,
    }
    mixed_result = {
        "result": "batch",
        "members": [
            {
                "event_id": entry["envelope"]["event_id"],
                "disposition": "replay",
                "evidence": {
                    "result": "replay",
                    "event_id": entry["envelope"]["event_id"],
                    "acceptance_sequence": entry["acceptance_sequence"],
                    "location": "ready",
                },
            },
            {
                "event_id": mixed_new_entry["envelope"]["event_id"],
                "disposition": "accepted",
                "acceptance_sequence": mixed_new_entry["acceptance_sequence"],
                "queue_sequence": mixed_new_entry["queue_sequence"],
            },
        ],
        "checkpoint": mixed_checkpoint,
    }
    legacy_receipt = next(
        receipt
        for receipt in upgraded["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["legacy_receipt"].get("event_id")
        == original_v1_input["envelope"]["event_id"]
    )
    legacy_replay_result = {
        "result": "replay",
        "event_id": legacy_receipt["legacy_receipt"]["event_id"],
        "acceptance_sequence": legacy_receipt["legacy_receipt"][
            "accepted_delivery_sequence"
        ],
        "terminal_receipt_sequence": legacy_receipt["receipt_sequence"],
        "terminal_disposition": legacy_receipt["legacy_receipt"]["outcome"][
            "disposition"
        ],
        "request_digest_domain": "determa-inbox-envelope-digest-1",
    }

    def legacy_delivery(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "delivery_mode": request["delivery_mode"],
            "envelope": request["envelope"],
            "envelope_digest": request["envelope_digest"],
            "request_digest_domain": "determa-inbox-envelope-digest-1",
        }

    def legacy_terminal_evidence(
        checkpoint: dict[str, Any], delivery: dict[str, Any]
    ) -> dict[str, Any]:
        event_id = delivery["envelope"]["event_id"]
        wrapper = next(
            (
                receipt
                for receipt in checkpoint["operation_receipts"]
                if receipt["operation_kind"] == "legacy_v1_operation"
                and receipt["legacy_receipt"].get("event_id") == event_id
            ),
            None,
        )
        if wrapper is not None:
            nested = wrapper["legacy_receipt"]
            return {
                "result": "replay",
                "event_id": event_id,
                "acceptance_sequence": nested["accepted_delivery_sequence"],
                "terminal_receipt_sequence": wrapper["receipt_sequence"],
                "terminal_disposition": nested["outcome"]["disposition"],
                "request_digest_domain": "determa-inbox-envelope-digest-1",
            }
        event_tombstone = next(
            item
            for item in checkpoint["event_identity_tombstones"]
            if item["event_id"] == event_id
            and item["request_digest_domain"]
            == "determa-inbox-envelope-digest-1"
        )
        return {
            "result": "replay",
            "event_id": event_id,
            "acceptance_sequence": event_tombstone["acceptance_sequence"],
            "terminal_receipt_sequence": event_tombstone[
                "terminal_receipt_sequence"
            ],
            "terminal_disposition": event_tombstone["terminal_disposition"],
            "request_digest_domain": "determa-inbox-envelope-digest-1",
        }

    tombstone_replay_deliveries = [
        legacy_delivery(original_v1_inputs["accept_increment"]),
        legacy_delivery(original_v1_inputs["unhandled"]),
    ]
    spawned_trace_inputs = load(
        CHECKPOINT.parent
        / "checkpoint-06-terminal-spawned-host-trace"
        / "inputs.json"
    )["requests"]
    spawned_child_replay_delivery = legacy_delivery(
        spawned_trace_inputs["process_child"]
    )
    spawned_root_replay_delivery = legacy_delivery(spawned_trace_inputs["start"])
    spawned_mixed_replay_deliveries = [
        spawned_root_replay_delivery,
        spawned_child_replay_delivery,
    ]
    spawned_mixed_replay_result = {
        "result": "batch",
        "members": [
            {
                "event_id": delivery["envelope"]["event_id"],
                "disposition": "replay",
                "evidence": legacy_terminal_evidence(
                    spawned_tombstoned, delivery
                ),
            }
            for delivery in spawned_mixed_replay_deliveries
        ],
        "checkpoint": spawned_tombstoned,
    }
    tombstone_batch_result = {
        "result": "batch",
        "members": [
            {
                "event_id": delivery["envelope"]["event_id"],
                "disposition": "replay",
                "evidence": legacy_terminal_evidence(tombstoned, delivery),
            }
            for delivery in tombstone_replay_deliveries
        ],
        "checkpoint": tombstoned,
    }
    wrong_root_duplicate_delivery = {
        "delivery_mode": entry["delivery_mode"],
        "envelope": copy.deepcopy(entry["envelope"]),
        "envelope_digest": entry["envelope_digest"],
    }
    wrong_root_target = next(
        iter(wrong_root_duplicate_delivery["envelope"]["target"].values())
    )
    wrong_root_target["root_instance_id"] = "foreign-checkpoint-root"
    wrong_root_duplicate_delivery["envelope_digest"] = digest(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            "foreign-checkpoint-root",
            wrong_root_duplicate_delivery["delivery_mode"],
            wrong_root_duplicate_delivery["envelope"],
        ]
    )
    operations = {
        "upgrade": with_checkpoint_cas(
            {"operation": "upgrade_checkpoint_v1_to_v2"}, v1
        ),
        "upgrade_outbox": with_checkpoint_cas(
            {"operation": "upgrade_checkpoint_v1_to_v2"}, outbox_v1
        ),
        "upgrade_spawned_child": with_checkpoint_cas(
            {"operation": "upgrade_checkpoint_v1_to_v2"},
            spawned_checkpoint_v1,
        ),
        "upgrade_multi_pending": with_checkpoint_cas(
            {"operation": "upgrade_checkpoint_v1_to_v2"},
            multi_pending_v1,
        ),
        "admit": with_checkpoint_cas({"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]}, operational_base),
        "v1_admit": with_checkpoint_cas({"operation": "checkpoint_v1_accept", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]}, v1),
        "terminal_step": with_checkpoint_cas(
            {"operation": "checkpoint_step_v2", "target_runtime_id": aggregate["root_runtime_id"]},
            admitted,
        ),
        "native_emit_admit": with_checkpoint_cas(
            {"operation": "checkpoint_admit_v2", "deliveries": [{
                "delivery_mode": native_host_entry["delivery_mode"],
                "envelope": native_host_entry["envelope"],
                "envelope_digest": native_host_entry["envelope_digest"],
            }]},
            terminal,
        ),
        "native_emit_step": with_checkpoint_cas(
            {"operation": "checkpoint_step_v2", "target_runtime_id": native_aggregate["root_runtime_id"]},
            native_emit_admitted,
        ),
        "native_internal_step": with_checkpoint_cas(
            {"operation": "checkpoint_step_v2", "target_runtime_id": native_aggregate["root_runtime_id"]},
            native_internal,
        ),
        "terminal_equal_replay": with_checkpoint_cas({"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]}, operational_base),
        "pending_equal_replay": with_checkpoint_cas({"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]}, operational_base),
        "all_replay_batch": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": all_replay_deliveries,
            },
            operational_base,
        ),
        "mixed_replay_new_batch": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [
                    {
                        "delivery_mode": entry["delivery_mode"],
                        "envelope": entry["envelope"],
                        "envelope_digest": entry["envelope_digest"],
                    },
                    {
                        "delivery_mode": mixed_new_entry["delivery_mode"],
                        "envelope": mixed_new_entry["envelope"],
                        "envelope_digest": mixed_new_entry["envelope_digest"],
                    },
                ],
            },
            admitted,
        ),
        "legacy_terminal_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [legacy_replay_delivery],
            },
            v1,
        ),
        "compacted_legacy_terminal_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [legacy_replay_delivery],
            },
            compacted_legacy,
        ),
        "tombstoned_single_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [tombstone_replay_deliveries[0]],
            },
            faulted_upgraded,
        ),
        "tombstoned_batch_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": tombstone_replay_deliveries,
            },
            faulted_upgraded,
        ),
        "tombstoned_spawned_child_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [spawned_child_replay_delivery],
            },
            spawned_tombstoned,
        ),
        "tombstoned_mixed_runtime_batch_replay": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": spawned_mixed_replay_deliveries,
            },
            spawned_tombstoned,
        ),
        "tombstone_equal_replay": with_checkpoint_cas({"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"],
        }]}, operational_base),
        "stale_admit": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [
                    {
                        "delivery_mode": stale_writer_entry["delivery_mode"],
                        "envelope": stale_writer_entry["envelope"],
                        "envelope_digest": stale_writer_entry["envelope_digest"],
                    }
                ],
            },
            operational_base,
        ),
        "terminal_conflict": with_checkpoint_cas({"operation": "checkpoint_admit_v2", "deliveries": [{
            "delivery_mode": entry["delivery_mode"],
            "envelope": {**entry["envelope"], "payload": typed_value({"amount": 2})},
            "envelope_digest": digest(["determa-inbox-envelope-digest-2", "2", aggregate["root_instance_id"], entry["delivery_mode"], {**entry["envelope"], "payload": typed_value({"amount": 2})}]),
        }]}, terminal),
        "terminal_changed_payload_stale_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [changed_payload_stale_digest],
            },
            terminal,
        ),
        "terminal_unchanged_bad_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [unchanged_envelope_bad_digest],
            },
            terminal,
        ),
        "event_tombstone_changed_payload_stale_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [changed_payload_stale_digest],
            },
            compact,
        ),
        "event_tombstone_unchanged_bad_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [unchanged_envelope_bad_digest],
            },
            compact,
        ),
        "terminal_precedes_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [terminal_mismatch_delivery],
            },
            faulted_upgraded,
        ),
        "tombstone_precedes_digest": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [tombstoned_fresh_delivery],
            },
            tombstoned,
        ),
        "malformed_delivery": with_checkpoint_cas(
            {"operation": "checkpoint_admit_v2", "deliveries": [{}]},
            operational_base,
        ),
        "invalid_delivery_mode": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [invalid_mode_delivery],
            },
            operational_base,
        ),
        "wrong_root_duplicate": with_checkpoint_cas(
            {
                "operation": "checkpoint_admit_v2",
                "deliveries": [
                    wrong_root_duplicate_delivery,
                    copy.deepcopy(wrong_root_duplicate_delivery),
                ],
            },
            operational_base,
        ),
        "bounded_prune": with_checkpoint_cas({
            "operation": "checkpoint_prune_v2",
            "cutoff_receipt_sequence": event_terminal["receipt_sequence"],
        }, terminal),
        "equal_prune": with_checkpoint_cas({
            "operation": "checkpoint_prune_v2",
            "cutoff_receipt_sequence": event_terminal["receipt_sequence"],
        }, compact),
        "lower_prune": with_checkpoint_cas({
            "operation": "checkpoint_prune_v2",
            "cutoff_receipt_sequence": "1",
        }, compact),
        "dependency_prune": with_checkpoint_cas({
            "operation": "checkpoint_prune_v2",
            "cutoff_receipt_sequence": native_host_terminal_receipt_sequence,
        }, native_internal),
        "invalid_high_prune": with_checkpoint_cas({
            "operation": "checkpoint_prune_v2",
            "cutoff_receipt_sequence": "9",
        }, terminal),
        "tombstone": with_checkpoint_cas(
            {"operation": "checkpoint_tombstone_v2"}, terminal
        ),
    }
    return {
        "base-checkpoint-v1.json": canonical(v1),
        "multi-pending-checkpoint-v1.json": canonical(multi_pending_v1),
        "multi-pending-upgraded-checkpoint-v2.json": canonical(
            multi_pending_upgraded
        ),
        "multi-pending-upgraded-with-metadata-checkpoint-v2.json": canonical(
            multi_pending_upgraded_with_metadata
        ),
        "base-outbox-checkpoint-v1.json": canonical(outbox_v1),
        "base-checkpoint.json": canonical(operational_base),
        "spawned-child-checkpoint-v1.json": canonical(spawned_checkpoint_v1),
        "spawned-child-checkpoint-v2.json": canonical(spawned_checkpoint_v2),
        "spawned-terminal-checkpoint-v1.json": canonical(
            spawned_terminal_checkpoint_v1
        ),
        "spawned-terminal-checkpoint-v2.json": canonical(
            spawned_terminal_checkpoint_v2
        ),
        "spawned-tombstoned-checkpoint-v2.json": canonical(spawned_tombstoned),
        "upgraded-checkpoint-v2.json": canonical(upgraded),
        "upgraded-outbox-checkpoint-v2.json": canonical(upgraded_outbox),
        "admitted-checkpoint-v2.json": canonical(admitted),
        "mixed-admitted-checkpoint-v2.json": canonical(mixed_checkpoint),
        "terminal-checkpoint-v2.json": canonical(terminal),
        "native-emit-admitted-checkpoint-v2.json": canonical(native_emit_admitted),
        "native-internal-checkpoint-v2.json": canonical(native_internal),
        "native-internal-terminal-checkpoint-v2.json": canonical(native_terminal),
        "compact-checkpoint-v2.json": canonical(compact),
        "compacted-legacy-checkpoint-v2.json": canonical(compacted_legacy),
        "tombstoned-checkpoint-v2.json": canonical(tombstoned),
        "faulted-checkpoint-v2.json": canonical(faulted_upgraded),
        "invalid-duplicate-location-checkpoint-v2.json": canonical(invalid),
        "invalid-acceptance-tombstone-overlap-checkpoint-v2.json": canonical(
            invalid_acceptance_tombstone_overlap
        ),
        "invalid-tombstone-counter-checkpoint-v2.json": canonical(
            invalid_tombstone_counter
        ),
        "invalid-pruning-claim-checkpoint-v2.json": canonical(
            invalid_pruning_claim
        ),
        "invalid-creation-identity-checkpoint-v2.json": canonical(
            invalid_creation_identity
        ),
        "invalid-future-receipt-revision-checkpoint-v2.json": canonical(
            invalid_future_receipt_revision
        ),
        "operation-inputs.json": canonical(operations),
        "terminal-replay-result.json": canonical(
            {"result": "replay", "acceptance_receipt_sequence": receipt_sequence, "terminal_receipt_sequence": terminal_sequence}
        ),
        "pending-replay-result.json": canonical(
            {
                "result": "replay",
                "event_id": entry["envelope"]["event_id"],
                "acceptance_sequence": entry["acceptance_sequence"],
                "location": "ready",
            }
        ),
        "all-replay-batch-result.json": canonical(all_replay_result),
        "mixed-replay-new-batch-result.json": canonical(mixed_result),
        "legacy-terminal-replay-result.json": canonical(legacy_replay_result),
        "compacted-legacy-replay-result.json": canonical(
            legacy_terminal_evidence(compacted_legacy, legacy_replay_delivery)
        ),
        "tombstoned-single-replay-result.json": canonical(
            legacy_terminal_evidence(tombstoned, tombstone_replay_deliveries[0])
        ),
        "tombstoned-batch-replay-result.json": canonical(tombstone_batch_result),
        "tombstoned-spawned-child-replay-result.json": canonical(
            legacy_terminal_evidence(
                spawned_tombstoned, spawned_child_replay_delivery
            )
        ),
        "tombstoned-mixed-runtime-batch-replay-result.json": canonical(
            spawned_mixed_replay_result
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
