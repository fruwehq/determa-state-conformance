#!/usr/bin/env python3
"""Validate conformance fixture structure against a checked-out specification."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError
from ruamel.yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEntryToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingStartToken,
    FlowSequenceStartToken,
    ScalarToken,
    TagToken,
    ValueToken,
)

from closed_code_registry import RegistryValidationError, validate_registry


JSON_NUMBER = re.compile(
    r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$"
)
NUMERIC_CANDIDATE = re.compile(
    r"^[+-]?(?:[0-9][0-9A-Za-z_.+-]*|\.[0-9][0-9A-Za-z_+-]*)$"
)
SPECIAL_NUMERIC_SCALARS = frozenset(
    {".inf", "+.inf", "-.inf", ".nan", "+.nan", "-.nan"}
)
INVALID_BOOLEAN_SCALARS = frozenset({"True", "TRUE", "False", "FALSE"})
INVALID_NULL_SCALARS = frozenset({"Null", "NULL", "~"})
SOURCE_ERROR_CODES = frozenset(
    {
        "duplicate_key",
        "non_string_map_key",
        "unsupported_yaml_feature",
        "non_json_value",
        "invalid_unicode",
        "invalid_numeric_syntax",
        "invalid_boolean_syntax",
        "invalid_null_syntax",
        "numeric_value_out_of_range",
    }
)
MINIMUM_INTEGER = -9_223_372_036_854_775_808
MAXIMUM_INTEGER = 9_223_372_036_854_775_807
_CLOSED_CODE_REGISTRY = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "conformance/closed-code-registry/registry.json"
    ).read_text(encoding="utf-8")
)
ENGINE_FAULT_CODES = frozenset(
    entry["code"]
    for entry in _CLOSED_CODE_REGISTRY["entries"]
    if entry["category"] == "engine_fault"
)
DURABLE_HOST_FAILURE_CODES = frozenset(
    entry["code"]
    for entry in _CLOSED_CODE_REGISTRY["entries"]
    if entry["category"]
    in {
        "checkpoint_artifact_failure",
        "checkpoint_host_failure",
        "checkpoint_pre_acceptance_failure",
        "creation_rejection",
        "execution_store_adapter_failure",
        "execution_store_failure",
    }
)
NON_FINITE_DOUBLE_MARKERS = frozenset(
    {"nan", "positive_infinity", "negative_infinity"}
)
INSTANCE_REFERENCE_FIELDS = frozenset(
    {"root_instance_id", "instance_id", "machine_id", "machine_version"}
)
ARTIFACT_KINDS = {
    "aggregate_state_v2": "aggregate-state-v2.schema.json",
    "migration_descriptor_v2": "migration-descriptor-v2.schema.json",
    "aggregate_state_package_v2": "aggregate-state-package-v2.schema.json",
    "core_step_result_v2": "core-step-result-v2.schema.json",
    "execution_checkpoint_v2": "execution-checkpoint-v2.schema.json",
}
DRIVER_ARTIFACT_KINDS = {
    "version2_operation_inputs": "version2-operation-inputs.schema.json",
    "version2_operation_result": "version2-operation-result.schema.json",
    "durable_host_inputs_v2": "durable-host-inputs-v2.schema.json",
    "durable_host_results_v2": "durable-host-results-v2.schema.json",
    "durable_host_store_v2": "durable-host-store-v2.schema.json",
    "durable_host_call_log_v2": "durable-host-call-log-v2.schema.json",
}
HOST_PROFILE_REQUIREMENTS = {
    "durable_embedded_processing": {
        "store": {"root_identity_retention"},
        "host": {"atomic_accept_process"},
        "durable": True,
        "permanent": False,
    },
    "exactly_once_committed_processing": {
        "store": {"root_identity_retention", "permanent_receipt_retention"},
        "host": {"atomic_accept_process"},
        "durable": True,
        "permanent": True,
    },
    "broker_integrated": {
        "store": {"root_identity_retention"},
        "host": {
            "atomic_accept_process",
            "ingress_ack_after_commit",
            "durable_redelivery",
            "outbox_worker",
        },
        "durable": True,
        "permanent": False,
    },
    "strict_durable_outbox": {
        "store": {
            "root_identity_retention",
            "permanent_outbox_terminal_retention",
        },
        "host": {
            "total_outbox_lifecycle",
            "outbox_worker",
            "retain_unresolved_outbox",
        },
        "durable": True,
        "permanent": False,
    },
    "compact_durable_outbox": {
        "store": {
            "root_identity_retention",
            "compact_effect_identity_retention",
        },
        "host": {
            "total_outbox_lifecycle",
            "outbox_worker",
            "retain_receipt_references",
        },
        "durable": True,
        "permanent": False,
    },
    "shared_application_transaction": {
        "store": {"root_identity_retention", "shared_application_transaction"},
        "host": {"native_shared_transaction_used"},
        "durable": True,
        "permanent": False,
    },
}
REQUIRED_DURABLE_HOST_COVERAGE = frozenset(
    {
        "acceptance_receipt_native_v2",
        "adapter_capability_failure",
        "all_replay_conflict_precedence",
        "ambiguous_scope_rejected",
        "admission_event_conflict_precedence",
        "admission_malformed_precedence",
        "admission_wrong_root_precedence",
        "checkpoint_admission_commit",
        "checkpoint_broker_requirements",
        "checkpoint_capability_composition",
        "checkpoint_create_commit",
        "checkpoint_creation_conflict",
        "checkpoint_creation_replay",
        "checkpoint_dependency_safe_pruning",
        "checkpoint_durable_profile_requirements",
        "checkpoint_equal_pruning_replay",
        "checkpoint_exactly_once_requirements",
        "checkpoint_lower_pruning_rejected",
        "checkpoint_permanent_to_bounded",
        "checkpoint_physical_deletion_unsupported",
        "checkpoint_precommit_crash_rollback",
        "checkpoint_processing_commit",
        "checkpoint_public_adapter_registry",
        "checkpoint_root_identity_retention",
        "checkpoint_root_no_reuse",
        "checkpoint_root_tombstone",
        "checkpoint_root_tombstone_replay",
        "checkpoint_scope_fail_closed",
        "checkpoint_scope_isolation",
        "checkpoint_stale_pruning_rejected",
        "checkpoint_stale_writer_rejected",
        "checkpoint_strict_outbox_requirements",
        "checkpoint_terminal_replay",
        "checkpoint_third_party_adapter_registration",
        "creation_receipt_native_v2",
        "creation_rejection_without_checkpoint",
        "backup_completeness_bounded",
        "backup_completeness_permanent",
        "bounded_exactly_once_rejected",
        "bounded_terminal_retention",
        "bounded_to_permanent_rejected",
        "bounded_tombstone_retention",
        "broker_profile_negative",
        "broker_profile_positive",
        "bundled_public_registration",
        "committed_replay_precedes_stale_writer",
        "compact_outbox_profile_negative",
        "compact_outbox_profile_positive",
        "concurrent_loser_revision_conflict",
        "concurrent_one_winner",
        "delayed_processing",
        "delivery_digest_mismatch",
        "direct_store_injection",
        "duplicate_adapter_registration",
        "durable_embedded_profile_negative",
        "durable_embedded_profile_positive",
        "equal_effect_separate_scope_a",
        "equal_effect_separate_scope_b",
        "equal_identity_separate_scope_a",
        "equal_identity_separate_scope_b",
        "exact_admission_revision_equation",
        "exact_creation_revision_equation",
        "exact_outbox_revision_equation",
        "exact_persistence_revision_equation",
        "exact_pruning_revision_equation",
        "exact_processing_revision_equation",
        "exact_tombstone_revision_equation",
        "exactly_once_profile_negative",
        "exactly_once_profile_positive",
        "faulted_delivery",
        "file_capability_boundary",
        "foreground_delayed_equivalence",
        "foreground_processing",
        "handled_delivery",
        "invalid_adapter_configuration",
        "invalid_delivery_mode",
        "invalid_delivery_source",
        "invalid_instance_target",
        "inactive_component_target",
        "invalid_payload",
        "invalid_correlation",
        "duplicate_event_id_in_batch",
        "duplicate_batch_precedes_replay_conflict",
        "terminal_root",
        "terminal_root_precedes_delivery_validation",
        "replay_precedes_terminal_root",
        "replay_conflict_precedes_terminal_root",
        "tombstoned_root_precedes_delivery_validation",
        "tombstone_replay_precedes_tombstoned_root",
        "delivery_mode_precedes_source",
        "delivery_source_precedes_target",
        "instance_target_precedes_event",
        "payload_precedes_correlation",
        "correlation_precedes_digest",
        "ordered_batch_admission",
        "ordered_batch_single_revision",
        "ordered_batch_caller_order",
        "ordered_batch_malformed_failure",
        "all_replay_batch_read_only",
        "mixed_replay_new_batch",
        "checkpoint_request_exact_before_identity",
        "capability_requirements_derived_from_profile",
        "adapter_vendor_scheme_positive",
        "adapter_vendor_scheme_resolution",
        "adapter_identifier_underscore_rejected",
        "adapter_scheme_underscore_rejected",
        "cross_scope_store_record_isolation",
        "memory_capability_boundary",
        "mismatched_scope_rejected",
        "missing_scope_rejected",
        "pending_admission_replay",
        "permanent_terminal_retention",
        "permanent_tombstone_retention",
        "postgresql_capability_boundary",
        "pruning_dependency_closed_variants",
        "pruning_effect_receipt_dependency",
        "pruning_live_acceptance_dependency",
        "pruning_producer_receipt_dependency",
        "pruning_terminal_pair_dependency",
        "rejected_delivery",
        "replay_event_conflict_precedes_invalid_mode",
        "restore_completeness_bounded",
        "restore_completeness_permanent",
        "restore_incomplete_rejected",
        "restore_retains_bounded_horizon",
        "shared_transaction_profile_negative",
        "shared_transaction_profile_positive",
        "sqlite_capability_boundary",
        "stale_tombstoning_rejected",
        "strict_outbox_profile_negative",
        "strict_outbox_profile_positive",
        "third_party_public_registration",
        "tombstoned_ingress_rejected",
        "unauthorized_scope_rejected",
        "unhandled_delivery",
        "unknown_adapter",
        "outbox_ambiguous",
        "outbox_confirmed",
        "outbox_dead_lettered",
        "outbox_discarded",
        "outbox_effect_tombstone",
        "outbox_equal_pending_replay",
        "outbox_equal_terminal_replay",
        "outbox_forbidden_deletion",
        "outbox_not_attempted",
        "outbox_operator_cancelled",
        "outbox_permanently_rejected",
        "outbox_receipt_linkage",
        "outbox_retryable_failure",
        "outbox_terminal_conflict",
        "persistence_atomic_aggregate_inbox_outbox_audit",
        "persistence_atomic_application_rows",
        "persistence_atomic_precommit_rollback",
        "persistence_capabilities_before_transaction",
        "persistence_crash_after_commit_before_acknowledgement",
        "persistence_crash_before_commit",
        "persistence_crash_redelivery_replay",
        "persistence_inbox_first_commit",
        "persistence_inbox_idempotency",
        "persistence_inbox_replay_no_core_call",
        "persistence_local_cache_boundary",
        "persistence_permanent_failure_quarantine",
        "persistence_quarantine_no_core_call",
        "persistence_quarantine_release_semantics",
        "persistence_released_event_processing",
        "persistence_resolve_before_transaction",
        "persistence_transient_failure_rollback",
        "persistence_transient_retry_from_committed_state",
        "persistence_transient_retry_required",
        "replay_precedes_stale_writer",
        "spawned_child_admission",
        "spawned_host_creation",
        "spawned_host_start",
        "spawned_host_start_admission",
        "spawned_child_processing",
        "spawned_root_mailbox_isolation",
        "spawned_target_identity",
        "terminal_receipt_native_v2",
        "terminal_spawned_child_admission",
        "terminal_spawned_child_processing",
        "terminal_spawned_creation",
        "terminal_spawned_root_admission",
        "terminal_spawned_root_processing",
        "terminal_spawned_start",
        "terminal_spawned_start_admission",
    }
)
REQUIRED_VERSION2_COVERAGE = frozenset(
    {
        "aggregate_v2_schema_positive_negative",
        "automatic_selective_recall",
        "batch_duplicate_rejection",
        "canonical_v2_bytes_and_digests",
        "capacity_unbounded",
        "capacity_zero_and_overflow_fault",
        "cleanup_fault_rollback",
        "component_mailbox_isolation",
        "core_step_v2_schema_positive_negative",
        "deferred_only_not_runnable",
        "conflicting_pending_replay",
        "equal_pending_replay",
        "pending_changed_payload_stale_digest_conflict",
        "pending_replay_precedes_supplied_digest_validation",
        "explicit_target_single_step",
        "fault_frozen_mailbox_retention",
        "fifo_recall_to_ready_tail",
        "fresh_queue_sequence_on_recall",
        "completed_component_admission_rejection",
        "completed_component_step_rejection",
        "completed_root_step_rejection",
        "completed_root_admission_rejection",
        "disposed_component_admission_rejection",
        "disposed_component_step_rejection",
        "faulted_component_admission_rejection",
        "faulted_component_step_rejection",
        "faulted_root_descendant_admission_rejection",
        "faulted_root_descendant_step_rejection",
        "faulted_root_admission_rejection",
        "internal_emission_active_target",
        "internal_emission_chained_provenance",
        "internal_emission_disposed_target",
        "internal_emission_retained_faulted_target",
        "internal_emission_rollback",
        "invalid_machine_runtime_target",
        "invalid_event_batch_atomic_rejection",
        "invalid_payload_batch_atomic_rejection",
        "host_cause_identity_rejection",
        "lifecycle_aggregate_completion_disposal",
        "lifecycle_cancellation_disposal",
        "lifecycle_natural_completion_disposal",
        "mailbox_envelope_identity_preserved",
        "mailbox_location_totality",
        "native_v2_maintenance_empty_route",
        "native_v2_maintenance_one_hop",
        "native_v2_maintenance_two_hop",
        "native_v2_maintenance_replay_before_cas",
        "native_v2_maintenance_operation_conflict",
        "native_v2_maintenance_stale_writer",
        "native_v2_maintenance_historical_noop_identity",
        "native_v2_maintenance_tombstone_identity",
        "migration_backlog_independent_descriptor",
        "migration_audit_exact_order_content",
        "migration_capacity_totality",
        "migration_descriptor_v2_schema_positive_negative",
        "migration_empty_route_audit",
        "migration_fault_frozen_preservation",
        "migration_historical_fault_locator_preservation",
        "migration_package_v2_schema_positive_negative",
        "mailbox_payload_matches_event_declaration",
        "migration_multiple_audit_order",
        "migration_preserve_dispose_default",
        "migration_stale_target_transform",
        "migration_removed_event_failure",
        "migration_payload_incompatible_failure",
        "migration_correlation_incompatible_failure",
        "reclassification_and_repeated_deferral",
        "reserved_events_not_deferrable",
        "reserved_internal_event_admission",
        "delivery_digest_rejection",
        "root_mailbox_isolation",
        "spawned_mailbox_isolation",
        "version2_counter_allocation",
        "aggregate_byte_limit_exceeded",
        "aggregate_digest_mismatch",
        "all_typed_values_round_trip",
        "ambiguous_active_state_mapping",
        "attachment_never_overrides_existing_key",
        "attachments_seed_empty_resolver_and_drive_route",
        "chain_limit_exceeded",
        "compatible_definition_migration",
        "completed_preserved",
        "component_activation_first_javascript_unsafe",
        "component_activation_javascript_safe_maximum",
        "component_activation_unbounded",
        "component_numeric_activation_rejected",
        "component_placement_mapping",
        "component_target_extra_component_definition_pointer",
        "component_target_extra_field",
        "component_target_missing_activation_sequence",
        "component_target_missing_component_id",
        "component_target_missing_component_runtime_id",
        "component_target_missing_owner_runtime_id",
        "component_target_missing_root_instance_id",
        "configured_active_states_limit_exceeded",
        "configured_cel_ast_nodes_limit_exceeded",
        "configured_cel_expression_length_limit_exceeded",
        "configured_definition_bytes_limit_exceeded",
        "configured_descriptor_rules_limit_exceeded",
        "configured_json_nesting_depth_limit_exceeded",
        "configured_list_members_limit_exceeded",
        "configured_map_members_limit_exceeded",
        "configured_runtimes_limit_exceeded",
        "configured_string_utf8_bytes_limit_exceeded",
        "configured_variables_limit_exceeded",
        "counter_and_identity_preservation",
        "definition_is_present_but_untrusted",
        "definition_key_collision",
        "descriptor_byte_limit_exceeded",
        "descriptor_understates_actual_cel_evaluation",
        "descriptor_understates_actual_transformed_output",
        "duplicate_attachment",
        "empty_route_canonical_input_preserves_canonical_bytes",
        "empty_route_changed_definition_is_missing",
        "empty_route_same_definition_is_exact_noop",
        "exact_component_target_shape",
        "exact_root_target_shape",
        "exact_spawned_instance_target_shape",
        "exact_two_hop_route",
        "explicit_leaf_remap",
        "faulted_aggregate_round_trip",
        "faulted_diagnostic_tree_preserved",
        "guessed_reset",
        "identical_failed_retry",
        "identical_retry",
        "maintenance_required",
        "matching_definition",
        "migration_then_processing_faulted",
        "migration_then_processing_handled",
        "migration_then_processing_rejected",
        "migration_then_processing_unhandled",
        "minimum_supported_floors_accept_all_listed_dimensions",
        "missing_active_state_mapping",
        "missing_definition",
        "missing_maintenance_mode_is_invalid_request",
        "native_created_aggregate_matches_canonical_artifact",
        "non_boolean_maintenance_mode_is_invalid_request",
        "null_history_pointer_mapping",
        "owned_runtime_binding_mapping",
        "partial_variable_mapping",
        "put_if_absent_is_idempotent",
        "recorded_deep_history_pointer_mapping",
        "recorded_shallow_history_pointer_mapping",
        "repeated_activation_values_are_occurrence_local",
        "repeated_descriptor_cycle",
        "repeated_runtime_values_are_occurrence_local",
        "root_target_extra_field",
        "root_target_missing_root_instance_id",
        "root_target_missing_root_runtime_id",
        "runtime_transform_fault",
        "semantic_relation_mismatch",
        "spawned_instance_target_extra_field",
        "spawned_instance_target_extra_namespace",
        "spawned_instance_target_extra_owner_runtime_id",
        "spawned_instance_target_extra_spawn_sequence",
        "spawned_instance_target_missing_instance_id",
        "spawned_instance_target_missing_machine_id",
        "spawned_instance_target_missing_machine_version",
        "spawned_instance_target_missing_root_instance_id",
        "spawned_machine_version_above_signed64_rejected",
        "spawned_machine_version_first_javascript_unsafe",
        "spawned_machine_version_javascript_rounding_gap",
        "spawned_machine_version_javascript_safe_maximum",
        "spawned_machine_version_signed64_maximum",
        "spawned_numeric_machine_version_rejected",
        "target_definition_is_unavailable",
        "terminal_policy_rejects",
        "total_variable_transform",
        "unchanged_definition_resume",
        "unsupported_aggregate_discriminator",
        "unsupported_aggregate_schema_version",
        "unsupported_descriptor_discriminator",
        "unsupported_descriptor_schema_version",
        "unsupported_package_discriminator",
        "unsupported_package_schema_version",
        "untrusted_descriptor",
        "valid_self_contained_package",
        "wrong_descriptor_order",
    }
)

ARTIFACT_FORMAT_FIELDS = {
    "aggregate_state_v2": (
        "aggregate_state_format",
        "determa.aggregate_state",
        "aggregate_state_schema_version",
        2,
        "unsupported_aggregate_state_format",
        "unsupported_aggregate_state_schema_version",
        "invalid_aggregate_state",
    ),
    "migration_descriptor_v2": (
        "migration_descriptor_format",
        "determa.aggregate_migration",
        "migration_descriptor_schema_version",
        2,
        "unsupported_migration_descriptor_format",
        "unsupported_migration_descriptor_schema_version",
        "invalid_migration_descriptor",
    ),
    "aggregate_state_package_v2": (
        "aggregate_state_package_format",
        "determa.aggregate_state_package",
        "aggregate_state_package_schema_version",
        2,
        "unsupported_aggregate_state_package_format",
        "unsupported_aggregate_state_package_schema_version",
        "invalid_aggregate_state_package",
    ),
    "core_step_result_v2": (
        "core_step_result_format",
        "determa.core_step_result",
        "core_step_result_schema_version",
        2,
        "unsupported_core_step_result_format",
        "unsupported_core_step_result_schema_version",
        "invalid_core_step_result",
    ),
    "execution_checkpoint_v2": (
        "execution_checkpoint_format",
        "determa.execution_checkpoint",
        "execution_checkpoint_schema_version",
        2,
        "unsupported_execution_checkpoint_format",
        "unsupported_execution_checkpoint_schema_version",
        "invalid_execution_checkpoint",
    ),
}
ARTIFACT_SOURCE_ERROR_CODES = frozenset(
    {"duplicate_key", "invalid_json", "invalid_unicode", "non_json_value"}
)


class ValidationFailure(Exception):
    """One durable validation failure."""


@dataclass(frozen=True)
class SourceAnalysis:
    error: str | None
    document: Any | None


@dataclass(frozen=True)
class ArtifactAnalysis:
    error: str | None
    document: Any | None
    source: bytes


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant {value}")


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationFailure("duplicate_key")
        result[key] = value
    return result


def analyze_artifact(path: Path) -> ArtifactAnalysis:
    try:
        source = path.read_bytes()
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return ArtifactAnalysis("invalid_unicode", None, source)
    try:
        document = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except ValidationFailure as error:
        return ArtifactAnalysis(str(error), None, source)
    except (json.JSONDecodeError, ValueError):
        return ArtifactAnalysis("invalid_json", None, source)
    value_error = parsed_value_error(document)
    if value_error:
        return ArtifactAnalysis(
            "invalid_unicode" if value_error == "invalid_unicode" else "non_json_value",
            None,
            source,
        )
    return ArtifactAnalysis(None, document, source)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, rfc8785.IntegerDomainError) as error:
        raise ValidationFailure(f"value cannot be canonicalized: {error}") from error


def hash_value(value: Any) -> str:
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def hash_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def encode_typed_value(value: Any) -> list[Any]:
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
        return ["list", [encode_typed_value(item) for item in value]]
    if isinstance(value, dict):
        return [
            "map",
            [
                [key, encode_typed_value(value[key])]
                for key in sorted(value, key=lambda item: item.encode("utf-8"))
            ],
        ]
    raise ValidationFailure("operation input contains a non-JSON value")


def normalized_bundle_value(path: Path) -> dict[str, Any]:
    document = yaml_loader().load(path.read_text(encoding="utf-8"))
    bundle = copy.deepcopy(document)

    def normalize_payload(payload: dict[str, Any]) -> None:
        for declaration in payload.values():
            declaration.setdefault("required", False)
            if declaration.get("type") == "float" and isinstance(declaration.get("default"), int):
                declaration["default"] = float(declaration["default"])

    def normalize_transition(transition: dict[str, Any], event_transition: bool) -> None:
        if event_transition:
            transition.setdefault("lang", "cel")
        for action in transition.get("action", []):
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
        for value in state.get("on_events", {}).values():
            for transition in value if isinstance(value, list) else [value]:
                normalize_transition(transition, True)
        if "initial" in state:
            normalize_transition(state["initial"], False)
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


def validated_bundle_fingerprint(path: Path) -> str:
    return hash_value([
        "determa-validated-bundle-fingerprint-1",
        encode_typed_value(normalized_bundle_value(path)),
    ])


def aggregate_shape_fingerprint_for_path(path: Path) -> str:
    bundle = normalized_bundle_value(path)

    def state_projection(
        state: dict[str, Any],
        pointer: str,
        parent_scopes: tuple[tuple[str, dict[str, Any]], ...] = (),
    ) -> dict[str, Any]:
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
        scopes = parent_scopes + ((pointer, state.get("variables", {})),)
        children = [
            state_projection(child, f"{pointer}/states/{name}", scopes)
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
        spawn_sites: list[dict[str, Any]] = []

        def scan(value: Any, action_pointer: str) -> None:
            if isinstance(value, list):
                for index, item in enumerate(value):
                    scan(item, f"{action_pointer}/{index}")
                return
            if not isinstance(value, dict):
                return
            spawn = value.get("spawn")
            if isinstance(spawn, dict):
                holder_pointer = None
                holder = spawn.get("bind_to")
                if holder is not None:
                    for scope_pointer, declarations in reversed(scopes):
                        if holder in declarations:
                            holder_pointer = f"{scope_pointer}/variables/{holder}"
                            break
                spawn_sites.append(
                    {
                        "action_pointer": f"{action_pointer}/spawn",
                        "machine_id": spawn["machine_id"],
                        "holder_variable_declaration_pointer": holder_pointer,
                    }
                )
            for key, item in value.items():
                if key != "spawn":
                    scan(item, f"{action_pointer}/{key}")

        for action_name in ("entry", "exit"):
            scan(state.get(action_name, []), f"{pointer}/{action_name}")
        if "initial" in state:
            scan(state["initial"].get("action", []), f"{pointer}/initial/action")
        for event_name, transitions in state.get("on_events", {}).items():
            for transition_index, transition in enumerate(
                transitions if isinstance(transitions, list) else [transitions]
            ):
                suffix = f"/{transition_index}" if isinstance(transitions, list) else ""
                scan(
                    transition.get("action", []),
                    f"{pointer}/on_events/{event_name}{suffix}/action",
                )
        if spawn_sites:
            result["spawn_sites"] = sorted(
                spawn_sites, key=lambda item: item["action_pointer"].encode("utf-8")
            )
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
    return hash_value(["determa-aggregate-shape-fingerprint-1", encode_typed_value(tree)])


def validate_aggregate_against_bundle(
    aggregate: dict[str, Any], bundle_path: Path, *historical_bundle_paths: Path
) -> None:
    bundle = normalized_bundle_value(bundle_path)
    fingerprint = validated_bundle_fingerprint(bundle_path)
    bundles_by_fingerprint = {fingerprint: bundle}
    for historical_path in historical_bundle_paths:
        bundles_by_fingerprint[validated_bundle_fingerprint(historical_path)] = (
            normalized_bundle_value(historical_path)
        )

    def resolve(pointer: str, definition_bundle: dict[str, Any] = bundle) -> Any:
        value: Any = definition_bundle
        try:
            for encoded in pointer.split("/")[1:]:
                token = encoded.replace("~1", "/").replace("~0", "~")
                value = value[int(token)] if isinstance(value, list) else value[token]
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise ValidationFailure(
                f"aggregate v2: unresolved definition pointer {pointer}"
            ) from error
        return value

    if aggregate["validated_bundle_fingerprint"] != fingerprint:
        raise ValidationFailure("aggregate v2: current bundle fingerprint mismatch")
    for runtime in aggregate["runtimes"]:
        origin = runtime["identity_origin"]
        origin_machine = origin["definition"]["machine"]
        if origin["kind"] == "root":
            expected_runtime_id = hash_value(
                [
                    "determa-root-runtime-identity-2",
                    "1",
                    origin["definition"]["validated_bundle_fingerprint"],
                    origin_machine["namespace"],
                    origin_machine["machine_id"],
                    origin_machine["machine_version"],
                    aggregate["root_instance_id"],
                ]
            )
            expected_target = {
                "root": {
                    "root_instance_id": aggregate["root_instance_id"],
                    "root_runtime_id": expected_runtime_id,
                }
            }
        elif origin["kind"] == "component":
            expected_runtime_id = hash_value(
                [
                    "determa-component-runtime-identity-1",
                    "1",
                    aggregate["root_instance_id"],
                    origin["owner_runtime_id"],
                    origin["component_definition_pointer"],
                    origin["activation_sequence"],
                    origin_machine["namespace"],
                    origin_machine["machine_id"],
                    origin_machine["machine_version"],
                ]
            )
            origin_fingerprint = origin["definition"][
                "validated_bundle_fingerprint"
            ]
            origin_bundle = bundles_by_fingerprint.get(origin_fingerprint)
            if origin_bundle is None:
                raise ValidationFailure(
                    "aggregate v2: component identity definition is unavailable"
                )
            origin_placement = resolve(
                origin["component_definition_pointer"], origin_bundle
            )
            expected_target = {
                "component": {
                    "root_instance_id": aggregate["root_instance_id"],
                    "owner_runtime_id": origin["owner_runtime_id"],
                    "component_id": origin_placement["component_id"],
                    "activation_sequence": origin["activation_sequence"],
                    "component_runtime_id": expected_runtime_id,
                }
            }
        else:
            expected_runtime_id = hash_value(
                [
                    "determa-spawned-runtime-identity-1",
                    "1",
                    aggregate["root_instance_id"],
                    origin["owner_runtime_id"],
                    origin["spawn_action_pointer"],
                    origin["spawn_sequence"],
                    origin_machine["namespace"],
                    origin_machine["machine_id"],
                    origin_machine["machine_version"],
                ]
            )
            expected_target = runtime["target_identity"]
            spawned_target = expected_target["spawned_instance"]
            if (
                spawned_target["root_instance_id"]
                != aggregate["root_instance_id"]
                or spawned_target["instance_id"] != expected_runtime_id
                or spawned_target["machine_id"] != origin_machine["machine_id"]
                or spawned_target["machine_version"]
                != origin_machine["machine_version"]
            ):
                raise ValidationFailure("aggregate v2: spawned target identity mismatch")
        if runtime["runtime_id"] != expected_runtime_id:
            raise ValidationFailure("aggregate v2: noncanonical runtime identity")
        if runtime["target_identity"] != expected_target:
            raise ValidationFailure("aggregate v2: runtime target identity mismatch")
        current = runtime["current_definition"]
        if current["validated_bundle_fingerprint"] != fingerprint:
            raise ValidationFailure("aggregate v2: runtime current definition mismatch")
        resolve(current["machine"]["root_definition_pointer"])
        current_machine = next(
            (
                machine
                for machine in bundle["machines"]
                if machine["machine_id"] == current["machine"]["machine_id"]
                and str(machine["version"])
                == current["machine"]["machine_version"]
            ),
            None,
        )
        if current_machine is None:
            raise ValidationFailure("aggregate v2: current machine is unavailable")
        for mailbox_name in ("ready_mailbox", "deferred_mailbox"):
            for entry in runtime.get(mailbox_name, []):
                event_name = entry["envelope"]["event"]
                declaration = current_machine.get("events", {}).get(event_name)
                if declaration is None:
                    declaration = bundle.get("events", {}).get(event_name)
                if declaration is None:
                    continue
                payload_entries = entry["envelope"]["payload"]
                if payload_entries[0] != "map":
                    raise ValidationFailure(
                        "aggregate v2: mailbox payload is not a typed map"
                    )
                payload = dict(payload_entries[1])
                fields = declaration.get("payload", {})
                if set(payload) - set(fields):
                    raise ValidationFailure(
                        "aggregate v2: mailbox payload has undeclared fields"
                    )
                required_fields = {
                    name
                    for name, field in fields.items()
                    if field.get("required", False) or "default" in field
                }
                if not required_fields <= set(payload):
                    raise ValidationFailure(
                        "aggregate v2: mailbox payload lacks materialized fields"
                    )
                expected_tags = {
                    "string": "string",
                    "int": "integer",
                    "float": "float",
                    "bool": "boolean",
                    "map": "map",
                    "list": "list",
                }
                if any(
                    payload[name][0] != expected_tags[fields[name]["type"]]
                    for name in payload
                ):
                    raise ValidationFailure(
                        "aggregate v2: mailbox payload field type mismatch"
                    )
        for pointer in runtime["active_leaf_state_definition_pointers"]:
            resolve(pointer)
        for item in runtime["active_state_activations"]:
            resolve(item["state_definition_pointer"])
        for item in runtime["variables"]:
            declaration = resolve(item["variable_declaration_pointer"])
            if not isinstance(declaration, dict) or "type" not in declaration:
                raise ValidationFailure("aggregate v2: variable pointer is not a declaration")
        for item in runtime["next_state_activation_sequences"]:
            resolve(item["definition_pointer"])
        for item in runtime["next_component_activation_sequences"]:
            resolve(item["definition_pointer"])
        fault = runtime.get("fault")
        if fault is not None and fault["source_locator"].startswith("/"):
            fault_bundle = bundles_by_fingerprint.get(
                fault["definition_fingerprint"]
            )
            if fault_bundle is None:
                raise ValidationFailure(
                    "aggregate v2: historical fault definition is unavailable"
                )
            resolve(fault["source_locator"], fault_bundle)
        if runtime["relation"]["kind"] == "component":
            placement = resolve(runtime["relation"]["current_component_definition_pointer"])
            if placement["component_id"] != runtime["relation"]["component_id"]:
                raise ValidationFailure("aggregate v2: component placement mismatch")


def decode_typed_value(value: list[Any]) -> Any:
    tag = value[0]
    if tag == "null":
        return None
    if tag == "boolean" or tag == "string":
        return value[1]
    if tag == "integer":
        return int(value[1])
    if tag == "float":
        return struct.unpack(">d", bytes.fromhex(value[1]))[0]
    if tag == "list":
        return [decode_typed_value(item) for item in value[1]]
    if tag == "map":
        return {key: decode_typed_value(item) for key, item in value[1]}
    raise ValidationFailure(f"unsupported typed-value tag {tag!r}")


def validate_typed_value_canonical(value: list[Any], location: str) -> None:
    tag = value[0]
    if tag == "list":
        for index, child in enumerate(value[1]):
            validate_typed_value_canonical(child, f"{location}[{index}]")
        return
    if tag != "map":
        return
    entries = value[1]
    keys = [entry[0] for entry in entries]
    if keys != sorted(keys, key=lambda item: item.encode("utf-8")):
        raise ValidationFailure(f"{location}: typed-map keys are not canonical")
    if len(keys) != len(set(keys)):
        raise ValidationFailure(f"{location}: typed-map keys are not unique")
    for key, child in entries:
        validate_typed_value_canonical(child, f"{location}.{key}")


def validate_engine_fault_code(fault: Any, location: str) -> None:
    if fault is None:
        return
    code = fault.get("code") if isinstance(fault, dict) else None
    if code not in ENGINE_FAULT_CODES:
        raise ValidationFailure(
            f"{location}: fault record uses non-closed engine code {code!r}"
        )




def validate_reserved_failure_envelope(envelope: dict[str, Any], location: str) -> None:
    if envelope["event"] not in {
        "determa.component_failed",
        "determa.spawned_instance_failed",
    }:
        return
    payload = decode_typed_value(envelope["payload"])
    validate_engine_fault_code(payload.get("fault"), location)


def verify_artifact_digest(kind: str, document: Any, path: Path) -> None:
    if kind == "aggregate_state_v2":
        digest = document.get("aggregate_state_digest")
        without_digest = dict(document)
        without_digest.pop("aggregate_state_digest", None)
        expected = hash_value(["determa-aggregate-state-digest-2", without_digest])
        if digest != expected:
            raise ValidationFailure(
                f"{path}: aggregate_state_digest {digest!r} != {expected!r}"
            )
    elif kind == "migration_descriptor_v2":
        digest = document.get("migration_descriptor_digest")
        without_digest = dict(document)
        without_digest.pop("migration_descriptor_digest", None)
        expected = hash_value(["determa-migration-descriptor-2", without_digest])
        if digest != expected:
            raise ValidationFailure(
                f"{path}: migration_descriptor_digest {digest!r} != {expected!r}"
            )
    elif kind == "aggregate_state_package_v2":
        verify_artifact_digest("aggregate_state_v2", document["aggregate_state"], path)
        definition_digests: set[str] = set()
        for attachment in document["normalized_definitions"]:
            digest = attachment["validated_bundle_fingerprint"]
            expected = hash_value(
                [
                    "determa-validated-bundle-fingerprint-1",
                    attachment["normalized_bundle"],
                ]
            )
            if digest != expected or digest in definition_digests:
                raise ValidationFailure(
                    f"{path}: invalid or duplicate definition attachment {digest}"
                )
            definition_digests.add(digest)
        descriptor_digests: set[str] = set()
        for descriptor in document["migration_descriptors"]:
            verify_artifact_digest("migration_descriptor_v2", descriptor, path)
            digest = descriptor["migration_descriptor_digest"]
            if digest in descriptor_digests:
                raise ValidationFailure(
                    f"{path}: duplicate descriptor attachment {digest}"
                )
            descriptor_digests.add(digest)
    elif kind == "execution_checkpoint_v2":
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            verify_artifact_digest(
                "aggregate_state_v2",
                root_record["aggregate_state"],
                path,
            )
        digest = document.get("execution_checkpoint_digest")
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        expected = hash_value(
            ["determa-execution-checkpoint-digest-2", without_digest]
        )
        if digest != expected:
            raise ValidationFailure(
                f"{path}: execution_checkpoint_digest {digest!r} != {expected!r}"
            )


def canonical_decimal(value: Any, location: str) -> int:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None
    ):
        raise ValidationFailure(f"{location}: expected canonical decimal")
    return int(value)




def validate_aggregate_v2_semantics(document: dict[str, Any]) -> None:
    runtime_ids: set[str] = set()
    event_ids: set[str] = set()
    acceptance_sequences: set[int] = set()
    queue_sequences: set[int] = set()
    entries: list[dict[str, Any]] = []
    root_runtime = None

    runtime_order = [runtime["runtime_id"].encode("utf-8") for runtime in document["runtimes"]]
    if runtime_order != sorted(runtime_order) or len(runtime_order) != len(set(runtime_order)):
        raise ValidationFailure("aggregate v2: runtime order is not canonical")

    def require_canonical_collection(
        values: list[dict[str, Any]], key, label: str
    ) -> None:
        keys = [key(item) for item in values]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValidationFailure(f"aggregate v2: {label} order is not canonical")

    for runtime in document["runtimes"]:
        validate_engine_fault_code(runtime["fault"], "aggregate v2 runtime")
        runtime_id = runtime["runtime_id"]
        if runtime_id in runtime_ids:
            raise ValidationFailure("aggregate v2: duplicate runtime id")
        runtime_ids.add(runtime_id)
        if runtime["relation"]["kind"] == "root":
            if root_runtime is not None:
                raise ValidationFailure("aggregate v2: multiple root runtimes")
            root_runtime = runtime
        if runtime["status"] == "completed" and (
            runtime["ready_mailbox"] or runtime["deferred_mailbox"]
        ):
            raise ValidationFailure("aggregate v2: completed runtime retains mailbox work")
        leaves = runtime["active_leaf_state_definition_pointers"]
        if leaves != sorted(leaves, key=lambda item: item.encode("utf-8")) or len(leaves) != len(set(leaves)):
            raise ValidationFailure("aggregate v2: active leaf order is not canonical")
        require_canonical_collection(
            runtime["active_state_activations"],
            lambda item: (item["state_definition_pointer"].encode("utf-8"), canonical_decimal(item["activation_sequence"], "state activation sequence")),
            "state activation",
        )
        require_canonical_collection(
            runtime["variables"],
            lambda item: (item["variable_declaration_pointer"].encode("utf-8"), canonical_decimal(item["declaring_state_activation_sequence"], "variable activation sequence")),
            "variable",
        )
        for variable in runtime["variables"]:
            validate_typed_value_canonical(
                variable["value"],
                f"aggregate v2 variable {variable['variable_declaration_pointer']}",
            )
        for mailbox_name in ("ready_mailbox", "deferred_mailbox"):
            for entry in runtime[mailbox_name]:
                validate_typed_value_canonical(
                    entry["envelope"]["payload"],
                    f"aggregate v2 {mailbox_name} envelope payload",
                )
        require_canonical_collection(
            runtime["history"],
            lambda item: item["history_declaration_pointer"].encode("utf-8"),
            "history",
        )
        state_counters = runtime["next_state_activation_sequences"]
        component_counters = runtime["next_component_activation_sequences"]
        require_canonical_collection(
            state_counters,
            lambda item: item["definition_pointer"].encode("utf-8"),
            "state counter",
        )
        require_canonical_collection(
            component_counters,
            lambda item: item["definition_pointer"].encode("utf-8"),
            "component counter",
        )
        state_next = {
            item["definition_pointer"]: canonical_decimal(item["next_sequence"], "next state activation sequence")
            for item in state_counters
        }
        for activation in runtime["active_state_activations"]:
            pointer = activation["state_definition_pointer"]
            sequence = canonical_decimal(activation["activation_sequence"], "state activation sequence")
            if pointer not in state_next or state_next[pointer] <= sequence:
                raise ValidationFailure("aggregate v2: state activation counter regression")
        if runtime["relation"]["kind"] == "component":
            owner_id = runtime["relation"]["owner_runtime_id"]
            owner = next((item for item in document["runtimes"] if item["runtime_id"] == owner_id), None)
            pointer = runtime["relation"]["current_component_definition_pointer"]
            sequence = canonical_decimal(runtime["relation"]["activation_sequence"], "component activation sequence")
            if owner is None:
                raise ValidationFailure("aggregate v2: component owner is missing")
            owner_next = {
                item["definition_pointer"]: canonical_decimal(item["next_sequence"], "next component activation sequence")
                for item in owner["next_component_activation_sequences"]
            }
            if pointer not in owner_next or owner_next[pointer] <= sequence:
                raise ValidationFailure("aggregate v2: component activation counter regression")
        for mailbox_name in ("ready_mailbox", "deferred_mailbox"):
            mailbox = runtime[mailbox_name]
            order = [
                canonical_decimal(entry["queue_sequence"], "mailbox queue sequence")
                for entry in mailbox
            ]
            if order != sorted(order) or len(order) != len(set(order)):
                raise ValidationFailure("aggregate v2: mailbox order is not strict")
            for entry in mailbox:
                event_id = entry["envelope"]["event_id"]
                acceptance = canonical_decimal(
                    entry["acceptance_sequence"], "mailbox acceptance sequence"
                )
                queue = canonical_decimal(
                    entry["queue_sequence"], "mailbox queue sequence"
                )
                if event_id in event_ids or acceptance in acceptance_sequences:
                    raise ValidationFailure("aggregate v2: duplicate mailbox identity")
                if queue in queue_sequences:
                    raise ValidationFailure("aggregate v2: reused queue sequence")
                event_ids.add(event_id)
                acceptance_sequences.add(acceptance)
                queue_sequences.add(queue)
                if entry["envelope"]["target"] != runtime["target_identity"]:
                    raise ValidationFailure("aggregate v2: mailbox target mismatch")
                validate_reserved_failure_envelope(
                    entry["envelope"], "aggregate v2 reserved failure event"
                )
                expected_digest = hash_value(
                    [
                        "determa-inbox-envelope-digest-2",
                        "2",
                        document["root_instance_id"],
                        entry["delivery_mode"],
                        entry["envelope"],
                    ]
                )
                if entry["envelope_digest"] != expected_digest:
                    raise ValidationFailure(
                        f"aggregate v2: envelope digest mismatch for {event_id}"
                    )
                entries.append(entry)

    if root_runtime is None:
        raise ValidationFailure("aggregate v2: missing root runtime")
    if (
        root_runtime["runtime_id"] != document["root_runtime_id"]
        or root_runtime["target_identity"].get("root", {}).get("root_instance_id")
        != document["root_instance_id"]
    ):
        raise ValidationFailure("aggregate v2: root identity mismatch")
    next_acceptance = canonical_decimal(
        document["next_acceptance_sequence"], "next acceptance sequence"
    )
    next_queue = canonical_decimal(
        document["next_queue_sequence"], "next queue sequence"
    )
    if acceptance_sequences and next_acceptance <= max(acceptance_sequences):
        raise ValidationFailure("aggregate v2: acceptance counter regression")
    if queue_sequences and next_queue <= max(queue_sequences):
        raise ValidationFailure("aggregate v2: queue counter regression")


def validate_core_step_v2_semantics(document: dict[str, Any]) -> None:
    validate_engine_fault_code(document["fault"], "core step v2")
    disposition = document["disposition"]
    rejection = document["rejection"]
    if disposition == "rejected":
        if rejection is None or document["fault"] is not None:
            raise ValidationFailure("core step v2: malformed rejection")
        if document["emissions"] or document["lifecycle_dispositions"]:
            raise ValidationFailure("core step v2: rejection has side effects")
    elif rejection is not None:
        raise ValidationFailure("core step v2: non-rejection carries rejection")
    if disposition == "faulted":
        if document["fault"] is None:
            raise ValidationFailure("core step v2: faulted result lacks fault")
    elif document["fault"] is not None:
        raise ValidationFailure("core step v2: non-fault result carries fault")
    if disposition == "not_runnable" and (
        document["emissions"] or document["lifecycle_dispositions"]
    ):
        raise ValidationFailure("core step v2: not-runnable result mutated output")

    mailbox_entries: dict[str, dict[str, Any]] = {}
    for runtime in document["state"]["runtimes"]:
        for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"]):
            for entry in mailbox:
                mailbox_entries[entry["envelope"]["event_id"]] = entry
    lifecycle_dispositions = document["lifecycle_dispositions"]
    disposition_event_ids = [item["event_id"] for item in lifecycle_dispositions]
    if len(disposition_event_ids) != len(set(disposition_event_ids)):
        raise ValidationFailure("core step v2: duplicate lifecycle disposition")
    if mailbox_entries.keys() & set(disposition_event_ids):
        raise ValidationFailure("core step v2: emitted event has two locations")

    internal_event_ids: set[str] = set()
    for emission in document["emissions"]:
        kind = emission.get("kind")
        if kind not in {"internal_mailbox", "internal_disposed"}:
            continue
        event_id = emission["event_id"]
        if event_id in internal_event_ids:
            raise ValidationFailure("core step v2: duplicate internal emission reference")
        internal_event_ids.add(event_id)
        if kind == "internal_mailbox":
            entry = mailbox_entries.get(event_id)
            if entry is None or (
                entry["acceptance_sequence"] != emission["acceptance_sequence"]
                or entry["queue_sequence"] != emission["queue_sequence"]
            ):
                raise ValidationFailure(
                    "core step v2: unresolved internal mailbox emission"
                )
            continue
        index = canonical_decimal(
            emission["lifecycle_disposition_index"],
            "lifecycle disposition index",
        )
        if index >= len(lifecycle_dispositions):
            raise ValidationFailure(
                "core step v2: unresolved internal disposed emission"
            )
        lifecycle = lifecycle_dispositions[index]
        if (
            lifecycle["event_id"] != event_id
            or lifecycle["acceptance_sequence"] != emission["acceptance_sequence"]
        ):
            raise ValidationFailure(
                "core step v2: mismatched internal disposed emission"
            )


def validate_execution_checkpoint_v2_semantics(document: dict[str, Any]) -> None:
    revision = canonical_decimal(document["revision"], "checkpoint v2 revision")
    root_record = document["root_record"]
    mailbox_entries: dict[str, dict[str, Any]] = {}
    mailbox_acceptance_sequences: set[str] = set()
    if root_record["status"] == "retained":
        aggregate = root_record["aggregate_state"]
        validate_aggregate_v2_semantics(aggregate)
        if aggregate["root_instance_id"] != document["root_instance_id"]:
            raise ValidationFailure("checkpoint v2: root mismatch")
        for runtime in aggregate["runtimes"]:
            for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"]):
                for entry in mailbox:
                    event_id = entry["envelope"]["event_id"]
                    if event_id in mailbox_entries:
                        raise ValidationFailure("checkpoint v2: duplicate mailbox event identity")
                    if entry["acceptance_sequence"] in mailbox_acceptance_sequences:
                        raise ValidationFailure("checkpoint v2: duplicate mailbox acceptance identity")
                    mailbox_entries[event_id] = entry
                    mailbox_acceptance_sequences.add(entry["acceptance_sequence"])

    receipts = document["operation_receipts"]
    if not receipts or receipts[0]["receipt_sequence"] != "0":
        raise ValidationFailure("checkpoint v2: creation receipt must remain first")
    creation_receipt = receipts[0]
    if creation_receipt["operation_kind"] != "creation":
        raise ValidationFailure("checkpoint v2: creation receipt must remain first")
    checkpoint_creation_id = (
        root_record["aggregate_state"]["creation_id"]
        if root_record["status"] == "retained"
        else root_record["creation_id"]
    )
    if creation_receipt["creation_id"] != checkpoint_creation_id:
        raise ValidationFailure("checkpoint v2: creation identity mismatch")
    for receipt in receipts:
        receipt_revision = receipt.get("committed_revision")
        if receipt_revision is not None and canonical_decimal(
            receipt_revision, "checkpoint v2 receipt revision"
        ) > revision:
            raise ValidationFailure("checkpoint v2: receipt revision is in the future")
        accepted_revision = receipt.get("accepted_revision")
        if accepted_revision is not None and canonical_decimal(
            accepted_revision, "checkpoint v2 accepted revision"
        ) > revision:
            raise ValidationFailure("checkpoint v2: accepted revision is in the future")
        validate_engine_fault_code(receipt.get("fault"), "checkpoint v2 receipt")
        outcome = receipt.get("outcome")
        if isinstance(outcome, dict):
            validate_engine_fault_code(
                outcome.get("fault"), "checkpoint v2 terminal outcome"
            )
    sequences = [
        canonical_decimal(receipt["receipt_sequence"], "receipt sequence")
        for receipt in receipts
    ]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise ValidationFailure("checkpoint v2: receipt order is invalid")

    receipt_chronology: list[tuple[int, int]] = []
    for receipt, receipt_sequence in zip(receipts, sequences, strict=True):
        if "committed_revision" in receipt:
            effective_revision = receipt["committed_revision"]
        else:
            effective_revision = receipt["accepted_revision"]
        receipt_chronology.append(
            (
                canonical_decimal(
                    effective_revision,
                    "checkpoint v2 receipt chronology revision",
                ),
                receipt_sequence,
            )
        )
    if receipt_chronology != sorted(receipt_chronology):
        raise ValidationFailure("checkpoint v2: receipt chronology is invalid")
    next_receipt_sequence = canonical_decimal(
        document["next_operation_receipt_sequence"], "next receipt sequence"
    )
    if sequences and next_receipt_sequence <= max(sequences):
        raise ValidationFailure("checkpoint v2: receipt counter regression")
    pruning_cutoff = document["replay_retention"][
        "pruned_through_receipt_sequence"
    ]
    cutoff = (
        canonical_decimal(pruning_cutoff, "checkpoint pruning cutoff")
        if pruning_cutoff is not None
        else None
    )
    if cutoff is not None and cutoff >= next_receipt_sequence:
        raise ValidationFailure(
            "checkpoint v2: pruning cutoff covers an unallocated receipt"
        )
    if document["replay_retention"]["mode"] == "permanent" or cutoff is None:
        expected_receipt_sequences = list(range(next_receipt_sequence))
    else:
        expected_receipt_sequences = [
            0,
            *range(cutoff + 1, next_receipt_sequence),
        ]
    if sequences != expected_receipt_sequences:
        raise ValidationFailure(
            "checkpoint v2: receipt retention interval is incomplete"
        )

    def require_sequence_order(values: list[dict[str, Any]], field: str, label: str) -> set[int]:
        allocations = [canonical_decimal(item[field], label) for item in values]
        if allocations != sorted(allocations) or len(allocations) != len(set(allocations)):
            raise ValidationFailure(f"checkpoint v2: {label} order is invalid")
        return set(allocations)

    pending_intent_sequences = [
        canonical_decimal(item["intent"]["sequence"], "pending outbox sequence")
        for item in document["pending_outbox_intents"]
    ]
    for index, item in enumerate(document["pending_outbox_intents"]):
        validate_typed_value_canonical(
            item["intent"]["payload"],
            f"checkpoint v2 pending outbox intent {index} payload",
        )
        if canonical_decimal(
            item["state_revision"], "checkpoint v2 pending outbox revision"
        ) > revision:
            raise ValidationFailure("checkpoint v2: outbox revision is in the future")
    if (
        pending_intent_sequences != sorted(pending_intent_sequences)
        or len(pending_intent_sequences) != len(set(pending_intent_sequences))
    ):
        raise ValidationFailure("checkpoint v2: pending outbox order is invalid")
    terminal_outbox_sequences = require_sequence_order(
        document["terminal_outbox_records"], "terminal_sequence", "terminal outbox sequence"
    )
    for index, item in enumerate(document["terminal_outbox_records"]):
        validate_typed_value_canonical(
            item["intent"]["payload"],
            f"checkpoint v2 terminal outbox intent {index} payload",
        )
        if canonical_decimal(
            item["committed_revision"], "checkpoint v2 terminal outbox revision"
        ) > revision:
            raise ValidationFailure("checkpoint v2: outbox revision is in the future")
    for item in document["outbox_effect_tombstones"]:
        if canonical_decimal(
            item["committed_revision"], "checkpoint v2 outbox tombstone revision"
        ) > revision:
            raise ValidationFailure("checkpoint v2: outbox revision is in the future")
    tombstone_outbox_sequences = require_sequence_order(
        document["outbox_effect_tombstones"], "terminal_sequence", "outbox tombstone sequence"
    )
    audit_sequences = require_sequence_order(
        document["migration_audit_records"], "migration_sequence", "migration audit sequence"
    )
    audits_by_sequence = {
        item["migration_sequence"]: item
        for item in document["migration_audit_records"]
    }
    expected_audit_root_runtime_id = (
        root_record["aggregate_state"]["root_runtime_id"]
        if root_record["status"] == "retained"
        else None
    )
    for audit in document["migration_audit_records"]:
        if audit["root_instance_id"] != document["root_instance_id"] or (
            expected_audit_root_runtime_id is not None
            and audit["root_runtime_id"] != expected_audit_root_runtime_id
        ):
            raise ValidationFailure("checkpoint v2: migration audit root mismatch")
    fingerprints_by_aggregate_digest: dict[str, set[str]] = {}

    def remember_fingerprint(aggregate_digest: str, fingerprint: str) -> None:
        fingerprints_by_aggregate_digest.setdefault(
            aggregate_digest, set()
        ).add(fingerprint)

    for audit in document["migration_audit_records"]:
        remember_fingerprint(
            audit["source_aggregate_state_digest"],
            audit["source_validated_bundle_fingerprint"],
        )
        remember_fingerprint(
            audit["target_aggregate_state_digest"],
            audit["target_validated_bundle_fingerprint"],
        )
    if root_record["status"] == "retained":
        retained_aggregate = root_record["aggregate_state"]
        if audit_sequences and canonical_decimal(
            retained_aggregate["migration_sequence"],
            "retained aggregate migration sequence",
        ) < max(audit_sequences):
            raise ValidationFailure(
                "checkpoint v2: aggregate migration counter trails retained audit"
            )
        remember_fingerprint(
            retained_aggregate["aggregate_state_digest"],
            retained_aggregate["validated_bundle_fingerprint"],
        )
        identity_fingerprint = next(
            runtime
            for runtime in retained_aggregate["runtimes"]
            if runtime["relation"]["kind"] == "root"
        )["identity_origin"]["definition"]["validated_bundle_fingerprint"]
        remember_fingerprint(
            creation_receipt["resulting_aggregate_state_digest"],
            identity_fingerprint,
        )

    maintenance_operation_ids: set[str] = set()
    referenced_audit_sequences: list[str] = []
    for receipt in receipts:
        if receipt["operation_kind"] != "maintenance_migration":
            continue
        operation_id = receipt["operation_id"]
        if canonical_decimal(
            receipt["committed_revision"],
            "maintenance committed revision",
        ) == 0:
            raise ValidationFailure(
                "checkpoint v2: creation is the sole revision-zero receipt"
            )
        if operation_id in maintenance_operation_ids:
            raise ValidationFailure(
                "checkpoint v2: duplicate maintenance operation identity"
            )
        maintenance_operation_ids.add(operation_id)
        sequences_for_receipt = receipt["migration_sequences"]
        selected_audits = [
            audits_by_sequence.get(sequence) for sequence in sequences_for_receipt
        ]
        if any(item is None for item in selected_audits):
            raise ValidationFailure(
                "checkpoint v2: maintenance receipt has dangling audit"
            )
        selected = [item for item in selected_audits if item is not None]
        referenced_audit_sequences.extend(sequences_for_receipt)
        if receipt["result_code"] == "migration_no_operation":
            if (
                sequences_for_receipt
                or receipt["source_aggregate_state_digest"]
                != receipt["resulting_aggregate_state_digest"]
            ):
                raise ValidationFailure(
                    "checkpoint v2: malformed maintenance no-operation receipt"
                )
            target_fingerprint = receipt[
                "target_validated_bundle_fingerprint"
            ]
            candidate_fingerprints = fingerprints_by_aggregate_digest.get(
                receipt["source_aggregate_state_digest"], set()
            )
            if candidate_fingerprints and target_fingerprint not in candidate_fingerprints:
                raise ValidationFailure(
                    "checkpoint v2: historical no-operation identity is inconsistent"
                )
            descriptor_route: list[str] = []
        else:
            if not selected:
                raise ValidationFailure(
                    "checkpoint v2: applied maintenance receipt lacks audits"
                )
            if (
                [item["migration_sequence"] for item in selected]
                != sequences_for_receipt
                or any(
                    int(right["migration_sequence"])
                    != int(left["migration_sequence"]) + 1
                    for left, right in zip(selected, selected[1:])
                )
                or selected[0]["source_aggregate_state_digest"]
                != receipt["source_aggregate_state_digest"]
                or selected[-1]["target_aggregate_state_digest"]
                != receipt["resulting_aggregate_state_digest"]
                or any(
                    left["target_aggregate_state_digest"]
                    != right["source_aggregate_state_digest"]
                    for left, right in zip(selected, selected[1:])
                )
                or any(
                    left["target_validated_bundle_fingerprint"]
                    != right["source_validated_bundle_fingerprint"]
                    for left, right in zip(selected, selected[1:])
                )
            ):
                raise ValidationFailure(
                    "checkpoint v2: maintenance audit chain is inconsistent"
                )
            target_fingerprint = selected[-1][
                "target_validated_bundle_fingerprint"
            ]
            if receipt["target_validated_bundle_fingerprint"] != target_fingerprint:
                raise ValidationFailure(
                    "checkpoint v2: maintenance target identity is inconsistent"
                )
            descriptor_route = [
                item["migration_descriptor_digest"] for item in selected
            ]
        possible_request_digests = {
            hash_value(
                [
                    "determa-maintenance-migration-request-digest-2",
                    "2",
                    document["root_instance_id"],
                    operation_id,
                    receipt["source_aggregate_state_digest"],
                    target_fingerprint,
                    descriptor_route,
                    maintenance_mode,
                ]
            )
            for maintenance_mode in (False, True)
        }
        if receipt["request_digest"] not in possible_request_digests:
            raise ValidationFailure(
                "checkpoint v2: maintenance request digest is not canonical"
            )
    if len(referenced_audit_sequences) != len(set(referenced_audit_sequences)):
        raise ValidationFailure(
            "checkpoint v2: maintenance audit ownership is inconsistent"
        )
    if terminal_outbox_sequences & tombstone_outbox_sequences:
        raise ValidationFailure("checkpoint v2: outbox terminal sequence overlap")
    next_terminal = canonical_decimal(
        document["next_outbox_terminal_sequence"], "next outbox terminal sequence"
    )
    if terminal_outbox_sequences | tombstone_outbox_sequences:
        if max(terminal_outbox_sequences | tombstone_outbox_sequences) >= next_terminal:
            raise ValidationFailure("checkpoint v2: outbox terminal counter regression")
    full_intent_sequences = pending_intent_sequences + [
        canonical_decimal(item["intent"]["sequence"], "terminal outbox intent sequence")
        for item in document["terminal_outbox_records"]
    ]
    if len(full_intent_sequences) != len(set(full_intent_sequences)):
        raise ValidationFailure("checkpoint v2: outbox intent sequence overlap")
    effect_ids = [
        item["intent"]["effect_id"]
        for item in document["pending_outbox_intents"]
    ]
    effect_ids += [
        item["intent"]["effect_id"]
        for item in document["terminal_outbox_records"]
    ]
    effect_ids += [item["effect_id"] for item in document["outbox_effect_tombstones"]]
    if len(effect_ids) != len(set(effect_ids)):
        raise ValidationFailure("checkpoint v2: outbox effect identity overlap")
    if len(audit_sequences) != len(document["migration_audit_records"]):
        raise ValidationFailure("checkpoint v2: duplicate migration audit sequence")

    acceptance_list = [receipt for receipt in receipts if receipt["operation_kind"] == "acceptance"]
    acceptance_receipts: dict[str, dict[str, Any]] = {}
    acceptance_sequences: set[str] = set()
    for receipt in acceptance_list:
        if receipt["event_id"] in acceptance_receipts or receipt["acceptance_sequence"] in acceptance_sequences:
            raise ValidationFailure("checkpoint v2: duplicate acceptance receipt identity")
        acceptance_receipts[receipt["event_id"]] = receipt
        acceptance_sequences.add(receipt["acceptance_sequence"])
    terminal_list = [receipt for receipt in receipts if receipt["operation_kind"] == "event_terminal"]
    terminal_receipts: dict[str, dict[str, Any]] = {}
    terminal_acceptance_sequences: set[str] = set()
    for receipt in terminal_list:
        if receipt["event_id"] in terminal_receipts or receipt["acceptance_sequence"] in terminal_acceptance_sequences:
            raise ValidationFailure("checkpoint v2: duplicate terminal event identity")
        terminal_receipts[receipt["event_id"]] = receipt
        terminal_acceptance_sequences.add(receipt["acceptance_sequence"])
    tombstone_list = document["event_identity_tombstones"]
    tombstone_order = [
        canonical_decimal(item["terminal_receipt_sequence"], "tombstone terminal receipt sequence")
        for item in tombstone_list
    ]
    if tombstone_order != sorted(tombstone_order) or len(tombstone_order) != len(set(tombstone_order)):
        raise ValidationFailure("checkpoint v2: event tombstone order is invalid")
    tombstones: dict[str, dict[str, Any]] = {}
    tombstone_acceptance_sequences: set[str] = set()
    for item in tombstone_list:
        if item["event_id"] in tombstones or item["acceptance_sequence"] in tombstone_acceptance_sequences:
            raise ValidationFailure("checkpoint v2: duplicate event tombstone identity")
        tombstones[item["event_id"]] = item
        tombstone_acceptance_sequences.add(item["acceptance_sequence"])
    if terminal_acceptance_sequences & tombstone_acceptance_sequences:
        raise ValidationFailure(
            "checkpoint v2: terminal and tombstone acceptance allocations overlap"
        )
    if mailbox_acceptance_sequences & (
        terminal_acceptance_sequences
        | tombstone_acceptance_sequences
    ):
        raise ValidationFailure(
            "checkpoint v2: live and terminal acceptance allocations overlap"
        )
    for sequence in acceptance_sequences & terminal_acceptance_sequences:
        acceptance_event = next(
            event_id
            for event_id, receipt in acceptance_receipts.items()
            if receipt["acceptance_sequence"] == sequence
        )
        terminal_event = next(
            event_id
            for event_id, receipt in terminal_receipts.items()
            if receipt["acceptance_sequence"] == sequence
        )
        if acceptance_event != terminal_event:
            raise ValidationFailure(
                "checkpoint v2: acceptance allocation names conflicting events"
            )
    if acceptance_sequences & tombstone_acceptance_sequences:
        raise ValidationFailure(
            "checkpoint v2: acceptance receipt overlaps replacement tombstone allocation"
        )
    mailbox_event_ids = set(mailbox_entries)
    if mailbox_event_ids & terminal_receipts.keys():
        raise ValidationFailure("checkpoint v2: event is live and terminal")
    if mailbox_event_ids & tombstones.keys() or terminal_receipts.keys() & tombstones.keys():
        raise ValidationFailure("checkpoint v2: event overlaps tombstone")
    if acceptance_receipts.keys() & tombstones.keys():
        raise ValidationFailure("checkpoint v2: acceptance receipt overlaps replacement tombstone")
    next_receipt = canonical_decimal(
        document["next_operation_receipt_sequence"], "next receipt sequence"
    )
    if any(sequence >= next_receipt for sequence in tombstone_order):
        raise ValidationFailure("checkpoint v2: tombstone receipt counter regression")
    if root_record["status"] == "retained":
        next_acceptance = canonical_decimal(
            root_record["aggregate_state"]["next_acceptance_sequence"],
            "next acceptance sequence",
        )
        retained_acceptance_allocations = [
            canonical_decimal(value, "retained acceptance sequence")
            for value in (
                list(acceptance_sequences)
                + list(terminal_acceptance_sequences)
                + list(tombstone_acceptance_sequences)
            )
        ]
        if retained_acceptance_allocations and max(retained_acceptance_allocations) >= next_acceptance:
            raise ValidationFailure("checkpoint v2: acceptance counter regression")
    producer_references: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    referenced_effects: set[str] = set()
    for producer in receipts:
        for reference in producer.get("emission_references", []):
            if reference.get("kind") in {"internal_mailbox", "internal_terminal"}:
                producer_references.setdefault(reference["event_id"], []).append((producer, reference))
            elif reference.get("kind") == "external_outbox":
                referenced_effects.add(reference["effect_id"])

    available_effects = set(effect_ids)
    if not referenced_effects.issubset(available_effects):
        raise ValidationFailure("checkpoint v2: outbox emission reference is dangling")
    if (
        document["replay_retention"]["mode"] == "permanent"
        and available_effects != referenced_effects
    ):
        raise ValidationFailure("checkpoint v2: permanent outbox record lacks producer")

    def validate_producer(event_id: str, entry: dict[str, Any] | None, terminal: dict[str, Any] | None) -> None:
        matches = producer_references.get(event_id, [])
        if len(matches) != 1:
            raise ValidationFailure("checkpoint v2: internal event producer is not unique")
        producer, reference = matches[0]
        if entry is not None:
            if reference["kind"] != "internal_mailbox" or reference["acceptance_sequence"] != entry["acceptance_sequence"] or reference["queue_sequence"] != entry["queue_sequence"]:
                raise ValidationFailure("checkpoint v2: internal mailbox producer mismatch")
        else:
            assert terminal is not None
            if reference["kind"] != "internal_terminal" or reference["acceptance_sequence"] != terminal["acceptance_sequence"] or reference["terminal_receipt_sequence"] != terminal["receipt_sequence"]:
                raise ValidationFailure("checkpoint v2: internal terminal producer mismatch")
            producer_revision = producer.get("committed_revision")
            if (
                producer_revision is not None
                and canonical_decimal(
                    terminal["committed_revision"],
                    "checkpoint v2 internal terminal revision",
                )
                < canonical_decimal(
                    producer_revision,
                    "checkpoint v2 producer committed revision",
                )
            ):
                raise ValidationFailure(
                    "checkpoint v2: internal terminal precedes its producer"
                )

    for event_id, entry in mailbox_entries.items():
        source = entry["envelope"]["source"]
        receipt = acceptance_receipts.get(event_id)
        requires_acceptance = "host" in source
        if requires_acceptance:
            if receipt is None:
                raise ValidationFailure("checkpoint v2: accepted mailbox event lacks receipt")
            if receipt["request_digest"] != entry["envelope_digest"] or receipt["acceptance_sequence"] != entry["acceptance_sequence"] or receipt["delivery_mode"] != entry["delivery_mode"]:
                raise ValidationFailure("checkpoint v2: mailbox acceptance identity mismatch")
        else:
            if receipt is not None:
                raise ValidationFailure("checkpoint v2: native internal event has host acceptance receipt")
            validate_producer(event_id, entry, None)
    for event_id, terminal in terminal_receipts.items():
        acceptance = acceptance_receipts.get(event_id)
        if acceptance is not None:
            if acceptance["request_digest"] != terminal["request_digest"] or acceptance["acceptance_sequence"] != terminal["acceptance_sequence"]:
                raise ValidationFailure("checkpoint v2: terminal identity mismatch")
            if (
                canonical_decimal(
                    terminal["committed_revision"],
                    "checkpoint v2 terminal committed revision",
                )
                < canonical_decimal(
                    acceptance["accepted_revision"],
                    "checkpoint v2 acceptance revision",
                )
                or canonical_decimal(
                    terminal["receipt_sequence"],
                    "checkpoint v2 terminal receipt sequence",
                )
                <= canonical_decimal(
                    acceptance["receipt_sequence"],
                    "checkpoint v2 acceptance receipt sequence",
                )
            ):
                raise ValidationFailure(
                    "checkpoint v2: terminal evidence precedes acceptance"
                )
        else:
            references = producer_references.get(event_id, [])
            producer_was_attested_pruned = (
                not references
                and pruning_cutoff is not None
                and canonical_decimal(
                    pruning_cutoff, "checkpoint pruning cutoff"
                )
                < canonical_decimal(
                    terminal["receipt_sequence"],
                    "checkpoint v2 internal terminal receipt sequence",
                )
            )
            if not producer_was_attested_pruned:
                validate_producer(event_id, None, terminal)
    located = (
        mailbox_event_ids
        | set(terminal_receipts)
        | set(tombstones)
    )
    if set(acceptance_receipts) - located:
        raise ValidationFailure("checkpoint v2: orphan acceptance receipt")
    for event_id, references in producer_references.items():
        if event_id not in located:
            raise ValidationFailure("checkpoint v2: orphan internal producer reference")
        if len(references) != 1:
            raise ValidationFailure("checkpoint v2: duplicate internal producer reference")


def artifact_error(
    kind: str,
    document: Any,
    validator: Draft202012Validator,
) -> str | None:
    if kind == "json_value":
        return None
    if kind in DRIVER_ARTIFACT_KINDS:
        if next(validator.iter_errors(document), None) is not None:
            return f"invalid_{kind}"
        return None
    (
        format_field,
        expected_format,
        version_field,
        expected_version,
        format_error,
        version_error,
        structural_error,
    ) = ARTIFACT_FORMAT_FIELDS[kind]
    if not isinstance(document, dict):
        return structural_error
    if document.get(format_field) != expected_format:
        return format_error
    if document.get(version_field) != expected_version:
        return version_error
    if next(validator.iter_errors(document), None) is not None:
        return structural_error
    if kind == "aggregate_state_v2":
        try:
            validate_aggregate_v2_semantics(document)
        except ValidationFailure:
            return structural_error
    if kind == "migration_descriptor_v2":
        selectors = [
            (rule["machine_id"], rule["event"], rule["delivery_mode"])
            for rule in document["queued_event_rules"]
        ]
        if len(selectors) != len(set(selectors)):
            return structural_error
    if kind == "core_step_result_v2":
        try:
            validate_aggregate_v2_semantics(document["state"])
            validate_core_step_v2_semantics(document)
        except ValidationFailure:
            return structural_error
    if kind == "execution_checkpoint_v2":
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            try:
                verify_artifact_digest(
                    "aggregate_state_v2",
                    root_record["aggregate_state"],
                    Path("<embedded aggregate>"),
                )
            except ValidationFailure:
                return structural_error
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        expected_digest = hash_value(
            [
                "determa-execution-checkpoint-digest-2",
                without_digest,
            ]
        )
        if document["execution_checkpoint_digest"] != expected_digest:
            return "execution_checkpoint_digest_mismatch"
        try:
            validate_execution_checkpoint_v2_semantics(document)
        except ValidationFailure:
            return structural_error
    return None


def yaml_loader() -> YAML:
    loader = YAML(typ="safe")
    loader.version = (1, 2)
    loader.allow_duplicate_keys = False
    return loader


def unicode_error(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def parsed_value_error(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                return "non_string_map_key"
            if unicode_error(key):
                return "invalid_unicode"
            error = parsed_value_error(child)
            if error:
                return error
    elif isinstance(value, list):
        for child in value:
            error = parsed_value_error(child)
            if error:
                return error
    elif isinstance(value, str):
        if unicode_error(value):
            return "invalid_unicode"
    elif isinstance(value, bool) or value is None:
        pass
    elif isinstance(value, int):
        if not MINIMUM_INTEGER <= value <= MAXIMUM_INTEGER:
            return "numeric_value_out_of_range"
    elif isinstance(value, float):
        if not math.isfinite(value):
            return "numeric_value_out_of_range"
    else:
        return "non_json_value"
    return None


def analyze_source(path: Path) -> SourceAnalysis:
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return SourceAnalysis("invalid_unicode", None)

    loader = yaml_loader()
    try:
        tokens = list(loader.scan(source))
    except YAMLError as error:
        raise ValidationFailure(f"{path}: invalid YAML source: {error}") from error

    for token in tokens:
        if isinstance(token, (AliasToken, AnchorToken, TagToken)):
            return SourceAnalysis("unsupported_yaml_feature", None)

    for token in tokens:
        if not isinstance(token, ScalarToken) or token.style is not None:
            continue
        if token.value in INVALID_BOOLEAN_SCALARS:
            return SourceAnalysis("invalid_boolean_syntax", None)
        if token.value in INVALID_NULL_SCALARS:
            return SourceAnalysis("invalid_null_syntax", None)
        if (
            NUMERIC_CANDIDATE.fullmatch(token.value)
            or token.value.lower() in SPECIAL_NUMERIC_SCALARS
        ) and not JSON_NUMBER.fullmatch(token.value):
            return SourceAnalysis("invalid_numeric_syntax", None)

    value_start_tokens = (
        ScalarToken,
        BlockMappingStartToken,
        BlockSequenceStartToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
    )
    for index, token in enumerate(tokens):
        if isinstance(token, (ValueToken, BlockEntryToken)) and (
            index + 1 == len(tokens)
            or not isinstance(tokens[index + 1], value_start_tokens)
        ):
            return SourceAnalysis("invalid_null_syntax", None)

    try:
        document = loader.load(source)
    except DuplicateKeyError:
        return SourceAnalysis("duplicate_key", None)
    except YAMLError as error:
        raise ValidationFailure(f"{path}: YAML construction failed: {error}") from error

    return SourceAnalysis(parsed_value_error(document), document)


def load_fixture_document(path: Path) -> dict[str, Any]:
    analysis = analyze_source(path)
    if analysis.error:
        raise ValidationFailure(f"{path}: unexpected {analysis.error}")
    if not isinstance(analysis.document, dict):
        raise ValidationFailure(f"{path}: expected a document map")
    return analysis.document


def validate_driver_markers(value: Any, location: str) -> None:
    if isinstance(value, dict):
        if set(value) == {"non_finite_double"}:
            if value["non_finite_double"] not in NON_FINITE_DOUBLE_MARKERS:
                raise ValidationFailure(f"{location}: invalid non_finite_double marker")
            return
        if set(value) == {"normalized_double"}:
            if value["normalized_double"] != "positive_zero":
                raise ValidationFailure(f"{location}: invalid normalized_double assertion")
            return
        for key, child in value.items():
            validate_driver_markers(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_driver_markers(child, f"{location}[{index}]")


def validate_driver_target(value: Any, location: str) -> None:
    if value == "root":
        return
    if not isinstance(value, dict) or len(value) != 1:
        raise ValidationFailure(f"{location}: invalid target selector")
    kind, identity = next(iter(value.items()))
    if kind not in {"bound_instance", "component"}:
        raise ValidationFailure(f"{location}: unsupported target selector {kind!r}")
    if not isinstance(identity, str) or not identity:
        raise ValidationFailure(f"{location}: target selector needs a non-empty name")


def validate_deliver_replace(value: Any, location: str) -> None:
    if not isinstance(value, dict) or not value:
        raise ValidationFailure(f"{location}: replace must be a non-empty map")
    unknown = set(value) - {"payload", "target", "spawned_instance_reference"}
    if unknown:
        raise ValidationFailure(
            f"{location}: unsupported replacement field {sorted(unknown)[0]}"
        )
    if "payload" in value and not isinstance(value["payload"], dict):
        raise ValidationFailure(f"{location}.payload: replacement must be a map")
    if "target" in value:
        validate_driver_target(value["target"], f"{location}.target")
    if "spawned_instance_reference" in value:
        replacement = value["spawned_instance_reference"]
        if not isinstance(replacement, dict) or not replacement:
            raise ValidationFailure(
                f"{location}.spawned_instance_reference: expected non-empty map"
            )
        unknown_reference = set(replacement) - INSTANCE_REFERENCE_FIELDS
        if unknown_reference:
            raise ValidationFailure(
                f"{location}.spawned_instance_reference: unsupported field "
                f"{sorted(unknown_reference)[0]}"
            )
        for name, field_value in replacement.items():
            if name == "machine_version":
                if (
                    isinstance(field_value, bool)
                    or not isinstance(field_value, int)
                    or field_value < 1
                ):
                    raise ValidationFailure(
                        f"{location}.spawned_instance_reference.machine_version: "
                        "expected positive integer"
                    )
            elif not isinstance(field_value, str) or not field_value:
                raise ValidationFailure(
                    f"{location}.spawned_instance_reference.{name}: "
                    "expected non-empty string"
                )


def validate_inspect(value: Any, location: str) -> None:
    if not isinstance(value, dict) or set(value) != {"corrupt_prior_state"}:
        raise ValidationFailure(f"{location}: unsupported inspect operation")
    mutation = value["corrupt_prior_state"]
    required = {"runtime", "variable", "path", "value"}
    if not isinstance(mutation, dict) or set(mutation) != required:
        raise ValidationFailure(f"{location}.corrupt_prior_state: malformed mutation")
    if mutation["runtime"] != "root":
        raise ValidationFailure(
            f"{location}.corrupt_prior_state.runtime: only root is supported"
        )
    if not isinstance(mutation["variable"], str) or not mutation["variable"]:
        raise ValidationFailure(
            f"{location}.corrupt_prior_state.variable: expected non-empty name"
        )
    path = mutation["path"]
    if not isinstance(path, list) or not path:
        raise ValidationFailure(
            f"{location}.corrupt_prior_state.path: expected non-empty list"
        )
    for part in path:
        valid_index = (
            isinstance(part, int) and not isinstance(part, bool) and part >= 0
        )
        if not valid_index and (not isinstance(part, str) or not part):
            raise ValidationFailure(
                f"{location}.corrupt_prior_state.path: invalid path member {part!r}"
            )


def exact_case_file(case: Path, filename: Any) -> Path:
    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or not filename.endswith(".yaml")
        or filename == "test.yaml"
    ):
        raise ValidationFailure(f"{case.name}: invalid bundle filename {filename!r}")
    path = case / filename
    if not path.is_file():
        raise ValidationFailure(f"{case.name}: missing referenced bundle {filename}")
    return path


def exact_artifact_file(case: Path, filename: Any) -> Path:
    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or not filename.endswith(".json")
    ):
        raise ValidationFailure(f"{case.name}: invalid artifact filename {filename!r}")
    path = case / filename
    if not path.is_file():
        raise ValidationFailure(f"{case.name}: missing referenced artifact {filename}")
    return path


def artifact_entries(
    case: Path,
    test: dict[str, Any],
    artifact_validators: dict[str, Draft202012Validator],
) -> set[Path]:
    manifest = test.get("artifacts")
    if not isinstance(manifest, dict) or set(manifest) != {"documents"}:
        raise ValidationFailure(f"{case.name}: malformed artifacts manifest")
    documents = manifest["documents"]
    if not isinstance(documents, list) or not documents:
        raise ValidationFailure(f"{case.name}: empty artifacts manifest")

    referenced: set[Path] = set()
    by_name: dict[str, tuple[str, Any, bytes]] = {}
    canonical_pairs: list[tuple[Path, str]] = []
    for entry in documents:
        if not isinstance(entry, dict):
            raise ValidationFailure(f"{case.name}: artifact entry must be a map")
        unknown = set(entry) - {
            "file",
            "kind",
            "valid",
            "error",
            "canonical_of",
            "verify_digest",
            "semantic_probe",
            "semantic_source",
            "semantic_expected",
            "semantic_input_file",
            "semantic_input_pointer",
        }
        if unknown:
            raise ValidationFailure(
                f"{case.name}: unsupported artifact field {sorted(unknown)[0]}"
            )
        path = exact_artifact_file(case, entry.get("file"))
        if path in referenced:
            raise ValidationFailure(f"{case.name}: duplicate artifact {path.name}")
        referenced.add(path)
        kind = entry.get("kind")
        if kind not in {*ARTIFACT_KINDS, *DRIVER_ARTIFACT_KINDS, "json_value"}:
            raise ValidationFailure(f"{case.name}: invalid artifact kind {kind!r}")
        if not isinstance(entry.get("valid"), bool):
            raise ValidationFailure(f"{case.name}: artifact needs Boolean valid")
        expected_error = entry.get("error")
        if entry["valid"] and expected_error is not None:
            raise ValidationFailure(f"{case.name}: valid artifact cannot declare error")
        if not entry["valid"] and (
            not isinstance(expected_error, str) or not expected_error
        ):
            raise ValidationFailure(f"{case.name}: invalid artifact needs exact error")

        analysis = analyze_artifact(path)
        actual_error = analysis.error
        if actual_error is None:
            validator = artifact_validators.get(kind)
            actual_error = artifact_error(kind, analysis.document, validator) if validator else None
        if entry["valid"]:
            if actual_error is not None:
                raise ValidationFailure(
                    f"{path}: expected valid artifact, got {actual_error}"
                )
            if kind in ARTIFACT_KINDS and entry.get("verify_digest", True):
                verify_artifact_digest(kind, analysis.document, path)
        elif entry.get("semantic_probe") is not None:
            if (
                actual_error is not None
                or expected_error != "invalid_execution_checkpoint"
                or kind != "execution_checkpoint"
            ):
                raise ValidationFailure(
                    f"{path}: malformed relational semantic probe"
                )
        elif actual_error != expected_error:
            raise ValidationFailure(
                f"{path}: expected {expected_error}, got {actual_error or 'valid'}"
            )

        if actual_error is None:
            by_name[path.name] = (kind, analysis.document, analysis.source)
        canonical_of = entry.get("canonical_of")
        if canonical_of is not None:
            if not entry["valid"]:
                raise ValidationFailure(
                    f"{case.name}: invalid artifact cannot be canonical"
                )
            canonical_pairs.append((path, canonical_of))

    for canonical_path, source_name in canonical_pairs:
        source = by_name.get(source_name)
        if source is None:
            raise ValidationFailure(
                f"{case.name}: canonical source {source_name!r} is not a valid artifact"
            )
        canonical = by_name[canonical_path.name]
        if canonical[0] != source[0] or canonical[1] != source[1]:
            raise ValidationFailure(
                f"{canonical_path}: canonical and readable artifacts differ"
            )
        expected_bytes = canonical_json_bytes(source[1])
        if canonical[2] != expected_bytes:
            raise ValidationFailure(
                f"{canonical_path}: bytes are not exact RFC 8785 output"
            )
    return referenced


def validate_fixture_schema(
    test: dict[str, Any],
    validator: Draft202012Validator,
    case: Path,
) -> None:
    errors = sorted(
        validator.iter_errors(test),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        first = errors[0]
        raise ValidationFailure(
            f"{case.name}/test.yaml: invalid persistence fixture at "
            f"{list(first.path)}: {first.message}"
        )


def validate_direct_descriptor_expectation(
    location: str,
    expectation: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    if manifest["valid"]:
        required_expectation = {"result": "success"}
    else:
        manifest_error = manifest["error"]
        decoder_error = (
            "invalid_migration_descriptor"
            if manifest_error in ARTIFACT_SOURCE_ERROR_CODES
            else manifest_error
        )
        required_expectation = {"result": "failure", "code": decoder_error}
    if expectation != required_expectation:
        raise ValidationFailure(
            f"{location}: selected descriptor requires expectation "
            f"{required_expectation}"
        )


def validate_direct_descriptor_expectation_probes() -> None:
    valid_manifest = {"valid": True}
    invalid_manifest = {
        "valid": False,
        "error": "unsupported_migration_descriptor_format",
    }
    validate_direct_descriptor_expectation(
        "valid success probe", {"result": "success"}, valid_manifest
    )
    validate_direct_descriptor_expectation(
        "invalid exact failure probe",
        {
            "result": "failure",
            "code": "unsupported_migration_descriptor_format",
        },
        invalid_manifest,
    )
    rejected_probes = (
        (
            "valid failure probe",
            {
                "result": "failure",
                "code": "unsupported_migration_descriptor_format",
            },
            valid_manifest,
        ),
        ("invalid success probe", {"result": "success"}, invalid_manifest),
    )
    for name, expectation, manifest in rejected_probes:
        try:
            validate_direct_descriptor_expectation(name, expectation, manifest)
        except ValidationFailure:
            continue
        raise ValidationFailure(f"{name}: adversarial expectation was accepted")


def validate_operation_input_schema_probes(
    validator: Draft202012Validator,
) -> None:
    digest = "sha256:" + "0" * 64
    bundle = {
        "bundle_file": "machine.yaml",
        "bundle_source_digest": digest,
        "validated_bundle_fingerprint": digest,
    }
    migration = {
        "operation": "migrate_aggregate_v2",
        "source_bundle": bundle,
        "target_bundle": bundle,
        "migration_descriptor_files": [],
        "migration_descriptor_digest_route": [],
        "maintenance_mode": False,
    }

    valid_probes = [
        migration,
        {
            key: value
            for key, value in migration.items()
            if key != "maintenance_mode"
        },
    ]
    invalid_mode_probe = copy.deepcopy(migration)
    invalid_mode_probe["maintenance_mode"] = "not-a-boolean"
    valid_probes.append(invalid_mode_probe)
    for index, probe in enumerate(valid_probes):
        if not validator.is_valid({"probe": probe}):
            raise ValidationFailure(
                f"operation-input schema rejected semantic migration probe {index}"
            )

    arbitrary_mode = copy.deepcopy(migration)
    arbitrary_mode["maintenance_mode"] = "false"
    unrelated_operation = {
        "operation": "create_v2",
        "bundle": bundle,
        "machine_id": "machine",
        "machine_version": "1",
        "root_instance_id": "root",
        "creation_id": "creation",
        "bindings": {"input": {}, "external": {}},
        "maintenance_mode": "not-a-boolean",
    }
    for index, probe in enumerate((arbitrary_mode, unrelated_operation)):
        if validator.is_valid({"probe": probe}):
            raise ValidationFailure(
                f"operation-input schema accepted permissive request probe {index}"
            )


def validate_version2_vectors(
    case: Path,
    test: dict[str, Any],
    bundle_paths: set[Path],
    artifact_paths: set[Path],
    *,
    artifact_overrides: dict[str, Any] | None = None,
) -> set[str]:
    """Validate the closed language-neutral version-2 operation table."""
    bundle_names = {path.name for path in bundle_paths}
    artifact_names = {path.name for path in artifact_paths}
    manifests = {
        entry["file"]: entry for entry in test["artifacts"]["documents"]
    }
    coverage: set[str] = set()
    names: set[str] = set()
    artifact_overrides = artifact_overrides or {}

    def artifact(filename: str) -> ArtifactAnalysis:
        if filename not in artifact_overrides:
            return analyze_artifact(case / filename)
        document = artifact_overrides[filename]
        return ArtifactAnalysis(None, document, canonical_json_bytes(document))

    state_operations = {
        "round_trip_aggregate_v2",
        "admit_v2",
        "step_v2",
        "migrate_aggregate_v2",
        "migrate_then_process_v2",
    }
    package_operations = {"restore_package_v2"}
    checkpoint_operations = {
        "checkpoint_migrate_v2",
    }
    descriptor_operations = {
        "migrate_aggregate_v2",
        "migrate_then_process_v2",
        "checkpoint_migrate_v2",
    }
    core_admission_rejection_codes = {
        "malformed_delivery",
        "duplicate_event_id_in_batch",
        "event_id_conflict",
        "invalid_delivery_mode",
        "invalid_delivery_source",
        "invalid_instance_target",
        "inactive_component_target",
        "invalid_event",
        "invalid_payload",
        "invalid_correlation",
        "delivery_digest_mismatch",
    }
    aggregate_artifact_failure_codes = {
        "unsupported_aggregate_state_format",
        "unsupported_aggregate_state_schema_version",
        "invalid_aggregate_state",
        "aggregate_state_digest_mismatch",
    }
    checkpoint_artifact_failure_codes = {
        "unsupported_execution_checkpoint_format",
        "unsupported_execution_checkpoint_schema_version",
        "invalid_execution_checkpoint",
        "execution_checkpoint_digest_mismatch",
    }
    migration_failure_codes = {
        "invalid_aggregate_state",
        "invalid_aggregate_state_package",
        "definition_fingerprint_mismatch",
        "definition_untrusted",
        "invalid_migration_request",
        "source_definition_unavailable",
        "target_definition_unavailable",
        "migration_descriptor_untrusted",
        "invalid_migration_descriptor",
        "migration_route_missing",
        "migration_route_mismatch",
        "migration_transform_fault",
        "migration_totality_failure",
        "migration_resource_limit_exceeded",
        "terminal_migration_requires_maintenance",
        "terminal_migration_rejected",
        "unsupported_aggregate_state_format",
        "unsupported_aggregate_state_schema_version",
        "unsupported_migration_descriptor_format",
        "unsupported_migration_descriptor_schema_version",
    }
    operation_failure_codes = {
        "create_v2": {
            "invalid_creation_request",
            "invalid_machine_target",
            "invalid_binding",
        },
        "round_trip_aggregate_v2": aggregate_artifact_failure_codes
        | {
            "source_definition_unavailable",
            "definition_fingerprint_mismatch",
            "definition_untrusted",
        },
        "restore_package_v2": migration_failure_codes
        | {
            "aggregate_state_digest_mismatch",
            "unsupported_aggregate_state_package_format",
            "unsupported_aggregate_state_package_schema_version",
        },
        "admit_v2": core_admission_rejection_codes
        | aggregate_artifact_failure_codes,
        "step_v2": aggregate_artifact_failure_codes,
        "migrate_aggregate_v2": migration_failure_codes,
        "migrate_then_process_v2": migration_failure_codes
        | core_admission_rejection_codes,
        "checkpoint_migrate_v2": checkpoint_artifact_failure_codes
        | migration_failure_codes
        | {"checkpoint_revision_conflict", "operation_id_conflict"},
    }
    declared_version2_operations = set(
        json.loads(
            (
                Path(__file__).resolve().parent
                / "schemas/version2-vectors.schema.json"
            ).read_text(encoding="utf-8")
        )["$defs"]["vector"]["properties"]["operation"]["enum"]
    )
    if set(operation_failure_codes) != declared_version2_operations:
        raise ValidationFailure(
            "version-2 operation failure vocabulary is not total"
        )

    def require_allowed_operation_failure_code(operation: str, code: str) -> None:
        if code not in operation_failure_codes[operation]:
            raise ValidationFailure(
                f"rejection code {code} is not allowed for {operation}"
            )


    def aggregate_from_vector(vector: dict[str, Any]) -> dict[str, Any] | None:
        filename = vector.get("state_before")
        if filename is not None:
            return artifact(filename).document
        filename = vector.get("checkpoint_before")
        if filename is None:
            return None
        checkpoint = artifact(filename).document
        root_record = checkpoint["root_record"]
        return root_record.get("aggregate_state") if root_record["status"] == "retained" else None

    def target_runtime(aggregate: dict[str, Any], runtime_id: str) -> dict[str, Any] | None:
        return next((runtime for runtime in aggregate["runtimes"] if runtime["runtime_id"] == runtime_id), None)

    def delivery_validation_error(
        delivery: dict[str, Any], aggregate_or_root: dict[str, Any] | str, location: str
    ) -> str | None:
        if delivery["delivery_mode"] not in {"input", "internal"}:
            return "invalid_delivery_mode"
        validate_typed_value_canonical(
            delivery["envelope"]["payload"], f"{location}: delivery payload"
        )
        digest_domain = delivery.get(
            "request_digest_domain", "determa-inbox-envelope-digest-2"
        )
        digest_version = "1" if digest_domain.endswith("-1") else "2"
        root_instance_id = (
            aggregate_or_root["root_instance_id"]
            if isinstance(aggregate_or_root, dict)
            else aggregate_or_root
        )
        expected = hash_value([
            digest_domain, digest_version, root_instance_id,
            delivery["delivery_mode"], delivery["envelope"],
        ])
        if delivery["envelope_digest"] != expected:
            return "delivery_digest_mismatch"
        return None


    def aggregate_has_conflicting_identity(
        aggregate: dict[str, Any], delivery: dict[str, Any]
    ) -> bool:
        event_id = delivery["envelope"]["event_id"]
        digest = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                aggregate["root_instance_id"],
                delivery["delivery_mode"],
                delivery["envelope"],
            ]
        )
        return any(
            entry["envelope"]["event_id"] == event_id
            and entry["envelope_digest"] != digest
            for runtime in aggregate["runtimes"]
            for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
            for entry in mailbox
        )


    def delivery_contract_error(
        delivery: dict[str, Any],
        aggregate: dict[str, Any],
        bundle_path: Path,
        *,
        checkpoint_host: bool,
    ) -> str | None:
        envelope = delivery["envelope"]
        root = next(
            runtime
            for runtime in aggregate["runtimes"]
            if runtime["relation"]["kind"] == "root"
        )
        runtime = next(
            (
                item
                for item in aggregate["runtimes"]
                if item["target_identity"] == envelope["target"]
            ),
            None,
        )
        if runtime is None:
            return "invalid_instance_target"
        if root["status"] != "running":
            return (
                "terminal_root"
                if checkpoint_host and runtime["relation"]["kind"] == "root"
                else "invalid_instance_target"
            )
        if runtime["relation"]["kind"] == "component":
            if runtime["status"] != "running":
                return "inactive_component_target"
            if delivery["delivery_mode"] == "input":
                return "invalid_instance_target"
        elif runtime["status"] != "running":
            return "invalid_instance_target"

        bundle = normalized_bundle_value(bundle_path)
        machine_identity = runtime["current_definition"]["machine"]
        machine = next(
            (
                item
                for item in bundle["machines"]
                if item["machine_id"] == machine_identity["machine_id"]
                and str(item["version"]) == machine_identity["machine_version"]
            ),
            None,
        )
        if machine is None:
            return "invalid_instance_target"
        def value_matches_type(value: Any, expected_type: str) -> bool:
            return {
                "string": isinstance(value, str),
                "int": isinstance(value, int) and not isinstance(value, bool),
                "float": isinstance(value, (int, float))
                and not isinstance(value, bool),
                "bool": isinstance(value, bool),
                "map": isinstance(value, dict),
                "list": isinstance(value, list),
            }[expected_type]

        if delivery["delivery_mode"] == "input":
            if envelope["source"] != {"host": True} or envelope["cause_id"] != envelope["event_id"]:
                return "invalid_delivery_source"

        reserved_event = envelope["event"]
        if reserved_event in {
            "done",
            "determa.component_completed",
            "determa.component_failed",
            "determa.spawned_instance_failed",
        }:
            if delivery["delivery_mode"] != "internal" or "host" in envelope["source"]:
                return "invalid_event"
            payload = decode_typed_value(envelope["payload"])
            if not isinstance(payload, dict):
                return "invalid_payload"
            public_fault_fields = {
                "runtime_id",
                "cause_id",
                "code",
                "step_sequence",
                "source_locator",
            }
            if reserved_event == "determa.component_completed":
                valid = set(payload) == {"component_id", "component_runtime_id"} and all(
                    isinstance(payload[field], str) for field in payload
                )
            elif reserved_event == "determa.component_failed":
                fault = payload.get("fault")
                valid = (
                    set(payload) == {"component_id", "component_runtime_id", "fault"}
                    and isinstance(payload.get("component_id"), str)
                    and isinstance(payload.get("component_runtime_id"), str)
                    and isinstance(fault, dict)
                    and set(fault) == public_fault_fields
                    and all(isinstance(fault[field], str) for field in fault)
                )
            elif reserved_event == "determa.spawned_instance_failed":
                fault = payload.get("fault")
                valid = (
                    set(payload) == {"instance", "instance_id", "machine_id", "machine_version", "fault"}
                    and isinstance(payload.get("instance"), dict)
                    and isinstance(payload.get("instance_id"), str)
                    and isinstance(payload.get("machine_id"), str)
                    and isinstance(payload.get("machine_version"), int)
                    and not isinstance(payload.get("machine_version"), bool)
                    and isinstance(fault, dict)
                    and set(fault) == public_fault_fields
                    and all(isinstance(fault[field], str) for field in fault)
                )
            elif payload.get("relationship") == "parallel":
                valid = set(payload) == {"relationship", "state_path", "owner_runtime_id"} and all(
                    isinstance(payload[field], str) for field in payload
                )
            elif payload.get("relationship") == "spawned_instance":
                valid = (
                    set(payload) == {"relationship", "instance", "instance_id", "machine_id", "machine_version"}
                    and isinstance(payload.get("instance"), dict)
                    and isinstance(payload.get("instance_id"), str)
                    and isinstance(payload.get("machine_id"), str)
                    and isinstance(payload.get("machine_version"), int)
                    and not isinstance(payload.get("machine_version"), bool)
                )
            else:
                valid = False
            return None if valid else "invalid_payload"

        declaration = bundle.get("events", {}).get(envelope["event"])
        if declaration is None:
            declaration = machine.get("events", {}).get(envelope["event"])
        if envelope["event"] == "env":
            if "correlation_id" in envelope:
                return "invalid_correlation"
            payload = decode_typed_value(envelope["payload"])
            changed = payload.get("changed") if isinstance(payload, dict) else None
            external_variables = {
                name: field
                for name, field in machine["root"].get("variables", {}).items()
                if field.get("external", False)
            }
            if (
                not isinstance(changed, dict)
                or not changed
                or set(payload) != {"changed"}
                or not set(changed) <= set(external_variables)
                or any(
                    not value_matches_type(value, external_variables[name]["type"])
                    for name, value in changed.items()
                )
            ):
                return "invalid_payload"
            return None
        if declaration is None:
            return "invalid_event"
        direction = declaration.get("direction", "internal")
        required_direction = (
            "input" if delivery["delivery_mode"] == "input" else "internal"
        )
        if direction != required_direction:
            return "invalid_event"
        if declaration.get("correlates_to") is not None and not isinstance(
            envelope.get("correlation_id"), str
        ):
            return "invalid_correlation"

        payload = decode_typed_value(envelope["payload"])
        if not isinstance(payload, dict):
            return "invalid_payload"
        fields = declaration.get("payload", {})
        if set(payload) - set(fields):
            return "invalid_payload"
        for name, field in fields.items():
            if field.get("required", False) and name not in payload:
                return "invalid_payload"
            if name not in payload:
                continue
            value = payload[name]
            expected_type = field["type"]
            if not value_matches_type(value, expected_type):
                return "invalid_payload"
        return None

    def validate_embedded_checkpoint(
        checkpoint: dict[str, Any], location: str
    ) -> None:
        root_record = checkpoint["root_record"]
        if root_record["status"] == "retained":
            aggregate = root_record["aggregate_state"]
            expected_aggregate_digest = hash_value(
                [
                    "determa-aggregate-state-digest-2",
                    {
                        key: value
                        for key, value in aggregate.items()
                        if key != "aggregate_state_digest"
                    },
                ]
            )
            if aggregate["aggregate_state_digest"] != expected_aggregate_digest:
                raise ValidationFailure(
                    f"{location}: embedded aggregate digest mismatch"
                )
        expected_checkpoint_digest = hash_value(
            [
                "determa-execution-checkpoint-digest-2",
                {
                    key: value
                    for key, value in checkpoint.items()
                    if key != "execution_checkpoint_digest"
                },
            ]
        )
        if checkpoint["execution_checkpoint_digest"] != expected_checkpoint_digest:
            raise ValidationFailure(
                f"{location}: embedded checkpoint digest mismatch"
            )
        validate_execution_checkpoint_v2_semantics(checkpoint)


    operation_signatures: dict[tuple[str, str | None, str], str] = {}

    for index, vector in enumerate(test["version2_vectors"]):
        location = f"{case.name}: version2 vector {index}"
        name = vector["name"]
        if name in names:
            raise ValidationFailure(f"{location}: duplicate name {name}")
        names.add(name)

        duplicate = coverage & set(vector["covers"])
        if duplicate:
            raise ValidationFailure(
                f"{location}: duplicate coverage {sorted(duplicate)}"
            )
        coverage.update(vector["covers"])
        covers = set(vector["covers"])

        operation = vector["operation"]
        descriptor_names = (
            list(vector.get("descriptor_files", []))
            if "descriptor_files" in vector
            else ([vector["descriptor_file"]] if "descriptor_file" in vector else [])
        )
        descriptors: list[dict[str, Any]] = []
        if operation == "create_v2" and "bundle" not in vector:
            raise ValidationFailure(f"{location}: create_v2 requires bundle")
        if operation in state_operations and "state_before" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires state_before")
        if operation in checkpoint_operations and "checkpoint_before" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires checkpoint_before")
        if operation in package_operations and "package_file" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires package_file")
        if operation in descriptor_operations and (
            ("descriptor_file" in vector) == ("descriptor_files" in vector)
        ):
            raise ValidationFailure(
                f"{location}: {operation} requires exactly one descriptor-file form"
            )
        if "request_file" not in vector or "request_pointer" not in vector:
            raise ValidationFailure(f"{location}: operation requires a closed request")

        if "bundle" in vector and vector["bundle"] not in bundle_names:
            raise ValidationFailure(f"{location}: undeclared bundle {vector['bundle']}")
        for field in (
            "state_before",
            "checkpoint_before",
            "checkpoint_after",
            "migration_state_after",
            "package_file",
            "request_file",
            "descriptor_file",
        ):
            filename = vector.get(field)
            if filename is not None and filename not in artifact_names:
                raise ValidationFailure(f"{location}: undeclared artifact {filename}")
        for filename in vector.get("descriptor_files", []):
            if filename not in artifact_names:
                raise ValidationFailure(f"{location}: undeclared artifact {filename}")
        request_manifest = manifests.get(vector["request_file"])
        if request_manifest is None or request_manifest["kind"] != "version2_operation_inputs" or not request_manifest["valid"]:
            raise ValidationFailure(f"{location}: request must use the closed operation-input artifact")
        request = artifact(vector["request_file"])
        selected: Any = request.document
        try:
            for encoded in vector["request_pointer"].split("/")[1:]:
                token = encoded.replace("~1", "/").replace("~0", "~")
                selected = selected[int(token)] if isinstance(selected, list) else selected[token]
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise ValidationFailure(
                f"{location}: unresolved request pointer {vector['request_pointer']}"
            ) from error
        if not isinstance(selected, dict) or selected.get("operation") != operation:
            raise ValidationFailure(f"{location}: selected request operation mismatch")

        def resolver_evidence(
            resolver: dict[str, Any],
            required_definitions: set[str],
            required_descriptors: set[str],
        ) -> set[str]:
            evidence: set[str] = set()
            definitions = {
                entry["validated_bundle_fingerprint"]: entry
                for entry in resolver["definitions"]
            }
            descriptors_by_digest = {
                entry["migration_descriptor_digest"]: entry
                for entry in resolver["migration_descriptors"]
            }
            for fingerprint in required_definitions:
                entry = definitions.get(fingerprint)
                if entry is None:
                    evidence.add(
                        "source_definition_unavailable"
                        if fingerprint
                        == (prior_aggregate or {}).get(
                            "validated_bundle_fingerprint"
                        )
                        else "target_definition_unavailable"
                    )
                    continue
                actual = validated_bundle_fingerprint(case / entry["bundle_file"])
                if actual != fingerprint:
                    evidence.add("definition_fingerprint_mismatch")
                elif not entry["trusted"]:
                    evidence.add("definition_untrusted")
            for descriptor_digest in required_descriptors:
                entry = descriptors_by_digest.get(descriptor_digest)
                if entry is None:
                    evidence.add("migration_route_missing")
                    continue
                descriptor_document = artifact(entry["descriptor_file"]).document
                actual = hash_value(
                    [
                        "determa-migration-descriptor-2",
                        {
                            key: value
                            for key, value in descriptor_document.items()
                            if key != "migration_descriptor_digest"
                        },
                    ]
                )
                if actual != descriptor_digest:
                    evidence.add("invalid_migration_descriptor")
                elif not entry["trusted"]:
                    evidence.add("migration_descriptor_untrusted")
            return evidence

        expectation = vector["expect"]
        failure_evidence: set[str] = set()
        maintenance_replay = False
        if expectation["result"] == "failure":
            require_allowed_operation_failure_code(operation, expectation["code"])
        signature = (
            operation,
            vector.get("state_before", vector.get("checkpoint_before")),
            vector["request_pointer"],
        )
        if signature in operation_signatures:
            raise ValidationFailure(
                f"{location}: duplicates executable input of "
                f"{operation_signatures[signature]}"
            )
        operation_signatures[signature] = name

        invalid_input_error = None
        invalid_candidates = [
            ("state_before", vector.get("state_before")),
            ("checkpoint_before", vector.get("checkpoint_before")),
            ("package_file", vector.get("package_file")),
            *[("descriptor_file", filename) for filename in descriptor_names],
        ]
        for field, filename in invalid_candidates:
            if filename is None or manifests[filename]["valid"]:
                continue
            manifest_error = manifests[filename]["error"]
            if manifest_error in ARTIFACT_SOURCE_ERROR_CODES:
                manifest_error = {
                    "state_before": "invalid_aggregate_state",
                    "checkpoint_before": "invalid_execution_checkpoint",
                    "package_file": "invalid_aggregate_state_package",
                    "descriptor_file": "invalid_migration_descriptor",
                }[field]
            invalid_input_error = manifest_error
            break
        if invalid_input_error is not None:
            if (
                expectation
                != {
                    "result": "failure",
                    "code": invalid_input_error,
                    "unchanged_file": vector.get(
                        "state_before",
                        vector.get("checkpoint_before", vector.get("package_file")),
                    ),
                }
            ):
                raise ValidationFailure(
                    f"{location}: invalid input artifact requires exact "
                    f"{invalid_input_error} rejection"
                )
            continue
        if operation == "checkpoint_migrate_v2":
            checkpoint_before = artifact(vector["checkpoint_before"]).document
            source_digest = (
                checkpoint_before["root_record"]["aggregate_state"][
                    "aggregate_state_digest"
                ]
                if checkpoint_before["root_record"]["status"] == "retained"
                else checkpoint_before["root_record"][
                    "final_aggregate_state_digest"
                ]
            )
            expected_request_digest = hash_value(
                [
                    "determa-maintenance-migration-request-digest-2",
                    "2",
                    checkpoint_before["root_instance_id"],
                    selected["operation_id"],
                    source_digest,
                    selected["target_bundle"]["validated_bundle_fingerprint"],
                    selected["migration_descriptor_digest_route"],
                    selected["maintenance_mode"],
                ]
            )
            if selected["request_digest"] != expected_request_digest:
                raise ValidationFailure(
                    f"{location}: maintenance request digest is not canonical"
                )
            maintenance_receipt = next(
                (
                    receipt
                    for receipt in checkpoint_before["operation_receipts"]
                    if receipt["operation_kind"] == "maintenance_migration"
                    and receipt["operation_id"] == selected["operation_id"]
                ),
                None,
            )
            maintenance_replay = (
                maintenance_receipt is not None
                and maintenance_receipt["request_digest"] == selected["request_digest"]
            )
            maintenance_conflict = maintenance_receipt is not None and not maintenance_replay
            cas_matches = (
                selected.get("expected_revision")
                == checkpoint_before["revision"]
                and selected.get("expected_checkpoint_digest")
                == checkpoint_before["execution_checkpoint_digest"]
            )
            if (
                not cas_matches
                and not (maintenance_replay or maintenance_conflict)
                and expectation.get("code") != "checkpoint_revision_conflict"
            ):
                raise ValidationFailure(
                    f"{location}: checkpoint write lacks exact compare-and-swap input"
                )
            if (
                expectation.get("code") == "checkpoint_revision_conflict"
                and (cas_matches or maintenance_replay or maintenance_conflict)
            ):
                raise ValidationFailure(
                    f"{location}: checkpoint revision rejection lacks a distinct stale write"
                )
            if (
                expectation.get("code") == "checkpoint_revision_conflict"
                and not cas_matches
                and not (maintenance_replay or maintenance_conflict)
            ):
                failure_evidence.add("checkpoint_revision_conflict")
            if maintenance_conflict:
                if expectation.get("code") != "operation_id_conflict":
                    raise ValidationFailure(
                        f"{location}: maintenance identity conflict lacks exact rejection"
                    )
                failure_evidence.add("operation_id_conflict")
            elif expectation.get("code") == "operation_id_conflict":
                raise ValidationFailure(
                    f"{location}: maintenance conflict lacks retained conflicting identity"
                )
            if maintenance_replay and expectation["result"] != "success":
                raise ValidationFailure(
                    f"{location}: exact maintenance replay must precede stale CAS"
                )
        if operation in descriptor_operations and not isinstance(
            selected.get("maintenance_mode"), bool
        ):
            if expectation.get("code") != "invalid_migration_request":
                raise ValidationFailure(
                    f"{location}: migration request lacks mandatory maintenance mode"
                )
            failure_evidence.add("invalid_migration_request")

        prior_aggregate = aggregate_from_vector(vector)
        if operation in descriptor_operations and prior_aggregate is not None:
            root_status = next(
                runtime["status"]
                for runtime in prior_aggregate["runtimes"]
                if runtime["relation"]["kind"] == "root"
            )
            if descriptor_names and root_status in {"completed", "faulted"}:
                if selected.get("maintenance_mode") is False:
                    failure_evidence.add(
                        "terminal_migration_requires_maintenance"
                    )
                elif any(
                    artifact(name).document["terminal_policy"][root_status]
                    == "reject"
                    for name in descriptor_names
                ):
                    failure_evidence.add("terminal_migration_rejected")
        if operation == "round_trip_aggregate_v2":
            assert prior_aggregate is not None
            resolver = selected["definition_resolver"]
            resolver_failures = resolver_evidence(
                resolver,
                {prior_aggregate["validated_bundle_fingerprint"]},
                set(),
            )
            failure_evidence.update(resolver_failures)
            if expectation.get("code") == "invalid_aggregate_state" and any(
                int(runtime["target_identity"]["spawned_instance"]["machine_version"])
                > MAXIMUM_INTEGER
                for runtime in prior_aggregate["runtimes"]
                if "spawned_instance" in runtime["target_identity"]
            ):
                failure_evidence.add("invalid_aggregate_state")
            if expectation["result"] == "success":
                if resolver_failures:
                    raise ValidationFailure(
                        f"{location}: successful round trip has unresolved definition"
                    )
                entry = next(
                    item
                    for item in resolver["definitions"]
                    if item["validated_bundle_fingerprint"]
                    == prior_aggregate["validated_bundle_fingerprint"]
                )
                validate_aggregate_against_bundle(
                    prior_aggregate, case / entry["bundle_file"]
                )
        if operation == "restore_package_v2":
            package = artifact(vector["package_file"]).document
            embedded = package.get("aggregate_state", {})
            supplied_digest = embedded.get("aggregate_state_digest")
            if supplied_digest is not None:
                expected_digest = hash_value(
                    [
                        "determa-aggregate-state-digest-2",
                        {
                            key: value
                            for key, value in embedded.items()
                            if key != "aggregate_state_digest"
                        },
                    ]
                )
                if supplied_digest != expected_digest:
                    failure_evidence.add("aggregate_state_digest_mismatch")
            definition_keys = [
                item["validated_bundle_fingerprint"]
                for item in package.get("normalized_definitions", [])
            ]
            descriptor_keys = [
                item["migration_descriptor_digest"]
                for item in package.get("migration_descriptors", [])
            ]
            if (
                len(definition_keys) != len(set(definition_keys))
                or len(descriptor_keys) != len(set(descriptor_keys))
            ):
                failure_evidence.add("invalid_aggregate_state_package")
            package_resolver_failures = resolver_evidence(
                selected["artifact_resolver"], set(), set()
            )
            failure_evidence.update(package_resolver_failures)
            for entry in selected["artifact_resolver"]["definitions"]:
                if (
                    entry["validated_bundle_fingerprint"] in definition_keys
                    and validated_bundle_fingerprint(case / entry["bundle_file"])
                    != entry["validated_bundle_fingerprint"]
                ):
                    failure_evidence.add("definition_fingerprint_mismatch")
        if (
            prior_aggregate is not None
            and prior_aggregate.get("aggregate_state_schema_version") == 2
            and "bundle" in vector
            and operation in {"admit_v2", "step_v2"}
        ):
            validate_aggregate_against_bundle(prior_aggregate, case / vector["bundle"])
        if "deliveries" in selected:
            delivery_identity: dict[str, Any] | str | None = prior_aggregate
            if delivery_identity is None:
                raise ValidationFailure(f"{location}: delivery operation lacks a retained aggregate")
            malformed_deliveries = any(
                not isinstance(delivery, dict)
                or not {"delivery_mode", "envelope", "envelope_digest"}
                <= set(delivery)
                for delivery in selected["deliveries"]
            )
            if malformed_deliveries:
                if expectation.get("code") != "malformed_delivery":
                    raise ValidationFailure(
                        f"{location}: malformed delivery lacks precedence rejection"
                    )
                event_ids: list[str] = []
            else:
                if expectation.get("code") == "malformed_delivery":
                    raise ValidationFailure(
                        f"{location}: malformed rejection lacks a malformed member"
                    )
                event_ids = [
                    delivery["envelope"]["event_id"]
                    for delivery in selected["deliveries"]
                ]
            duplicate_event_ids = (
                not malformed_deliveries
                and len(event_ids) != len(set(event_ids))
            )
            if duplicate_event_ids:
                if expectation.get("code") != "duplicate_event_id_in_batch":
                    raise ValidationFailure(
                        f"{location}: duplicate input identity lacks exact rejection"
                    )
            elif expectation.get("code") == "duplicate_event_id_in_batch":
                raise ValidationFailure(
                    f"{location}: duplicate rejection lacks duplicate input identity"
                )
            conflicting_event_identity = (
                not malformed_deliveries
                and not duplicate_event_ids
                and operation == "admit_v2"
                and any(
                    aggregate_has_conflicting_identity(prior_aggregate, delivery)
                    for delivery in selected["deliveries"]
                )
            )
            if conflicting_event_identity:
                if expectation.get("code") != "event_id_conflict":
                    raise ValidationFailure(
                        f"{location}: conflicting retained identity lacks exact rejection"
                    )
            elif expectation.get("code") == "event_id_conflict":
                raise ValidationFailure(
                    f"{location}: conflict rejection lacks retained conflicting evidence"
                )
            replay_evidence = (
                [None for _ in selected["deliveries"]]
                if malformed_deliveries
                else [
                    next(
                        (
                            entry
                            for runtime in prior_aggregate["runtimes"]
                            for mailbox in (
                                runtime["ready_mailbox"],
                                runtime["deferred_mailbox"],
                            )
                            for entry in mailbox
                            if entry["envelope"]["event_id"]
                            == delivery["envelope"]["event_id"]
                            and entry["envelope_digest"]
                            == hash_value(
                                [
                                    "determa-inbox-envelope-digest-2",
                                    "2",
                                    prior_aggregate["root_instance_id"],
                                    delivery["delivery_mode"],
                                    delivery["envelope"],
                                ]
                            )
                        ),
                        None,
                    )
                    for delivery in selected["deliveries"]
                ]
                if operation == "admit_v2"
                else [None for _ in selected["deliveries"]]
            )
            delivery_errors: list[str] = []
            contract_errors: list[str] = []
            for delivery, replay in zip(
                selected["deliveries"], replay_evidence, strict=True
            ):
                if (
                    malformed_deliveries
                    or duplicate_event_ids
                    or conflicting_event_identity
                ):
                    continue
                if replay is not None:
                    continue
                delivery_error = delivery_validation_error(
                    delivery, delivery_identity, location
                )
                if delivery_error is not None:
                    delivery_errors.append(delivery_error)
                    if expectation.get("code") != delivery_error:
                        raise ValidationFailure(
                            f"{location}: delivery requires {delivery_error}"
                        )
                    continue
                if (
                    replay is None
                    and prior_aggregate is not None
                    and "bundle" in vector
                    and operation == "admit_v2"
                ):
                    contract_error = delivery_contract_error(
                        delivery,
                        prior_aggregate,
                        case / vector["bundle"],
                        checkpoint_host=False,
                    )
                    if contract_error is not None:
                        contract_errors.append(contract_error)
                        if expectation.get("code") != contract_error:
                            raise ValidationFailure(
                                f"{location}: delivery contract requires {contract_error}"
                            )
            if expectation.get("code") in {
                "delivery_digest_mismatch",
                "invalid_delivery_mode",
            } and expectation.get("code") not in delivery_errors:
                raise ValidationFailure(
                    f"{location}: delivery rejection lacks its declared violation"
                )
            if expectation.get("code") in {
                "invalid_delivery_source",
                "invalid_instance_target",
                "inactive_component_target",
                "invalid_event",
                "invalid_payload",
                "invalid_correlation",
            } and expectation.get("code") not in contract_errors:
                raise ValidationFailure(
                    f"{location}: contract rejection lacks its declared violation"
                )
            if operation == "admit_v2" and expectation["result"] == "failure":
                evidenced_rejections = (
                    {"malformed_delivery"}
                    if malformed_deliveries
                    else {"duplicate_event_id_in_batch"}
                    if duplicate_event_ids
                    else {"event_id_conflict"}
                    if conflicting_event_identity
                    else set(delivery_errors) | set(contract_errors)
                )
                if expectation.get("code") not in evidenced_rejections:
                    raise ValidationFailure(
                        f"{location}: rejection label lacks relational evidence"
                    )
                failure_evidence.update(evidenced_rejections)

        if operation == "step_v2":
            if prior_aggregate is None:
                raise ValidationFailure(f"{location}: step lacks a retained aggregate")
            runtime_id = selected["target_runtime_id"]
            runtime = target_runtime(prior_aggregate, runtime_id)
            aggregate_root = next(
                item
                for item in prior_aggregate["runtimes"]
                if item["relation"]["kind"] == "root"
            )
            rejection = expectation.get("code")
            if runtime is None and rejection != "invalid_instance_target" and expectation.get("result") != "success":
                raise ValidationFailure(f"{location}: fabricated runtime target was accepted")
            if aggregate_root["status"] != "running" and runtime is not None:
                result_document = (
                    artifact(expectation["exact_result_file"]).document
                    if expectation.get("exact_result_file")
                    else None
                )
                if (
                    result_document is None
                    or result_document.get("rejection", {}).get("code")
                    != "invalid_instance_target"
                ):
                    raise ValidationFailure(
                        f"{location}: terminal aggregate descendant step is not distinguished"
                    )
            elif runtime is not None and runtime["relation"]["kind"] == "component" and runtime["status"] in {"completed", "faulted"}:
                result_document = artifact(expectation["exact_result_file"]).document if expectation.get("exact_result_file") else None
                if result_document is None or result_document.get("rejection", {}).get("code") != "inactive_component_target":
                    raise ValidationFailure(f"{location}: inactive component step is not distinguished")
            if (
                runtime is not None
                and runtime["relation"]["kind"] != "component"
                and runtime["status"] in {"completed", "faulted"}
            ):
                result_document = (
                    artifact(expectation["exact_result_file"]).document
                    if expectation.get("exact_result_file")
                    else None
                )
                if (
                    result_document is None
                    or result_document.get("rejection", {}).get("code")
                    != "invalid_instance_target"
                ):
                    raise ValidationFailure(
                        f"{location}: terminal machine runtime step is not distinguished"
                    )

        if operation == "create_v2" and expectation["result"] == "success":
            bundle_path = case / selected["bundle"]["bundle_file"]
            fingerprint = validated_bundle_fingerprint(bundle_path)
            if selected["bundle"]["bundle_source_digest"] != hash_bytes(bundle_path.read_bytes()) or selected["bundle"]["validated_bundle_fingerprint"] != fingerprint:
                raise ValidationFailure(f"{location}: creation bundle binding mismatch")
            result = artifact(expectation["exact_result_file"]).document
            machine_index, machine = next(
                (index, machine) for index, machine in enumerate(normalized_bundle_value(bundle_path)["machines"])
                if machine["machine_id"] == selected["machine_id"] and str(machine["version"]) == selected["machine_version"]
            )
            root_pointer = f"/machines/{machine_index}/root"
            expected_pointers = [root_pointer]
            current = machine["root"]
            while current.get("type") == "composite" and "initial" in current:
                cursor = machine["root"]
                pointer = root_pointer
                for segment in current["initial"]["transition_to"].split("."):
                    cursor = cursor["states"][segment]
                    pointer += f"/states/{segment}"
                expected_pointers.append(pointer)
                current = cursor
            expected_runtime_id = hash_value([
                "determa-root-runtime-identity-2", "1", fingerprint,
                normalized_bundle_value(bundle_path)["namespace"], selected["machine_id"],
                selected["machine_version"], selected["root_instance_id"],
            ])
            root = result["runtimes"][0]
            if (
                result["validated_bundle_fingerprint"] != fingerprint
                or result["root_runtime_id"] != expected_runtime_id
                or root["runtime_id"] != expected_runtime_id
                or root["active_leaf_state_definition_pointers"] != [expected_pointers[-1]]
                or [item["state_definition_pointer"] for item in root["active_state_activations"]] != expected_pointers
                or [item["definition_pointer"] for item in root["next_state_activation_sequences"]] != expected_pointers
                or root["history"]
                or result["migration_sequence"] != "0"
                or result["next_logical_step_sequence"] != "1"
                or result["next_output_sequence"] != "0"
                or result["next_acceptance_sequence"] != "0"
                or result["next_queue_sequence"] != "0"
                or root["ready_mailbox"]
                or root["deferred_mailbox"]
            ):
                raise ValidationFailure(f"{location}: creation result was not derived from its exact input")

        if operation in descriptor_operations and not maintenance_replay:
            if prior_aggregate is None:
                raise ValidationFailure(f"{location}: migration lacks source aggregate")
            for key in ("source_bundle", "target_bundle"):
                binding = selected[key]
                bundle_path = case / binding["bundle_file"]
                if binding["bundle_source_digest"] != hash_bytes(bundle_path.read_bytes()) or binding["validated_bundle_fingerprint"] != validated_bundle_fingerprint(bundle_path):
                    raise ValidationFailure(f"{location}: {key} binding mismatch")
            selected_descriptor_names = (
                list(selected.get("migration_descriptor_files", []))
                if "migration_descriptor_files" in selected
                else (
                    [selected["migration_descriptor_file"]]
                    if "migration_descriptor_file" in selected
                    else []
                )
            )
            if selected_descriptor_names != descriptor_names:
                raise ValidationFailure(f"{location}: descriptor request and vector differ")
            descriptors = [artifact(name).document for name in descriptor_names]
            resolver_failures = resolver_evidence(
                selected.get(
                    "artifact_resolver",
                    {"definitions": [], "migration_descriptors": []},
                ),
                {
                    selected["source_bundle"]["validated_bundle_fingerprint"],
                    selected["target_bundle"]["validated_bundle_fingerprint"],
                    *{
                        fingerprint
                        for descriptor in descriptors
                        for fingerprint in (
                            descriptor["source_validated_bundle_fingerprint"],
                            descriptor["target_validated_bundle_fingerprint"],
                        )
                    },
                },
                set(selected["migration_descriptor_digest_route"]),
            )
            failure_evidence.update(resolver_failures)
            if expectation.get("code") == "invalid_migration_descriptor":
                duplicate_mapping_key = any(
                    len(keys) != len(set(keys))
                    for descriptor in descriptors
                    for keys in (
                        [
                            item["source_leaf_state_definition_pointer"]
                            for item in descriptor["mappings"]["active_states"]
                        ],
                        [
                            item.get("target_declaration_pointer")
                            for item in descriptor["mappings"]["variables"]
                            if "target_declaration_pointer" in item
                        ],
                    )
                )
                if duplicate_mapping_key:
                    failure_evidence.add("invalid_migration_descriptor")
            if expectation.get("code") == "migration_totality_failure":
                for descriptor in descriptors:
                    active_sources = {
                        item["source_leaf_state_definition_pointer"]
                        for item in descriptor["mappings"]["active_states"]
                    }
                    live_sources = {
                        pointer
                        for runtime in prior_aggregate["runtimes"]
                        for pointer in runtime[
                            "active_leaf_state_definition_pointers"
                        ]
                    }
                    active_targets = {
                        pointer
                        for item in descriptor["mappings"]["active_states"]
                        for pointer in item[
                            "target_leaf_state_definition_pointers"
                        ]
                    }
                    counter_targets = {
                        item.get("target_definition_pointer")
                        for item in descriptor["mappings"]["counters"]
                    }
                    produced_variables = {
                        item.get("target_declaration_pointer")
                        for item in descriptor["mappings"]["variables"]
                    }
                    target_bundle = normalized_bundle_value(
                        case / selected["target_bundle"]["bundle_file"]
                    )
                    target_variables: set[str] = set()

                    def collect_variables(state: dict[str, Any], pointer: str) -> None:
                        target_variables.update(
                            f"{pointer}/variables/{name}"
                            for name in state.get("variables", {})
                        )
                        for child_name, child in state.get("states", {}).items():
                            if child.get("type") != "choice":
                                collect_variables(
                                    child, f"{pointer}/states/{child_name}"
                                )

                    for machine_index, machine in enumerate(
                        target_bundle["machines"]
                    ):
                        collect_variables(
                            machine["root"], f"/machines/{machine_index}/root"
                        )
                    if (
                        not live_sources <= active_sources
                        or not active_targets <= counter_targets
                        or target_variables - produced_variables
                    ):
                        failure_evidence.add("migration_totality_failure")
            if expectation.get("code") == "migration_resource_limit_exceeded":
                exceeded = False
                limits = selected.get("resource_limits")
                if limits is not None:
                    candidates: list[Any] = [prior_aggregate]
                    candidates.extend(
                        normalized_bundle_value(
                            case / selected[key]["bundle_file"]
                        )
                        for key in ("source_bundle", "target_bundle")
                    )
                    candidates.extend(descriptors)

                    def maximum_depth(value: Any) -> int:
                        if isinstance(value, dict):
                            return 1 + max(
                                (maximum_depth(item) for item in value.values()),
                                default=0,
                            )
                        if isinstance(value, list):
                            return 1 + max(
                                (maximum_depth(item) for item in value),
                                default=0,
                            )
                        return 1

                    def walk(value: Any) -> tuple[int, int, int]:
                        map_members = list_members = string_bytes = 0
                        if isinstance(value, dict):
                            map_members = len(value)
                            string_bytes += max(
                                (len(key.encode("utf-8")) for key in value),
                                default=0,
                            )
                            children = value.values()
                        elif isinstance(value, list):
                            list_members = len(value)
                            children = value
                        elif isinstance(value, str):
                            return 0, 0, len(value.encode("utf-8"))
                        else:
                            return 0, 0, 0
                        for child in children:
                            child_map, child_list, child_string = walk(child)
                            map_members = max(map_members, child_map)
                            list_members = max(list_members, child_list)
                            string_bytes = max(string_bytes, child_string)
                        return map_members, list_members, string_bytes

                    maximum_map, maximum_list, maximum_string = (0, 0, 0)
                    for candidate in candidates:
                        item_map, item_list, item_string = walk(candidate)
                        maximum_map = max(maximum_map, item_map)
                        maximum_list = max(maximum_list, item_list)
                        maximum_string = max(maximum_string, item_string)
                    expression_bytes = sum(
                        len(rule["expression"].encode("utf-8"))
                        for descriptor in descriptors
                        for rule in descriptor["mappings"]["variables"]
                        if "expression" in rule
                    )
                    descriptor_rules = max(
                        (
                            sum(len(items) for items in descriptor["mappings"].values())
                            for descriptor in descriptors
                        ),
                        default=0,
                    )
                    exceeded = any(
                        (
                            len(descriptors) > int(limits["maximum_chain_length"]),
                            len(canonical_json_bytes(prior_aggregate))
                            > int(limits["maximum_aggregate_bytes"]),
                            max(
                                len(canonical_json_bytes(candidates[1])),
                                len(canonical_json_bytes(candidates[2])),
                            )
                            > int(limits["maximum_definition_bytes"]),
                            max(
                                (
                                    len(canonical_json_bytes(descriptor))
                                    for descriptor in descriptors
                                ),
                                default=0,
                            )
                            > int(limits["maximum_descriptor_bytes"]),
                            maximum_depth(candidates)
                            > int(limits["maximum_json_nesting_depth"]),
                            len(prior_aggregate["runtimes"])
                            > int(limits["maximum_runtimes"]),
                            max(
                                len(runtime["active_state_activations"])
                                for runtime in prior_aggregate["runtimes"]
                            )
                            > int(limits["maximum_active_states_per_runtime"]),
                            max(
                                len(runtime["variables"])
                                for runtime in prior_aggregate["runtimes"]
                            )
                            > int(limits["maximum_variables_per_runtime"]),
                            maximum_map > int(limits["maximum_map_members"]),
                            maximum_list > int(limits["maximum_list_members"]),
                            maximum_string
                            > int(limits["maximum_string_utf8_bytes"]),
                            descriptor_rules
                            > int(limits["maximum_descriptor_rules"]),
                            expression_bytes
                            > int(limits["maximum_cel_expression_length"]),
                            expression_bytes > 0
                            and int(limits["maximum_cel_ast_nodes"]) == 0,
                        )
                    )
                if not exceeded:
                    transform_occurrences = sum(
                        1
                        for runtime in prior_aggregate["runtimes"]
                        for descriptor in descriptors
                        for rule in descriptor["mappings"]["variables"]
                        if rule.get("operation") in {"transform", "initialize"}
                        and runtime["variables"]
                    )
                    exceeded = any(
                        int(descriptor["resource_requirements"][field])
                        < transform_occurrences
                        for descriptor in descriptors
                        for field in (
                            "maximum_transformed_output_bytes",
                            "maximum_cel_evaluation_steps",
                        )
                    )
                if exceeded:
                    failure_evidence.add("migration_resource_limit_exceeded")
            if expectation.get("code") == "migration_transform_fault" and any(
                "/ 0" in rule.get("expression", "")
                for descriptor in descriptors
                for rule in descriptor["mappings"]["variables"]
            ):
                failure_evidence.add("migration_transform_fault")
            route = selected["migration_descriptor_digest_route"]
            if route != [item["migration_descriptor_digest"] for item in descriptors]:
                raise ValidationFailure(f"{location}: migration descriptor route mismatch")
            source_bundle_path = case / selected["source_bundle"]["bundle_file"]
            validate_aggregate_against_bundle(prior_aggregate, source_bundle_path)
            source_fingerprint = selected["source_bundle"][
                "validated_bundle_fingerprint"
            ]
            target_fingerprint = selected["target_bundle"][
                "validated_bundle_fingerprint"
            ]
            if prior_aggregate["validated_bundle_fingerprint"] != source_fingerprint:
                raise ValidationFailure(f"{location}: migration source is not exact")
            bundle_by_fingerprint = {
                validated_bundle_fingerprint(path): path for path in bundle_paths
            }
            if not descriptors:
                if source_fingerprint != target_fingerprint:
                    if expectation.get("code") != "migration_route_missing":
                        raise ValidationFailure(
                            f"{location}: empty migration route changes definition"
                        )
                    failure_evidence.add("migration_route_missing")
            else:
                expected_source_fingerprint = source_fingerprint
                visited_fingerprints = {source_fingerprint}
                route_mismatch = False
                for descriptor in descriptors:
                    if (
                        descriptor["source_validated_bundle_fingerprint"]
                        != expected_source_fingerprint
                    ):
                        route_mismatch = True
                    descriptor_source_path = bundle_by_fingerprint.get(
                        descriptor["source_validated_bundle_fingerprint"]
                    )
                    descriptor_target_fingerprint = descriptor[
                        "target_validated_bundle_fingerprint"
                    ]
                    descriptor_target_path = bundle_by_fingerprint.get(
                        descriptor_target_fingerprint
                    )
                    if descriptor_source_path is None or descriptor_target_path is None:
                        raise ValidationFailure(
                            f"{location}: migration descriptor definition is unavailable"
                        )
                    if (
                        descriptor["source_aggregate_shape_fingerprint"]
                        != aggregate_shape_fingerprint_for_path(
                            descriptor_source_path
                        )
                        or descriptor["target_aggregate_shape_fingerprint"]
                        != aggregate_shape_fingerprint_for_path(
                            descriptor_target_path
                        )
                    ):
                        raise ValidationFailure(
                            f"{location}: migration shape fingerprint is not exact"
                        )
                    if expected_source_fingerprint == descriptor_target_fingerprint:
                        route_mismatch = True
                    if descriptor_target_fingerprint in visited_fingerprints:
                        route_mismatch = True
                    if descriptor["mode"] == "compatible" and (
                        descriptor["source_aggregate_shape_fingerprint"]
                        != descriptor["target_aggregate_shape_fingerprint"]
                        or any(descriptor["mappings"].values())
                    ):
                        raise ValidationFailure(
                            f"{location}: compatible descriptor is not shape-identical"
                        )
                    expected_source_fingerprint = descriptor_target_fingerprint
                    visited_fingerprints.add(descriptor_target_fingerprint)
                if expected_source_fingerprint != target_fingerprint:
                    route_mismatch = True
                if route_mismatch:
                    if expectation.get("code") != "migration_route_mismatch":
                        raise ValidationFailure(
                            f"{location}: migration route is not exact and acyclic"
                        )
                    failure_evidence.add("migration_route_mismatch")
            target_document = normalized_bundle_value(case / selected["target_bundle"]["bundle_file"])
            queued_entries = [
                entry for runtime in prior_aggregate["runtimes"]
                for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
                for entry in mailbox
            ]
            if "migration_fault_frozen_preservation" in covers:
                faulted = next(
                    runtime
                    for runtime in prior_aggregate["runtimes"]
                    if runtime["status"] == "faulted"
                )
                fault = faulted["fault"]
                retained_event_ids = {
                    entry["envelope"]["event_id"]
                    for runtime in prior_aggregate["runtimes"]
                    for mailbox in (
                        runtime["ready_mailbox"],
                        runtime["deferred_mailbox"],
                    )
                    for entry in mailbox
                }
                if (
                    fault["code"] != "action_fault"
                    or int(prior_aggregate["next_logical_step_sequence"])
                    != int(fault["step_sequence"]) + 1
                    or fault["cause_id"] in retained_event_ids
                ):
                    raise ValidationFailure(
                        f"{location}: fault-frozen seed is not a committed consumed fault"
                    )
            if "migration_removed_event_failure" in covers and not any(
                entry["envelope"]["event"] not in target_document.get("events", {}) for entry in queued_entries
            ):
                raise ValidationFailure(f"{location}: removed-event failure has no removed queued event")
            if "migration_payload_incompatible_failure" in covers:
                incompatible = False
                for entry in queued_entries:
                    declaration = target_document.get("events", {}).get(entry["envelope"]["event"], {})
                    payload_declarations = declaration.get("payload", {})
                    payload_values = dict(entry["envelope"]["payload"][1])
                    incompatible |= any(
                        name in payload_values and payload_values[name][0] != {"int": "integer", "string": "string", "bool": "boolean", "float": "float"}.get(field["type"], field["type"])
                        for name, field in payload_declarations.items()
                    )
                if not incompatible:
                    raise ValidationFailure(f"{location}: payload failure has no incompatible queued payload")
            if "migration_correlation_incompatible_failure" in covers and not any(
                target_document.get("events", {}).get(entry["envelope"]["event"], {}).get("correlates_to")
                and "correlation_id" not in entry["envelope"]
                for entry in queued_entries
            ):
                raise ValidationFailure(f"{location}: correlation failure has no incompatible queued envelope")
            if "migration_capacity_totality" in covers:
                capacity = target_document["machines"][0]["root"].get("deferred_event_capacity")
                deferred_count = sum(len(runtime["deferred_mailbox"]) for runtime in prior_aggregate["runtimes"])
                if capacity is None or deferred_count <= capacity:
                    raise ValidationFailure(f"{location}: capacity failure has no over-capacity retained mailbox")
            if "migration_stale_target_transform" in covers:
                pointers = {
                    item
                    for runtime in prior_aggregate["runtimes"]
                    for item in runtime["active_leaf_state_definition_pointers"]
                }
                def resolves_pointer(pointer: str) -> bool:
                    value: Any = target_document
                    try:
                        for token in pointer.split("/")[1:]:
                            value = value[int(token)] if isinstance(value, list) else value[token]
                    except (KeyError, IndexError, TypeError, ValueError):
                        return False
                    return True
                if all(resolves_pointer(pointer) for pointer in pointers):
                    raise ValidationFailure(
                        f"{location}: stale-target transform has no renamed active state"
                    )
            if (
                expectation["result"] == "failure"
                and expectation.get("code") == "migration_totality_failure"
                and covers
                & {
                    "migration_removed_event_failure",
                    "migration_payload_incompatible_failure",
                    "migration_correlation_incompatible_failure",
                    "migration_capacity_totality",
                }
            ):
                failure_evidence.add("migration_totality_failure")



        result_file = expectation.get("exact_result_file")
        if result_file is not None:
            manifest = manifests.get(result_file)
            if manifest is None or not manifest["valid"]:
                raise ValidationFailure(
                    f"{location}: exact result must be a valid declared artifact"
                )
            analysis = artifact(result_file)
            if analysis.error is not None or analysis.source != canonical_json_bytes(
                analysis.document
            ):
                raise ValidationFailure(
                    f"{location}: exact result is not canonical RFC 8785 bytes"
                )
            result_document = analysis.document
            if operation == "round_trip_aggregate_v2":
                assert prior_aggregate is not None
                prior_analysis = artifact(vector["state_before"])
                if (
                    result_document != prior_aggregate
                    or analysis.source != prior_analysis.source
                ):
                    raise ValidationFailure(
                        f"{location}: aggregate round trip is not byte-identical"
                    )
                if "all_typed_values_round_trip" in covers:
                    typed_tags = {
                        variable["value"][0]
                        for runtime in prior_aggregate["runtimes"]
                        for variable in runtime["variables"]
                    }
                    if typed_tags != {
                        "null",
                        "boolean",
                        "string",
                        "integer",
                        "float",
                        "list",
                        "map",
                    }:
                        raise ValidationFailure(
                            f"{location}: typed-value round trip is not total"
                        )
            expected_kinds = (
                {"aggregate_state_v2"}
                if operation in {"create_v2", "round_trip_aggregate_v2"}
                else {"aggregate_state_v2", "version2_operation_result"}
                if operation == "restore_package_v2"
                else {"core_step_result_v2"} if operation == "step_v2"
                else {"version2_operation_result"}
            )
            if manifests[result_file]["kind"] not in expected_kinds:
                raise ValidationFailure(f"{location}: result artifact kind is not closed for {operation}")
            if operation == "migrate_then_process_v2":
                assert prior_aggregate is not None
                migration_state_name = vector.get("migration_state_after")
                migration_manifest = manifests.get(migration_state_name)
                if (
                    migration_state_name is None
                    or migration_manifest is None
                    or migration_manifest["kind"] != "aggregate_state_v2"
                    or not migration_manifest["valid"]
                ):
                    raise ValidationFailure(
                        f"{location}: combined operation lacks its exact migration state"
                    )
                migration_state = artifact(migration_state_name).document
                validate_aggregate_against_bundle(
                    migration_state,
                    case / selected["target_bundle"]["bundle_file"],
                    case / selected["source_bundle"]["bundle_file"],
                )
                expected_audits: list[dict[str, Any]] = []
                audit_source = prior_aggregate
                for descriptor_index, descriptor in enumerate(descriptors):
                    if descriptor_index == len(descriptors) - 1:
                        audit_target = migration_state
                    else:
                        if descriptor["mode"] != "compatible":
                            raise ValidationFailure(
                                f"{location}: intermediate transform lacks exact candidate"
                            )
                        audit_target = copy.deepcopy(audit_source)
                        target_fingerprint = descriptor[
                            "target_validated_bundle_fingerprint"
                        ]
                        audit_target["validated_bundle_fingerprint"] = target_fingerprint
                        audit_target["migration_sequence"] = str(
                            int(audit_target["migration_sequence"]) + 1
                        )
                        for runtime in audit_target["runtimes"]:
                            runtime["current_definition"][
                                "validated_bundle_fingerprint"
                            ] = target_fingerprint
                        audit_target.pop("aggregate_state_digest", None)
                        audit_target["aggregate_state_digest"] = hash_value(
                            ["determa-aggregate-state-digest-2", audit_target]
                        )
                    expected_audits.append(
                        {
                            "migration_audit_record_schema_version": 2,
                            "root_instance_id": prior_aggregate["root_instance_id"],
                            "root_runtime_id": prior_aggregate["root_runtime_id"],
                            "migration_sequence": audit_target["migration_sequence"],
                            "source_validated_bundle_fingerprint": audit_source[
                                "validated_bundle_fingerprint"
                            ],
                            "target_validated_bundle_fingerprint": audit_target[
                                "validated_bundle_fingerprint"
                            ],
                            "migration_descriptor_digest": descriptor[
                                "migration_descriptor_digest"
                            ],
                            "source_aggregate_state_digest": audit_source[
                                "aggregate_state_digest"
                            ],
                            "target_aggregate_state_digest": audit_target[
                                "aggregate_state_digest"
                            ],
                            "result_code": "migration_applied",
                        }
                    )
                    audit_source = audit_target
                if result_document["migration_audit_records"] != expected_audits:
                    raise ValidationFailure(
                        f"{location}: combined operation audits do not close the migration commit"
                    )
                processing = result_document["processing"]
                processing_state = processing["state"]
                validate_aggregate_against_bundle(
                    processing_state,
                    case / selected["target_bundle"]["bundle_file"],
                    case / selected["source_bundle"]["bundle_file"],
                )
                if processing["disposition"] == "rejected":
                    if processing_state != migration_state or processing["rejection"] is None:
                        raise ValidationFailure(
                            f"{location}: rejected delivery changed the migration commit"
                        )
                elif (
                    int(processing_state["next_acceptance_sequence"])
                    != int(migration_state["next_acceptance_sequence"]) + 1
                    or int(processing_state["next_queue_sequence"])
                    != int(migration_state["next_queue_sequence"]) + 1
                    or processing["rejection"] is not None
                ):
                    raise ValidationFailure(
                        f"{location}: admitted delivery did not follow the migration commit"
                    )
            if operation == "checkpoint_migrate_v2":
                checkpoint_after_name = vector.get("checkpoint_after")
                if checkpoint_after_name is None:
                    raise ValidationFailure(
                        f"{location}: successful maintenance migration lacks checkpoint_after"
                    )
                checkpoint_after_manifest = manifests.get(checkpoint_after_name)
                if (
                    checkpoint_after_manifest is None
                    or checkpoint_after_manifest["kind"] != "execution_checkpoint_v2"
                    or not checkpoint_after_manifest["valid"]
                ):
                    raise ValidationFailure(
                        f"{location}: maintenance checkpoint_after is not a valid v2 checkpoint"
                    )
                checkpoint_after = artifact(checkpoint_after_name).document
                validate_embedded_checkpoint(checkpoint_after, location)
                if maintenance_replay:
                    if (
                        checkpoint_after != checkpoint_before
                        or maintenance_receipt is None
                        or result_document
                        != {"result": "committed", "receipt": maintenance_receipt}
                    ):
                        raise ValidationFailure(
                            f"{location}: maintenance replay changed state or receipt"
                        )
                else:
                    projected_aggregate = copy.deepcopy(prior_aggregate)
                    expected_audits: list[dict[str, Any]] = []
                    for descriptor in descriptors:
                        source_aggregate = projected_aggregate
                        target_fingerprint = descriptor[
                            "target_validated_bundle_fingerprint"
                        ]
                        projected_aggregate = copy.deepcopy(source_aggregate)
                        projected_aggregate["validated_bundle_fingerprint"] = (
                            target_fingerprint
                        )
                        projected_aggregate["migration_sequence"] = str(
                            int(source_aggregate["migration_sequence"]) + 1
                        )
                        for runtime in projected_aggregate["runtimes"]:
                            runtime["current_definition"][
                                "validated_bundle_fingerprint"
                            ] = target_fingerprint
                        projected_aggregate.pop("aggregate_state_digest", None)
                        projected_aggregate["aggregate_state_digest"] = hash_value(
                            ["determa-aggregate-state-digest-2", projected_aggregate]
                        )
                        expected_audits.append(
                            {
                                "migration_audit_record_schema_version": 2,
                                "root_instance_id": source_aggregate[
                                    "root_instance_id"
                                ],
                                "root_runtime_id": source_aggregate[
                                    "root_runtime_id"
                                ],
                                "migration_sequence": projected_aggregate[
                                    "migration_sequence"
                                ],
                                "source_validated_bundle_fingerprint": source_aggregate[
                                    "validated_bundle_fingerprint"
                                ],
                                "target_validated_bundle_fingerprint": target_fingerprint,
                                "migration_descriptor_digest": descriptor[
                                    "migration_descriptor_digest"
                                ],
                                "source_aggregate_state_digest": source_aggregate[
                                    "aggregate_state_digest"
                                ],
                                "target_aggregate_state_digest": projected_aggregate[
                                    "aggregate_state_digest"
                                ],
                                "result_code": "migration_applied",
                            }
                        )
                    receipt_sequence = checkpoint_before[
                        "next_operation_receipt_sequence"
                    ]
                    expected_receipt = {
                        "operation_kind": "maintenance_migration",
                        "receipt_sequence": receipt_sequence,
                        "operation_id": selected["operation_id"],
                        "request_digest": selected["request_digest"],
                        "committed_revision": str(
                            int(checkpoint_before["revision"]) + 1
                        ),
                        "source_aggregate_state_digest": prior_aggregate[
                            "aggregate_state_digest"
                        ],
                        "target_validated_bundle_fingerprint": selected[
                            "target_bundle"
                        ]["validated_bundle_fingerprint"],
                        "resulting_aggregate_state_digest": projected_aggregate[
                            "aggregate_state_digest"
                        ],
                        "migration_sequences": [
                            audit["migration_sequence"] for audit in expected_audits
                        ],
                        "result_code": (
                            "migration_applied"
                            if expected_audits
                            else "migration_no_operation"
                        ),
                    }
                    expected_checkpoint = copy.deepcopy(checkpoint_before)
                    expected_checkpoint["revision"] = expected_receipt[
                        "committed_revision"
                    ]
                    expected_checkpoint["root_record"]["aggregate_state"] = (
                        projected_aggregate
                    )
                    expected_checkpoint["operation_receipts"].append(
                        expected_receipt
                    )
                    expected_checkpoint["next_operation_receipt_sequence"] = str(
                        int(receipt_sequence) + 1
                    )
                    expected_checkpoint["migration_audit_records"].extend(
                        expected_audits
                    )
                    expected_checkpoint.pop("execution_checkpoint_digest", None)
                    expected_checkpoint["execution_checkpoint_digest"] = hash_value(
                        ["determa-execution-checkpoint-digest-2", expected_checkpoint]
                    )
                    if (
                        checkpoint_after != expected_checkpoint
                        or result_document
                        != {"result": "committed", "receipt": expected_receipt}
                    ):
                        raise ValidationFailure(
                            f"{location}: maintenance transaction projection is not exact"
                        )
            if operation == "admit_v2":
                assert prior_aggregate is not None
                deliveries = selected["deliveries"]
                result_state = result_document["state"]
                validate_aggregate_v2_semantics(result_state)
                validate_aggregate_against_bundle(
                    result_state, case / vector["bundle"]
                )
                expected_digest = hash_value(
                    [
                        "determa-aggregate-state-digest-2",
                        {
                            key: value
                            for key, value in result_state.items()
                            if key != "aggregate_state_digest"
                        },
                    ]
                )
                if result_state["aggregate_state_digest"] != expected_digest:
                    raise ValidationFailure(
                        f"{location}: admit result aggregate digest mismatch"
                    )
                root = next(
                    runtime
                    for runtime in result_state["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                if (
                    result_document["status"] != root["status"]
                    or result_document["rejection"] is not None
                ):
                    raise ValidationFailure(
                        f"{location}: admit result status or rejection is not exact"
                    )
                if result_document["result"] == "replay":
                    if len(deliveries) != 1 or result_state != prior_aggregate:
                        raise ValidationFailure(
                            f"{location}: core replay mutated aggregate or batch shape"
                        )
                    delivery = deliveries[0]
                    candidate_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-2",
                            "2",
                            prior_aggregate["root_instance_id"],
                            delivery["delivery_mode"],
                            delivery["envelope"],
                        ]
                    )
                    matches = [
                        (mailbox_name, entry)
                        for runtime in prior_aggregate["runtimes"]
                        for mailbox_name, mailbox in (
                            ("ready", runtime["ready_mailbox"]),
                            ("deferred", runtime["deferred_mailbox"]),
                        )
                        for entry in mailbox
                        if entry["envelope"] == delivery["envelope"]
                        and entry["envelope_digest"]
                        == candidate_digest
                    ]
                    if len(matches) != 1:
                        raise ValidationFailure(
                            f"{location}: replay is not backed by one retained request"
                        )
                    mailbox_name, entry = matches[0]
                    expected_replay = {
                        "result": "replay",
                        "status": root["status"],
                        "event_id": delivery["envelope"]["event_id"],
                        "acceptance_sequence": entry["acceptance_sequence"],
                        "location": mailbox_name,
                        "state": prior_aggregate,
                        "rejection": None,
                    }
                    if result_document != expected_replay:
                        raise ValidationFailure(
                            f"{location}: core replay evidence is not request-bound"
                        )
                else:
                    accepted = result_document["accepted"]
                    if len(accepted) != len(deliveries):
                        raise ValidationFailure(
                            f"{location}: admission result count differs from request"
                        )
                    before_runtimes = {
                        runtime["runtime_id"]: runtime
                        for runtime in prior_aggregate["runtimes"]
                    }
                    after_runtimes = {
                        runtime["runtime_id"]: runtime
                        for runtime in result_state["runtimes"]
                    }
                    if before_runtimes.keys() != after_runtimes.keys():
                        raise ValidationFailure(
                            f"{location}: admission changed runtime identities"
                        )
                    admitted_entries: dict[str, dict[str, Any]] = {}
                    for runtime_id, before_runtime in before_runtimes.items():
                        after_runtime = after_runtimes[runtime_id]
                        requested = [
                            delivery
                            for delivery in deliveries
                            if delivery["envelope"]["target"]
                            == before_runtime["target_identity"]
                        ]
                        before_ready = before_runtime["ready_mailbox"]
                        appended = after_runtime["ready_mailbox"][len(before_ready) :]
                        if (
                            after_runtime["ready_mailbox"][: len(before_ready)]
                            != before_ready
                            or after_runtime["deferred_mailbox"]
                            != before_runtime["deferred_mailbox"]
                            or len(appended) != len(requested)
                        ):
                            raise ValidationFailure(
                                f"{location}: admission mailbox delta is not exact"
                            )
                        for delivery, entry in zip(requested, appended, strict=True):
                            if (
                                entry["envelope"] != delivery["envelope"]
                                or entry["envelope_digest"]
                                != delivery["envelope_digest"]
                                or entry["delivery_mode"]
                                != delivery["delivery_mode"]
                                or entry["deferral_count"] != "0"
                            ):
                                raise ValidationFailure(
                                    f"{location}: admitted mailbox entry metadata differs from request"
                                )
                            admitted_entries[entry["envelope"]["event_id"]] = entry
                        before_projection = copy.deepcopy(before_runtime)
                        after_projection = copy.deepcopy(after_runtime)
                        for projection in (before_projection, after_projection):
                            projection.pop("ready_mailbox")
                            projection.pop("deferred_mailbox")
                        if before_projection != after_projection:
                            raise ValidationFailure(
                                f"{location}: admission changed non-mailbox runtime state"
                            )
                    if set(admitted_entries) != {
                        delivery["envelope"]["event_id"] for delivery in deliveries
                    }:
                        raise ValidationFailure(
                            f"{location}: admission result contains an event not in request"
                        )
                    before_projection = copy.deepcopy(prior_aggregate)
                    after_projection = copy.deepcopy(result_state)
                    for projection in (before_projection, after_projection):
                        projection.pop("aggregate_state_digest")
                        projection.pop("next_acceptance_sequence")
                        projection.pop("next_queue_sequence")
                        for runtime in projection["runtimes"]:
                            runtime.pop("ready_mailbox")
                            runtime.pop("deferred_mailbox")
                    if before_projection != after_projection:
                        raise ValidationFailure(
                            f"{location}: admission changed unrelated aggregate state"
                        )
                    expected_accepted = []
                    for offset, delivery in enumerate(deliveries):
                        event_id = delivery["envelope"]["event_id"]
                        entry = admitted_entries[event_id]
                        expected_acceptance = str(
                            int(prior_aggregate["next_acceptance_sequence"])
                            + offset
                        )
                        expected_queue = str(
                            int(prior_aggregate["next_queue_sequence"]) + offset
                        )
                        if (
                            entry["acceptance_sequence"] != expected_acceptance
                            or entry["queue_sequence"] != expected_queue
                        ):
                            raise ValidationFailure(
                                f"{location}: admission allocation is not contiguous"
                            )
                        expected_accepted.append(
                            {
                                "event_id": event_id,
                                "acceptance_sequence": expected_acceptance,
                                "queue_sequence": expected_queue,
                            }
                        )
                    if (
                        accepted != expected_accepted
                        or result_state["next_acceptance_sequence"]
                        != str(
                            int(prior_aggregate["next_acceptance_sequence"])
                            + len(deliveries)
                        )
                        or result_state["next_queue_sequence"]
                        != str(
                            int(prior_aggregate["next_queue_sequence"])
                            + len(deliveries)
                        )
                    ):
                        raise ValidationFailure(
                            f"{location}: admission reply is not relationally bound"
                        )
            if operation == "step_v2":
                assert prior_aggregate is not None
                target_id = selected["target_runtime_id"]
                prior_runtime = target_runtime(prior_aggregate, target_id)
                result_state = result_document["state"]
                validate_aggregate_against_bundle(result_state, case / vector["bundle"])
                if result_state["root_instance_id"] != prior_aggregate["root_instance_id"]:
                    raise ValidationFailure(f"{location}: step result switched root aggregate")
                if prior_runtime is None:
                    if result_document["disposition"] != "rejected" or result_document["rejection"]["code"] != "invalid_instance_target" or canonical_json_bytes(result_state) != canonical_json_bytes(prior_aggregate):
                        raise ValidationFailure(f"{location}: fabricated runtime identity did not fail unchanged")
                elif (
                    result_document["disposition"] == "rejected"
                    and result_document["rejection"]["code"]
                    == "invalid_instance_target"
                    and not (
                        aggregate_root["status"] != "running"
                        or (
                            prior_runtime["relation"]["kind"] != "component"
                            and prior_runtime["status"] in {"completed", "faulted"}
                        )
                    )
                ):
                    raise ValidationFailure(
                        f"{location}: existing runtime was fabricated as invalid"
                    )
                elif result_document["disposition"] == "rejected" and canonical_json_bytes(result_state) != canonical_json_bytes(prior_aggregate):
                    raise ValidationFailure(f"{location}: rejected target did not preserve exact state")
                elif target_runtime(result_state, target_id) is None and not any(
                    item["target_runtime_id"] == target_id for item in result_document["lifecycle_dispositions"]
                ):
                    raise ValidationFailure(f"{location}: result lost the input runtime identity without disposition")
                if "spawned_mailbox_isolation" in covers and (
                    result_document["disposition"] != "unhandled"
                    or result_state["next_logical_step_sequence"]
                    != prior_aggregate["next_logical_step_sequence"]
                ):
                    raise ValidationFailure(
                        f"{location}: unhandled spawned delivery allocated a logical step"
                    )
                if "fifo_recall_to_ready_tail" in covers:
                    before_runtime = target_runtime(prior_aggregate, target_id)
                    after_runtime = target_runtime(result_state, target_id)
                    assert before_runtime is not None and after_runtime is not None
                    if len(before_runtime["deferred_mailbox"]) < 2 or len(before_runtime["ready_mailbox"]) < 2 or len(after_runtime["deferred_mailbox"]) != 1:
                        raise ValidationFailure(f"{location}: selective recall lacks multiple deferred entries and a ready competitor")
                    competitor = before_runtime["ready_mailbox"][1]["envelope"]["event_id"]
                    recalled = before_runtime["deferred_mailbox"][0]["envelope"]["event_id"]
                    if [entry["envelope"]["event_id"] for entry in after_runtime["ready_mailbox"]] != [competitor, recalled]:
                        raise ValidationFailure(f"{location}: recalled event is not appended behind existing ready work")
                    recalled_event = before_runtime["deferred_mailbox"][0]["envelope"]["event"]
                    retained_event = before_runtime["deferred_mailbox"][1]["envelope"]["event"]
                    remaining = after_runtime["deferred_mailbox"][0]["envelope"]["event"]
                    authorizing = normalized_bundle_value(case / vector["bundle"])["machines"][0]["root"]["states"]["busy"]["states"]["authorizing"]
                    if (
                        recalled_event != "retry"
                        or authorizing["on_events"][recalled_event].get("guard") != "false"
                        or retained_event != "held_request"
                        or remaining != retained_event
                        or retained_event not in authorizing["deferred_events"]
                        or retained_event in authorizing.get("on_events", {})
                    ):
                        raise ValidationFailure(f"{location}: structural recall and deferral-only retention are not distinguished")
                if "deferred_only_not_runnable" in covers:
                    before_runtime = target_runtime(prior_aggregate, target_id)
                    if before_runtime is None or before_runtime["ready_mailbox"] or not before_runtime["deferred_mailbox"] or result_document["disposition"] != "not_runnable":
                        raise ValidationFailure(f"{location}: deferred-only mailbox is not truly non-runnable")
                lifecycle_expectations = {
                    "internal_emission_active_target": ("fanout", "handled"),
                    "internal_emission_retained_faulted_target": ("enter_faulty", "handled"),
                    "lifecycle_cancellation_disposal": ("cancel_after_send", "handled"),
                    "lifecycle_natural_completion_disposal": ("component_finish", "handled"),
                    "internal_emission_chained_provenance": ("component_finish", "handled"),
                    "lifecycle_aggregate_completion_disposal": ("aggregate_finish", "handled"),
                    "cleanup_fault_rollback": ("cleanup_rollback", "faulted"),
                    "reserved_events_not_deferrable": ("determa.component_completed", "handled"),
                }
                for label, (event, disposition) in lifecycle_expectations.items():
                    if label not in covers:
                        continue
                    if result_document["disposition"] != disposition:
                        raise ValidationFailure(f"{location}: lifecycle disposition does not distinguish {label}")
                    if event is not None:
                        before_runtime = target_runtime(prior_aggregate, target_id)
                        if before_runtime is None or not before_runtime["ready_mailbox"] or before_runtime["ready_mailbox"][0]["envelope"]["event"] != event:
                            raise ValidationFailure(f"{location}: lifecycle input does not execute {event}")
                if "lifecycle_cancellation_disposal" in covers and (
                    result_document["status"] != "completed"
                    or not result_document["lifecycle_dispositions"]
                    or any(item["reason"] != "runtime_cancelled" for item in result_document["lifecycle_dispositions"])
                ):
                    raise ValidationFailure(f"{location}: cancellation result lacks exact disposal evidence")
                if "lifecycle_cancellation_disposal" in covers:
                    prior_root = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    result_root = next(
                        runtime
                        for runtime in result_state["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    expected_counters = copy.deepcopy(
                        prior_root["next_state_activation_sequences"]
                    )
                    expected_counters.append(
                        {
                            "definition_pointer": "/machines/0/root/states/finished",
                            "next_sequence": "1",
                        }
                    )
                    expected_counters.sort(key=lambda item: item["definition_pointer"])
                    if (
                        result_root["active_state_activations"]
                        or result_root["next_state_activation_sequences"]
                        != expected_counters
                    ):
                        raise ValidationFailure(
                            f"{location}: completed root lost final-state allocation"
                        )
                    source_entry = prior_root["ready_mailbox"][0]
                    target = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "component"
                        and runtime["relation"]["declaration_index"] == "0"
                    )
                    cause_id = source_entry["envelope"]["cause_id"]
                    expected_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            prior_root["runtime_id"],
                            target["runtime_id"],
                            cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            "/machines/0/root/states/processing/on_events/"
                            "cancel_after_send/action/0/send",
                            "0",
                        ]
                    )
                    expected_envelope = {
                        "event": "component_work",
                        "event_id": expected_event_id,
                        "cause_id": cause_id,
                        "source": {"runtime": prior_root["target_identity"]},
                        "target": target["target_identity"],
                        "payload": ["map", []],
                    }
                    expected_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-2",
                            "2",
                            prior_aggregate["root_instance_id"],
                            "internal",
                            expected_envelope,
                        ]
                    )
                    if (
                        result_document["emissions"][0]["event_id"]
                        != expected_event_id
                        or result_document["lifecycle_dispositions"][0][
                            "request_digest"
                        ]
                        != expected_digest
                    ):
                        raise ValidationFailure(
                            f"{location}: cancelled internal emission provenance is not exact"
                        )
                if "lifecycle_natural_completion_disposal" in covers and not any(
                    item["reason"] == "runtime_completed" for item in result_document["lifecycle_dispositions"]
                ):
                    raise ValidationFailure(f"{location}: natural completion lacks exact disposal evidence")
                if "lifecycle_natural_completion_disposal" in covers:
                    prior_completed_runtime = target_runtime(prior_aggregate, target_id)
                    completed_runtime = target_runtime(result_state, target_id)
                    assert prior_completed_runtime is not None
                    assert completed_runtime is not None
                    complete_pointer = (
                        "/machines/0/root/states/processing/components/0/root/"
                        "states/complete"
                    )
                    expected_counters = copy.deepcopy(
                        prior_completed_runtime["next_state_activation_sequences"]
                    )
                    expected_counters.append(
                        {"definition_pointer": complete_pointer, "next_sequence": "1"}
                    )
                    expected_counters.sort(key=lambda item: item["definition_pointer"])
                    if (
                        completed_runtime["status"] != "completed"
                        or completed_runtime["active_state_activations"]
                        or completed_runtime["next_state_activation_sequences"]
                        != expected_counters
                    ):
                        raise ValidationFailure(
                            f"{location}: completed component lost final-state allocation"
                        )
                    source_entry = prior_completed_runtime["ready_mailbox"][0]
                    cause_id = source_entry["envelope"]["cause_id"]
                    self_locator = (
                        "/machines/0/root/states/processing/components/0/root/"
                        "states/running/on_events/component_finish/action/0/send"
                    )
                    expected_self_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            prior_completed_runtime["runtime_id"],
                            prior_completed_runtime["runtime_id"],
                            cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            self_locator,
                            "0",
                        ]
                    )
                    expected_self_envelope = {
                        "event": "component_work",
                        "event_id": expected_self_event_id,
                        "cause_id": cause_id,
                        "source": {
                            "runtime": prior_completed_runtime[
                                "target_identity"
                            ]
                        },
                        "target": prior_completed_runtime["target_identity"],
                        "payload": ["map", []],
                    }
                    expected_disposal_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-2",
                            "2",
                            prior_aggregate["root_instance_id"],
                            "internal",
                            expected_self_envelope,
                        ]
                    )
                    owner = next(
                        runtime
                        for runtime in result_state["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    completion = owner["ready_mailbox"][0]
                    expected_completion_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            prior_completed_runtime["runtime_id"],
                            owner["runtime_id"],
                            cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            "system:component_completion",
                            "0",
                        ]
                    )
                    if (
                        result_document["emissions"][0]["event_id"]
                        != expected_self_event_id
                        or result_document["lifecycle_dispositions"][0][
                            "request_digest"
                        ]
                        != expected_disposal_digest
                        or completion["envelope"]["event_id"]
                        != expected_completion_id
                        or completion["envelope"]["cause_id"] != cause_id
                        or completion["envelope"]["source"]
                        != {"system": "system:component_completion"}
                        or completion["envelope"]["target"]
                        != owner["target_identity"]
                    ):
                        raise ValidationFailure(
                            f"{location}: completion provenance or disposal digest is not exact"
                        )
                if "internal_emission_chained_provenance" in covers:
                    delivered_runtime = target_runtime(prior_aggregate, target_id)
                    assert delivered_runtime is not None
                    delivered = delivered_runtime["ready_mailbox"][0]["envelope"]
                    owner = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    inherited_cause_id = delivered["cause_id"]
                    first_generation_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            owner["runtime_id"],
                            delivered_runtime["runtime_id"],
                            inherited_cause_id,
                            str(
                                int(
                                    prior_aggregate[
                                        "next_logical_step_sequence"
                                    ]
                                )
                                - 1
                            ),
                            "/machines/0/root/states/processing/on_events/"
                            "finish_left/action/0/send",
                            "0",
                        ]
                    )
                    behavior_cause_id = delivered["event_id"]
                    self_locator = (
                        "/machines/0/root/states/processing/components/0/root/"
                        "states/running/on_events/component_finish/action/0/send"
                    )
                    second_generation_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            delivered_runtime["runtime_id"],
                            delivered_runtime["runtime_id"],
                            behavior_cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            self_locator,
                            "0",
                        ]
                    )
                    second_generation_envelope = {
                        "event": "component_work",
                        "event_id": second_generation_event_id,
                        "cause_id": behavior_cause_id,
                        "source": {
                            "runtime": delivered_runtime["target_identity"]
                        },
                        "target": delivered_runtime["target_identity"],
                        "payload": ["map", []],
                    }
                    disposal_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-2",
                            "2",
                            prior_aggregate["root_instance_id"],
                            "internal",
                            second_generation_envelope,
                        ]
                    )
                    result_owner = next(
                        runtime
                        for runtime in result_state["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    completion = result_owner["ready_mailbox"][0]["envelope"]
                    completion_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            delivered_runtime["runtime_id"],
                            result_owner["runtime_id"],
                            behavior_cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            "system:component_completion",
                            "0",
                        ]
                    )
                    if (
                        delivered["event_id"] != first_generation_event_id
                        or delivered["event_id"] == inherited_cause_id
                        or result_document["emissions"][0]["event_id"]
                        != second_generation_event_id
                        or result_document["lifecycle_dispositions"][0][
                            "request_digest"
                        ]
                        != disposal_digest
                        or completion["event_id"] != completion_event_id
                        or completion["cause_id"] != behavior_cause_id
                        or completion["cause_id"] == inherited_cause_id
                        or completion["source"]
                        != {"system": "system:component_completion"}
                    ):
                        raise ValidationFailure(
                            f"{location}: chained internal emission reused inherited cause"
                        )
                if "lifecycle_aggregate_completion_disposal" in covers and (
                    result_document["status"] != "completed"
                    or not any(item["reason"] == "aggregate_completed" for item in result_document["lifecycle_dispositions"])
                ):
                    raise ValidationFailure(f"{location}: aggregate completion lacks exact disposal evidence")
                if "lifecycle_aggregate_completion_disposal" in covers:
                    prior_root = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    source_entry = prior_root["ready_mailbox"][0]
                    cause_id = source_entry["envelope"]["cause_id"]
                    expected_event_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            prior_root["runtime_id"],
                            prior_root["runtime_id"],
                            cause_id,
                            prior_aggregate["next_logical_step_sequence"],
                            "/machines/0/root/on_events/aggregate_finish/action/0/send",
                            "0",
                        ]
                    )
                    expected_envelope = {
                        "event": "component_work",
                        "event_id": expected_event_id,
                        "cause_id": cause_id,
                        "source": {"runtime": prior_root["target_identity"]},
                        "target": prior_root["target_identity"],
                        "payload": ["map", []],
                    }
                    expected_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-2",
                            "2",
                            prior_aggregate["root_instance_id"],
                            "internal",
                            expected_envelope,
                        ]
                    )
                    if (
                        result_document["emissions"][0]["event_id"]
                        != expected_event_id
                        or result_document["lifecycle_dispositions"][0][
                            "request_digest"
                        ]
                        != expected_digest
                    ):
                        raise ValidationFailure(
                            f"{location}: aggregate-completion emission provenance is not exact"
                        )
                if "cleanup_fault_rollback" in covers and (result_document["emissions"] or result_document["lifecycle_dispositions"]):
                    raise ValidationFailure(f"{location}: cleanup fault did not roll back emissions and disposal")
                if "internal_emission_active_target" in covers:
                    source = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    parent_cause = source["ready_mailbox"][0]["envelope"][
                        "cause_id"
                    ]
                    result_entries = {
                        entry["envelope"]["event_id"]: entry
                        for runtime in result_state["runtimes"]
                        for entry in runtime["ready_mailbox"]
                        if entry["delivery_mode"] == "internal"
                    }
                    targets = sorted(
                        (
                            runtime
                            for runtime in prior_aggregate["runtimes"]
                            if runtime["relation"]["kind"] == "component"
                        ),
                        key=lambda runtime: int(
                            runtime["relation"]["declaration_index"]
                        ),
                    )
                    for ordinal, target in enumerate(targets):
                        expected_event_id = hash_value(
                            [
                                "determa-event-identity-1",
                                "1",
                                prior_aggregate["root_instance_id"],
                                source["runtime_id"],
                                target["runtime_id"],
                                parent_cause,
                                prior_aggregate["next_logical_step_sequence"],
                                "/machines/0/root/states/processing/on_events/"
                                "fanout/action/0/send",
                                str(ordinal),
                            ]
                        )
                        entry = result_entries.get(expected_event_id)
                        if (
                            entry is None
                            or entry["envelope"]["cause_id"] != parent_cause
                            or entry["envelope"]["source"]
                            != {"runtime": source["target_identity"]}
                            or entry["envelope"]["target"]
                            != target["target_identity"]
                            or entry["envelope"]["event_id"]
                            == entry["envelope"]["cause_id"]
                        ):
                            raise ValidationFailure(
                                f"{location}: internal fanout provenance is not normative"
                            )
                    component_targets = {runtime["runtime_id"] for runtime in prior_aggregate["runtimes"] if runtime["relation"]["kind"] == "component"}
                    emitted_targets = {
                        entry["envelope"]["target"]["component"]["component_runtime_id"]
                        for runtime in result_state["runtimes"]
                        for entry in runtime["ready_mailbox"]
                        if "component" in entry["envelope"]["target"] and entry["delivery_mode"] == "internal"
                    }
                    if emitted_targets != component_targets:
                        raise ValidationFailure(f"{location}: fanout did not account for every component target")
                if "internal_emission_retained_faulted_target" in covers:
                    faulty = next(
                        runtime
                        for runtime in result_state["runtimes"]
                        if runtime["relation"].get("component_id") == "faulty"
                    )
                    owner = next(
                        runtime
                        for runtime in result_state["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    parent_cause = next(
                        runtime
                        for runtime in prior_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )["ready_mailbox"][0]["envelope"]["cause_id"]
                    pointer = faulty["identity_origin"][
                        "component_definition_pointer"
                    ]
                    activation = faulty["identity_origin"]["activation_sequence"]
                    initialization_cause = hash_value(
                        [
                            "determa-cause-identity-1",
                            "1",
                            "component_initialization",
                            prior_aggregate["root_instance_id"],
                            owner["runtime_id"],
                            faulty["runtime_id"],
                            parent_cause,
                            prior_aggregate["next_logical_step_sequence"],
                            pointer,
                            faulty["identity_origin"]["declaration_index"],
                        ]
                    )
                    pending = faulty["ready_mailbox"][0]
                    expected_pending_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            owner["runtime_id"],
                            faulty["runtime_id"],
                            parent_cause,
                            prior_aggregate["next_logical_step_sequence"],
                            f"{pointer.rsplit('/components/', 1)[0]}/entry/0/send",
                            "0",
                        ]
                    )
                    failure = owner["ready_mailbox"][0]
                    expected_failure_id = hash_value(
                        [
                            "determa-event-identity-1",
                            "1",
                            prior_aggregate["root_instance_id"],
                            faulty["runtime_id"],
                            owner["runtime_id"],
                            initialization_cause,
                            prior_aggregate["next_logical_step_sequence"],
                            "system:component_failure",
                            "0",
                        ]
                    )
                    if (
                        not isinstance(activation, str)
                        or faulty["status"] != "faulted"
                        or faulty["active_state_activations"]
                        or faulty["variables"]
                        or len(faulty["ready_mailbox"]) != 1
                        or faulty["ready_mailbox"][0]["envelope"]["event"]
                        != "component_work"
                        or faulty["fault"]["code"] != "action_fault"
                        or len(owner["ready_mailbox"]) != 1
                        or owner["ready_mailbox"][0]["envelope"]["event"]
                        != "determa.component_failed"
                        or faulty["fault"]["cause_id"] != initialization_cause
                        or pending["envelope"]["event_id"] != expected_pending_id
                        or pending["envelope"]["cause_id"] != parent_cause
                        or failure["envelope"]["event_id"]
                        != expected_failure_id
                        or failure["envelope"]["cause_id"]
                        != initialization_cause
                        or failure["envelope"]["source"]
                        != {"system": "system:component_failure"}
                        or len(result_document["emissions"]) != 2
                        or result_document["fault"] is not None
                    ):
                        raise ValidationFailure(
                            f"{location}: same-RTC retained fault is not closed"
                        )
            if operation == "migrate_aggregate_v2":
                assert prior_aggregate is not None
                migrated = result_document["aggregate_state"]
                expected_audit_records = []
                audit_source = prior_aggregate
                for descriptor_index, descriptor in enumerate(descriptors):
                    if descriptor_index == len(descriptors) - 1:
                        audit_target = migrated
                    else:
                        if descriptor["mode"] != "compatible":
                            raise ValidationFailure(
                                f"{location}: intermediate transform lacks exact candidate"
                            )
                        audit_target = copy.deepcopy(audit_source)
                        next_fingerprint = descriptor[
                            "target_validated_bundle_fingerprint"
                        ]
                        audit_target["validated_bundle_fingerprint"] = next_fingerprint
                        audit_target["migration_sequence"] = str(
                            int(audit_target["migration_sequence"]) + 1
                        )
                        for runtime in audit_target["runtimes"]:
                            runtime["current_definition"][
                                "validated_bundle_fingerprint"
                            ] = next_fingerprint
                        audit_target.pop("aggregate_state_digest", None)
                        audit_target["aggregate_state_digest"] = hash_value(
                            ["determa-aggregate-state-digest-2", audit_target]
                        )
                    expected_audit_records.append(
                        {
                            "migration_audit_record_schema_version": 2,
                            "root_instance_id": prior_aggregate["root_instance_id"],
                            "root_runtime_id": prior_aggregate["root_runtime_id"],
                            "migration_sequence": audit_target[
                                "migration_sequence"
                            ],
                            "source_validated_bundle_fingerprint": audit_source[
                                "validated_bundle_fingerprint"
                            ],
                            "target_validated_bundle_fingerprint": audit_target[
                                "validated_bundle_fingerprint"
                            ],
                            "migration_descriptor_digest": descriptor[
                                "migration_descriptor_digest"
                            ],
                            "source_aggregate_state_digest": audit_source[
                                "aggregate_state_digest"
                            ],
                            "target_aggregate_state_digest": audit_target[
                                "aggregate_state_digest"
                            ],
                            "result_code": "migration_applied",
                        }
                    )
                    audit_source = audit_target
                if result_document.get("audit_records") != expected_audit_records:
                    raise ValidationFailure(
                        f"{location}: migration audit omission, order, or content mismatch"
                    )
                if not descriptors and (
                    migrated != prior_aggregate or result_document["dispositions"]
                ):
                    raise ValidationFailure(
                        f"{location}: empty migration route is not an exact no-op"
                    )
                validate_aggregate_against_bundle(
                    migrated,
                    case / selected["target_bundle"]["bundle_file"],
                    case / selected["source_bundle"]["bundle_file"],
                )
                target_fingerprint = selected["target_bundle"][
                    "validated_bundle_fingerprint"
                ]
                if (
                    migrated["validated_bundle_fingerprint"] != target_fingerprint
                    or int(migrated["migration_sequence"])
                    != int(prior_aggregate["migration_sequence"])
                    + len(descriptors)
                    or any(
                        runtime["current_definition"]["validated_bundle_fingerprint"]
                        != target_fingerprint
                        for runtime in migrated["runtimes"]
                    )
                ):
                    raise ValidationFailure(f"{location}: migration result does not bind the exact target")
                prior_runtime_ids = {runtime["runtime_id"] for runtime in prior_aggregate["runtimes"]}
                if {runtime["runtime_id"] for runtime in migrated["runtimes"]} != prior_runtime_ids:
                    raise ValidationFailure(f"{location}: migration changed runtime identity")
                if "migration_historical_fault_locator_preservation" in covers:
                    faulted = next(
                        runtime
                        for runtime in migrated["runtimes"]
                        if runtime["fault"] is not None
                    )
                    if (
                        faulted["fault"]["definition_fingerprint"]
                        != selected["source_bundle"][
                            "validated_bundle_fingerprint"
                        ]
                        or faulted["fault"]["source_locator"]
                        != (
                            "/machines/0/root/states/busy/states/receiving/"
                            "on_events/received/action/0/send/payload/amount"
                        )
                        or faulted["active_leaf_state_definition_pointers"]
                        != [
                            "/machines/0/root/states/busy/states/"
                            "receiving_replacement"
                        ]
                    ):
                        raise ValidationFailure(
                            f"{location}: historical fault locator was rewritten"
                        )
            if operation == "migrate_aggregate_v2":
                assert prior_aggregate is not None
                migrated = result_document["aggregate_state"]
                if migrated["validated_bundle_fingerprint"] != selected["target_bundle"]["validated_bundle_fingerprint"]:
                    raise ValidationFailure(f"{location}: migration result is not bound to target definition")
                before_ids = {
                    entry["envelope"]["event_id"]
                    for runtime in prior_aggregate["runtimes"]
                    for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
                    for entry in mailbox
                }
                after_ids = {
                    entry["envelope"]["event_id"]
                    for runtime in migrated["runtimes"]
                    for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
                    for entry in mailbox
                }
                disposed_count = len(result_document["dispositions"])
                if len(before_ids - after_ids) != disposed_count or not after_ids <= before_ids:
                    raise ValidationFailure(f"{location}: migration preservation/disposal result is inconsistent")
            if "native_internal_handler_provenance" in covers:
                checkpoint_before = artifact(vector["checkpoint_before"]).document
                before_aggregate = checkpoint_before["root_record"]["aggregate_state"]
                before_root = next(
                    runtime
                    for runtime in before_aggregate["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                source_entry = before_root["ready_mailbox"][0]
                result_aggregate = result_document["root_record"]["aggregate_state"]
                result_root = next(
                    runtime
                    for runtime in result_aggregate["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                produced = result_root["ready_mailbox"]
                if len(produced) != 1:
                    raise ValidationFailure(
                        f"{location}: native handler did not produce exactly one event"
                    )
                expected_event_id = hash_value(
                    [
                        "determa-event-identity-1",
                        "1",
                        before_aggregate["root_instance_id"],
                        before_root["runtime_id"],
                        before_root["runtime_id"],
                        source_entry["envelope"]["cause_id"],
                        before_aggregate["next_logical_step_sequence"],
                        "/machines/0/root/on_events/emit_internal/action/0/send",
                        "0",
                    ]
                )
                producer_receipt = result_document["operation_receipts"][-1]
                if (
                    source_entry["envelope"]["event"] != "emit_internal"
                    or produced[0]["envelope"]["event"] != "internal_increment"
                    or produced[0]["envelope"]["event_id"] != expected_event_id
                    or produced[0]["envelope"]["cause_id"]
                    != source_entry["envelope"]["cause_id"]
                    or produced[0]["envelope"]["event_id"]
                    == produced[0]["envelope"]["cause_id"]
                    or produced[0]["envelope"]["source"]
                    != {"runtime": before_root["target_identity"]}
                    or producer_receipt["event_id"]
                    != source_entry["envelope"]["event_id"]
                    or producer_receipt["emission_references"][0]["event_id"]
                    != expected_event_id
                ):
                    raise ValidationFailure(
                        f"{location}: native internal provenance is not handler-derived"
                    )
        if (
            expectation["result"] == "failure"
            and expectation["code"] not in failure_evidence
        ):
            raise ValidationFailure(
                f"{location}: rejection label lacks an operation-specific supporting predicate"
            )
        unchanged_file = expectation.get("unchanged_file")
        if unchanged_file is not None:
            if unchanged_file not in artifact_names:
                raise ValidationFailure(
                    f"{location}: undeclared unchanged artifact {unchanged_file}"
                )
            prior = vector.get("state_before", vector.get("checkpoint_before"))
            if prior is not None and unchanged_file != prior:
                raise ValidationFailure(
                    f"{location}: failure must preserve the exact supplied artifact"
                )
    return coverage










def resolve_artifact_pointer(document: Any, pointer: str, location: str) -> Any:
    value = document
    try:
        for encoded in pointer.split("/")[1:]:
            part = encoded.replace("~1", "/").replace("~0", "~")
            value = value[int(part)] if isinstance(value, list) else value[part]
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise ValidationFailure(f"{location}: unresolved artifact pointer {pointer}") from error
    return value


def checkpoint_identity(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "root_instance_id": checkpoint["root_instance_id"],
        "revision": checkpoint["revision"],
        "digest": checkpoint["execution_checkpoint_digest"],
    }


def checkpoint_aggregate(checkpoint: dict[str, Any]) -> dict[str, Any] | None:
    root_record = checkpoint["root_record"]
    return root_record.get("aggregate_state") if root_record["status"] == "retained" else None


def checkpoint_mailbox_entries(checkpoint: dict[str, Any]) -> list[dict[str, Any]]:
    aggregate = checkpoint_aggregate(checkpoint)
    if aggregate is None:
        return []
    return [
        entry
        for runtime in aggregate["runtimes"]
        for mailbox in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
        for entry in mailbox
    ]


def validate_request_checkpoint_binding(
    operation_input: dict[str, Any],
    checkpoint_before: dict[str, Any],
    artifacts: dict[str, Any],
    location: str,
) -> None:
    expected = operation_input.get("expected_checkpoint") or operation_input.get(
        "existing_checkpoint"
    )
    if expected is None:
        return
    del artifacts
    if expected != checkpoint_identity(checkpoint_before):
        raise ValidationFailure(
            f"{location}: request checkpoint identity differs from checkpoint_before"
        )


def durable_admission_contract_error(
    delivery: dict[str, Any],
    checkpoint: dict[str, Any],
    bundle_path: Path,
) -> str | None:
    mode = delivery["delivery_mode"]
    envelope = delivery["envelope"]
    if mode not in {"input", "internal"}:
        return "invalid_delivery_mode"
    if mode == "input" and (
        envelope["source"] != {"host": True}
        or envelope["cause_id"] != envelope["event_id"]
    ):
        return "invalid_delivery_source"
    if mode == "internal" and "host" in envelope["source"]:
        return "invalid_delivery_source"

    aggregate = checkpoint_aggregate(checkpoint)
    if aggregate is None:
        return "tombstoned_root"
    runtime = next(
        (
            item
            for item in aggregate["runtimes"]
            if item["target_identity"] == envelope["target"]
        ),
        None,
    )
    if runtime is None:
        return "invalid_instance_target"
    if runtime["relation"]["kind"] == "component" and runtime["status"] != "running":
        return "inactive_component_target"
    if runtime["status"] != "running":
        return "invalid_instance_target"
    if runtime["relation"]["kind"] == "component" and mode == "input":
        return "invalid_instance_target"

    bundle = normalized_bundle_value(bundle_path)
    machine_identity = runtime["current_definition"]["machine"]
    machine = next(
        (
            item
            for item in bundle["machines"]
            if item["machine_id"] == machine_identity["machine_id"]
            and str(item["version"]) == machine_identity["machine_version"]
        ),
        None,
    )
    if machine is None:
        return "invalid_instance_target"
    declaration = bundle.get("events", {}).get(envelope["event"])
    if declaration is None:
        declaration = machine.get("events", {}).get(envelope["event"])
    if declaration is None:
        return "invalid_event"
    required_direction = "input" if mode == "input" else "internal"
    if declaration.get("direction", "internal") != required_direction:
        return "invalid_event"

    payload = decode_typed_value(envelope["payload"])
    if not isinstance(payload, dict):
        return "invalid_payload"
    fields = declaration.get("payload", {})
    if set(payload) - set(fields):
        return "invalid_payload"

    def value_matches_type(value: Any, expected_type: str) -> bool:
        return {
            "string": isinstance(value, str),
            "int": isinstance(value, int) and not isinstance(value, bool),
            "float": isinstance(value, (int, float)) and not isinstance(value, bool),
            "bool": isinstance(value, bool),
            "map": isinstance(value, dict),
            "list": isinstance(value, list),
        }[expected_type]

    for name, field in fields.items():
        if field.get("required", False) and name not in payload:
            return "invalid_payload"
        if name in payload and not value_matches_type(payload[name], field["type"]):
            return "invalid_payload"

    correlates_to = declaration.get("correlates_to")
    if correlates_to is not None:
        correlation_id = envelope.get("correlation_id")
        correlated_effects = {
            record["intent"]["effect_id"]
            for record in checkpoint["pending_outbox_intents"]
            if record["intent"]["event"] == correlates_to
        } | {
            record["intent"]["effect_id"]
            for record in checkpoint["terminal_outbox_records"]
            if record["intent"]["event"] == correlates_to
        }
        if not isinstance(correlation_id, str) or correlation_id not in correlated_effects:
            return "invalid_correlation"

    expected_digest = hash_value(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            checkpoint["root_instance_id"],
            mode,
            envelope,
        ]
    )
    if delivery["envelope_digest"] != expected_digest:
        return "delivery_digest_mismatch"
    return None


def host_profile_failure_code(operation_input: dict[str, Any]) -> str | None:
    requirements = HOST_PROFILE_REQUIREMENTS[operation_input["host_profile"]]
    store_capabilities = set(operation_input["store_capabilities"])
    host_guarantees = set(operation_input["host_guarantees"])
    durable = bool(
        store_capabilities & {"durable_single_writer", "durable_concurrent"}
    )
    satisfied = (
        requirements["store"] <= store_capabilities
        and requirements["host"] <= host_guarantees
        and (not requirements["durable"] or durable)
        and (
            not requirements["permanent"]
            or operation_input["retention_mode"] == "permanent"
        )
    )
    return None if satisfied else "adapter_capability_mismatch"


def validate_checkpoint_derivation(
    operation_input: dict[str, Any],
    operation_result: dict[str, Any],
    checkpoint_before: dict[str, Any] | None,
    checkpoint_after: dict[str, Any],
    location: str,
    bundle_path: Path,
) -> None:
    operation = operation_input["operation"]
    mutates = operation_result["mutation"] == "atomic"
    if checkpoint_before is not None and mutates:
        expected_revision = int(checkpoint_before["revision"]) + 1
        if int(checkpoint_after["revision"]) != expected_revision:
            raise ValidationFailure(
                f"{location}: atomic operation must advance revision exactly once"
            )
    if operation == "checkpoint_create_v2":
        if not mutates:
            return
        aggregate = checkpoint_aggregate(checkpoint_after)
        if aggregate is None:
            raise ValidationFailure(f"{location}: creation did not retain an aggregate")
        receipt = checkpoint_after["operation_receipts"][0]
        definition = next(
            runtime for runtime in aggregate["runtimes"] if runtime["relation"]["kind"] == "root"
        )["current_definition"]["machine"]
        if (
            checkpoint_after["revision"] != "0"
            or aggregate["root_instance_id"] != operation_input["root_instance_id"]
            or aggregate["creation_id"] != operation_input["creation_id"]
            or aggregate["validated_bundle_fingerprint"]
            != operation_input["bundle"]["validated_bundle_fingerprint"]
            or definition != operation_input["machine"]
            or receipt["creation_id"] != operation_input["creation_id"]
            or checkpoint_after["replay_retention"]["mode"]
            != operation_input["retention_mode"]
        ):
            raise ValidationFailure(f"{location}: creation result is not request-derived")
        return
    if checkpoint_before is None:
        return
    if operation == "checkpoint_admit_v2":
        deliveries = operation_input["envelopes"]
        expected_code = None
        if not deliveries:
            expected_code = "malformed_delivery"
        if expected_code is None:
            roots = []
            for delivery in deliveries:
                target = next(iter(delivery["envelope"]["target"].values()))
                roots.append(target["root_instance_id"])
            if any(root != checkpoint_before["root_instance_id"] for root in roots):
                expected_code = "wrong_root"
        event_ids = [item["envelope"]["event_id"] for item in deliveries]
        if expected_code is None and len(event_ids) != len(set(event_ids)):
            expected_code = "duplicate_event_id_in_batch"

        retained_digests: dict[str, set[str]] = {}
        for receipt in checkpoint_before["operation_receipts"]:
            if "event_id" in receipt:
                retained_digests.setdefault(receipt["event_id"], set()).add(
                    receipt["request_digest"]
                )
        for tombstone in checkpoint_before["event_identity_tombstones"]:
            retained_digests.setdefault(tombstone["event_id"], set()).add(
                tombstone["request_digest"]
            )
        for entry in checkpoint_mailbox_entries(checkpoint_before):
            retained_digests.setdefault(entry["envelope"]["event_id"], set()).add(
                entry["envelope_digest"]
            )
        replayed = []
        if expected_code is None:
            for delivery in deliveries:
                event_id = delivery["envelope"]["event_id"]
                known = retained_digests.get(event_id, set())
                canonical_digest = hash_value(
                    [
                        "determa-inbox-envelope-digest-2",
                        "2",
                        checkpoint_before["root_instance_id"],
                        delivery["delivery_mode"],
                        delivery["envelope"],
                    ]
                )
                if known and canonical_digest not in known:
                    expected_code = "event_id_conflict"
                    break
                replayed.append(bool(known))

        new_deliveries = [
            delivery
            for index, delivery in enumerate(deliveries)
            if index >= len(replayed) or not replayed[index]
        ]
        if expected_code is None and new_deliveries:
            if checkpoint_before["root_record"]["status"] == "tombstone":
                expected_code = "tombstoned_root"
            else:
                root = next(
                    runtime
                    for runtime in checkpoint_aggregate(checkpoint_before)["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                if root["status"] in {"completed", "faulted"}:
                    expected_code = "terminal_root"
        if expected_code is None:
            for delivery in new_deliveries:
                expected_code = durable_admission_contract_error(
                    delivery, checkpoint_before, bundle_path
                )
                if expected_code is not None:
                    break

        if expected_code is not None:
            if operation_result.get("code") != expected_code or mutates:
                raise ValidationFailure(
                    f"{location}: admission failure is not request-derived"
                )
        elif operation_result.get("code") == "checkpoint_revision_conflict":
            if mutates:
                raise ValidationFailure(f"{location}: stale admission mutated checkpoint")
        elif not new_deliveries:
            if operation_result["result"] != "replayed" or mutates:
                raise ValidationFailure(f"{location}: all-replay batch is not read-only")
        else:
            if operation_result["result"] != "committed" or not mutates:
                raise ValidationFailure(f"{location}: valid admission batch did not commit")
            before_acceptance = int(
                checkpoint_aggregate(checkpoint_before)["next_acceptance_sequence"]
            )
            before_queue = int(
                checkpoint_aggregate(checkpoint_before)["next_queue_sequence"]
            )
            accepted_revision = checkpoint_after["revision"]
            for offset, delivery in enumerate(new_deliveries):
                envelope = delivery["envelope"]
                matching_receipts = [
                    receipt
                    for receipt in checkpoint_after["operation_receipts"]
                    if receipt["operation_kind"] == "acceptance"
                    and receipt["event_id"] == envelope["event_id"]
                    and receipt["request_digest"] == delivery["envelope_digest"]
                    and receipt["acceptance_sequence"]
                    == str(before_acceptance + offset)
                    and receipt["accepted_revision"] == accepted_revision
                ]
                matching_entries = [
                    entry
                    for entry in checkpoint_mailbox_entries(checkpoint_after)
                    if entry["envelope"] == envelope
                    and entry["envelope_digest"] == delivery["envelope_digest"]
                    and entry["acceptance_sequence"] == str(before_acceptance + offset)
                    and entry["queue_sequence"] == str(before_queue + offset)
                ]
                if len(matching_receipts) != 1 or len(matching_entries) != 1:
                    raise ValidationFailure(
                        f"{location}: ordered admission result is not request-derived"
                    )
    elif operation == "checkpoint_step_v2" and mutates:
        before_entries = [
            entry
            for entry in checkpoint_mailbox_entries(checkpoint_before)
            if entry["envelope"]["event_id"] == operation_input["event_id"]
            and entry["envelope_digest"] == operation_input["envelope_digest"]
            and entry["envelope"]["target"] == operation_input["target"]
            and entry["acceptance_sequence"] == operation_input["acceptance_sequence"]
            and entry["queue_sequence"] == operation_input["queue_sequence"]
        ]
        receipts = [
            receipt
            for receipt in checkpoint_after["operation_receipts"]
            if receipt["operation_kind"] == "event_terminal"
            and receipt["event_id"] == operation_input["event_id"]
            and receipt["request_digest"] == operation_input["envelope_digest"]
        ]
        if len(before_entries) != 1 or len(receipts) != 1:
            raise ValidationFailure(f"{location}: processing result is not request-derived")
    elif operation in {"checkpoint_update_outbox_v2", "checkpoint_terminalize_outbox_v2"}:
        effect_id = operation_input["effect_id"]
        before_matches = [
            record
            for record in checkpoint_before["pending_outbox_intents"]
            if record["intent"]["effect_id"] == effect_id
        ]
        after_pending = [
            record
            for record in checkpoint_after["pending_outbox_intents"]
            if record["intent"]["effect_id"] == effect_id
        ]
        after_terminal = [
            record
            for record in checkpoint_after["terminal_outbox_records"]
            if record["intent"]["effect_id"] == effect_id
        ]
        if mutates and len(before_matches) != 1:
            raise ValidationFailure(f"{location}: outbox effect is not pending")
        if mutates and operation == "checkpoint_update_outbox_v2":
            expected_state = {"status": operation_input["target_disposition"]}
            if operation_input["outcome"]["reason_code"] is not None:
                expected_state["reason_code"] = operation_input["outcome"]["reason_code"]
            if len(after_pending) != 1 or after_pending[0]["delivery_state"] != expected_state:
                raise ValidationFailure(f"{location}: pending outbox result is not request-derived")
        if mutates and operation == "checkpoint_terminalize_outbox_v2":
            expected_outcome = {"status": operation_input["target_disposition"]}
            if operation_input["outcome"]["reason_code"] is not None:
                expected_outcome["reason_code"] = operation_input["outcome"]["reason_code"]
            if (
                len(after_terminal) != 1
                or after_terminal[0]["outcome"] != expected_outcome
                or operation_input["outcome"]["durable_acceptance"]
                != (operation_input["target_disposition"] == "confirmed")
            ):
                raise ValidationFailure(f"{location}: terminal outbox result is not request-derived")
        if not mutates:
            retained_dispositions = [
                record["delivery_state"]["status"] for record in after_pending
            ] + [record["outcome"]["status"] for record in after_terminal]
            retained_dispositions.extend(
                record["outcome"]["status"]
                for record in checkpoint_after["outbox_effect_tombstones"]
                if record["effect_id"] == effect_id
            )
            if operation_result["result"] == "replayed" and operation_input["target_disposition"] not in retained_dispositions:
                raise ValidationFailure(f"{location}: outbox replay is not retained")
            if operation_result.get("code") == "effect_id_conflict" and (
                not retained_dispositions
                or operation_input["target_disposition"] in retained_dispositions
            ):
                raise ValidationFailure(f"{location}: outbox conflict is not request-derived")
        before_other = {
            record["intent"]["effect_id"]: record
            for record in checkpoint_before["pending_outbox_intents"]
            if record["intent"]["effect_id"] != effect_id
        }
        after_other = {
            record["intent"]["effect_id"]: record
            for record in checkpoint_after["pending_outbox_intents"]
            if record["intent"]["effect_id"] != effect_id
        }
        if mutates and before_other != after_other:
            raise ValidationFailure(f"{location}: outbox request changed unrelated effects")
    elif operation == "checkpoint_compact_outbox_v2":
        effect_id = operation_input["effect_id"]
        before_terminal = [
            record
            for record in checkpoint_before["terminal_outbox_records"]
            if record["intent"]["effect_id"] == effect_id
        ]
        after_tombstones = [
            record
            for record in checkpoint_after["outbox_effect_tombstones"]
            if record["effect_id"] == effect_id
        ]
        if mutates and (
            len(before_terminal) != 1
            or len(after_tombstones) != 1
            or after_tombstones[0]["intent_digest"] != operation_input["intent_digest"]
            or any(
                record["intent"]["effect_id"] == effect_id
                for record in checkpoint_after["terminal_outbox_records"]
            )
        ):
            raise ValidationFailure(f"{location}: outbox compaction is not request-derived")
        if not mutates and not after_tombstones:
            raise ValidationFailure(f"{location}: compacted effect identity was deleted")
    elif operation == "checkpoint_prune_v2" and mutates:
        retention = checkpoint_after["replay_retention"]
        if (
            retention["mode"] != operation_input["target_mode"]
            or retention["pruned_through_receipt_sequence"]
            != operation_input["cutoff_receipt_sequence"]
            or retention["policy_identifier"] != operation_input["policy_identifier"]
        ):
            raise ValidationFailure(f"{location}: pruning result is not request-derived")
    elif operation == "checkpoint_prune_v2" and operation_result["result"] == "replayed":
        retention = checkpoint_before["replay_retention"]
        if (
            retention["mode"] != operation_input["target_mode"]
            or retention["pruned_through_receipt_sequence"]
            != operation_input["cutoff_receipt_sequence"]
        ):
            raise ValidationFailure(f"{location}: pruning replay is not request-derived")
    elif operation == "checkpoint_prune_v2" and operation_result["result"] == "rejected":
        receipt_sequences = {
            receipt["receipt_sequence"]
            for receipt in checkpoint_before["operation_receipts"]
        }
        effect_ids = {
            record["intent"]["effect_id"]
            for record in checkpoint_before["pending_outbox_intents"]
        } | {
            record["intent"]["effect_id"]
            for record in checkpoint_before["terminal_outbox_records"]
        } | {
            record["effect_id"] for record in checkpoint_before["outbox_effect_tombstones"]
        }
        if not (
            operation_result.get("code") == "checkpoint_revision_conflict"
            or
            set(operation_input["dependency_receipt_sequences"]) & receipt_sequences
            or set(operation_input["dependency_effect_ids"]) & effect_ids
            or operation_input["target_mode"] == "permanent"
            or int(operation_input["cutoff_receipt_sequence"])
            < int(checkpoint_before["replay_retention"].get("pruned_through_receipt_sequence") or 0)
            or operation_input["expected_checkpoint"] != checkpoint_identity(checkpoint_before)
        ):
            raise ValidationFailure(f"{location}: rejected pruning has no request-derived conflict")
    elif operation == "checkpoint_tombstone_v2" and mutates:
        root_record = checkpoint_after["root_record"]
        if (
            root_record["status"] != "tombstone"
            or root_record["terminal_status"] != operation_input["terminal_status"]
            or root_record["tombstone_operation_id"]
            != operation_input["tombstone_operation_id"]
        ):
            raise ValidationFailure(f"{location}: tombstone result is not request-derived")
    elif operation == "checkpoint_tombstone_v2" and operation_result["result"] == "replayed":
        root_record = checkpoint_before["root_record"]
        if (
            root_record["status"] != "tombstone"
            or root_record["terminal_status"] != operation_input["terminal_status"]
            or root_record["tombstone_operation_id"]
            != operation_input["tombstone_operation_id"]
        ):
            raise ValidationFailure(f"{location}: tombstone replay is not request-derived")
    elif operation == "checkpoint_register_adapter_v2":
        identifier = operation_input["registration"]["adapter_identifier"]
        duplicate = any(
            item["adapter_identifier"] == identifier
            for item in operation_input["existing_registrations"]
        )
        expected_code = "duplicate_adapter_registration" if duplicate else None
        if operation_result.get("code") != expected_code:
            raise ValidationFailure(f"{location}: adapter registration result is not request-derived")
    elif operation == "checkpoint_resolve_adapter_v2":
        matches = [
            item
            for item in operation_input["registrations"]
            if item["adapter_identifier"] == operation_input["adapter_identifier"]
            and operation_input["uri"].split(":", 1)[0] == item["uri_scheme"]
        ]
        expected_code = None
        if not matches:
            expected_code = "unknown_adapter"
        else:
            configuration_errors = list(
                Draft202012Validator(matches[0]["configuration_schema"]).iter_errors(
                    operation_input["configuration"]
                )
            )
            if configuration_errors:
                expected_code = "invalid_adapter_configuration"
            elif not set(operation_input["requested_capabilities"]) <= set(
                matches[0]["capabilities"]
            ):
                expected_code = "adapter_capability_mismatch"
        if operation_result.get("code") != expected_code:
            raise ValidationFailure(f"{location}: adapter resolution result is not request-derived")
    elif operation == "checkpoint_validate_capabilities_v2":
        expected_code = host_profile_failure_code(operation_input)
        if operation_result.get("code") != expected_code:
            raise ValidationFailure(f"{location}: composed profile result is not request-derived")
    elif operation == "checkpoint_scope_operation_v2":
        expected_code = (
            None
            if operation_input["scope"]["authorization"] == "authorized"
            else "invalid_store_scope"
        )
        if operation_result.get("code") != expected_code:
            raise ValidationFailure(f"{location}: scope result is not request-derived")
        records = operation_input["store_records"]
        record_keys = {
            (record["scope_id"], record["ownership_binding"]) for record in records
        }
        matching = [
            record
            for record in records
            if record["scope_id"] == operation_input["scope"]["scope_id"]
            and record["ownership_binding"]
            == operation_input["scope"]["ownership_binding"]
        ]
        if (
            len(record_keys) != len(records)
            or any(
                record["portable_identity"] != operation_input["portable_identity"]
                or record["effect_id"] != operation_input["effect_id"]
                for record in records
            )
            or operation_input["portable_identity"]
            != checkpoint_before["root_instance_id"]
            or (
                operation_input["scope"]["authorization"] == "authorized"
                and len(matching) != 1
            )
        ):
            raise ValidationFailure(f"{location}: scoped store records are not isolated")
    elif operation == "checkpoint_backup_restore_v2":
        complete = bool(operation_input["checkpoint_digests"]) and (
            checkpoint_before["root_record"]["status"] == "tombstone"
            or bool(operation_input["trusted_artifact_digests"])
        )
        expected_code = None if complete else "invalid_execution_checkpoint"
        if operation_result.get("code") != expected_code:
            raise ValidationFailure(f"{location}: backup or restore result is not request-derived")
        if checkpoint_before["execution_checkpoint_digest"] not in operation_input["checkpoint_digests"]:
            raise ValidationFailure(f"{location}: backup omits the supplied checkpoint")
        if operation_input["retention_mode"] != checkpoint_before["replay_retention"]["mode"]:
            raise ValidationFailure(f"{location}: backup changes the retention mode")
    elif operation == "checkpoint_inject_store_v2":
        if operation_result["result"] != "validated" or not operation_input["capabilities"]:
            raise ValidationFailure(f"{location}: direct store injection result is not request-derived")


def validate_persistence_derivation(
    operation_input: dict[str, Any],
    operation_result: dict[str, Any],
    store_before: dict[str, Any],
    store_after: dict[str, Any],
    location: str,
) -> None:
    checkpoint_before = store_before["checkpoint"]
    if operation_input["expected_checkpoint"] != checkpoint_identity(checkpoint_before):
        raise ValidationFailure(f"{location}: persistence request checkpoint mismatch")
    if operation_input["operation"] == "persistence_release_quarantine_v2":
        if operation_result["mutation"] == "atomic" and (
            store_before["quarantine"] is None
            or store_before["quarantine"]["event_id"] != operation_input["event_id"]
            or store_before["quarantine"]["reason_code"]
            != operation_input["quarantine_reason_code"]
            or not store_after["quarantine"]["released"]
        ):
            raise ValidationFailure(f"{location}: quarantine release is not request-derived")
        return
    if host_profile_failure_code(operation_input) is not None:
        raise ValidationFailure(
            f"{location}: persistence capabilities do not satisfy host_profile"
        )
    envelope = operation_input["presented_envelope"]
    expected_digest = hash_value(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            checkpoint_before["root_instance_id"],
            "input",
            envelope,
        ]
    )
    transaction_inputs = operation_input["transaction_inputs"]
    aggregate = checkpoint_aggregate(checkpoint_before)
    if (
        operation_input["envelope_digest"] != expected_digest
        or aggregate is None
        or transaction_inputs["target_validated_bundle_fingerprint"]
        != aggregate["validated_bundle_fingerprint"]
    ):
        raise ValidationFailure(f"{location}: persistence request is not definition-bound")
    if operation_result["mutation"] == "atomic":
        inbox = [
            row
            for row in store_after["inbox"]
            if row["event_id"] == envelope["event_id"]
            and row["request_digest"] == expected_digest
        ]
        if not inbox:
            raise ValidationFailure(f"{location}: persistence result omits request inbox identity")
        if operation_result["result"] == "committed" and store_after["application_rows"] != transaction_inputs["application_writes"]:
            raise ValidationFailure(f"{location}: application writes are not request-derived")
        if operation_result["result"] in {"committed", "crashed"} and (
            int(store_after["checkpoint"]["revision"])
            != int(checkpoint_before["revision"]) + 2
        ):
            raise ValidationFailure(
                f"{location}: admitted-and-processed transaction must advance revision exactly twice"
            )


def validate_cross_scope_pair(
    operations: list[dict[str, Any]], location: str
) -> None:
    if len(operations) != 2:
        raise ValidationFailure(f"{location}: requires exactly two authorized scope vectors")
    left, right = operations
    if (
        left["scope"]["authorization"] != "authorized"
        or right["scope"]["authorization"] != "authorized"
        or left["scope"]["scope_id"] == right["scope"]["scope_id"]
        or left["scope"]["ownership_binding"]
        == right["scope"]["ownership_binding"]
        or left["portable_identity"] != right["portable_identity"]
        or left["effect_id"] != right["effect_id"]
    ):
        raise ValidationFailure(
            f"{location}: authorized scopes do not share the same portable identities"
        )
    expected_records = {
        (
            operation["scope"]["scope_id"],
            operation["scope"]["ownership_binding"],
            operation["portable_identity"],
            operation["effect_id"],
        )
        for operation in operations
    }
    for operation in operations:
        actual_records = {
            (
                record["scope_id"],
                record["ownership_binding"],
                record["portable_identity"],
                record["effect_id"],
            )
            for record in operation["store_records"]
        }
        if actual_records != expected_records:
            raise ValidationFailure(
                f"{location}: cross-scope store records are not relationally isolated"
            )


def validate_durable_host_vectors(
    case: Path, test: dict[str, Any], artifact_paths: set[Path]
) -> set[str]:
    """Validate the closed schema-v2 durable host profile table."""
    manifests = {entry["file"]: entry for entry in test["artifacts"]["documents"]}
    artifacts = {path.name: analyze_artifact(path).document for path in artifact_paths}
    coverage: set[str] = set()
    names: set[str] = set()
    cross_scope_operations: list[dict[str, Any]] = []

    def require_kind(filename: str, kind: str, location: str) -> Any:
        manifest = manifests.get(filename)
        if manifest is None or manifest["kind"] != kind or not manifest["valid"]:
            raise ValidationFailure(
                f"{location}: {filename} is not a valid {kind} artifact"
            )
        return artifacts[filename]

    for index, vector in enumerate(test["durable_host_vectors"]):
        location = f"{case.name}: durable host vector {index}"
        if vector["name"] in names:
            raise ValidationFailure(f"{location}: duplicate vector name")
        names.add(vector["name"])
        duplicate = coverage & set(vector["covers"])
        if duplicate:
            raise ValidationFailure(f"{location}: duplicate coverage {sorted(duplicate)}")
        coverage.update(vector["covers"])

        request_ref = vector["request"]
        request_document = require_kind(request_ref["file"], "durable_host_inputs_v2", location)
        operation_input = resolve_artifact_pointer(request_document, request_ref["pointer"], location)
        if operation_input["operation"] != vector["operation"]:
            raise ValidationFailure(f"{location}: operation input does not match vector")
        if {
            "equal_identity_separate_scope_a",
            "equal_identity_separate_scope_b",
        } & set(vector["covers"]):
            cross_scope_operations.append(operation_input)

        result_ref = vector["result"]
        result_document = require_kind(result_ref["file"], "durable_host_results_v2", location)
        operation_result = resolve_artifact_pointer(result_document, result_ref["pointer"], location)
        expected_result = dict(vector["expect"])
        expected_result.setdefault("broker_acknowledged", False)
        if operation_result != expected_result:
            raise ValidationFailure(f"{location}: exact result does not match expectation")
        failure_result = operation_result["result"] in {
            "rejected",
            "crashed",
            "quarantined",
        }
        failure_code = operation_result.get("code")
        if failure_result != (failure_code is not None):
            raise ValidationFailure(
                f"{location}: failure code presence does not match result"
            )
        if failure_code is not None and failure_code not in DURABLE_HOST_FAILURE_CODES:
            raise ValidationFailure(
                f"{location}: durable host failure code is absent from the closed registry"
            )

        before_name = vector.get("checkpoint_before")
        after_name = vector.get("checkpoint_after")
        if after_name is not None:
            checkpoint_after = require_kind(after_name, "execution_checkpoint_v2", location)
            validate_execution_checkpoint_v2_semantics(checkpoint_after)
            if before_name is None:
                if checkpoint_after["revision"] != "0":
                    raise ValidationFailure(f"{location}: creation must commit revision zero")
            else:
                checkpoint_before = require_kind(before_name, "execution_checkpoint_v2", location)
                validate_request_checkpoint_binding(
                    operation_input, checkpoint_before, artifacts, location
                )
                if vector["expect"]["mutation"] == "none":
                    stale_conflict = (
                        operation_result.get("code")
                        == "checkpoint_revision_conflict"
                    )
                    if checkpoint_before != checkpoint_after and not stale_conflict:
                        raise ValidationFailure(f"{location}: non-mutating result changed checkpoint")
                    if stale_conflict and (
                        checkpoint_before["root_instance_id"]
                        != checkpoint_after["root_instance_id"]
                        or int(checkpoint_after["revision"])
                        <= int(checkpoint_before["revision"])
                    ):
                        raise ValidationFailure(
                            f"{location}: stale conflict lacks a newer committed checkpoint"
                        )
            validate_checkpoint_derivation(
                operation_input,
                operation_result,
                checkpoint_before if before_name is not None else None,
                checkpoint_after,
                location,
                case / "machine.yaml",
            )
        elif vector["operation"] == "checkpoint_create_v2":
            if (
                before_name is not None
                or operation_result.get("code") != "creation_rejected"
                or operation_result["mutation"] != "none"
                or operation_input["bindings"] == {"input": {}, "external": {}}
            ):
                raise ValidationFailure(
                    f"{location}: rejected creation is not request-derived"
                )

        store_before_name = vector.get("store_before")
        store_after_name = vector.get("store_after")
        if store_before_name is not None and store_after_name is not None:
            store_before = require_kind(store_before_name, "durable_host_store_v2", location)
            store_after = require_kind(store_after_name, "durable_host_store_v2", location)
            for store_value in (store_before, store_after):
                validate_execution_checkpoint_v2_semantics(store_value["checkpoint"])
            changed = store_before != store_after
            if changed != (vector["expect"]["mutation"] == "atomic"):
                raise ValidationFailure(f"{location}: store mutation classification is inconsistent")
            if "persistence_atomic_aggregate_inbox_outbox_audit" in vector["covers"]:
                checkpoint = store_after["checkpoint"]
                if (
                    not store_after["inbox"]
                    or not checkpoint["pending_outbox_intents"]
                    or not checkpoint["migration_audit_records"]
                    or not store_after["application_rows"]
                ):
                    raise ValidationFailure(
                        f"{location}: atomic store omits inbox, outbox, audit, or application state"
                    )
            validate_persistence_derivation(
                operation_input,
                operation_result,
                store_before,
                store_after,
                location,
            )

        call_log_name = vector.get("call_log")
        if call_log_name is not None:
            call_log = require_kind(call_log_name, "durable_host_call_log_v2", location)["calls"]
            if call_log.count("call_core") != vector["expect"]["core_calls"]:
                raise ValidationFailure(f"{location}: core call count differs")
            if ("acknowledge" in call_log) != operation_result["broker_acknowledged"]:
                raise ValidationFailure(
                    f"{location}: acknowledgement result differs from the call trace"
                )
            if "begin_transaction" in call_log:
                transaction_index = call_log.index("begin_transaction")
                for required in ("select_scope", "resolve_artifacts", "validate_capabilities"):
                    if required not in call_log or call_log.index(required) > transaction_index:
                        raise ValidationFailure(f"{location}: {required} must precede transaction begin")
            if "acknowledge" in call_log and "commit" in call_log:
                if call_log.index("acknowledge") < call_log.index("commit"):
                    raise ValidationFailure(f"{location}: acknowledgement precedes commit")

    if cross_scope_operations:
        validate_cross_scope_pair(
            cross_scope_operations, f"{case.name}: cross-scope pair"
        )
    adapter_probes = {
        "adapter_identifier_underscore_rejected": "invalid-adapter-identifier-v2.json",
        "adapter_scheme_underscore_rejected": "invalid-uri-scheme-v2.json",
    }
    for cover, filename in adapter_probes.items():
        if cover in coverage:
            manifest = manifests.get(filename)
            if manifest != {
                "file": filename,
                "kind": "durable_host_inputs_v2",
                "valid": False,
                "error": "invalid_durable_host_inputs_v2",
            }:
                raise ValidationFailure(
                    f"{case.name}: missing exact negative adapter grammar probe {filename}"
                )
    return coverage


def validate_static_entry(entry: Any, case: Path) -> tuple[Path, bool, str | None]:
    if not isinstance(entry, dict):
        raise ValidationFailure(f"{case.name}: static entry must be a map")
    unknown = set(entry) - {"file", "valid", "error"}
    if unknown:
        raise ValidationFailure(
            f"{case.name}: unsupported static entry field {sorted(unknown)[0]}"
        )
    if not isinstance(entry.get("valid"), bool):
        raise ValidationFailure(f"{case.name}: static entry needs Boolean valid")
    expected_valid = entry["valid"]
    expected_error = entry.get("error")
    if expected_valid and expected_error is not None:
        raise ValidationFailure(f"{case.name}: valid document cannot declare error")
    if not expected_valid and (
        not isinstance(expected_error, str) or not expected_error
    ):
        raise ValidationFailure(f"{case.name}: invalid document needs exact error")
    filename = entry.get("file", "machine.yaml")
    return exact_case_file(case, filename), expected_valid, expected_error


def validate_bundle(
    path: Path,
    expected_valid: bool,
    expected_error: str | None,
    schema_validator: Draft202012Validator,
) -> tuple[str | None, bool]:
    analysis = analyze_source(path)
    expected_source_error = expected_error in SOURCE_ERROR_CODES
    if expected_source_error:
        if analysis.error != expected_error:
            actual = analysis.error or "constructible document"
            raise ValidationFailure(
                f"{path}: expected {expected_error}, got {actual}"
            )
        return analysis.error, False
    if analysis.error:
        raise ValidationFailure(f"{path}: unexpected {analysis.error}")

    format_value = (
        analysis.document.get("format")
        if isinstance(analysis.document, dict)
        else None
    )
    format_is_current = (
        isinstance(format_value, int)
        and not isinstance(format_value, bool)
        and format_value == 1
    )
    if not format_is_current:
        if expected_error == "unsupported_format":
            return None, False
        raise ValidationFailure(
            f"{path}: expected {expected_error or 'valid'}, got unsupported_format"
        )
    if expected_error == "unsupported_format":
        raise ValidationFailure(f"{path}: expected unsupported_format, got format 1")

    schema_errors = sorted(
        schema_validator.iter_errors(analysis.document),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if expected_error == "structural_validation":
        if not schema_errors:
            raise ValidationFailure(f"{path}: expected structural_validation")
        return None, True
    if schema_errors:
        first = schema_errors[0]
        raise ValidationFailure(
            f"{path}: unexpected schema error at {list(first.path)}: {first.message}"
        )
    if not expected_valid and expected_error is None:
        raise ValidationFailure(f"{path}: invalid document has no disposition")
    return None, False


def static_entries(static: Any, case: Path) -> list[tuple[Path, bool, str | None]]:
    if not isinstance(static, dict):
        raise ValidationFailure(f"{case.name}: static must be a map")
    if "documents" in static:
        if set(static) != {"documents"} or not isinstance(static["documents"], list):
            raise ValidationFailure(f"{case.name}: malformed static.documents")
        if not static["documents"]:
            raise ValidationFailure(f"{case.name}: empty static.documents")
        return [validate_static_entry(entry, case) for entry in static["documents"]]
    return [validate_static_entry(static, case)]


def validate_case_62(case: Path, test: dict[str, Any]) -> None:
    expected_errors = {
        "invalid-boolean-titlecase.yaml": "invalid_boolean_syntax",
        "invalid-boolean-uppercase.yaml": "invalid_boolean_syntax",
        "invalid-boolean-false-titlecase.yaml": "invalid_boolean_syntax",
        "invalid-boolean-false-uppercase.yaml": "invalid_boolean_syntax",
        "invalid-null-tilde.yaml": "invalid_null_syntax",
        "invalid-null-titlecase.yaml": "invalid_null_syntax",
        "invalid-null-uppercase.yaml": "invalid_null_syntax",
        "invalid-null-empty-scalar.yaml": "invalid_null_syntax",
    }
    for filename, expected in expected_errors.items():
        analysis = analyze_source(case / filename)
        if analysis.error != expected:
            raise ValidationFailure(
                f"{case.name}/{filename}: expected {expected}, got {analysis.error}"
            )

    machine_path = case / "machine.yaml"
    machine = load_fixture_document(machine_path)
    expected_strings = {"no", "off", "yes", "on"}
    if set(machine["events"]) != expected_strings:
        raise ValidationFailure(f"{machine_path}: event identities are not strings")
    root = machine["machines"][0]["root"]
    if set(root["states"]) != expected_strings:
        raise ValidationFailure(f"{machine_path}: state identities are not strings")
    if root["initial"]["transition_to"] != "no":
        raise ValidationFailure(f"{machine_path}: initial target is not string no")
    expected_targets = {"no": "off", "off": "yes", "yes": "on", "on": "no"}
    for source, target in expected_targets.items():
        handler = root["states"][source]["on_events"][source]
        default = machine["events"][source]["payload"]["value"]["default"]
        if handler["transition_to"] != target:
            raise ValidationFailure(
                f"{machine_path}: transition {source} did not retain {target}"
            )
        if default != source or not isinstance(default, str):
            raise ValidationFailure(
                f"{machine_path}: default {source} is not the same string"
            )

    if test.get("load") != {"valid": True}:
        raise ValidationFailure(f"{case.name}: load validity marker is required")
    expected_trace = [
        ("no", "off"),
        ("off", "yes"),
        ("yes", "on"),
        ("on", "no"),
    ]
    if test.get("create", {}).get("expect", {}).get("config") != ["no"]:
        raise ValidationFailure(f"{case.name}: creation must begin in string state no")
    test_source = (case / "test.yaml").read_text(encoding="utf-8")
    for index, (event_name, target_state) in enumerate(expected_trace):
        step = test["steps"][index]
        if step["send"]["event"] != event_name:
            raise ValidationFailure(f"{case.name}: step {index} event changed")
        if step["expect"]["config"] != [target_state]:
            raise ValidationFailure(f"{case.name}: step {index} target changed")
        if step["expect"]["variables"]["observed_value"] != event_name:
            raise ValidationFailure(f"{case.name}: step {index} value changed")
        required_fragments = (
            f'event: "{event_name}"',
            f'config: ["{target_state}"]',
            f'observed_value: "{event_name}"',
        )
        if any(fragment not in test_source for fragment in required_fragments):
            raise ValidationFailure(
                f"{case.name}: step {index} driver scalar is not quoted"
            )










def validate_repository(repository_root: Path, spec_root: Path) -> str:
    try:
        registry_categories, registry_entries = validate_registry(repository_root)
    except RegistryValidationError as error:
        raise ValidationFailure(f"closed-code registry: {error}") from error
    validate_direct_descriptor_expectation_probes()
    schema_paths = {
        "machine": spec_root / "schema" / "machine.schema.json",
        **{
            kind: spec_root / "schema" / filename
            for kind, filename in ARTIFACT_KINDS.items()
        },
        **{
            kind: repository_root / "scripts" / "schemas" / filename
            for kind, filename in DRIVER_ARTIFACT_KINDS.items()
        },
        "version2_vectors": (
            repository_root / "scripts" / "schemas" / "version2-vectors.schema.json"
        ),
        "durable_host_vectors": (
            repository_root
            / "scripts"
            / "schemas"
            / "durable-host-profile-v2.schema.json"
        ),
    }
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for name, schema_path in schema_paths.items():
        if not schema_path.is_file():
            raise ValidationFailure(f"missing schema: {schema_path}")
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValidationFailure(f"{schema_path}: invalid JSON: {error}") from error
        Draft202012Validator.check_schema(schema)
        schemas[name] = schema
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            resources.append((schema_id, Resource.from_contents(schema)))
        resources.append((schema_path.name, Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    schema_validator = Draft202012Validator(
        schemas["machine"], registry=registry
    )
    artifact_validators = {
        kind: Draft202012Validator(schemas[kind], registry=registry)
        for kind in (*ARTIFACT_KINDS, *DRIVER_ARTIFACT_KINDS)
    }
    validate_operation_input_schema_probes(
        artifact_validators["version2_operation_inputs"]
    )
    version2_vector_validator = Draft202012Validator(
        schemas["version2_vectors"], registry=registry
    )
    durable_host_vector_validator = Draft202012Validator(
        schemas["durable_host_vectors"], registry=registry
    )

    conformance_version = (repository_root / "VERSION").read_text().strip()
    spec_version = (spec_root / "VERSION").read_text().strip()
    if conformance_version != spec_version:
        raise ValidationFailure(
            f"VERSION mismatch: conformance {conformance_version}, spec {spec_version}"
        )

    case_roots = [
        repository_root / "conformance" / "core",
        repository_root / "conformance" / "profiles",
    ]
    for root in case_roots:
        if not root.is_dir():
            continue
        for fixture_path in root.rglob("*.yaml"):
            if not (fixture_path.parent / "test.yaml").is_file():
                raise ValidationFailure(
                    f"{fixture_path}: fixture directory is missing test.yaml"
                )
    cases = sorted(
        {
            test_path.parent
            for root in case_roots
            if root.is_dir()
            for test_path in root.rglob("test.yaml")
        }
    )
    if not cases:
        raise ValidationFailure("no conformance cases found")

    document_paths: set[Path] = set()
    root_instance_ids: set[str] = set()
    creation_ids: set[str] = set()
    input_event_ids: set[str] = set()
    structural_rejections = 0
    source_rejections = 0
    static_schema_passes = 0
    scenarios = 0
    artifact_documents = 0
    version2_vectors = 0
    version2_coverage: set[str] = set()
    durable_host_vectors = 0
    durable_host_coverage: set[str] = set()

    for case in cases:
        test = load_fixture_document(case / "test.yaml")
        validate_driver_markers(test, case.name)
        profile_modes = {
            name
            for name in ("version2_vectors", "durable_host_vectors")
            if name in test
        }
        if len(profile_modes) > 1:
            raise ValidationFailure(
                f"{case.name}: profile driver modes are mutually exclusive"
            )
        if "version2_vectors" in test:
            validate_fixture_schema(test, version2_vector_validator, case)
        if "durable_host_vectors" in test:
            validate_fixture_schema(test, durable_host_vector_validator, case)
        if "load" in test and test["load"] != {"valid": True}:
            raise ValidationFailure(f"{case.name}: unsupported load assertion")

        referenced: set[Path] = set()
        referenced_artifacts: set[Path] = set()
        static = test.get("static")
        if static is not None:
            for path, expected_valid, expected_error in static_entries(static, case):
                if path in referenced:
                    raise ValidationFailure(
                        f"{case.name}: duplicate bundle reference {path.name}"
                    )
                referenced.add(path)
                source_error, structural_error = validate_bundle(
                    path, expected_valid, expected_error, schema_validator
                )
                source_rejections += int(source_error is not None)
                structural_rejections += int(structural_error)
                static_schema_passes += int(
                    source_error is None and not structural_error
                )
        if "artifacts" in test:
            referenced_artifacts = artifact_entries(
                case, test, artifact_validators
            )
            artifact_documents += len(referenced_artifacts)

        has_persistence_mode = bool(profile_modes)
        has_scenario = (
            not has_persistence_mode
            and (bool(test.get("steps")) or "create" in test or static is None)
        )
        if has_scenario:
            primary = exact_case_file(case, "machine.yaml")
            if primary not in referenced:
                validate_bundle(primary, True, None, schema_validator)
                referenced.add(primary)
            scenarios += 1

            create = test.get("create") or {}
            root_instance_id = create.get(
                "root_instance_id", f"conformance:{case.name}:root"
            )
            creation_id = create.get(
                "creation_id", f"conformance:{case.name}:create"
            )
            invalid_unicode_sentinel = {"invalid_unicode_scalar": "D800"}
            if root_instance_id != invalid_unicode_sentinel:
                if not isinstance(root_instance_id, str) or not root_instance_id:
                    raise ValidationFailure(
                        f"{case.name}: invalid root_instance_id"
                    )
                if root_instance_id in root_instance_ids:
                    raise ValidationFailure(
                        f"{case.name}: duplicate root_instance_id"
                    )
                root_instance_ids.add(root_instance_id)
            if not isinstance(creation_id, str) or not creation_id:
                raise ValidationFailure(f"{case.name}: invalid creation_id")
            if creation_id in creation_ids:
                raise ValidationFailure(f"{case.name}: duplicate creation_id")
            creation_ids.add(creation_id)

            captures: set[str] = set()
            for index, step in enumerate(test.get("steps", [])):
                if not isinstance(step, dict):
                    raise ValidationFailure(f"{case.name}: step {index} is not a map")
                location = f"{case.name}: step {index}"
                validate_driver_markers(step, location)
                operations = {"send", "deliver", "inspect"} & set(step)
                if len(operations) != 1:
                    raise ValidationFailure(
                        f"{location} must have exactly one send, deliver, or inspect"
                    )
                unknown_step_fields = set(step) - {
                    "send",
                    "deliver",
                    "inspect",
                    "capture_emissions_as",
                    "expect",
                }
                if unknown_step_fields:
                    raise ValidationFailure(
                        f"{location} has unsupported field "
                        f"{sorted(unknown_step_fields)[0]}"
                    )
                send = step.get("send")
                if send is not None:
                    if not isinstance(send, dict):
                        raise ValidationFailure(
                            f"{case.name}: step {index} send is not a map"
                        )
                    unknown_send_fields = set(send) - {
                        "bound_instance",
                        "bundle",
                        "component",
                        "correlation_id",
                        "event",
                        "event_id",
                        "payload",
                    }
                    if unknown_send_fields:
                        raise ValidationFailure(
                            f"{location} send has unsupported field "
                            f"{sorted(unknown_send_fields)[0]}"
                        )
                    if not isinstance(send.get("event"), str) or not send["event"]:
                        raise ValidationFailure(
                            f"{location} send needs a non-empty event"
                        )
                    if {"bound_instance", "component"} <= set(send):
                        raise ValidationFailure(
                            f"{location} send target selectors are mutually exclusive"
                        )
                    for selector in ("bound_instance", "component"):
                        if selector in send and (
                            not isinstance(send[selector], str) or not send[selector]
                        ):
                            raise ValidationFailure(
                                f"{location} send.{selector} needs a non-empty name"
                            )
                    if "payload" in send and not isinstance(send["payload"], dict):
                        raise ValidationFailure(
                            f"{location} send.payload must be a map"
                        )
                    if "correlation_id" in send and (
                        not isinstance(send["correlation_id"], str)
                        or not send["correlation_id"]
                    ):
                        raise ValidationFailure(
                            f"{location} send.correlation_id must be non-empty"
                        )
                    event_id = send.get(
                        "event_id",
                        f"conformance:{case.name}:step:{index}:input",
                    )
                    if not isinstance(event_id, str) or not event_id:
                        raise ValidationFailure(
                            f"{case.name}: step {index} has invalid event_id"
                        )
                    if event_id in input_event_ids:
                        raise ValidationFailure(
                            f"{case.name}: step {index} repeats event_id"
                        )
                    input_event_ids.add(event_id)
                    if "bundle" in send:
                        alternate = exact_case_file(case, send["bundle"])
                        if alternate not in referenced:
                            validate_bundle(
                                alternate, True, None, schema_validator
                            )
                            referenced.add(alternate)
                deliver = step.get("deliver")
                if deliver is not None:
                    if (
                        not isinstance(deliver, dict)
                        or set(deliver) - {"captured", "index", "replace"}
                        or deliver.get("captured") not in captures
                    ):
                        raise ValidationFailure(
                            f"{case.name}: step {index} references an unavailable capture"
                        )
                    delivery_index = deliver.get("index")
                    if (
                        isinstance(delivery_index, bool)
                        or not isinstance(delivery_index, int)
                        or delivery_index < 0
                    ):
                        raise ValidationFailure(
                            f"{location} deliver.index must be non-negative"
                        )
                    if "replace" in deliver:
                        validate_deliver_replace(
                            deliver["replace"], f"{location} deliver.replace"
                        )
                inspect = step.get("inspect")
                if inspect is not None:
                    validate_inspect(inspect, f"{location} inspect")
                    if "capture_emissions_as" in step:
                        raise ValidationFailure(
                            f"{location} inspect cannot capture emissions"
                        )
                capture = step.get("capture_emissions_as")
                if capture is not None:
                    if not isinstance(capture, str) or not capture:
                        raise ValidationFailure(
                            f"{case.name}: step {index} has invalid capture name"
                        )
                    if capture in captures:
                        raise ValidationFailure(
                            f"{case.name}: duplicate capture {capture}"
                        )
                    captures.add(capture)
                expected = step.get("expect")
                if not isinstance(expected, dict):
                    raise ValidationFailure(f"{location} needs an expect map")
                if expected.get("caller_still_owns_state") is not None and (
                    operations != {"inspect"}
                    or expected["caller_still_owns_state"] is not True
                ):
                    raise ValidationFailure(
                        f"{location} caller_still_owns_state is inspect-only true"
                    )
                if "state_bytes_unchanged" in expected and (
                    expected["state_bytes_unchanged"] is not True
                    or expected.get("disposition") != "deferred"
                    or expected.get("caller_still_owns_input") is not True
                ):
                    raise ValidationFailure(
                        f"{location} state_bytes_unchanged requires caller-owned deferral"
                    )
        elif "version2_vectors" in test:
            case_coverage = validate_version2_vectors(
                case, test, referenced, referenced_artifacts
            )
            duplicate_coverage = version2_coverage & case_coverage
            if duplicate_coverage:
                raise ValidationFailure(
                    f"{case.name}: version-2 coverage repeated across cases: "
                    f"{sorted(duplicate_coverage)}"
                )
            version2_coverage.update(case_coverage)
            version2_vectors += len(test["version2_vectors"])
        elif "durable_host_vectors" in test:
            case_coverage = validate_durable_host_vectors(
                case, test, referenced_artifacts
            )
            duplicate_coverage = durable_host_coverage & case_coverage
            if duplicate_coverage:
                raise ValidationFailure(
                    f"{case.name}: durable host coverage repeated across cases: "
                    f"{sorted(duplicate_coverage)}"
                )
            durable_host_coverage.update(case_coverage)
            durable_host_vectors += len(test["durable_host_vectors"])

        actual_bundles = {
            path
            for path in case.rglob("*.yaml")
            if path.name != "test.yaml"
        }
        if referenced != actual_bundles:
            missing = sorted(path.name for path in referenced - actual_bundles)
            unreferenced = sorted(path.name for path in actual_bundles - referenced)
            raise ValidationFailure(
                f"{case.name}: missing={missing}, unreferenced={unreferenced}"
            )
        actual_artifacts = set(case.glob("*.json"))
        if referenced_artifacts != actual_artifacts:
            missing = sorted(
                path.name for path in referenced_artifacts - actual_artifacts
            )
            unreferenced = sorted(
                path.name for path in actual_artifacts - referenced_artifacts
            )
            raise ValidationFailure(
                f"{case.name}: artifact missing={missing}, unreferenced={unreferenced}"
            )
        document_paths.update(referenced)

        if case.name == "62-parsed-value-model":
            validate_case_62(case, test)

    all_test_files = {
        path for root in case_roots if root.is_dir() for path in root.rglob("test.yaml")
    }
    if len(all_test_files) != len(cases):
        raise ValidationFailure("duplicate or nested conformance test discovery")
    if version2_vectors:
        missing_coverage = REQUIRED_VERSION2_COVERAGE - version2_coverage
        unexpected_coverage = version2_coverage - REQUIRED_VERSION2_COVERAGE
        if missing_coverage or unexpected_coverage:
            raise ValidationFailure(
                "version-2 coverage mismatch: "
                f"missing={sorted(missing_coverage)}, "
                f"unexpected={sorted(unexpected_coverage)}"
            )
    if durable_host_vectors:
        missing_coverage = REQUIRED_DURABLE_HOST_COVERAGE - durable_host_coverage
        unexpected_coverage = durable_host_coverage - REQUIRED_DURABLE_HOST_COVERAGE
        if missing_coverage or unexpected_coverage:
            raise ValidationFailure(
                "durable host coverage mismatch: "
                f"missing={sorted(missing_coverage)}, "
                f"unexpected={sorted(unexpected_coverage)}"
            )

    return (
        f"validated {registry_entries} closed-code entries across "
        f"{registry_categories} categories; "
        f"validated {len(document_paths)} bundle documents across {len(cases)} "
        f"case directories against spec {spec_version}; "
        f"{artifact_documents} JSON artifacts, "
        f"{source_rejections} expected source rejections, "
        f"{structural_rejections} expected structural rejections, "
        f"{static_schema_passes} schema-valid static documents, and "
        f"{scenarios} runtime scenarios, {version2_vectors} version-2 vectors, "
        f"and {durable_host_vectors} durable host vectors"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--spec-root",
        required=True,
        type=Path,
        help="Path to the checked-out determa-state-spec repository",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args()
    try:
        print(
            validate_repository(
                arguments.repository_root.resolve(),
                arguments.spec_root.resolve(),
            )
        )
    except ValidationFailure as error:
        print(f"validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
