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
NON_FINITE_DOUBLE_MARKERS = frozenset(
    {"nan", "positive_infinity", "negative_infinity"}
)
INSTANCE_REFERENCE_FIELDS = frozenset(
    {"root_instance_id", "instance_id", "machine_id", "machine_version"}
)
ARTIFACT_KINDS = {
    "aggregate_state": "aggregate-state.schema.json",
    "aggregate_state_v2": "aggregate-state-v2.schema.json",
    "migration_descriptor": "migration-descriptor.schema.json",
    "migration_descriptor_v2": "migration-descriptor-v2.schema.json",
    "aggregate_state_package": "aggregate-state-package.schema.json",
    "aggregate_state_package_v2": "aggregate-state-package-v2.schema.json",
    "core_step_result_v2": "core-step-result-v2.schema.json",
    "execution_checkpoint": "execution-checkpoint.schema.json",
    "execution_checkpoint_v2": "execution-checkpoint-v2.schema.json",
}
DRIVER_ARTIFACT_KINDS = {
    "artifact_resolver": "artifact-resolver.schema.json",
    "resource_limits": "resource-limits.schema.json",
    "execution_checkpoint_inputs": "execution-checkpoint-inputs.schema.json",
    "execution_checkpoint_core_evidence": (
        "execution-checkpoint-core-evidence.schema.json"
    ),
    "execution_store_scope_state": "execution-store-scope-state.schema.json",
    "version2_operation_inputs": "version2-operation-inputs.schema.json",
    "version2_operation_result": "version2-operation-result.schema.json",
}
MINIMUM_RESOURCE_LIMIT_FLOORS = {
    "maximum_aggregate_bytes": "1048576",
    "maximum_definition_bytes": "1048576",
    "maximum_descriptor_bytes": "65536",
    "maximum_transformed_output_bytes": "65536",
    "maximum_json_nesting_depth": "64",
    "maximum_runtimes": "256",
    "maximum_active_states_per_runtime": "1024",
    "maximum_variables_per_runtime": "4096",
    "maximum_map_members": "4096",
    "maximum_list_members": "4096",
    "maximum_string_utf8_bytes": "65536",
    "maximum_chain_length": "8",
    "maximum_descriptor_rules": "1024",
    "maximum_cel_expression_length": "65536",
    "maximum_cel_ast_nodes": "65536",
    "maximum_cel_evaluation_steps": "1000000",
}
REQUIRED_EXECUTION_CHECKPOINT_COVERAGE = frozenset(
    {
        "creation_commit",
        "spawned_trace_creation",
        "spawned_trace_start",
        "spawned_trace_child_acceptance",
        "terminal_spawn_trace_creation",
        "terminal_spawn_trace_start",
        "terminal_spawn_trace_child_acceptance",
        "terminal_spawn_trace_child_processing",
        "terminal_spawn_trace_completion_processing",
        "creation_replay",
        "creation_conflict",
        "creation_rejection_without_checkpoint",
        "durable_pending_acceptance",
        "pending_acceptance_replay",
        "delayed_processing",
        "foreground_processing",
        "committed_receipt_replay",
        "revision_progression",
        "pre_commit_rollback",
        "post_commit_response_loss_replay",
        "rejected_delivery",
        "faulted_delivery",
        "unhandled_delivery",
        "internal_delivery_processing",
        "stale_processing_cas_conflict",
        "stale_outbox_cas_conflict",
        "stale_pruning_cas_conflict",
        "stale_tombstone_cas_conflict",
        "internal_pending_delivery",
        "maintenance_migration_commit",
        "maintenance_migration_replay",
        "maintenance_migration_conflict",
        "migration_audit_non_empty",
        "pre_acceptance_malformed_delivery",
        "pre_acceptance_wrong_root",
        "replay_event_id_conflict_precedes_invalid_delivery_mode",
        "replay_committed_receipt_precedes_invalid_delivery_origin",
        "pre_acceptance_invalid_delivery_mode",
        "pre_acceptance_invalid_delivery_origin",
        "pre_acceptance_delivery_digest_mismatch",
        "pre_acceptance_event_id_conflict",
        "pre_acceptance_tombstoned_root",
        "root_tombstoning",
        "root_tombstone_replay",
        "root_identity_no_reuse",
        "physical_deletion_unsupported",
        "permanent_receipt_retention",
        "bounded_receipt_retention",
        "dependency_safe_pruning",
        "permanent_to_bounded_irreversible",
        "bounded_to_permanent_rejected",
        "outbox_not_attempted",
        "outbox_retryable_failure",
        "outbox_ambiguous",
        "outbox_confirmed",
        "outbox_permanently_rejected",
        "outbox_operator_cancelled",
        "outbox_discarded",
        "outbox_dead_lettered",
        "outbox_compact_tombstone",
        "outbox_idempotent_pending_update",
        "outbox_idempotent_terminal_update",
        "outbox_effect_conflict",
        "outbox_forbidden_deletion",
        "outbox_receipt_linkage",
        "direct_store_injection",
        "public_adapter_registry",
        "duplicate_adapter_registration",
        "unknown_adapter",
        "invalid_adapter_configuration",
        "adapter_capability_mismatch",
        "memory_durable_profile_rejected",
        "bounded_exactly_once_rejected",
        "root_identity_profile_requirement",
        "strict_outbox_profile_requirements",
        "compact_outbox_profile_requirements",
        "durable_embedded_profile_requirements",
        "exactly_once_profile_requirements",
        "broker_profile_requirements",
        "shared_transaction_profile_requirements",
        "memory_capability_boundary",
        "file_capability_boundary",
        "sqlite_capability_boundary",
        "postgresql_capability_boundary",
        "bundled_public_registration",
        "third_party_public_registration",
        "durable_embedded_missing_durable",
        "durable_profile_missing_root_identity",
        "durable_profile_missing_atomic_processing",
        "exactly_once_missing_receipt_retention",
        "broker_profile_missing_redelivery",
        "broker_profile_missing_ack_after_commit",
        "broker_profile_missing_outbox_worker",
        "strict_outbox_missing_terminal_retention",
        "strict_outbox_missing_worker",
        "strict_outbox_missing_total_lifecycle",
        "strict_outbox_missing_unresolved_retention",
        "compact_outbox_missing_tombstone_retention",
        "compact_outbox_missing_worker",
        "compact_outbox_missing_total_lifecycle",
        "compact_outbox_missing_reference_retention",
        "shared_transaction_missing_native_use",
        "shared_transaction_missing_store_capability",
        "scoped_outbox_update_scope_a",
        "scoped_outbox_update_scope_b",
        "missing_scope_rejected",
        "ambiguous_scope_rejected",
        "mismatched_scope_rejected",
        "unauthorized_scope_rejected",
        "portable_state_scope_invariance",
    }
)
REQUIRED_VERSION2_COVERAGE = frozenset(
    {
        "aggregate_v2_schema_positive_negative",
        "all_replay_multi_event_batch",
        "automatic_selective_recall",
        "batch_duplicate_rejection",
        "canonical_v2_bytes_and_digests",
        "capacity_unbounded",
        "capacity_zero_and_overflow_fault",
        "checkpoint_v1_requires_upgrade",
        "checkpoint_v2_schema_positive_negative",
        "checkpoint_admission_invalid_artifact",
        "compacted_legacy_terminal_replay",
        "checkpoint_pending_replay_precedes_stale_cas",
        "cleanup_fault_rollback",
        "component_mailbox_isolation",
        "core_step_v2_schema_positive_negative",
        "deferred_only_not_runnable",
        "downgrade_permitted",
        "downgrade_prohibited",
        "invalid_aggregate_artifact_precedes_operation",
        "conflicting_pending_replay",
        "conflicting_terminal_replay",
        "equal_pending_replay",
        "equal_terminal_replay",
        "pending_changed_payload_stale_digest_conflict",
        "pending_replay_precedes_supplied_digest_validation",
        "terminal_changed_payload_stale_digest_conflict",
        "terminal_replay_precedes_supplied_digest_validation",
        "event_tombstone_changed_payload_stale_digest_conflict",
        "event_tombstone_replay_precedes_supplied_digest_validation",
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
        "native_internal_producer_reference",
        "processed_legacy_internal_producer_reference",
        "native_internal_handler_provenance",
        "native_internal_handler_admission",
        "migration_backlog_independent_descriptor",
        "migration_capacity_totality",
        "migration_descriptor_v2_schema_positive_negative",
        "migration_fault_frozen_preservation",
        "migration_historical_fault_locator_preservation",
        "migration_package_v2_schema_positive_negative",
        "mailbox_payload_matches_event_declaration",
        "migration_preserve_dispose_default",
        "migration_stale_target_transform",
        "mixed_replay_new_batch",
        "migration_removed_event_failure",
        "migration_payload_incompatible_failure",
        "migration_correlation_incompatible_failure",
        "receipt_acceptance_terminal_distinction",
        "reclassification_and_repeated_deferral",
        "reserved_events_not_deferrable",
        "reserved_internal_event_admission",
        "delivery_digest_rejection",
        "wrong_root_precedes_batch_duplicate",
        "root_mailbox_isolation",
        "spawned_mailbox_isolation",
        "terminal_receipt_replay",
        "terminal_replay_precedes_stale_cas",
        "terminal_root_precedes_delivery_validation",
        "distinct_stale_checkpoint_writer_rejected",
        "terminal_processing_receipt",
        "terminal_tombstone_replay",
        "tombstoned_root_batch_replay",
        "tombstoned_spawned_child_replay",
        "tombstoned_mixed_runtime_batch_replay",
        "tombstoned_root_single_replay",
        "tombstoned_root_precedes_delivery_validation",
        "upgrade_aggregate_v1_to_v2",
        "upgrade_checkpoint_v1_to_v2_legacy_evidence",
        "upgrade_checkpoint_v1_to_v2_populated_outbox",
        "upgrade_checkpoint_v1_spawned_target",
        "upgrade_checkpoint_v1_multi_pending_history",
        "processed_upgrade_history_without_optional_metadata",
        "processed_upgrade_history_with_optional_metadata",
        "multiple_converted_upgrade_history",
        "multiple_processed_upgrade_history_without_optional_metadata",
        "multiple_processed_upgrade_history_with_optional_metadata",
        "version2_malformed_delivery_rejected",
        "version2_invalid_delivery_mode_rejected",
        "version2_counter_allocation",
        "version2_dependency_safe_pruning",
        "version2_dependency_pruning_rejected",
        "version2_native_internal_producer_pruned",
        "version2_native_internal_terminal_pruned",
        "version2_native_internal_sequential_pruning",
        "version2_creation_internal_dependency_retained",
        "version2_creation_external_dependency_retained",
        "version2_legacy_origin_pruning_rejected",
        "version2_live_acceptance_pruning_rejected",
        "version2_terminal_pair_pruning_rejected",
        "version2_equal_pruning_cutoff",
        "version2_equal_pruning_precedes_stale_cas",
        "version2_invalid_pruning_cutoff_rejected",
        "version2_lower_pruning_cutoff_rejected",
        "wrapped_legacy_terminal_replay",
    }
)

EXECUTION_STORE_SCOPE_COVERAGE = frozenset(
    {
        "scoped_outbox_update_scope_a",
        "scoped_outbox_update_scope_b",
        "missing_scope_rejected",
        "ambiguous_scope_rejected",
        "mismatched_scope_rejected",
        "unauthorized_scope_rejected",
        "portable_state_scope_invariance",
    }
)
EXECUTION_CHECKPOINT_OPERATION_OUTCOMES: dict[
    str, dict[str, frozenset[str | None]]
] = {
    "create": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {
                "creation_rejected",
                "creation_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "accept_delivery": {
        "pending": frozenset({None}),
        "committed": frozenset({None}),
        "not_accepted": frozenset(
            {
                "malformed_delivery",
                "wrong_root",
                "invalid_delivery_mode",
                "invalid_delivery_origin",
                "delivery_digest_mismatch",
                "event_id_conflict",
                "tombstoned_root",
            }
        ),
        "failure": frozenset(
            {"checkpoint_revision_conflict", "invalid_execution_checkpoint"}
        ),
    },
    "process_pending_delivery": {
        "committed": frozenset({None}),
        "response_lost": frozenset({"response_lost_after_commit"}),
        "failure": frozenset(
            {
                "event_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
                "injected_pre_commit_failure",
            }
        ),
    },
    "foreground_process_delivery": {
        "committed": frozenset({None}),
        "response_lost": frozenset({"response_lost_after_commit"}),
        "failure": frozenset(
            {
                "event_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
                "injected_pre_commit_failure",
            }
        ),
    },
    "maintenance_migration": {
        "committed": frozenset({None}),
        "response_lost": frozenset({"response_lost_after_commit"}),
        "failure": frozenset(
            {
                "operation_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
                "injected_pre_commit_failure",
            }
        ),
    },
    "update_pending_outbox": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {
                "effect_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "terminalize_outbox": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {
                "effect_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "compact_outbox": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {
                "effect_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "delete_outbox_record": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "update_replay_retention": {
        "committed": frozenset({None}),
        "failure": frozenset(
            {"checkpoint_revision_conflict", "invalid_execution_checkpoint"}
        ),
    },
    "tombstone_root": {
        "tombstoned": frozenset({None}),
        "failure": frozenset(
            {
                "operation_id_conflict",
                "checkpoint_revision_conflict",
                "invalid_execution_checkpoint",
            }
        ),
    },
    "delete_checkpoint": {
        "unsupported": frozenset({"physical_deletion_unsupported"}),
    },
    "inject_execution_store": {"accepted": frozenset({None})},
    "register_adapter": {
        "accepted": frozenset({None}),
        "failure": frozenset(
            {
                "duplicate_adapter_registration",
                "invalid_adapter_configuration",
                "adapter_capability_mismatch",
            }
        ),
    },
    "resolve_adapter": {
        "accepted": frozenset({None}),
        "failure": frozenset(
            {
                "unknown_adapter",
                "invalid_adapter_configuration",
                "adapter_capability_mismatch",
            }
        ),
    },
    "validate_host_profile": {
        "accepted": frozenset({None}),
        "failure": frozenset({"adapter_capability_mismatch"}),
    },
}
EXECUTION_CHECKPOINT_COVERAGE_RULES = {
    "creation_commit": ("create", "committed", None, "created", "create", None, "creation"),
    "spawned_trace_creation": ("create", "committed", None, "created", "create", None, "creation"),
    "spawned_trace_start": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "foreground"),
    "spawned_trace_child_acceptance": ("accept_delivery", "pending", None, "changed", "none", None, "pending_acceptance"),
    "terminal_spawn_trace_creation": ("create", "committed", None, "created", "create", None, "creation"),
    "terminal_spawn_trace_start": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "foreground"),
    "terminal_spawn_trace_child_acceptance": ("accept_delivery", "pending", None, "changed", "none", None, "pending_acceptance"),
    "terminal_spawn_trace_child_processing": ("process_pending_delivery", "committed", None, "changed", "dispatch", None, "input_processing"),
    "terminal_spawn_trace_completion_processing": ("process_pending_delivery", "committed", None, "changed", "dispatch", None, "internal_processing"),
    "creation_replay": ("create", "committed", None, "unchanged", "none", None, "creation"),
    "creation_conflict": ("create", "failure", "creation_id_conflict", "unchanged", "none", None, "creation_conflict"),
    "creation_rejection_without_checkpoint": ("create", "failure", "creation_rejected", "absent", "create", None, "creation_rejection"),
    "durable_pending_acceptance": ("accept_delivery", "pending", None, "changed", "none", None, "pending_acceptance"),
    "pending_acceptance_replay": ("accept_delivery", "pending", None, "unchanged", "none", None, "pending_acceptance"),
    "delayed_processing": ("process_pending_delivery", "committed", None, "changed", "dispatch", None, "input_processing"),
    "foreground_processing": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "foreground"),
    "committed_receipt_replay": ("accept_delivery", "committed", None, "unchanged", "none", None, "receipt_replay"),
    "revision_progression": ("process_pending_delivery", "committed", None, "changed", "dispatch", None, "revision"),
    "pre_commit_rollback": ("process_pending_delivery", "failure", "injected_pre_commit_failure", "unchanged", "dispatch", "before_commit", "rollback"),
    "post_commit_response_loss_replay": ("process_pending_delivery", "response_lost", "response_lost_after_commit", "changed", "dispatch", "after_commit_before_response", "response_loss"),
    "rejected_delivery": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "rejected_receipt"),
    "faulted_delivery": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "faulted_receipt"),
    "unhandled_delivery": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "unhandled_receipt"),
    "internal_delivery_processing": ("process_pending_delivery", "committed", None, "changed", "dispatch", None, "internal_processing"),
    "stale_processing_cas_conflict": ("process_pending_delivery", "failure", "checkpoint_revision_conflict", "unchanged", "none", None, "stale_cas"),
    "stale_outbox_cas_conflict": ("update_pending_outbox", "failure", "checkpoint_revision_conflict", "unchanged", "none", None, "stale_cas"),
    "stale_pruning_cas_conflict": ("update_replay_retention", "failure", "checkpoint_revision_conflict", "unchanged", "none", None, "stale_cas"),
    "stale_tombstone_cas_conflict": ("tombstone_root", "failure", "checkpoint_revision_conflict", "unchanged", "none", None, "stale_cas"),
    "internal_pending_delivery": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "internal_pending"),
    "maintenance_migration_commit": ("maintenance_migration", "response_lost", "response_lost_after_commit", "changed", "migrate", "after_commit_before_response", "migration"),
    "maintenance_migration_replay": ("maintenance_migration", "committed", None, "unchanged", "none", None, "migration_replay"),
    "maintenance_migration_conflict": ("maintenance_migration", "failure", "operation_id_conflict", "unchanged", "none", None, "migration_conflict"),
    "migration_audit_non_empty": ("maintenance_migration", "response_lost", "response_lost_after_commit", "changed", "migrate", "after_commit_before_response", "migration"),
    "pre_acceptance_malformed_delivery": ("accept_delivery", "not_accepted", "malformed_delivery", "unchanged", "none", None, "malformed"),
    "pre_acceptance_wrong_root": ("accept_delivery", "not_accepted", "wrong_root", "unchanged", "none", None, "wrong_root"),
    "replay_event_id_conflict_precedes_invalid_delivery_mode": ("accept_delivery", "not_accepted", "event_id_conflict", "unchanged", "none", None, "replay_conflict_before_mode"),
    "replay_committed_receipt_precedes_invalid_delivery_origin": ("accept_delivery", "committed", None, "unchanged", "none", None, "replay_receipt_before_origin"),
    "pre_acceptance_invalid_delivery_mode": ("accept_delivery", "not_accepted", "invalid_delivery_mode", "unchanged", "none", None, "invalid_mode"),
    "pre_acceptance_invalid_delivery_origin": ("accept_delivery", "not_accepted", "invalid_delivery_origin", "unchanged", "none", None, "invalid_origin"),
    "pre_acceptance_delivery_digest_mismatch": ("accept_delivery", "not_accepted", "delivery_digest_mismatch", "unchanged", "none", None, "digest_mismatch"),
    "pre_acceptance_event_id_conflict": ("accept_delivery", "not_accepted", "event_id_conflict", "unchanged", "none", None, "event_conflict"),
    "pre_acceptance_tombstoned_root": ("accept_delivery", "not_accepted", "tombstoned_root", "unchanged", "none", None, "tombstoned_root"),
    "root_tombstoning": ("tombstone_root", "tombstoned", None, "changed", "none", None, "tombstone"),
    "root_tombstone_replay": ("tombstone_root", "tombstoned", None, "unchanged", "none", None, "tombstone"),
    "root_identity_no_reuse": ("create", "failure", "creation_id_conflict", "unchanged", "none", None, "tombstoned_root"),
    "physical_deletion_unsupported": ("delete_checkpoint", "unsupported", "physical_deletion_unsupported", "unchanged", "none", None, "tombstoned_root"),
    "permanent_receipt_retention": ("maintenance_migration", "committed", None, "unchanged", "none", None, "permanent_retention"),
    "bounded_receipt_retention": ("update_replay_retention", "committed", None, "changed", "none", None, "bounded_retention"),
    "dependency_safe_pruning": ("update_replay_retention", "failure", "invalid_execution_checkpoint", "unchanged", "none", None, "dependency_pruning"),
    "permanent_to_bounded_irreversible": ("update_replay_retention", "committed", None, "changed", "none", None, "bounded_retention"),
    "bounded_to_permanent_rejected": ("update_replay_retention", "failure", "invalid_execution_checkpoint", "unchanged", "none", None, "reverse_retention"),
    "outbox_not_attempted": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "outbox_not_attempted"),
    "outbox_retryable_failure": ("update_pending_outbox", "committed", None, "changed", "none", None, "pending_retryable"),
    "outbox_ambiguous": ("update_pending_outbox", "committed", None, "changed", "none", None, "pending_ambiguous"),
    "outbox_confirmed": ("terminalize_outbox", "committed", None, "changed", "none", None, "terminal_confirmed"),
    "outbox_permanently_rejected": ("terminalize_outbox", "committed", None, "changed", "none", None, "terminal_permanently_rejected"),
    "outbox_operator_cancelled": ("terminalize_outbox", "committed", None, "changed", "none", None, "terminal_operator_cancelled"),
    "outbox_discarded": ("terminalize_outbox", "committed", None, "changed", "none", None, "terminal_discarded"),
    "outbox_dead_lettered": ("terminalize_outbox", "committed", None, "changed", "none", None, "terminal_dead_lettered"),
    "outbox_compact_tombstone": ("compact_outbox", "committed", None, "changed", "none", None, "compact"),
    "outbox_idempotent_pending_update": ("update_pending_outbox", "committed", None, "unchanged", "none", None, "pending_retryable"),
    "outbox_idempotent_terminal_update": ("terminalize_outbox", "committed", None, "unchanged", "none", None, "terminal_dead_lettered"),
    "outbox_effect_conflict": ("terminalize_outbox", "failure", "effect_id_conflict", "unchanged", "none", None, "effect_conflict"),
    "outbox_forbidden_deletion": ("delete_outbox_record", "failure", "invalid_execution_checkpoint", "unchanged", "none", None, "referenced_effect"),
    "outbox_receipt_linkage": ("foreground_process_delivery", "committed", None, "changed", "dispatch", None, "outbox_linkage"),
    "direct_store_injection": ("inject_execution_store", "accepted", None, "absent", "none", None, "direct_injection"),
    "public_adapter_registry": ("resolve_adapter", "accepted", None, "absent", "none", None, "public_registry"),
    "duplicate_adapter_registration": ("register_adapter", "failure", "duplicate_adapter_registration", "absent", "none", None, "public_registry"),
    "unknown_adapter": ("resolve_adapter", "failure", "unknown_adapter", "absent", "none", None, "public_registry"),
    "invalid_adapter_configuration": ("resolve_adapter", "failure", "invalid_adapter_configuration", "absent", "none", None, "invalid_configuration"),
    "adapter_capability_mismatch": ("resolve_adapter", "failure", "adapter_capability_mismatch", "absent", "none", None, "capability_mismatch"),
    "memory_durable_profile_rejected": ("resolve_adapter", "failure", "adapter_capability_mismatch", "absent", "none", None, "memory"),
    "root_identity_profile_requirement": ("validate_host_profile", "accepted", None, "absent", "none", None, "root_identity_profile"),
    "strict_outbox_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "strict_complete"),
    "compact_outbox_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "compact_complete"),
    "durable_embedded_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "durable_complete"),
    "exactly_once_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "exactly_once_complete"),
    "broker_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "broker_complete"),
    "shared_transaction_profile_requirements": ("validate_host_profile", "accepted", None, "absent", "none", None, "shared_complete"),
    "memory_capability_boundary": ("register_adapter", "accepted", None, "absent", "none", None, "memory"),
    "file_capability_boundary": ("resolve_adapter", "failure", "adapter_capability_mismatch", "absent", "none", None, "file"),
    "sqlite_capability_boundary": ("resolve_adapter", "accepted", None, "absent", "none", None, "sqlite"),
    "postgresql_capability_boundary": ("resolve_adapter", "accepted", None, "absent", "none", None, "postgresql"),
    "bundled_public_registration": ("register_adapter", "accepted", None, "absent", "none", None, "bundled_public"),
    "third_party_public_registration": ("resolve_adapter", "accepted", None, "absent", "none", None, "third_party_public"),
    "durable_embedded_missing_durable": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_durable"),
    "durable_profile_missing_root_identity": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_root_identity"),
    "durable_profile_missing_atomic_processing": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_atomic"),
    "exactly_once_missing_receipt_retention": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_receipt_retention"),
    "bounded_exactly_once_rejected": ("validate_host_profile", "failure", "adapter_capability_mismatch", "unchanged", "none", None, "bounded_exactly_once"),
    "broker_profile_missing_redelivery": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_redelivery"),
    "broker_profile_missing_ack_after_commit": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_ack"),
    "broker_profile_missing_outbox_worker": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_worker"),
    "strict_outbox_missing_terminal_retention": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_terminal_retention"),
    "strict_outbox_missing_worker": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_worker"),
    "strict_outbox_missing_total_lifecycle": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_total_lifecycle"),
    "strict_outbox_missing_unresolved_retention": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_unresolved"),
    "compact_outbox_missing_tombstone_retention": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_compact_retention"),
    "compact_outbox_missing_worker": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_worker"),
    "compact_outbox_missing_total_lifecycle": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_total_lifecycle"),
    "compact_outbox_missing_reference_retention": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_reference_retention"),
    "shared_transaction_missing_native_use": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_native"),
    "shared_transaction_missing_store_capability": ("validate_host_profile", "failure", "adapter_capability_mismatch", "absent", "none", None, "missing_shared_capability"),
}
if frozenset(EXECUTION_CHECKPOINT_COVERAGE_RULES) != (
    REQUIRED_EXECUTION_CHECKPOINT_COVERAGE - EXECUTION_STORE_SCOPE_COVERAGE
):
    raise RuntimeError("execution-checkpoint coverage rules are not total")
ARTIFACT_FORMAT_FIELDS = {
    "aggregate_state": (
        "aggregate_state_format",
        "determa.aggregate_state",
        "aggregate_state_schema_version",
        1,
        "unsupported_aggregate_state_format",
        "unsupported_aggregate_state_schema_version",
        "invalid_aggregate_state",
    ),
    "aggregate_state_v2": (
        "aggregate_state_format",
        "determa.aggregate_state",
        "aggregate_state_schema_version",
        2,
        "unsupported_aggregate_state_format",
        "unsupported_aggregate_state_schema_version",
        "invalid_aggregate_state",
    ),
    "migration_descriptor": (
        "migration_descriptor_format",
        "determa.aggregate_migration",
        "migration_descriptor_schema_version",
        1,
        "unsupported_migration_descriptor_format",
        "unsupported_migration_descriptor_schema_version",
        "invalid_migration_descriptor",
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
    "aggregate_state_package": (
        "aggregate_state_package_format",
        "determa.aggregate_state_package",
        "aggregate_state_package_schema_version",
        1,
        "unsupported_aggregate_state_package_format",
        "unsupported_aggregate_state_package_schema_version",
        "invalid_aggregate_state_package",
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
    "execution_checkpoint": (
        "execution_checkpoint_format",
        "determa.execution_checkpoint",
        "execution_checkpoint_schema_version",
        1,
        "unsupported_execution_checkpoint_format",
        "unsupported_execution_checkpoint_schema_version",
        "invalid_execution_checkpoint",
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


def validate_aggregate_v1_fault_codes(document: dict[str, Any]) -> None:
    """Validate only normative runtime fault records in a standalone v1 aggregate."""
    for runtime in document["runtimes"]:
        validate_engine_fault_code(runtime.get("fault"), "aggregate v1 runtime")


def validate_reserved_failure_envelope(envelope: dict[str, Any], location: str) -> None:
    if envelope["event"] not in {
        "determa.component_failed",
        "determa.spawned_instance_failed",
    }:
        return
    payload = decode_typed_value(envelope["payload"])
    validate_engine_fault_code(payload.get("fault"), location)


def verify_artifact_digest(kind: str, document: Any, path: Path) -> None:
    if kind in {"aggregate_state", "aggregate_state_v2"}:
        digest = document.get("aggregate_state_digest")
        without_digest = dict(document)
        without_digest.pop("aggregate_state_digest", None)
        domain = (
            "determa-aggregate-state-digest-2"
            if kind == "aggregate_state_v2"
            else "determa-aggregate-state-digest-1"
        )
        expected = hash_value([domain, without_digest])
        if digest != expected:
            raise ValidationFailure(
                f"{path}: aggregate_state_digest {digest!r} != {expected!r}"
            )
    elif kind in {"migration_descriptor", "migration_descriptor_v2"}:
        digest = document.get("migration_descriptor_digest")
        without_digest = dict(document)
        without_digest.pop("migration_descriptor_digest", None)
        domain = (
            "determa-migration-descriptor-2"
            if kind == "migration_descriptor_v2"
            else "determa-migration-descriptor-1"
        )
        expected = hash_value([domain, without_digest])
        if digest != expected:
            raise ValidationFailure(
                f"{path}: migration_descriptor_digest {digest!r} != {expected!r}"
            )
    elif kind in {"aggregate_state_package", "aggregate_state_package_v2"}:
        aggregate_kind = (
            "aggregate_state_v2"
            if kind == "aggregate_state_package_v2"
            else "aggregate_state"
        )
        descriptor_kind = (
            "migration_descriptor_v2"
            if kind == "aggregate_state_package_v2"
            else "migration_descriptor"
        )
        verify_artifact_digest(aggregate_kind, document["aggregate_state"], path)
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
            verify_artifact_digest(descriptor_kind, descriptor, path)
            digest = descriptor["migration_descriptor_digest"]
            if digest in descriptor_digests:
                raise ValidationFailure(
                    f"{path}: duplicate descriptor attachment {digest}"
                )
            descriptor_digests.add(digest)
    elif kind in {"execution_checkpoint", "execution_checkpoint_v2"}:
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            verify_artifact_digest(
                "aggregate_state_v2" if kind == "execution_checkpoint_v2" else "aggregate_state",
                root_record["aggregate_state"],
                path,
            )
        digest = document.get("execution_checkpoint_digest")
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        domain = (
            "determa-execution-checkpoint-digest-2"
            if kind == "execution_checkpoint_v2"
            else "determa-execution-checkpoint-digest-1"
        )
        expected = hash_value([domain, without_digest])
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


def validate_execution_checkpoint_semantics(document: dict[str, Any]) -> None:
    root_id = document["root_instance_id"]
    revision = canonical_decimal(document["revision"], "checkpoint.revision")
    root_record = document["root_record"]
    receipts = document["operation_receipts"]
    creation = receipts[0]

    if creation["operation_kind"] != "creation" or creation["receipt_sequence"] != "0":
        raise ValidationFailure("checkpoint: creation receipt must remain first")
    if root_record["status"] == "retained":
        aggregate = root_record["aggregate_state"]
        for runtime in aggregate["runtimes"]:
            validate_engine_fault_code(runtime["fault"], "checkpoint runtime")
        if aggregate["root_instance_id"] != root_id:
            raise ValidationFailure("checkpoint: retained aggregate root mismatch")
        creation_id = aggregate["creation_id"]
        root_runtime_id = aggregate["root_runtime_id"]
    else:
        creation_id = root_record["creation_id"]
        root_runtime_id = root_record["root_runtime_id"]
    if creation["creation_id"] != creation_id:
        raise ValidationFailure("checkpoint: creation identity mismatch")
    for receipt in receipts:
        validate_engine_fault_code(receipt.get("fault"), "checkpoint receipt")
        outcome = receipt.get("outcome")
        if isinstance(outcome, dict):
            validate_engine_fault_code(
                outcome.get("fault"), "checkpoint terminal outcome"
            )

    next_receipt = canonical_decimal(
        document["next_operation_receipt_sequence"],
        "checkpoint.next_operation_receipt_sequence",
    )
    receipt_sequences = [
        canonical_decimal(
            receipt["receipt_sequence"],
            f"checkpoint.operation_receipts[{index}].receipt_sequence",
        )
        for index, receipt in enumerate(receipts)
    ]
    if receipt_sequences != sorted(receipt_sequences) or len(receipt_sequences) != len(
        set(receipt_sequences)
    ):
        raise ValidationFailure(
            "checkpoint: operation receipts are not canonically ordered"
        )
    if any(sequence >= next_receipt for sequence in receipt_sequences):
        raise ValidationFailure(
            "checkpoint: operation receipt counter was not advanced"
        )

    retention = document["replay_retention"]
    cutoff_value = retention["pruned_through_receipt_sequence"]
    cutoff = (
        canonical_decimal(cutoff_value, "checkpoint retention cutoff")
        if cutoff_value is not None
        else None
    )
    if retention["mode"] == "permanent":
        expected_receipts = list(range(next_receipt))
    elif cutoff is None:
        expected_receipts = list(range(next_receipt))
    else:
        expected_receipts = [0, *range(cutoff + 1, next_receipt)]
    if receipt_sequences != expected_receipts:
        raise ValidationFailure("checkpoint: receipt retention interval is incomplete")

    receipt_by_sequence = {
        receipt["receipt_sequence"]: receipt for receipt in receipts
    }
    prior_committed_revision = -1
    delivery_receipts: list[dict[str, Any]] = []
    referenced_effects: set[str] = set()
    referenced_migrations: set[str] = set()
    for receipt_index, receipt in enumerate(receipts):
        committed_revision = canonical_decimal(
            receipt["committed_revision"],
            f"checkpoint.operation_receipts[{receipt_index}].committed_revision",
        )
        if (
            committed_revision > revision
            or committed_revision <= prior_committed_revision
        ):
            raise ValidationFailure("checkpoint: receipt revisions are not increasing")
        prior_committed_revision = committed_revision
        if receipt["operation_kind"] == "creation" and committed_revision != 0:
            raise ValidationFailure("checkpoint: creation revision must be zero")
        if receipt["operation_kind"] == "delivery":
            delivery_receipts.append(receipt)
            accepted_revision = canonical_decimal(
                receipt["accepted_revision"], "checkpoint delivery accepted revision"
            )
            accepted_sequence = canonical_decimal(
                receipt["accepted_delivery_sequence"],
                "checkpoint delivery accepted sequence",
            )
            if (
                accepted_revision > committed_revision
                or accepted_sequence
                >= canonical_decimal(
                    document["next_delivery_sequence"],
                    "checkpoint.next_delivery_sequence",
                )
            ):
                raise ValidationFailure(
                    "checkpoint: impossible delivery receipt revision"
                )
            if (
                receipt["delivery_mode"] == "internal"
                and accepted_revision == committed_revision
            ):
                raise ValidationFailure(
                    "checkpoint: internal delivery cannot be foreground"
                )
        if receipt["operation_kind"] == "maintenance_migration":
            referenced_migrations.update(receipt["migration_sequences"])
        for emission_index, emission in enumerate(
            receipt.get("emission_references", [])
        ):
            if canonical_decimal(
                emission["emission_index"], "checkpoint emission index"
            ) != emission_index:
                raise ValidationFailure("checkpoint: noncontiguous emission indexes")
            if emission["kind"] == "external_outbox":
                referenced_effects.add(emission["effect_id"])

    next_delivery = canonical_decimal(
        document["next_delivery_sequence"], "checkpoint.next_delivery_sequence"
    )
    pending = document["pending_deliveries"]
    pending_sequences = [
        canonical_decimal(item["delivery_sequence"], "checkpoint pending delivery")
        for item in pending
    ]
    if (
        pending_sequences != sorted(pending_sequences)
        or len(pending_sequences) != len(set(pending_sequences))
        or any(sequence >= next_delivery for sequence in pending_sequences)
    ):
        raise ValidationFailure("checkpoint: pending delivery ordering is invalid")
    pending_event_ids = [item["envelope"]["event_id"] for item in pending]
    receipt_event_ids = [receipt["event_id"] for receipt in delivery_receipts]
    if (
        len(pending_event_ids) != len(set(pending_event_ids))
        or len(receipt_event_ids) != len(set(receipt_event_ids))
        or set(pending_event_ids) & set(receipt_event_ids)
    ):
        raise ValidationFailure("checkpoint: delivery identities overlap")
    allocated_delivery_sequences = pending_sequences + [
        canonical_decimal(
            receipt["accepted_delivery_sequence"],
            "checkpoint receipt delivery sequence",
        )
        for receipt in delivery_receipts
    ]
    if len(allocated_delivery_sequences) != len(set(allocated_delivery_sequences)):
        raise ValidationFailure("checkpoint: delivery sequences overlap")

    delivery_by_sequence = {
        item["delivery_sequence"]: (
            item["envelope"]["event_id"],
            item["accepted_revision"],
            item["delivery_mode"],
            item["origin"],
        )
        for item in pending
    }
    delivery_by_sequence.update(
        {
            receipt["accepted_delivery_sequence"]: (
                receipt["event_id"],
                receipt["accepted_revision"],
                receipt["delivery_mode"],
                receipt["origin"],
            )
            for receipt in delivery_receipts
        }
    )
    for item in pending:
        validate_typed_value_canonical(
            item["envelope"]["payload"],
            "checkpoint pending delivery envelope payload",
        )
        accepted_revision = canonical_decimal(
            item["accepted_revision"], "checkpoint pending accepted revision"
        )
        if accepted_revision > revision:
            raise ValidationFailure(
                "checkpoint: pending delivery revision is in the future"
            )
        expected_digest = hash_value(
            [
                "determa-inbox-envelope-digest-1",
                "1",
                root_id,
                item["delivery_mode"],
                item["envelope"],
            ]
        )
        if item["envelope_digest"] != expected_digest:
            raise ValidationFailure("checkpoint: pending delivery digest mismatch")
        target_member = next(iter(item["envelope"]["target"].values()))
        if target_member["root_instance_id"] != root_id:
            raise ValidationFailure(
                "checkpoint: pending delivery target belongs to another root"
            )

    if retention["mode"] == "permanent" and sorted(
        allocated_delivery_sequences
    ) != list(range(next_delivery)):
        raise ValidationFailure(
            "checkpoint: permanent delivery allocation interval has a gap"
        )

    for sequence, (
        event_id,
        accepted_revision,
        mode,
        origin,
    ) in delivery_by_sequence.items():
        if mode != "internal":
            continue
        producer_sequence = origin["producing_receipt_sequence"]
        producer = receipt_by_sequence.get(producer_sequence)
        if producer is None:
            raise ValidationFailure("checkpoint: internal delivery producer was pruned")
        if accepted_revision != producer["committed_revision"]:
            raise ValidationFailure("checkpoint: internal acceptance revision mismatch")
        emission_index = canonical_decimal(
            origin["emission_index"], "checkpoint internal emission index"
        )
        emissions = producer.get("emission_references", [])
        if emission_index >= len(emissions):
            raise ValidationFailure("checkpoint: internal emission origin is dangling")
        emission = emissions[emission_index]
        if (
            emission.get("kind") != "internal_delivery"
            or emission.get("event_id") != event_id
            or emission.get("delivery_sequence") != sequence
        ):
            raise ValidationFailure("checkpoint: internal emission linkage mismatch")

    for receipt in receipts:
        for emission in receipt.get("emission_references", []):
            if emission["kind"] != "internal_delivery":
                continue
            linked = delivery_by_sequence.get(emission["delivery_sequence"])
            if linked is None or linked[0] != emission["event_id"]:
                if retention["mode"] == "permanent":
                    raise ValidationFailure(
                        "checkpoint: internal delivery reference is dangling"
                    )

    pending_outbox = document["pending_outbox_intents"]
    terminal_outbox = document["terminal_outbox_records"]
    outbox_tombstones = document["outbox_effect_tombstones"]
    for index, item in enumerate(pending_outbox):
        validate_typed_value_canonical(
            item["intent"]["payload"],
            f"checkpoint pending outbox intent {index} payload",
        )
    for index, item in enumerate(terminal_outbox):
        validate_typed_value_canonical(
            item["intent"]["payload"],
            f"checkpoint terminal outbox intent {index} payload",
        )
    pending_intent_sequences = [
        canonical_decimal(
            item["intent"]["sequence"], "checkpoint outbox intent sequence"
        )
        for item in pending_outbox
    ]
    terminal_sequences = [
        canonical_decimal(
            item["terminal_sequence"], "checkpoint terminal outbox sequence"
        )
        for item in terminal_outbox
    ]
    tombstone_sequences = [
        canonical_decimal(
            item["terminal_sequence"], "checkpoint outbox tombstone sequence"
        )
        for item in outbox_tombstones
    ]
    if pending_intent_sequences != sorted(pending_intent_sequences):
        raise ValidationFailure("checkpoint: pending outbox order is invalid")
    full_intent_sequences = pending_intent_sequences + [
        canonical_decimal(
            item["intent"]["sequence"], "checkpoint terminal intent sequence"
        )
        for item in terminal_outbox
    ]
    if len(full_intent_sequences) != len(set(full_intent_sequences)):
        raise ValidationFailure("checkpoint: outbox intent sequences overlap")
    if terminal_sequences != sorted(terminal_sequences):
        raise ValidationFailure("checkpoint: terminal outbox order is invalid")
    if tombstone_sequences != sorted(tombstone_sequences):
        raise ValidationFailure("checkpoint: outbox tombstone order is invalid")
    all_terminal_sequences = terminal_sequences + tombstone_sequences
    if len(all_terminal_sequences) != len(set(all_terminal_sequences)):
        raise ValidationFailure("checkpoint: terminal outbox sequences overlap")
    next_terminal = canonical_decimal(
        document["next_outbox_terminal_sequence"],
        "checkpoint.next_outbox_terminal_sequence",
    )
    if any(sequence >= next_terminal for sequence in all_terminal_sequences):
        raise ValidationFailure("checkpoint: outbox terminal counter was not advanced")

    pending_effects = [item["intent"]["effect_id"] for item in pending_outbox]
    terminal_effects = [item["intent"]["effect_id"] for item in terminal_outbox]
    tombstone_effects = [item["effect_id"] for item in outbox_tombstones]
    all_effects = pending_effects + terminal_effects + tombstone_effects
    if len(all_effects) != len(set(all_effects)):
        raise ValidationFailure("checkpoint: effect identities overlap")
    if not referenced_effects.issubset(set(all_effects)):
        raise ValidationFailure("checkpoint: outbox emission reference is dangling")
    if retention["mode"] == "permanent" and set(all_effects) != referenced_effects:
        raise ValidationFailure("checkpoint: permanent outbox record lacks producer")
    for item in pending_outbox:
        state_revision = canonical_decimal(
            item["state_revision"], "checkpoint outbox state revision"
        )
        if state_revision > revision:
            raise ValidationFailure(
                "checkpoint: outbox state revision is in the future"
            )
        effect_id = item["intent"]["effect_id"]
        producers = [
            receipt
            for receipt in receipts
            if any(
                emission.get("kind") == "external_outbox"
                and emission.get("effect_id") == effect_id
                for emission in receipt.get("emission_references", [])
            )
        ]
        if len(producers) != 1:
            raise ValidationFailure("checkpoint: outbox producer is not unique")
        producer_revision = canonical_decimal(
            producers[0]["committed_revision"],
            "checkpoint outbox producer revision",
        )
        if item["delivery_state"]["status"] == "not_attempted":
            if state_revision != producer_revision:
                raise ValidationFailure(
                    "checkpoint: initial outbox state revision mismatches producer"
                )
        elif state_revision <= producer_revision:
            raise ValidationFailure(
                "checkpoint: attempted outbox state predates its producer"
            )
    for item in [*terminal_outbox, *outbox_tombstones]:
        if canonical_decimal(
            item["committed_revision"], "checkpoint outbox committed revision"
        ) > revision:
            raise ValidationFailure("checkpoint: outbox revision is in the future")

    audits = document["migration_audit_records"]
    audit_sequences = [
        canonical_decimal(item["migration_sequence"], "checkpoint migration sequence")
        for item in audits
    ]
    if audit_sequences != sorted(audit_sequences) or len(audit_sequences) != len(
        set(audit_sequences)
    ):
        raise ValidationFailure("checkpoint: migration audit order is invalid")
    audit_sequence_strings = {item["migration_sequence"] for item in audits}
    if not referenced_migrations.issubset(audit_sequence_strings):
        raise ValidationFailure("checkpoint: migration receipt has dangling audit")
    if (
        retention["mode"] == "permanent"
        and referenced_migrations != audit_sequence_strings
    ):
        raise ValidationFailure("checkpoint: permanent audit lacks receipt")
    for audit in audits:
        if (
            audit["root_instance_id"] != root_id
            or audit["root_runtime_id"] != root_runtime_id
        ):
            raise ValidationFailure("checkpoint: migration audit root mismatch")

    if root_record["status"] == "tombstone":
        final_receipt_digest = receipts[-1]["resulting_aggregate_state_digest"]
        if root_record["final_aggregate_state_digest"] != final_receipt_digest:
            raise ValidationFailure(
                "checkpoint: tombstone final aggregate digest lacks retained evidence"
            )


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
    creation_wrapper = receipts[0]
    if creation_wrapper["operation_kind"] == "legacy_v1_creation":
        creation_receipt = creation_wrapper["legacy_receipt"]
    elif creation_wrapper["operation_kind"] == "creation":
        creation_receipt = creation_wrapper
    else:
        raise ValidationFailure("checkpoint v2: creation receipt must remain first")
    checkpoint_creation_id = (
        root_record["aggregate_state"]["creation_id"]
        if root_record["status"] == "retained"
        else root_record["creation_id"]
    )
    if creation_receipt["creation_id"] != checkpoint_creation_id:
        raise ValidationFailure("checkpoint v2: creation identity mismatch")
    legacy_terminal_events: dict[str, dict[str, Any]] = {}
    legacy_terminal_acceptance_sequences: set[str] = set()
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
        legacy_receipt = receipt.get("legacy_receipt")
        if isinstance(legacy_receipt, dict):
            legacy_committed_revision = legacy_receipt.get("committed_revision")
            if legacy_committed_revision is not None and canonical_decimal(
                legacy_committed_revision, "checkpoint v2 legacy receipt revision"
            ) > revision:
                raise ValidationFailure(
                    "checkpoint v2: legacy receipt revision is in the future"
                )
            legacy_accepted_revision = legacy_receipt.get("accepted_revision")
            if legacy_accepted_revision is not None and canonical_decimal(
                legacy_accepted_revision, "checkpoint v2 legacy accepted revision"
            ) > revision:
                raise ValidationFailure(
                    "checkpoint v2: legacy accepted revision is in the future"
                )
            if (
                legacy_committed_revision is not None
                and legacy_accepted_revision is not None
                and canonical_decimal(
                    legacy_accepted_revision,
                    "checkpoint v2 legacy accepted revision",
                )
                > canonical_decimal(
                    legacy_committed_revision,
                    "checkpoint v2 legacy committed revision",
                )
            ):
                raise ValidationFailure(
                    "checkpoint v2: legacy terminal revision precedes acceptance"
                )
            if legacy_receipt.get("receipt_sequence") != receipt["receipt_sequence"]:
                raise ValidationFailure(
                    "checkpoint v2: legacy receipt wrapper sequence mismatch"
                )
            validate_engine_fault_code(
                legacy_receipt.get("fault"), "checkpoint v2 legacy receipt"
            )
            legacy_outcome = legacy_receipt.get("outcome")
            if isinstance(legacy_outcome, dict):
                validate_engine_fault_code(
                    legacy_outcome.get("fault"),
                    "checkpoint v2 legacy terminal outcome",
                )
            if legacy_receipt.get("operation_kind") == "delivery":
                event_id = legacy_receipt["event_id"]
                acceptance_sequence = legacy_receipt["accepted_delivery_sequence"]
                if (
                    event_id in legacy_terminal_events
                    or acceptance_sequence in legacy_terminal_acceptance_sequences
                ):
                    raise ValidationFailure(
                        "checkpoint v2: duplicate legacy terminal event identity"
                    )
                legacy_terminal_events[event_id] = legacy_receipt
                legacy_terminal_acceptance_sequences.add(acceptance_sequence)
    sequences = [
        canonical_decimal(receipt["receipt_sequence"], "receipt sequence")
        for receipt in receipts
    ]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise ValidationFailure("checkpoint v2: receipt order is invalid")

    terminal_location_receipts = {
        receipt["event_id"]: receipt
        for receipt in receipts
        if receipt["operation_kind"] == "event_terminal"
    }
    tombstone_locations = {
        item["event_id"]: item for item in document["event_identity_tombstones"]
    }

    def verify_legacy_acceptance_evidence(
        receipt: dict[str, Any], entry: dict[str, Any] | None
    ) -> None:
        evidence = receipt.get("legacy_v1_delivery")
        if evidence is None:
            return
        origin = evidence["origin"]
        if (
            evidence["delivery_sequence"] != receipt["acceptance_sequence"]
            or evidence["envelope_digest"] == "sha256:" + ("0" * 64)
            or evidence["envelope_digest"] == receipt["request_digest"]
        ):
            raise ValidationFailure(
                "checkpoint v2: legacy acceptance provenance mismatch"
            )
        if entry is None:
            valid_origin = (
                receipt["delivery_mode"] == "input"
                and origin == {"kind": "host_input"}
            ) or (
                receipt["delivery_mode"] == "internal"
                and origin.get("kind") == "internal_emission"
                and set(origin)
                == {"kind", "producing_receipt_sequence", "emission_index"}
            )
            if not valid_origin:
                raise ValidationFailure(
                    "checkpoint v2: legacy acceptance provenance mismatch"
                )
            return
        source = entry["envelope"]["source"]
        legacy_envelope = copy.deepcopy(entry["envelope"])
        legacy_envelope.pop("cause_id")
        legacy_envelope.pop("source")
        expected_legacy_digest = hash_value(
            [
                "determa-inbox-envelope-digest-1",
                "1",
                document["root_instance_id"],
                entry["delivery_mode"],
                legacy_envelope,
            ]
        )
        valid_origin = (
            "host" in source and origin == {"kind": "host_input"}
        ) or (
            "legacy_v1_internal" in source
            and origin
            == {
                "kind": "internal_emission",
                **source["legacy_v1_internal"],
            }
        )
        if evidence["envelope_digest"] != expected_legacy_digest or not valid_origin:
            raise ValidationFailure(
                "checkpoint v2: legacy acceptance provenance mismatch"
            )

    upgrade_acceptance_sequences: set[int] = set()
    legacy_wrappers = [
        receipt
        for receipt in receipts
        if receipt["operation_kind"]
        in {"legacy_v1_creation", "legacy_v1_operation"}
    ]
    if legacy_wrappers:
        if receipts[: len(legacy_wrappers)] != legacy_wrappers:
            raise ValidationFailure("checkpoint v2: legacy receipt prefix is invalid")
        source_revision = max(
            canonical_decimal(
                receipt["legacy_receipt"]["committed_revision"],
                "legacy source committed revision",
            )
            for receipt in legacy_wrappers
        )
        next_upgrade_sequence = None
        for receipt in receipts[len(legacy_wrappers) :]:
            receipt_sequence = canonical_decimal(
                receipt["receipt_sequence"], "upgrade acceptance sequence"
            )
            accepted_revision = canonical_decimal(
                receipt.get("accepted_revision", "0"),
                "upgrade preserved accepted revision",
            )
            if (
                receipt["operation_kind"] != "acceptance"
                or (
                    next_upgrade_sequence is not None
                    and receipt_sequence != next_upgrade_sequence
                )
                or accepted_revision > source_revision + 1
            ):
                break
            entry = mailbox_entries.get(receipt["event_id"])
            terminal = terminal_location_receipts.get(receipt["event_id"])
            tombstone = tombstone_locations.get(receipt["event_id"])
            live_match = entry is not None and (
                receipt["request_digest"] == entry["envelope_digest"]
                and receipt["acceptance_sequence"] == entry["acceptance_sequence"]
                and receipt["delivery_mode"] == entry["delivery_mode"]
            )
            terminal_match = terminal is not None and (
                receipt["request_digest"] == terminal["request_digest"]
                and receipt["acceptance_sequence"] == terminal["acceptance_sequence"]
            )
            tombstone_match = tombstone is not None and (
                tombstone.get(
                    "request_digest_domain", "determa-inbox-envelope-digest-2"
                )
                == "determa-inbox-envelope-digest-2"
                and receipt["request_digest"] == tombstone["request_digest"]
                and receipt["acceptance_sequence"] == tombstone["acceptance_sequence"]
            )
            if not (live_match or terminal_match or tombstone_match):
                break
            verify_legacy_acceptance_evidence(receipt, entry if live_match else None)
            if (
                receipt["delivery_mode"] == "internal"
                and "legacy_v1_delivery" not in receipt
            ):
                raise ValidationFailure(
                    "checkpoint v2: converted internal acceptance lacks legacy evidence"
                )
            upgrade_acceptance_sequences.add(receipt_sequence)
            next_upgrade_sequence = receipt_sequence + 1
            source_revision = max(source_revision, accepted_revision)

    preserved_acceptance_history = [
        (
            canonical_decimal(
                receipt["legacy_receipt"]["accepted_delivery_sequence"],
                "legacy acceptance sequence",
            ),
            canonical_decimal(
                receipt["legacy_receipt"]["accepted_revision"],
                "legacy accepted revision",
            ),
        )
        for receipt in legacy_wrappers
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["legacy_receipt"].get("operation_kind") == "delivery"
    ] + [
        (
            canonical_decimal(
                receipt["acceptance_sequence"],
                "converted acceptance sequence",
            ),
            canonical_decimal(
                receipt["accepted_revision"],
                "converted accepted revision",
            ),
        )
        for receipt in receipts
        if canonical_decimal(receipt["receipt_sequence"], "receipt sequence")
        in upgrade_acceptance_sequences
    ]
    preserved_acceptance_history.sort()
    if (
        len({sequence for sequence, _ in preserved_acceptance_history})
        != len(preserved_acceptance_history)
        or [revision for _, revision in preserved_acceptance_history]
        != sorted(revision for _, revision in preserved_acceptance_history)
    ):
        raise ValidationFailure(
            "checkpoint v2: preserved acceptance history is not monotonic"
        )

    receipt_chronology: list[tuple[int, int]] = []
    for receipt, receipt_sequence in zip(receipts, sequences, strict=True):
        if receipt_sequence in upgrade_acceptance_sequences:
            continue
        if "committed_revision" in receipt:
            effective_revision = receipt["committed_revision"]
        elif "accepted_revision" in receipt:
            effective_revision = receipt["accepted_revision"]
        else:
            effective_revision = receipt["legacy_receipt"]["committed_revision"]
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
    if sequences and canonical_decimal(
        document["next_operation_receipt_sequence"], "next receipt sequence"
    ) <= max(sequences):
        raise ValidationFailure("checkpoint v2: receipt counter regression")
    pruning_cutoff = document["replay_retention"][
        "pruned_through_receipt_sequence"
    ]
    if pruning_cutoff is not None:
        cutoff = canonical_decimal(pruning_cutoff, "checkpoint pruning cutoff")
        if any(sequence != 0 and sequence <= cutoff for sequence in sequences):
            raise ValidationFailure(
                "checkpoint v2: retained receipt contradicts pruning cutoff"
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
        | legacy_terminal_acceptance_sequences
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
    if acceptance_sequences & legacy_terminal_acceptance_sequences:
        raise ValidationFailure(
            "checkpoint v2: acceptance receipt overlaps legacy terminal allocation"
        )
    if legacy_terminal_acceptance_sequences & (
        terminal_acceptance_sequences | tombstone_acceptance_sequences
    ):
        raise ValidationFailure(
            "checkpoint v2: legacy and version-2 terminal allocations overlap"
        )
    mailbox_event_ids = set(mailbox_entries)
    if mailbox_event_ids & terminal_receipts.keys():
        raise ValidationFailure("checkpoint v2: event is live and terminal")
    if mailbox_event_ids & tombstones.keys() or terminal_receipts.keys() & tombstones.keys():
        raise ValidationFailure("checkpoint v2: event overlaps tombstone")
    if acceptance_receipts.keys() & tombstones.keys():
        raise ValidationFailure("checkpoint v2: acceptance receipt overlaps replacement tombstone")
    if acceptance_receipts.keys() & legacy_terminal_events.keys():
        raise ValidationFailure("checkpoint v2: acceptance receipt overlaps legacy terminal event")
    if mailbox_event_ids & legacy_terminal_events.keys():
        raise ValidationFailure("checkpoint v2: legacy terminal event remains in a mailbox")
    if (terminal_receipts.keys() | tombstones.keys()) & legacy_terminal_events.keys():
        raise ValidationFailure("checkpoint v2: legacy terminal event has multiple lifecycle locations")
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
                + list(legacy_terminal_acceptance_sequences)
            )
        ]
        if retained_acceptance_allocations and max(retained_acceptance_allocations) >= next_acceptance:
            raise ValidationFailure("checkpoint v2: acceptance counter regression")
    producer_references: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    legacy_producer_references: dict[
        str, list[tuple[dict[str, Any], dict[str, Any]]]
    ] = {}
    referenced_effects: set[str] = set()
    for producer in receipts:
        for reference in producer.get("emission_references", []):
            if reference.get("kind") in {"internal_mailbox", "internal_terminal"}:
                producer_references.setdefault(reference["event_id"], []).append((producer, reference))
            elif reference.get("kind") == "external_outbox":
                referenced_effects.add(reference["effect_id"])
        legacy_receipt = producer.get("legacy_receipt")
        if isinstance(legacy_receipt, dict):
            for reference in legacy_receipt.get("emission_references", []):
                if reference.get("kind") == "internal_delivery":
                    legacy_producer_references.setdefault(
                        reference["event_id"], []
                    ).append((producer, reference))
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
            if producer_revision is None and isinstance(
                producer.get("legacy_receipt"), dict
            ):
                producer_revision = producer["legacy_receipt"].get(
                    "committed_revision"
                )
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
        requires_acceptance = "host" in source or "legacy_v1_internal" in source
        if requires_acceptance:
            if receipt is None:
                raise ValidationFailure("checkpoint v2: accepted mailbox event lacks receipt")
            if receipt["request_digest"] != entry["envelope_digest"] or receipt["acceptance_sequence"] != entry["acceptance_sequence"] or receipt["delivery_mode"] != entry["delivery_mode"]:
                raise ValidationFailure("checkpoint v2: mailbox acceptance identity mismatch")
            legacy_evidence = receipt.get("legacy_v1_delivery")
            if legacy_evidence is not None:
                verify_legacy_acceptance_evidence(receipt, entry)
            if "legacy_v1_internal" in source:
                evidence = legacy_evidence
                origin = source["legacy_v1_internal"]
                if evidence is None or evidence["delivery_sequence"] != entry["acceptance_sequence"] or evidence["origin"].get("producing_receipt_sequence") != origin["producing_receipt_sequence"] or evidence["origin"].get("emission_index") != origin["emission_index"]:
                    raise ValidationFailure("checkpoint v2: legacy internal evidence mismatch")
                producers = legacy_producer_references.get(event_id, [])
                if (
                    len(producers) != 1
                    or producers[0][0]["receipt_sequence"]
                    != origin["producing_receipt_sequence"]
                    or producers[0][1]["emission_index"]
                    != origin["emission_index"]
                    or producers[0][1]["delivery_sequence"]
                    != entry["acceptance_sequence"]
                ):
                    raise ValidationFailure("checkpoint v2: legacy internal producer is missing")
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
            legacy_evidence = acceptance.get("legacy_v1_delivery")
            if (
                acceptance["delivery_mode"] == "internal"
                and legacy_evidence is not None
            ):
                origin = legacy_evidence["origin"]
                producers = legacy_producer_references.get(event_id, [])
                if (
                    len(producers) != 1
                    or producers[0][0]["receipt_sequence"]
                    != origin["producing_receipt_sequence"]
                    or producers[0][1]["emission_index"]
                    != origin["emission_index"]
                    or producers[0][1]["delivery_sequence"]
                    != terminal["acceptance_sequence"]
                ):
                    raise ValidationFailure(
                        "checkpoint v2: terminal legacy internal producer mismatch"
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
        | set(legacy_terminal_events)
    )
    if set(acceptance_receipts) - located:
        raise ValidationFailure("checkpoint v2: orphan acceptance receipt")
    for event_id, references in producer_references.items():
        if event_id not in located:
            raise ValidationFailure("checkpoint v2: orphan internal producer reference")
        if len(references) != 1:
            raise ValidationFailure("checkpoint v2: duplicate internal producer reference")
    for event_id, references in legacy_producer_references.items():
        if event_id not in located:
            raise ValidationFailure("checkpoint v2: orphan legacy producer reference")
        if len(references) != 1:
            raise ValidationFailure("checkpoint v2: duplicate legacy producer reference")
        _, reference = references[0]
        located_entry = mailbox_entries.get(event_id)
        located_terminal = terminal_receipts.get(event_id)
        located_tombstone = tombstones.get(event_id)
        located_legacy_terminal = legacy_terminal_events.get(event_id)
        location_evidence = (
            located_entry
            or located_terminal
            or located_tombstone
            or located_legacy_terminal
        )
        acceptance_sequence = location_evidence.get(
            "acceptance_sequence",
            location_evidence.get("accepted_delivery_sequence"),
        )
        if reference["delivery_sequence"] != acceptance_sequence:
            raise ValidationFailure(
                "checkpoint v2: legacy producer allocation does not match surviving event"
            )


def validate_version2_checkpoint_adversarial_probes(repository_root: Path) -> None:
    from generate_version2_vectors import upgrade_checkpoint

    case = repository_root / "conformance/profiles/execution-checkpoint/checkpoint-04-version2-mailboxes"

    def reseal(value: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(value)
        aggregate = result["root_record"].get("aggregate_state")
        if aggregate is not None:
            aggregate.pop("aggregate_state_digest", None)
            aggregate["aggregate_state_digest"] = hash_value(["determa-aggregate-state-digest-2", aggregate])
        result.pop("execution_checkpoint_digest", None)
        result["execution_checkpoint_digest"] = hash_value(["determa-execution-checkpoint-digest-2", result])
        return result

    admitted = analyze_artifact(case / "admitted-checkpoint-v2.json").document
    upgraded = analyze_artifact(case / "upgraded-checkpoint-v2.json").document
    upgraded_outbox = analyze_artifact(
        case / "upgraded-outbox-checkpoint-v2.json"
    ).document
    probes: dict[str, dict[str, Any]] = {}
    creation_mismatch = copy.deepcopy(admitted)
    creation_mismatch["root_record"]["aggregate_state"]["creation_id"] = (
        "different-creation"
    )
    probes["retained root creation identity mismatch"] = reseal(creation_mismatch)
    tombstoned = analyze_artifact(case / "tombstoned-checkpoint-v2.json").document
    tombstone_creation_mismatch = copy.deepcopy(tombstoned)
    tombstone_creation_mismatch["root_record"]["creation_id"] = (
        "different-creation"
    )
    probes["tombstone creation identity mismatch"] = reseal(
        tombstone_creation_mismatch
    )
    future_native_revision = copy.deepcopy(admitted)
    next(
        receipt
        for receipt in future_native_revision["operation_receipts"]
        if receipt["operation_kind"] == "acceptance"
    )["accepted_revision"] = "999"
    probes["native receipt revision beyond checkpoint"] = reseal(
        future_native_revision
    )
    future_legacy_revision = copy.deepcopy(upgraded)
    future_legacy_revision["operation_receipts"][0]["legacy_receipt"][
        "committed_revision"
    ] = "999"
    probes["legacy receipt revision beyond checkpoint"] = reseal(
        future_legacy_revision
    )
    native_terminal_before_acceptance = analyze_artifact(
        case / "terminal-checkpoint-v2.json"
    ).document
    next(
        receipt
        for receipt in native_terminal_before_acceptance["operation_receipts"]
        if receipt["operation_kind"] == "event_terminal"
    )["committed_revision"] = "0"
    probes["native terminal revision precedes acceptance"] = reseal(
        native_terminal_before_acceptance
    )
    legacy_terminal_before_acceptance = copy.deepcopy(upgraded)
    next(
        receipt["legacy_receipt"]
        for receipt in legacy_terminal_before_acceptance["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["legacy_receipt"].get("operation_kind") == "delivery"
        and receipt["legacy_receipt"].get("accepted_revision") == "1"
    )["committed_revision"] = "0"
    probes["wrapped legacy terminal revision precedes acceptance"] = reseal(
        legacy_terminal_before_acceptance
    )
    native_global_chronology = analyze_artifact(
        case / "native-internal-checkpoint-v2.json"
    ).document
    next(
        receipt
        for receipt in native_global_chronology["operation_receipts"]
        if receipt["operation_kind"] == "acceptance"
        and receipt["receipt_sequence"] == "3"
    )["accepted_revision"] = "2"
    probes["native receipt global chronology regression"] = reseal(
        native_global_chronology
    )
    legacy_global_chronology = copy.deepcopy(upgraded)
    next(
        receipt["legacy_receipt"]
        for receipt in legacy_global_chronology["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["receipt_sequence"] == "2"
    )["accepted_revision"] = "1"
    next(
        receipt["legacy_receipt"]
        for receipt in legacy_global_chronology["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["receipt_sequence"] == "2"
    )["committed_revision"] = "1"
    probes["wrapped legacy global chronology regression"] = reseal(
        legacy_global_chronology
    )
    orphan = copy.deepcopy(admitted)
    orphan["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"] = []
    probes["orphan acceptance"] = reseal(orphan)
    duplicate_acceptance = copy.deepcopy(admitted)
    receipt = copy.deepcopy(next(item for item in duplicate_acceptance["operation_receipts"] if item["operation_kind"] == "acceptance"))
    receipt["receipt_sequence"] = duplicate_acceptance["next_operation_receipt_sequence"]
    duplicate_acceptance["next_operation_receipt_sequence"] = str(int(receipt["receipt_sequence"]) + 1)
    duplicate_acceptance["operation_receipts"].append(receipt)
    probes["duplicate acceptance identity"] = reseal(duplicate_acceptance)
    wrong_digest = copy.deepcopy(admitted)
    wrong_digest["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]["envelope"]["payload"] = encode_typed_value({"amount": 9})
    probes["envelope digest mismatch"] = reseal(wrong_digest)
    missing_producer = copy.deepcopy(upgraded)
    internal_entry = missing_producer["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]
    producer_sequence = internal_entry["envelope"]["source"]["legacy_v1_internal"]["producing_receipt_sequence"]
    missing_producer["operation_receipts"] = [item for item in missing_producer["operation_receipts"] if item["receipt_sequence"] != producer_sequence]
    probes["missing legacy producer"] = reseal(missing_producer)
    missing_legacy_mailbox = copy.deepcopy(upgraded)
    missing_legacy_mailbox["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"] = []
    probes["removed upgraded legacy mailbox work"] = reseal(missing_legacy_mailbox)
    missing_legacy_acceptance = copy.deepcopy(upgraded)
    missing_legacy_acceptance["operation_receipts"] = [
        item
        for item in missing_legacy_acceptance["operation_receipts"]
        if not (
            item["operation_kind"] == "acceptance"
            and item.get("event_id") == internal_entry["envelope"]["event_id"]
        )
    ]
    probes["removed upgraded legacy acceptance receipt"] = reseal(missing_legacy_acceptance)
    removed_legacy_event = copy.deepcopy(missing_legacy_acceptance)
    removed_legacy_event["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"] = []
    probes["removed upgraded legacy work and receipt"] = reseal(removed_legacy_event)
    processed_legacy_internal = analyze_artifact(
        case / "processed-upgraded-internal-checkpoint-v2.json"
    ).document
    for field in ("producing_receipt_sequence", "emission_index"):
        invalid_provenance = copy.deepcopy(processed_legacy_internal)
        acceptance = next(
            receipt
            for receipt in invalid_provenance["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("delivery_mode") == "internal"
        )
        acceptance["legacy_v1_delivery"]["origin"][field] = "999"
        probes[f"processed legacy internal {field} mismatch"] = reseal(
            invalid_provenance
        )
    for filename, label in (
        (
            "multi-pending-processed-checkpoint-v2.json",
            "converted acceptance history regression without metadata",
        ),
        (
            "multi-pending-processed-with-metadata-checkpoint-v2.json",
            "converted acceptance history regression with metadata",
        ),
    ):
        backwards_history = analyze_artifact(case / filename).document
        next(
            receipt
            for receipt in backwards_history["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("event_id") == "delivery-unhandled"
        )["accepted_revision"] = "0"
        probes[label] = reseal(backwards_history)
    legacy_counter = copy.deepcopy(upgraded_outbox)
    legacy_counter["root_record"]["aggregate_state"][
        "next_acceptance_sequence"
    ] = "0"
    probes["legacy terminal acceptance counter"] = reseal(legacy_counter)
    legacy_duplicate_location = copy.deepcopy(upgraded)
    legacy_duplicate_aggregate = legacy_duplicate_location["root_record"][
        "aggregate_state"
    ]
    duplicate_entry = copy.deepcopy(
        legacy_duplicate_aggregate["runtimes"][0]["ready_mailbox"][0]
    )
    legacy_receipt = next(
        receipt["legacy_receipt"]
        for receipt in legacy_duplicate_location["operation_receipts"]
        if receipt["operation_kind"] == "legacy_v1_operation"
        and receipt["legacy_receipt"].get("operation_kind") == "delivery"
    )
    duplicate_entry["acceptance_sequence"] = legacy_receipt[
        "accepted_delivery_sequence"
    ]
    duplicate_entry["envelope"]["event_id"] = legacy_receipt["event_id"]
    duplicate_entry["envelope"]["cause_id"] = legacy_receipt["event_id"]
    duplicate_entry["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            legacy_duplicate_aggregate["root_instance_id"],
            duplicate_entry["delivery_mode"],
            duplicate_entry["envelope"],
        ]
    )
    legacy_duplicate_aggregate["runtimes"][0]["deferred_mailbox"] = [
        duplicate_entry
    ]
    probes["legacy terminal duplicated into mailbox"] = reseal(
        legacy_duplicate_location
    )
    duplicate_location = copy.deepcopy(admitted)
    duplicate_location["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"] = copy.deepcopy(
        duplicate_location["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"]
    )
    probes["duplicate mailbox location"] = reseal(duplicate_location)
    overlap = analyze_artifact(case / "compact-checkpoint-v2.json").document
    acceptance = copy.deepcopy(
        next(
            item
            for item in analyze_artifact(case / "terminal-checkpoint-v2.json").document["operation_receipts"]
            if item["operation_kind"] == "acceptance"
        )
    )
    acceptance["receipt_sequence"] = overlap["next_operation_receipt_sequence"]
    overlap["operation_receipts"].append(acceptance)
    overlap["next_operation_receipt_sequence"] = str(int(acceptance["receipt_sequence"]) + 1)
    probes["acceptance and replacement tombstone overlap"] = reseal(overlap)
    allocation_conflict = analyze_artifact(case / "compact-checkpoint-v2.json").document
    terminal = copy.deepcopy(
        next(
            item
            for item in analyze_artifact(case / "terminal-checkpoint-v2.json").document["operation_receipts"]
            if item["operation_kind"] == "event_terminal"
        )
    )
    terminal["event_id"] = "different-event-for-same-acceptance"
    terminal["receipt_sequence"] = allocation_conflict["next_operation_receipt_sequence"]
    allocation_conflict["operation_receipts"].append(terminal)
    allocation_conflict["next_operation_receipt_sequence"] = str(
        int(terminal["receipt_sequence"]) + 1
    )
    probes["terminal and tombstone acceptance allocation conflict"] = reseal(
        allocation_conflict
    )
    tombstone_counter = analyze_artifact(case / "compact-checkpoint-v2.json").document
    tombstone_counter["event_identity_tombstones"][0]["terminal_receipt_sequence"] = (
        tombstone_counter["next_operation_receipt_sequence"]
    )
    probes["tombstone allocation reaches next counter"] = reseal(tombstone_counter)
    populated_outbox = analyze_artifact(case / "upgraded-outbox-checkpoint-v2.json").document
    reversed_outbox = copy.deepcopy(populated_outbox)
    reversed_outbox["pending_outbox_intents"].reverse()
    probes["populated outbox order"] = reseal(reversed_outbox)
    duplicate_effect = copy.deepcopy(populated_outbox)
    duplicate_effect["pending_outbox_intents"][1]["intent"]["effect_id"] = (
        duplicate_effect["pending_outbox_intents"][0]["intent"]["effect_id"]
    )
    probes["populated outbox effect identity"] = reseal(duplicate_effect)
    for label, payload in (
        (
            "nested reordered pending outbox payload",
            [
                "map",
                [["details", ["map", [["beta", ["integer", "2"]], ["alpha", ["integer", "1"]]]]]],
            ],
        ),
        (
            "duplicate pending outbox payload key",
            [
                "map",
                [
                    ["transaction_id", ["string", "tx-1"]],
                    ["transaction_id", ["string", "tx-2"]],
                ],
            ],
        ),
    ):
        malformed_outbox = copy.deepcopy(populated_outbox)
        malformed_outbox["pending_outbox_intents"][0]["intent"]["payload"] = payload
        probes[label] = reseal(malformed_outbox)
    terminal_outbox = upgrade_checkpoint(
        analyze_artifact(
            repository_root
            / "conformance/profiles/execution-checkpoint/checkpoint-02-outbox-lifecycle/outbox-total-checkpoint.json"
        ).document
    )
    terminal_outbox["terminal_outbox_records"][0]["intent"]["payload"] = [
        "map",
        [["details", ["map", [["beta", ["integer", "2"]], ["alpha", ["integer", "1"]]]]]],
    ]
    probes["nested reordered terminal outbox payload"] = reseal(terminal_outbox)
    for label, members in (
        (
            "checkpoint reversed envelope payload",
            [["transaction_id", ["string", "tx-1"]], ["alpha", ["string", "a"]]],
        ),
        (
            "checkpoint duplicate envelope payload key",
            [
                ["transaction_id", ["string", "tx-1"]],
                ["transaction_id", ["string", "tx-2"]],
            ],
        ),
    ):
        malformed_payload = copy.deepcopy(admitted)
        entry = malformed_payload["root_record"]["aggregate_state"]["runtimes"][0][
            "ready_mailbox"
        ][0]
        entry["envelope"]["payload"] = ["map", members]
        entry["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                malformed_payload["root_instance_id"],
                entry["delivery_mode"],
                entry["envelope"],
            ]
        )
        acceptance = next(
            receipt
            for receipt in malformed_payload["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("event_id") == entry["envelope"]["event_id"]
        )
        acceptance["request_digest"] = entry["envelope_digest"]
        probes[label] = reseal(malformed_payload)
    for name, probe in probes.items():
        try:
            validate_execution_checkpoint_v2_semantics(probe)
        except ValidationFailure:
            continue
        raise ValidationFailure(f"version-2 adversarial probe was accepted: {name}")

    spawned_v1 = analyze_artifact(case / "spawned-child-checkpoint-v1.json").document
    for label, members in (
        (
            "version-1 reversed envelope payload",
            [["transaction_id", ["string", "tx-1"]], ["alpha", ["string", "a"]]],
        ),
        (
            "version-1 duplicate envelope payload key",
            [
                ["transaction_id", ["string", "tx-1"]],
                ["transaction_id", ["string", "tx-2"]],
            ],
        ),
    ):
        probe = copy.deepcopy(spawned_v1)
        pending = probe["pending_deliveries"][0]
        pending["envelope"]["payload"] = ["map", members]
        pending["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-1",
                "1",
                probe["root_instance_id"],
                pending["delivery_mode"],
                pending["envelope"],
            ]
        )
        probe.pop("execution_checkpoint_digest")
        probe["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-1", probe]
        )
        try:
            validate_execution_checkpoint_semantics(probe)
        except ValidationFailure:
            continue
        raise ValidationFailure(f"adversarial probe was accepted: {label}")

    outbox_case = (
        repository_root
        / "conformance/profiles/execution-checkpoint/checkpoint-02-outbox-lifecycle"
    )
    for outbox_location, filename, collection in (
        ("pending", "outbox-created-checkpoint.json", "pending_outbox_intents"),
        ("terminal", "outbox-total-checkpoint.json", "terminal_outbox_records"),
    ):
        source = analyze_artifact(outbox_case / filename).document
        for shape, payload in (
            (
                "reordered",
                [
                    "map",
                    [
                        [
                            "details",
                            [
                                "map",
                                [
                                    ["beta", ["integer", "2"]],
                                    ["alpha", ["integer", "1"]],
                                ],
                            ],
                        ]
                    ],
                ],
            ),
            (
                "duplicate",
                [
                    "map",
                    [
                        ["transaction_id", ["string", "tx-1"]],
                        ["transaction_id", ["string", "tx-2"]],
                    ],
                ],
            ),
        ):
            probe = copy.deepcopy(source)
            probe[collection][0]["intent"]["payload"] = payload
            probe.pop("execution_checkpoint_digest")
            probe["execution_checkpoint_digest"] = hash_value(
                ["determa-execution-checkpoint-digest-1", probe]
            )
            try:
                validate_execution_checkpoint_semantics(probe)
            except ValidationFailure:
                continue
            raise ValidationFailure(
                "adversarial probe was accepted: "
                f"v1 {outbox_location} outbox {shape} payload"
            )


def validate_all_retained_version1_checkpoint_upgrades(repository_root: Path) -> None:
    from generate_version2_vectors import target_runtime_id, upgrade_checkpoint

    target_probe_paths = (
        repository_root
        / "conformance/profiles/execution-checkpoint/checkpoint-01-delivery-lifecycle/created-checkpoint.json",
        repository_root
        / "conformance/core/117-version2-mailboxes/component-isolation-aggregate.json",
        repository_root
        / "conformance/core/105-owned-runtime-migration/source-aggregate-state.json",
    )
    targets = []
    for path in target_probe_paths:
        document = analyze_artifact(path).document
        aggregate = document.get("root_record", {}).get("aggregate_state", document)
        runtime = next(
            item
            for item in aggregate["runtimes"]
            if item["relation"]["kind"]
            in {"root", "component", "owned_spawned_instance"}
            and not any(
                next(iter(existing)) == next(iter(item["target_identity"]))
                for existing in targets
            )
        )
        targets.append(runtime["target_identity"])
        if target_runtime_id(runtime["target_identity"]) != runtime["runtime_id"]:
            raise ValidationFailure(
                "version-1 checkpoint target resolver changed runtime identity"
            )
    if {next(iter(target)) for target in targets} != {
        "root",
        "component",
        "spawned_instance",
    }:
        raise ValidationFailure("checkpoint target resolver probe is incomplete")

    checkpoint_root = repository_root / "conformance/profiles/execution-checkpoint"
    retained_paths: set[Path] = set()
    for test_path in checkpoint_root.rglob("test.yaml"):
        test = yaml_loader().load(test_path.read_text(encoding="utf-8"))
        for entry in test.get("artifacts", {}).get("documents", []):
            if entry.get("kind") != "execution_checkpoint" or not entry.get("valid"):
                continue
            path = test_path.parent / entry["file"]
            checkpoint = analyze_artifact(path).document
            if checkpoint["root_record"]["status"] == "retained":
                retained_paths.add(path)
    if len(retained_paths) != 42:
        raise ValidationFailure(
            "version-1 retained checkpoint upgrade probe set is incomplete"
        )
    for path in sorted(retained_paths):
        upgraded = upgrade_checkpoint(analyze_artifact(path).document)
        validate_execution_checkpoint_v2_semantics(upgraded)


def validate_version1_fault_code_adversarial_probes(repository_root: Path) -> None:
    faulted = analyze_artifact(
        repository_root
        / "conformance/core/94-aggregate-wire-round-trip/faulted-aggregate-state.json"
    ).document
    invalid = copy.deepcopy(faulted)
    next(runtime for runtime in invalid["runtimes"] if runtime["fault"] is not None)[
        "fault"
    ]["code"] = "action_evaluation_failed"
    try:
        validate_aggregate_v1_fault_codes(invalid)
    except ValidationFailure:
        pass
    else:
        raise ValidationFailure(
            "version-1 fault-code probe accepted action_evaluation_failed"
        )

    application_data = copy.deepcopy(
        analyze_artifact(
            repository_root
            / "conformance/core/105-owned-runtime-migration/source-aggregate-state.json"
        ).document
    )
    runtime = next(item for item in application_data["runtimes"] if item["variables"])
    runtime["variables"][0]["value"] = encode_typed_value(
        {"fault": {"code": "payment_declined"}}
    )
    validate_aggregate_v1_fault_codes(application_data)


def validate_version2_aggregate_adversarial_probes(repository_root: Path) -> None:
    from generate_version2_vectors import upgrade_aggregate

    case = repository_root / "conformance/core/117-version2-mailboxes"
    component = analyze_artifact(case / "component-isolation-aggregate.json").document
    mailbox = analyze_artifact(case / "base-aggregate.json").document
    payload_mailbox = analyze_artifact(case / "repeated-before.json").document
    probes: dict[str, dict[str, Any]] = {}

    def reseal(value: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(value)
        result.pop("aggregate_state_digest", None)
        result["aggregate_state_digest"] = hash_value(
            ["determa-aggregate-state-digest-2", result]
        )
        return result

    runtime_order = copy.deepcopy(component)
    runtime_order["runtimes"].reverse()
    probes["runtime order"] = runtime_order

    component_runtime = next(
        runtime for runtime in component["runtimes"] if runtime["relation"]["kind"] == "component"
    )
    for field, label in (
        ("active_state_activations", "state activation order"),
        ("next_state_activation_sequences", "state counter order"),
    ):
        probe = copy.deepcopy(component)
        target = next(runtime for runtime in probe["runtimes"] if runtime["runtime_id"] == component_runtime["runtime_id"])
        target[field].reverse()
        probes[label] = probe

    leaf_duplicate = copy.deepcopy(component)
    target = next(runtime for runtime in leaf_duplicate["runtimes"] if runtime["runtime_id"] == component_runtime["runtime_id"])
    target["active_leaf_state_definition_pointers"].append(target["active_leaf_state_definition_pointers"][0])
    probes["duplicate active leaf"] = leaf_duplicate

    variable_duplicate = copy.deepcopy(component)
    target = next(runtime for runtime in variable_duplicate["runtimes"] if runtime["runtime_id"] == component_runtime["runtime_id"])
    target["variables"].append(copy.deepcopy(target["variables"][0]))
    probes["duplicate variable key"] = variable_duplicate

    application_fault_data = copy.deepcopy(component)
    application_runtime = next(
        runtime
        for runtime in application_fault_data["runtimes"]
        if runtime["variables"]
    )
    application_runtime["variables"][0]["value"] = encode_typed_value(
        [{"fault": {"code": "payment_declined"}}]
    )
    application_fault_data = reseal(application_fault_data)
    validate_aggregate_v2_semantics(application_fault_data)
    validate_aggregate_against_bundle(
        application_fault_data, case / "component-machine.yaml"
    )

    reversed_nested_map = copy.deepcopy(application_fault_data)
    reversed_nested_map["runtimes"][
        reversed_nested_map["runtimes"].index(
            next(
                runtime
                for runtime in reversed_nested_map["runtimes"]
                if runtime["variables"]
            )
        )
    ]["variables"][0]["value"] = [
        "list",
        [["map", [["beta", ["integer", "2"]], ["alpha", ["integer", "1"]]]]],
    ]
    probes["reversed recursive typed-map keys"] = reseal(reversed_nested_map)

    duplicate_nested_map = copy.deepcopy(application_fault_data)
    duplicate_runtime = next(
        runtime
        for runtime in duplicate_nested_map["runtimes"]
        if runtime["variables"]
    )
    duplicate_runtime["variables"][0]["value"] = [
        "list",
        [["map", [["alpha", ["integer", "1"]], ["alpha", ["integer", "2"]]]]],
    ]
    probes["duplicate recursive typed-map keys"] = reseal(duplicate_nested_map)

    payload_entry = next(
        entry
        for runtime in payload_mailbox["runtimes"]
        for mailbox_entries in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
        for entry in mailbox_entries
        if any(
            member[0] == "transaction_id"
            for member in entry["envelope"]["payload"][1]
        )
    )
    for label, members in (
        (
            "reversed envelope payload map",
            [["transaction_id", ["string", "tx-1"]], ["alpha", ["string", "a"]]],
        ),
        (
            "duplicate envelope payload map key",
            [
                ["transaction_id", ["string", "tx-1"]],
                ["transaction_id", ["string", "tx-2"]],
            ],
        ),
    ):
        probe = copy.deepcopy(payload_mailbox)
        candidate = next(
            entry
            for runtime in probe["runtimes"]
            for mailbox_entries in (runtime["ready_mailbox"], runtime["deferred_mailbox"])
            for entry in mailbox_entries
            if entry["envelope"]["event_id"]
            == payload_entry["envelope"]["event_id"]
        )
        candidate["envelope"]["payload"] = ["map", members]
        candidate["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                probe["root_instance_id"],
                candidate["delivery_mode"],
                candidate["envelope"],
            ]
        )
        probes[label] = reseal(probe)

    component_counter_order = copy.deepcopy(component)
    root = next(runtime for runtime in component_counter_order["runtimes"] if runtime["relation"]["kind"] == "root")
    root["next_component_activation_sequences"].reverse()
    probes["component counter order"] = component_counter_order

    mailbox_order = copy.deepcopy(mailbox)
    root = next(runtime for runtime in mailbox_order["runtimes"] if runtime["relation"]["kind"] == "root")
    root["ready_mailbox"].reverse()
    probes["mailbox order"] = mailbox_order

    nested_fault = analyze_artifact(
        case / "faulted-component-aggregate.json"
    ).document
    nested_fault = copy.deepcopy(nested_fault)
    faulted_runtime = next(
        runtime for runtime in nested_fault["runtimes"] if runtime["fault"] is not None
    )
    faulted_runtime["fault"]["code"] = "action_evaluation_failed"
    probes["nested non-closed fault code"] = nested_fault

    reserved_failure = copy.deepcopy(
        analyze_artifact(
            case / "internal-emission-retained-faulted-result.json"
        ).document["state"]
    )
    failure_entry = next(
        entry
        for runtime in reserved_failure["runtimes"]
        for entry in runtime["ready_mailbox"]
        if entry["envelope"]["event"] == "determa.component_failed"
    )
    payload_members = dict(failure_entry["envelope"]["payload"][1])
    fault_members = dict(payload_members["fault"][1])
    fault_members["code"] = ["string", "action_evaluation_failed"]
    payload_members["fault"] = [
        "map",
        [[key, fault_members[key]] for key in sorted(fault_members)],
    ]
    failure_entry["envelope"]["payload"] = [
        "map",
        [[key, payload_members[key]] for key in sorted(payload_members)],
    ]
    failure_entry["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            reserved_failure["root_instance_id"],
            failure_entry["delivery_mode"],
            failure_entry["envelope"],
        ]
    )
    probes["reserved failure non-closed fault code"] = reseal(reserved_failure)

    for name, probe in probes.items():
        try:
            validate_aggregate_v2_semantics(probe)
        except ValidationFailure:
            continue
        raise ValidationFailure(f"version-2 aggregate adversarial probe was accepted: {name}")

    fabricated = copy.deepcopy(mailbox)
    original_root_id = fabricated["root_runtime_id"]
    fabricated_root_id = "sha256:" + "0" * 64
    fabricated = json.loads(
        json.dumps(fabricated).replace(original_root_id, fabricated_root_id)
    )
    for runtime in fabricated["runtimes"]:
        for mailbox_name in ("ready_mailbox", "deferred_mailbox"):
            for entry in runtime[mailbox_name]:
                entry["envelope_digest"] = hash_value(
                    [
                        "determa-inbox-envelope-digest-2",
                        "2",
                        fabricated["root_instance_id"],
                        entry["delivery_mode"],
                        entry["envelope"],
                    ]
                )
    fabricated.pop("aggregate_state_digest", None)
    fabricated["aggregate_state_digest"] = hash_value(
        ["determa-aggregate-state-digest-2", fabricated]
    )
    validate_aggregate_v2_semantics(fabricated)
    try:
        validate_aggregate_against_bundle(fabricated, case / "machine.yaml")
    except ValidationFailure:
        pass
    else:
        raise ValidationFailure(
            "version-2 aggregate adversarial probe accepted fabricated root identity"
        )

    component_migration_case = repository_root / "conformance/core/104-component-migration"
    migrated_component = upgrade_aggregate(
        analyze_artifact(
            component_migration_case / "expected-aggregate-state.json"
        ).document
    )
    validate_aggregate_v2_semantics(migrated_component)
    validate_aggregate_against_bundle(
        migrated_component,
        component_migration_case / "target.yaml",
        component_migration_case / "machine.yaml",
    )

    persistence_case = repository_root / "conformance/core/118-version2-persistence"
    undeclared_payload = copy.deepcopy(
        analyze_artifact(persistence_case / "disposal-before.json").document
    )
    undeclared_entry = undeclared_payload["runtimes"][0]["deferred_mailbox"][0]
    undeclared_entry["envelope"]["payload"] = encode_typed_value(
        {"transaction_id": "transaction-2"}
    )
    undeclared_entry["envelope_digest"] = hash_value(
        [
            "determa-inbox-envelope-digest-2",
            "2",
            undeclared_payload["root_instance_id"],
            undeclared_entry["delivery_mode"],
            undeclared_entry["envelope"],
        ]
    )
    undeclared_payload = reseal(undeclared_payload)
    validate_aggregate_v2_semantics(undeclared_payload)
    try:
        validate_aggregate_against_bundle(
            undeclared_payload, persistence_case / "machine.yaml"
        )
    except ValidationFailure:
        pass
    else:
        raise ValidationFailure(
            "version-2 aggregate adversarial probe accepted undeclared mailbox payload"
        )


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
    if kind == "aggregate_state":
        try:
            validate_aggregate_v1_fault_codes(document)
        except ValidationFailure:
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
    if kind in {"execution_checkpoint", "execution_checkpoint_v2"}:
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            try:
                verify_artifact_digest(
                    "aggregate_state_v2" if kind == "execution_checkpoint_v2" else "aggregate_state",
                    root_record["aggregate_state"],
                    Path("<embedded aggregate>"),
                )
            except ValidationFailure:
                return structural_error
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        expected_digest = hash_value(
            [
                "determa-execution-checkpoint-digest-2"
                if kind == "execution_checkpoint_v2"
                else "determa-execution-checkpoint-digest-1",
                without_digest,
            ]
        )
        if document["execution_checkpoint_digest"] != expected_digest:
            return "execution_checkpoint_digest_mismatch"
        if kind == "execution_checkpoint":
            try:
                validate_execution_checkpoint_semantics(document)
            except ValidationFailure:
                return structural_error
        else:
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
            if kind == "execution_checkpoint_inputs":
                probe = copy.deepcopy(analysis.document)
                first_request = next(iter(probe["requests"].values()))
                first_request["language_specific"] = True
                if next(validator.iter_errors(probe), None) is None:
                    raise ValidationFailure(
                        f"{path}: input schema accepts language-specific members"
                    )
            if kind == "execution_checkpoint_core_evidence":
                probe = copy.deepcopy(analysis.document)
                first_call = next(iter(probe["calls"].values()))
                first_call["language_specific"] = True
                if next(validator.iter_errors(probe), None) is None:
                    raise ValidationFailure(
                        f"{path}: core evidence schema accepts extra members"
                    )
                probe = copy.deepcopy(analysis.document)
                probe["provenance"]["python_core_commit"] = "0" * 40
                if next(validator.iter_errors(probe), None) is None:
                    raise ValidationFailure(
                        f"{path}: core evidence schema accepts a wrong provenance pin"
                    )
            if kind == "execution_store_scope_state":
                probe = copy.deepcopy(analysis.document)
                first_scope = probe["snapshots"][
                    next(iter(probe["snapshots"]))
                ]["scopes"][0]
                first_scope["language_specific"] = True
                if next(validator.iter_errors(probe), None) is None:
                    raise ValidationFailure(
                        f"{path}: scope-state schema accepts extra members"
                    )
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


def checkpoint_replay_result(
    checkpoint: dict[str, Any], delivery: dict[str, Any]
) -> dict[str, Any] | None:
    """Return the exact replay response justified by retained v2 evidence."""
    event_id = delivery["envelope"]["event_id"]
    digest_domain = delivery.get(
        "request_digest_domain", "determa-inbox-envelope-digest-2"
    )
    digest_version = "1" if digest_domain.endswith("-1") else "2"
    request_digest = hash_value(
        [
            digest_domain,
            digest_version,
            checkpoint["root_instance_id"],
            delivery["delivery_mode"],
            delivery["envelope"],
        ]
    )
    if digest_domain == "determa-inbox-envelope-digest-1":
        legacy = next(
            (
                receipt
                for receipt in checkpoint["operation_receipts"]
                if receipt.get("operation_kind") == "legacy_v1_operation"
                and receipt["legacy_receipt"].get("operation_kind") == "delivery"
                and receipt["legacy_receipt"].get("event_id") == event_id
                and receipt["legacy_receipt"].get("request_digest")
                == request_digest
            ),
            None,
        )
        if legacy is not None:
            nested = legacy["legacy_receipt"]
            return {
                "result": "replay",
                "event_id": event_id,
                "acceptance_sequence": nested["accepted_delivery_sequence"],
                "terminal_receipt_sequence": legacy["receipt_sequence"],
                "terminal_disposition": nested["outcome"]["disposition"],
                "request_digest_domain": digest_domain,
            }
        legacy_tombstone = next(
            (
                item
                for item in checkpoint["event_identity_tombstones"]
                if item["event_id"] == event_id
                and item["request_digest"] == request_digest
                and item["request_digest_domain"] == digest_domain
            ),
            None,
        )
        if legacy_tombstone is None:
            return None
        return {
            "result": "replay",
            "event_id": event_id,
            "acceptance_sequence": legacy_tombstone["acceptance_sequence"],
            "terminal_receipt_sequence": legacy_tombstone[
                "terminal_receipt_sequence"
            ],
            "terminal_disposition": legacy_tombstone["terminal_disposition"],
            "request_digest_domain": digest_domain,
        }
    root_record = checkpoint["root_record"]
    if root_record["status"] == "retained":
        for runtime in root_record["aggregate_state"]["runtimes"]:
            for location, mailbox in (
                ("ready", runtime["ready_mailbox"]),
                ("deferred", runtime["deferred_mailbox"]),
            ):
                for entry in mailbox:
                    if (
                        entry["envelope"]["event_id"] == event_id
                        and entry["envelope_digest"] == request_digest
                    ):
                        return {
                            "result": "replay",
                            "event_id": event_id,
                            "acceptance_sequence": entry["acceptance_sequence"],
                            "location": location,
                        }
    acceptance = next(
        (
            receipt
            for receipt in checkpoint["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("event_id") == event_id
            and receipt.get("request_digest") == request_digest
        ),
        None,
    )
    terminal = next(
        (
            receipt
            for receipt in checkpoint["operation_receipts"]
            if receipt.get("operation_kind") == "event_terminal"
            and receipt.get("event_id") == event_id
            and receipt.get("request_digest") == request_digest
        ),
        None,
    )
    if acceptance is not None and terminal is not None:
        return {
            "result": "replay",
            "acceptance_receipt_sequence": acceptance["receipt_sequence"],
            "terminal_receipt_sequence": terminal["receipt_sequence"],
        }
    tombstone = next(
        (
            item
            for item in checkpoint["event_identity_tombstones"]
            if item["event_id"] == event_id
            and item["request_digest"] == request_digest
        ),
        None,
    )
    if tombstone is not None:
        return {
            "result": "replay",
            "terminal_receipt_sequence": tombstone["terminal_receipt_sequence"],
            "terminal_disposition": tombstone["terminal_disposition"],
        }
    return None


def validate_version2_vectors(
    case: Path,
    test: dict[str, Any],
    bundle_paths: set[Path],
    artifact_paths: set[Path],
    *,
    artifact_overrides: dict[str, Any] | None = None,
    run_mutation_probes: bool = True,
) -> set[str]:
    """Validate the closed language-neutral version-2 operation table."""
    from generate_version2_vectors import upgrade_checkpoint

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
        "admit_v2",
        "step_v2",
        "downgrade_aggregate_v2_to_v1",
        "migrate_aggregate_v2",
    }
    checkpoint_operations = {
        "checkpoint_admit_v2",
        "checkpoint_step_v2",
        "checkpoint_prune_v2",
        "checkpoint_tombstone_v2",
        "checkpoint_migrate_v2",
        "checkpoint_v1_accept",
        "downgrade_checkpoint_v2_to_v1",
    }
    descriptor_operations = {"migrate_aggregate_v2", "checkpoint_migrate_v2"}
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
    checkpoint_admission_rejection_codes = core_admission_rejection_codes | {
        "wrong_root",
        "terminal_root",
        "tombstoned_root",
        "checkpoint_revision_conflict",
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
        "admit_v2": core_admission_rejection_codes
        | aggregate_artifact_failure_codes,
        "step_v2": aggregate_artifact_failure_codes,
        "upgrade_aggregate_v1_to_v2": aggregate_artifact_failure_codes,
        "downgrade_aggregate_v2_to_v1": aggregate_artifact_failure_codes
        | {"migration_totality_failure"},
        "migrate_aggregate_v2": migration_failure_codes,
        "upgrade_checkpoint_v1_to_v2": checkpoint_artifact_failure_codes
        | {"checkpoint_revision_conflict"},
        "downgrade_checkpoint_v2_to_v1": checkpoint_artifact_failure_codes
        | {"checkpoint_revision_conflict"},
        "checkpoint_admit_v2": checkpoint_artifact_failure_codes
        | checkpoint_admission_rejection_codes,
        "checkpoint_step_v2": checkpoint_artifact_failure_codes
        | {"checkpoint_revision_conflict"},
        "checkpoint_prune_v2": checkpoint_artifact_failure_codes
        | {"checkpoint_revision_conflict"},
        "checkpoint_tombstone_v2": checkpoint_artifact_failure_codes
        | {"checkpoint_revision_conflict", "operation_id_conflict"},
        "checkpoint_migrate_v2": checkpoint_artifact_failure_codes
        | migration_failure_codes
        | {"checkpoint_revision_conflict", "operation_id_conflict"},
        "checkpoint_v1_accept": checkpoint_artifact_failure_codes
        | {"checkpoint_upgrade_required"},
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

    if run_mutation_probes:
        all_registered_codes = {
            entry["code"] for entry in _CLOSED_CODE_REGISTRY["entries"]
        }
        for probed_operation, allowed_codes in operation_failure_codes.items():
            disallowed_code = next(
                code for code in all_registered_codes if code not in allowed_codes
            )
            try:
                require_allowed_operation_failure_code(
                    probed_operation, disallowed_code
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"operation-code relabel probe was accepted for {probed_operation}"
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

    def delivery_root_instance_id(delivery: dict[str, Any]) -> str:
        target = delivery["envelope"]["target"]
        return next(iter(target.values()))["root_instance_id"]

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

    def checkpoint_has_conflicting_identity(
        checkpoint: dict[str, Any], delivery: dict[str, Any]
    ) -> bool:
        event_id = delivery["envelope"]["event_id"]
        digest_domain = delivery.get(
            "request_digest_domain", "determa-inbox-envelope-digest-2"
        )
        digest_version = "1" if digest_domain.endswith("-1") else "2"
        digest = hash_value(
            [
                digest_domain,
                digest_version,
                checkpoint["root_instance_id"],
                delivery["delivery_mode"],
                delivery["envelope"],
            ]
        )
        retained_digests: list[str] = []
        if digest_domain == "determa-inbox-envelope-digest-1":
            retained_digests.extend(
                receipt["legacy_receipt"]["request_digest"]
                for receipt in checkpoint["operation_receipts"]
                if receipt.get("operation_kind") == "legacy_v1_operation"
                and receipt["legacy_receipt"].get("operation_kind") == "delivery"
                and receipt["legacy_receipt"].get("event_id") == event_id
            )
        else:
            if checkpoint["root_record"]["status"] == "retained":
                retained_digests.extend(
                    entry["envelope_digest"]
                    for runtime in checkpoint["root_record"]["aggregate_state"][
                        "runtimes"
                    ]
                    for mailbox in (
                        runtime["ready_mailbox"],
                        runtime["deferred_mailbox"],
                    )
                    for entry in mailbox
                    if entry["envelope"]["event_id"] == event_id
                )
            retained_digests.extend(
                receipt["request_digest"]
                for receipt in checkpoint["operation_receipts"]
                if receipt.get("operation_kind")
                in {"acceptance", "event_terminal"}
                and receipt.get("event_id") == event_id
            )
        retained_digests.extend(
            item["request_digest"]
            for item in checkpoint["event_identity_tombstones"]
            if item["event_id"] == event_id
            and item.get(
                "request_digest_domain", "determa-inbox-envelope-digest-2"
            )
            == digest_domain
        )
        return any(retained_digest != digest for retained_digest in retained_digests)

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

    def project_bounded_prune(
        checkpoint: dict[str, Any], cutoff: int
    ) -> dict[str, Any]:
        projected = copy.deepcopy(checkpoint)
        receipts = projected["operation_receipts"]
        removed = [
            receipt
            for receipt in receipts
            if receipt["receipt_sequence"] != "0"
            and canonical_decimal(
                receipt["receipt_sequence"], "pruned receipt sequence"
            )
            <= cutoff
        ]
        projected["operation_receipts"] = [
            receipt for receipt in receipts if receipt not in removed
        ]
        acceptance_by_event = {
            receipt["event_id"]: receipt
            for receipt in receipts
            if receipt["operation_kind"] == "acceptance"
        }
        derived_tombstones = list(projected["event_identity_tombstones"])
        for receipt in removed:
            if receipt["operation_kind"] == "event_terminal":
                acceptance = acceptance_by_event.get(receipt["event_id"])
                if acceptance is not None:
                    if (
                        acceptance["acceptance_sequence"]
                        != receipt["acceptance_sequence"]
                    ):
                        raise ValidationFailure(
                            "bounded pruning terminal acceptance mismatch"
                        )
                else:
                    producer_matches = [
                        reference
                        for producer in receipts
                        for reference in producer.get(
                            "emission_references", []
                        )
                        if reference.get("kind") == "internal_terminal"
                        and reference.get("event_id")
                        == receipt["event_id"]
                        and reference.get("acceptance_sequence")
                        == receipt["acceptance_sequence"]
                        and reference.get("terminal_receipt_sequence")
                        == receipt["receipt_sequence"]
                    ]
                    prior_cutoff_value = checkpoint["replay_retention"][
                        "pruned_through_receipt_sequence"
                    ]
                    producer_was_attested_pruned = (
                        not producer_matches
                        and prior_cutoff_value is not None
                        and canonical_decimal(
                            prior_cutoff_value,
                            "prior pruning cutoff",
                        )
                        < canonical_decimal(
                            receipt["receipt_sequence"],
                            "native terminal receipt sequence",
                        )
                    )
                    if (
                        len(producer_matches) != 1
                        and not producer_was_attested_pruned
                    ):
                        raise ValidationFailure(
                            "bounded pruning native terminal lacks exact producer"
                        )
                derived_tombstones.append(
                    {
                        "event_id": receipt["event_id"],
                        "request_digest": receipt["request_digest"],
                        "request_digest_domain": (
                            "determa-inbox-envelope-digest-2"
                        ),
                        "acceptance_sequence": receipt[
                            "acceptance_sequence"
                        ],
                        "terminal_receipt_sequence": receipt[
                            "receipt_sequence"
                        ],
                        "terminal_disposition": receipt["outcome"][
                            "disposition"
                        ],
                    }
                )
            elif (
                receipt["operation_kind"] == "legacy_v1_operation"
                and receipt["legacy_receipt"].get("operation_kind")
                == "delivery"
            ):
                legacy = receipt["legacy_receipt"]
                derived_tombstones.append(
                    {
                        "event_id": legacy["event_id"],
                        "request_digest": legacy["request_digest"],
                        "request_digest_domain": (
                            "determa-inbox-envelope-digest-1"
                        ),
                        "acceptance_sequence": legacy[
                            "accepted_delivery_sequence"
                        ],
                        "terminal_receipt_sequence": receipt[
                            "receipt_sequence"
                        ],
                        "terminal_disposition": legacy["outcome"][
                            "disposition"
                        ],
                    }
                )
        projected["event_identity_tombstones"] = sorted(
            derived_tombstones,
            key=lambda item: canonical_decimal(
                item["terminal_receipt_sequence"],
                "projected tombstone terminal sequence",
            ),
        )
        projected["replay_retention"][
            "pruned_through_receipt_sequence"
        ] = str(cutoff)
        projected["revision"] = str(int(checkpoint["revision"]) + 1)
        projected.pop("execution_checkpoint_digest", None)
        projected["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-2", projected]
        )
        return projected

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
        if operation == "create_v2" and "bundle" not in vector:
            raise ValidationFailure(f"{location}: create_v2 requires bundle")
        if operation in state_operations and "state_before" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires state_before")
        if operation == "upgrade_aggregate_v1_to_v2" and "state_before" not in vector:
            raise ValidationFailure(f"{location}: aggregate upgrade requires state_before")
        if operation in checkpoint_operations and "checkpoint_before" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires checkpoint_before")
        if operation == "upgrade_checkpoint_v1_to_v2" and "checkpoint_before" not in vector:
            raise ValidationFailure(f"{location}: checkpoint upgrade requires checkpoint_before")
        if operation in descriptor_operations and "descriptor_file" not in vector:
            raise ValidationFailure(f"{location}: {operation} requires descriptor_file")
        if "request_file" not in vector or "request_pointer" not in vector:
            raise ValidationFailure(f"{location}: operation requires a closed request")

        if "bundle" in vector and vector["bundle"] not in bundle_names:
            raise ValidationFailure(f"{location}: undeclared bundle {vector['bundle']}")
        for field in (
            "state_before",
            "checkpoint_before",
            "source_checkpoint_v1",
            "request_file",
            "descriptor_file",
        ):
            filename = vector.get(field)
            if filename is not None and filename not in artifact_names:
                raise ValidationFailure(f"{location}: undeclared artifact {filename}")
        if "source_checkpoint_v1" in vector:
            source_manifest = manifests[vector["source_checkpoint_v1"]]
            if (
                source_manifest["kind"] != "execution_checkpoint"
                or not source_manifest["valid"]
            ):
                raise ValidationFailure(
                    f"{location}: source checkpoint must be a valid version-1 checkpoint"
                )
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

        expectation = vector["expect"]
        failure_evidence: set[str] = set()
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
        for field in ("state_before", "checkpoint_before", "descriptor_file"):
            filename = vector.get(field)
            if filename is None or manifests[filename]["valid"]:
                continue
            manifest_error = manifests[filename]["error"]
            if manifest_error in ARTIFACT_SOURCE_ERROR_CODES:
                manifest_error = {
                    "state_before": "invalid_aggregate_state",
                    "checkpoint_before": "invalid_execution_checkpoint",
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
                        "state_before", vector.get("checkpoint_before")
                    ),
                }
            ):
                raise ValidationFailure(
                    f"{location}: invalid input artifact requires exact "
                    f"{invalid_input_error} rejection"
                )
            if "checkpoint_admission_invalid_artifact" in covers and (
                operation != "checkpoint_admit_v2"
                or manifests[vector["checkpoint_before"]]["kind"]
                != "execution_checkpoint_v2"
                or manifests[vector["checkpoint_before"]]["error"]
                != "invalid_execution_checkpoint"
                or not any(not delivery for delivery in selected["deliveries"])
            ):
                raise ValidationFailure(
                    f"{location}: invalid checkpoint admission does not prove "
                    "artifact validation precedence"
                )
            continue
        if operation.startswith("checkpoint_") or operation in {
            "upgrade_checkpoint_v1_to_v2",
            "downgrade_checkpoint_v2_to_v1",
        }:
            checkpoint_before = artifact(vector["checkpoint_before"]).document
            cas_matches = (
                selected.get("expected_revision")
                == checkpoint_before["revision"]
                and selected.get("expected_checkpoint_digest")
                == checkpoint_before["execution_checkpoint_digest"]
            )
            malformed_deliveries = (
                operation == "checkpoint_admit_v2"
                and any(
                    not isinstance(delivery, dict)
                    or not {"delivery_mode", "envelope", "envelope_digest"}
                    <= set(delivery)
                    for delivery in selected["deliveries"]
                )
            )
            replay_results = (
                [
                    checkpoint_replay_result(checkpoint_before, delivery)
                    for delivery in selected["deliveries"]
                ]
                if operation == "checkpoint_admit_v2" and not malformed_deliveries
                else []
            )
            all_replay = bool(replay_results) and all(
                result is not None for result in replay_results
            )
            equal_prune_replay = False
            if operation == "checkpoint_prune_v2":
                prior_cutoff = checkpoint_before["replay_retention"][
                    "pruned_through_receipt_sequence"
                ]
                equal_prune_replay = (
                    prior_cutoff is not None
                    and selected["cutoff_receipt_sequence"] == prior_cutoff
                )
            if (
                not cas_matches
                and not (all_replay or equal_prune_replay)
                and expectation.get("code") != "checkpoint_revision_conflict"
            ):
                raise ValidationFailure(
                    f"{location}: checkpoint write lacks exact compare-and-swap input"
                )
            if (
                expectation.get("code") == "checkpoint_revision_conflict"
                and (cas_matches or all_replay or equal_prune_replay)
            ):
                raise ValidationFailure(
                    f"{location}: checkpoint revision rejection lacks a distinct stale write"
                )
            if (
                expectation.get("code") == "checkpoint_revision_conflict"
                and not cas_matches
                and not (all_replay or equal_prune_replay)
            ):
                failure_evidence.add("checkpoint_revision_conflict")
            if "terminal_replay_precedes_stale_cas" in covers:
                original_request = request.document["admit"]
                if (
                    selected != original_request
                    or cas_matches
                    or not all_replay
                    or int(selected["expected_revision"])
                    >= int(checkpoint_before["revision"])
                ):
                    raise ValidationFailure(
                        f"{location}: terminal replay did not reuse the exact old request"
                    )
            if "checkpoint_pending_replay_precedes_stale_cas" in covers:
                if (
                    selected != request.document["admit"]
                    or cas_matches
                    or not all_replay
                    or replay_results[0].get("location") not in {"ready", "deferred"}
                ):
                    raise ValidationFailure(
                        f"{location}: pending replay is not derived from retained evidence"
                    )
            if "distinct_stale_checkpoint_writer_rejected" in covers:
                candidate_ids = {
                    delivery["envelope"]["event_id"]
                    for delivery in selected["deliveries"]
                }
                aggregate = checkpoint_before["root_record"]["aggregate_state"]
                retained_ids = {
                    entry["envelope"]["event_id"]
                    for runtime in aggregate["runtimes"]
                    for mailbox in (
                        runtime["ready_mailbox"],
                        runtime["deferred_mailbox"],
                    )
                    for entry in mailbox
                }
                terminal_ids = {
                    receipt["event_id"]
                    for receipt in checkpoint_before["operation_receipts"]
                    if receipt["operation_kind"] == "event_terminal"
                }
                tombstone_ids = {
                    item["event_id"]
                    for item in checkpoint_before["event_identity_tombstones"]
                }
                if (
                    cas_matches
                    or candidate_ids & (retained_ids | terminal_ids | tombstone_ids)
                    or expectation.get("code") != "checkpoint_revision_conflict"
                ):
                    raise ValidationFailure(
                        f"{location}: stale writer is not distinct from replay"
                    )
            if "version2_equal_pruning_precedes_stale_cas" in covers and (
                operation != "checkpoint_prune_v2"
                or cas_matches
                or not equal_prune_replay
                or expectation["result"] != "success"
            ):
                raise ValidationFailure(
                    f"{location}: equal-cutoff pruning did not precede stale CAS"
                )
        if operation in descriptor_operations and not isinstance(
            selected.get("maintenance_mode"), bool
        ):
            raise ValidationFailure(
                f"{location}: migration request lacks mandatory maintenance mode"
            )

        prior_aggregate = aggregate_from_vector(vector)
        if (
            prior_aggregate is not None
            and prior_aggregate.get("aggregate_state_schema_version") == 2
            and "bundle" in vector
            and operation in {"admit_v2", "step_v2"}
        ):
            validate_aggregate_against_bundle(prior_aggregate, case / vector["bundle"])
        if (
            prior_aggregate is not None
            and operation == "upgrade_checkpoint_v1_to_v2"
            and "bundle" in vector
        ):
            validate_aggregate_against_bundle(
                prior_aggregate, case / vector["bundle"]
            )
        if "deliveries" in selected:
            delivery_identity: dict[str, Any] | str | None = prior_aggregate
            if (
                delivery_identity is None
                and operation == "checkpoint_admit_v2"
                and checkpoint_before["root_record"]["status"] == "tombstone"
            ):
                delivery_identity = checkpoint_before["root_instance_id"]
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
            wrong_root = (
                not malformed_deliveries
                and operation == "checkpoint_admit_v2"
                and any(
                delivery_root_instance_id(delivery)
                != checkpoint_before["root_instance_id"]
                for delivery in selected["deliveries"]
                )
            )
            if wrong_root:
                if expectation.get("code") != "wrong_root":
                    raise ValidationFailure(
                        f"{location}: foreign root lacks precedence rejection"
                    )
            elif expectation.get("code") == "wrong_root":
                raise ValidationFailure(
                    f"{location}: wrong-root rejection lacks a foreign root"
                )
            duplicate_event_ids = (
                not malformed_deliveries
                and not wrong_root
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
                and not wrong_root
                and not duplicate_event_ids
                and operation in {"admit_v2", "checkpoint_admit_v2"}
                and any(
                    checkpoint_has_conflicting_identity(checkpoint_before, delivery)
                    if operation == "checkpoint_admit_v2"
                    else aggregate_has_conflicting_identity(prior_aggregate, delivery)
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
                    checkpoint_replay_result(checkpoint_before, delivery)
                    for delivery in selected["deliveries"]
                ]
                if operation == "checkpoint_admit_v2"
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
            liveness_error = None
            if (
                operation == "checkpoint_admit_v2"
                and not malformed_deliveries
                and not wrong_root
                and not duplicate_event_ids
                and not conflicting_event_identity
            ):
                non_replay_deliveries = [
                    delivery
                    for delivery, replay in zip(
                        selected["deliveries"], replay_evidence, strict=True
                    )
                    if replay is None
                ]
                if non_replay_deliveries:
                    if checkpoint_before["root_record"]["status"] == "tombstone":
                        liveness_error = "tombstoned_root"
                    elif prior_aggregate is not None:
                        aggregate_root = next(
                            runtime
                            for runtime in prior_aggregate["runtimes"]
                            if runtime["relation"]["kind"] == "root"
                        )
                        if aggregate_root["status"] in {"completed", "faulted"} and any(
                            delivery["envelope"]["target"]
                            == aggregate_root["target_identity"]
                            for delivery in non_replay_deliveries
                        ):
                            liveness_error = "terminal_root"
            if liveness_error is not None:
                if expectation.get("code") != liveness_error:
                    raise ValidationFailure(
                        f"{location}: checkpoint liveness requires {liveness_error}"
                    )
            elif expectation.get("code") in {"terminal_root", "tombstoned_root"}:
                raise ValidationFailure(
                    f"{location}: liveness rejection lacks matching checkpoint state"
                )
            delivery_errors: list[str] = []
            contract_errors: list[str] = []
            for delivery, replay in zip(
                selected["deliveries"], replay_evidence, strict=True
            ):
                if (
                    malformed_deliveries
                    or wrong_root
                    or duplicate_event_ids
                    or conflicting_event_identity
                    or liveness_error is not None
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
                    and operation in {"admit_v2", "checkpoint_admit_v2"}
                ):
                    contract_error = delivery_contract_error(
                        delivery,
                        prior_aggregate,
                        case / vector["bundle"],
                        checkpoint_host=operation == "checkpoint_admit_v2",
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
            if operation in {"admit_v2", "checkpoint_admit_v2"} and expectation["result"] == "failure":
                evidenced_rejections = (
                    {"malformed_delivery"}
                    if malformed_deliveries
                    else {"wrong_root"}
                    if wrong_root
                    else {"duplicate_event_id_in_batch"}
                    if duplicate_event_ids
                    else {"event_id_conflict"}
                    if conflicting_event_identity
                    else {liveness_error}
                    if liveness_error is not None
                    else set(delivery_errors) | set(contract_errors)
                )
                if (
                    operation == "checkpoint_admit_v2"
                    and expectation.get("code") == "checkpoint_revision_conflict"
                ):
                    evidenced_rejections.add("checkpoint_revision_conflict")
                if expectation.get("code") not in evidenced_rejections:
                    raise ValidationFailure(
                        f"{location}: rejection label lacks relational evidence"
                    )
                failure_evidence.update(evidenced_rejections)

        if operation in {"step_v2", "checkpoint_step_v2"}:
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

        if operation in descriptor_operations:
            if prior_aggregate is None:
                raise ValidationFailure(f"{location}: migration lacks source aggregate")
            for key in ("source_bundle", "target_bundle"):
                binding = selected[key]
                bundle_path = case / binding["bundle_file"]
                if binding["bundle_source_digest"] != hash_bytes(bundle_path.read_bytes()) or binding["validated_bundle_fingerprint"] != validated_bundle_fingerprint(bundle_path):
                    raise ValidationFailure(f"{location}: {key} binding mismatch")
            descriptor_name = selected["migration_descriptor_file"]
            if descriptor_name != vector["descriptor_file"]:
                raise ValidationFailure(f"{location}: descriptor request and vector differ")
            descriptor = artifact(descriptor_name).document
            if selected["migration_descriptor_digest_route"] != [descriptor["migration_descriptor_digest"]]:
                raise ValidationFailure(f"{location}: migration descriptor route mismatch")
            base_descriptor = descriptor["base_descriptor"]
            if (
                base_descriptor["source_validated_bundle_fingerprint"] != selected["source_bundle"]["validated_bundle_fingerprint"]
                or base_descriptor["target_validated_bundle_fingerprint"] != selected["target_bundle"]["validated_bundle_fingerprint"]
                or prior_aggregate["validated_bundle_fingerprint"] != selected["source_bundle"]["validated_bundle_fingerprint"]
            ):
                raise ValidationFailure(f"{location}: migration definition pair is not exact")
            source_bundle_path = case / selected["source_bundle"]["bundle_file"]
            target_bundle_path = case / selected["target_bundle"]["bundle_file"]
            validate_aggregate_against_bundle(prior_aggregate, source_bundle_path)
            if (
                base_descriptor["source_aggregate_shape_fingerprint"]
                != aggregate_shape_fingerprint_for_path(source_bundle_path)
                or base_descriptor["target_aggregate_shape_fingerprint"]
                != aggregate_shape_fingerprint_for_path(target_bundle_path)
            ):
                raise ValidationFailure(f"{location}: migration shape fingerprint is not exact")
            if (
                base_descriptor["source_validated_bundle_fingerprint"]
                == base_descriptor["target_validated_bundle_fingerprint"]
            ):
                raise ValidationFailure(f"{location}: migration route contains a self-cycle")
            if base_descriptor["mode"] == "compatible" and (
                base_descriptor["source_aggregate_shape_fingerprint"]
                != base_descriptor["target_aggregate_shape_fingerprint"]
                or any(base_descriptor["mappings"].values())
            ):
                raise ValidationFailure(f"{location}: compatible descriptor is not shape-identical")
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

        if operation == "downgrade_aggregate_v2_to_v1" and expectation["result"] == "failure":
            assert prior_aggregate is not None
            has_version2_state = any(
                runtime["ready_mailbox"] or runtime["deferred_mailbox"]
                for runtime in prior_aggregate["runtimes"]
            ) or any(
                canonical_decimal(prior_aggregate[field], field) != 0
                for field in ("next_acceptance_sequence", "next_queue_sequence")
            )
            if has_version2_state:
                failure_evidence.add("migration_totality_failure")

        if operation == "checkpoint_v1_accept" and expectation["result"] == "failure":
            bundle_document = normalized_bundle_value(case / vector["bundle"])

            def contains_deferred_events(value: Any) -> bool:
                if isinstance(value, dict):
                    return "deferred_events" in value or any(
                        contains_deferred_events(item) for item in value.values()
                    )
                if isinstance(value, list):
                    return any(contains_deferred_events(item) for item in value)
                return False

            if contains_deferred_events(bundle_document):
                failure_evidence.add("checkpoint_upgrade_required")

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
            expected_kinds = (
                {"aggregate_state_v2"} if operation in {"create_v2", "upgrade_aggregate_v1_to_v2"}
                else {"core_step_result_v2"} if operation == "step_v2"
                else {"execution_checkpoint_v2"} if operation in {"upgrade_checkpoint_v1_to_v2", "checkpoint_step_v2", "checkpoint_prune_v2", "checkpoint_tombstone_v2", "checkpoint_migrate_v2"}
                else {"execution_checkpoint_v2", "version2_operation_result"} if operation == "checkpoint_admit_v2"
                else {"version2_operation_result"}
            )
            if manifests[result_file]["kind"] not in expected_kinds:
                raise ValidationFailure(f"{location}: result artifact kind is not closed for {operation}")
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
                descriptor = artifact(vector["descriptor_file"]).document
                validate_aggregate_against_bundle(
                    migrated,
                    case / selected["target_bundle"]["bundle_file"],
                    case / selected["source_bundle"]["bundle_file"],
                )
                target_fingerprint = descriptor["base_descriptor"]["target_validated_bundle_fingerprint"]
                if (
                    migrated["validated_bundle_fingerprint"] != target_fingerprint
                    or int(migrated["migration_sequence"])
                    != int(prior_aggregate["migration_sequence"]) + 1
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
            if operation == "upgrade_aggregate_v1_to_v2":
                source = artifact(vector["state_before"]).document
                if result_document["next_acceptance_sequence"] != "0" or result_document["next_queue_sequence"] != "0" or any(
                    runtime["ready_mailbox"] or runtime["deferred_mailbox"] for runtime in result_document["runtimes"]
                ):
                    raise ValidationFailure(f"{location}: aggregate upgrade did not insert empty version-2 mailboxes")
                comparable = copy.deepcopy(result_document)
                comparable["aggregate_state_schema_version"] = 1
                comparable.pop("next_acceptance_sequence")
                comparable.pop("next_queue_sequence")
                comparable.pop("aggregate_state_digest")
                for runtime in comparable["runtimes"]:
                    runtime.pop("ready_mailbox")
                    runtime.pop("deferred_mailbox")
                source_without_digest = copy.deepcopy(source)
                source_without_digest.pop("aggregate_state_digest")
                if comparable != source_without_digest:
                    raise ValidationFailure(f"{location}: aggregate upgrade changed version-1 logical state")
            if operation == "upgrade_checkpoint_v1_to_v2":
                source = artifact(vector["checkpoint_before"]).document
                aggregate = result_document["root_record"]["aggregate_state"]
                if "upgrade_checkpoint_v1_to_v2_legacy_evidence" in covers and (
                    not source["pending_deliveries"]
                    or int(source["next_delivery_sequence"]) == 0
                ):
                    raise ValidationFailure(f"{location}: checkpoint upgrade lacks nonempty legacy pending evidence")
                if "upgrade_checkpoint_v1_to_v2_populated_outbox" in covers and (
                    not source["pending_outbox_intents"]
                    or result_document["pending_outbox_intents"]
                    != source["pending_outbox_intents"]
                ):
                    raise ValidationFailure(
                        f"{location}: checkpoint upgrade lost populated outbox"
                    )
                if "upgrade_checkpoint_v1_spawned_target" in covers:
                    pending = source["pending_deliveries"]
                    spawned = next(
                        runtime
                        for runtime in source["root_record"]["aggregate_state"][
                            "runtimes"
                        ]
                        if runtime["relation"]["kind"]
                        == "owned_spawned_instance"
                    )
                    if (
                        len(pending) != 1
                        or pending[0]["envelope"]["target"]
                        != spawned["target_identity"]
                    ):
                        raise ValidationFailure(
                            f"{location}: source lacks an exact spawned-child target"
                        )
                if "upgrade_checkpoint_v1_multi_pending_history" in covers:
                    pending = source["pending_deliveries"]
                    terminal_receipts = [
                        receipt
                        for receipt in source["operation_receipts"]
                        if receipt["operation_kind"] == "delivery"
                    ]
                    upgraded_acceptances = [
                        receipt
                        for receipt in result_document["operation_receipts"]
                        if receipt["operation_kind"] == "acceptance"
                    ]
                    if (
                        source["revision"] != "3"
                        or len(pending) != 1
                        or pending[0]["accepted_revision"] != "2"
                        or len(terminal_receipts) != 1
                        or terminal_receipts[0]["accepted_revision"] != "1"
                        or terminal_receipts[0]["committed_revision"] != "3"
                        or len(upgraded_acceptances) != 1
                        or upgraded_acceptances[0]["accepted_revision"] != "2"
                        or int(upgraded_acceptances[0]["receipt_sequence"])
                        <= int(terminal_receipts[0]["receipt_sequence"])
                    ):
                        raise ValidationFailure(
                            f"{location}: multi-pending upgrade lacks the A1/B2/A3 host history"
                        )
                    optional_metadata_result = artifact(
                        "multi-pending-upgraded-with-metadata-checkpoint-v2.json"
                    ).document
                    optional_acceptance = next(
                        receipt
                        for receipt in optional_metadata_result[
                            "operation_receipts"
                        ]
                        if receipt["operation_kind"] == "acceptance"
                    )
                    if (
                        "legacy_v1_delivery" in upgraded_acceptances[0]
                        or optional_acceptance.get("legacy_v1_delivery")
                        != {
                            "delivery_sequence": pending[0]["delivery_sequence"],
                            "envelope_digest": pending[0]["envelope_digest"],
                            "origin": pending[0]["origin"],
                        }
                        or optional_acceptance["accepted_revision"] != "2"
                    ):
                        raise ValidationFailure(
                            f"{location}: optional host upgrade metadata changed acceptance history"
                        )
                converted = {
                    entry["envelope"]["event_id"]: entry
                    for runtime in aggregate["runtimes"]
                    for entry in runtime["ready_mailbox"]
                }
                if aggregate["next_acceptance_sequence"] != source["next_delivery_sequence"]:
                    raise ValidationFailure(f"{location}: checkpoint upgrade renumbered delivery allocation")
                for pending in source["pending_deliveries"]:
                    entry = converted.get(pending["envelope"]["event_id"])
                    if entry is None or entry["acceptance_sequence"] != pending["delivery_sequence"] or entry["envelope_digest"] == pending["envelope_digest"]:
                        raise ValidationFailure(f"{location}: legacy pending delivery conversion is incomplete")
                    if entry["envelope"]["target"] != pending["envelope"]["target"]:
                        raise ValidationFailure(
                            f"{location}: checkpoint upgrade changed target identity"
                        )
                    acceptance = next((receipt for receipt in result_document["operation_receipts"] if receipt.get("operation_kind") == "acceptance" and receipt.get("event_id") == pending["envelope"]["event_id"]), None)
                    expected_legacy_evidence = {
                        "delivery_sequence": pending["delivery_sequence"],
                        "envelope_digest": pending["envelope_digest"],
                        "origin": pending["origin"],
                    }
                    if acceptance is None:
                        raise ValidationFailure(
                            f"{location}: converted delivery acceptance was lost"
                        )
                    if (
                        "legacy_v1_delivery" in acceptance
                        and acceptance["legacy_v1_delivery"]
                        != expected_legacy_evidence
                    ):
                        raise ValidationFailure(
                            f"{location}: optional legacy pending evidence is invalid"
                        )
                    if (
                        pending["delivery_mode"] == "internal"
                        and (
                            "legacy_v1_delivery" not in acceptance
                            or "legacy_v1_internal"
                            not in entry["envelope"]["source"]
                        )
                    ):
                        raise ValidationFailure(
                            f"{location}: legacy internal delivery source was lost"
                        )
                if "upgrade_checkpoint_v1_to_v2_legacy_evidence" in covers:
                    legacy_operations = [receipt["legacy_receipt"] for receipt in result_document["operation_receipts"] if receipt["operation_kind"] == "legacy_v1_operation"]
                    if not any(receipt.get("emission_references") for receipt in legacy_operations) or not any(receipt.get("outcome") for receipt in legacy_operations):
                        raise ValidationFailure(f"{location}: legacy internal or terminal replay evidence is absent")
            processed_upgrade_coverage = {
                "processed_upgrade_history_without_optional_metadata",
                "processed_upgrade_history_with_optional_metadata",
                "multiple_processed_upgrade_history_without_optional_metadata",
                "multiple_processed_upgrade_history_with_optional_metadata",
            }
            if operation == "checkpoint_step_v2" and covers & processed_upgrade_coverage:
                checkpoint_before = artifact(vector["checkpoint_before"]).document
                before_aggregate = checkpoint_before["root_record"]["aggregate_state"]
                result_aggregate = result_document["root_record"]["aggregate_state"]
                event_id = "delivery-unhandled"
                before_entry = next(
                    entry
                    for runtime in before_aggregate["runtimes"]
                    for entry in runtime["ready_mailbox"]
                    if entry["envelope"]["event_id"] == event_id
                )
                if any(
                    entry["envelope"]["event_id"] == event_id
                    for runtime in result_aggregate["runtimes"]
                    for mailbox in (
                        runtime["ready_mailbox"],
                        runtime["deferred_mailbox"],
                    )
                    for entry in mailbox
                ):
                    raise ValidationFailure(
                        f"{location}: processed upgraded event remained in a mailbox"
                    )
                before_acceptance = next(
                    receipt
                    for receipt in checkpoint_before["operation_receipts"]
                    if receipt.get("operation_kind") == "acceptance"
                    and receipt.get("event_id") == event_id
                )
                result_acceptance = next(
                    receipt
                    for receipt in result_document["operation_receipts"]
                    if receipt.get("operation_kind") == "acceptance"
                    and receipt.get("event_id") == event_id
                )
                terminal_receipt = next(
                    receipt
                    for receipt in result_document["operation_receipts"]
                    if receipt.get("operation_kind") == "event_terminal"
                    and receipt.get("event_id") == event_id
                )
                expects_metadata = any("with_optional_metadata" in item for item in covers)
                if (
                    result_acceptance != before_acceptance
                    or result_acceptance["accepted_revision"] != "2"
                    or ("legacy_v1_delivery" in result_acceptance)
                    != expects_metadata
                    or terminal_receipt["request_digest"]
                    != before_entry["envelope_digest"]
                    or terminal_receipt["acceptance_sequence"]
                    != before_entry["acceptance_sequence"]
                    or terminal_receipt["outcome"]["disposition"] != "unhandled"
                    or before_aggregate["next_logical_step_sequence"] != "2"
                    or result_aggregate["next_logical_step_sequence"] != "2"
                    or result_document["revision"]
                    != str(int(checkpoint_before["revision"]) + 1)
                ):
                    raise ValidationFailure(
                        f"{location}: processed upgrade history is not exact"
                    )
                if "multiple" in next(iter(covers & processed_upgrade_coverage)):
                    remaining = [
                        entry
                        for runtime in result_aggregate["runtimes"]
                        for mailbox in (
                            runtime["ready_mailbox"],
                            runtime["deferred_mailbox"],
                        )
                        for entry in mailbox
                    ]
                    if len(remaining) != 1 or remaining[0]["envelope"]["event_id"] != "delivery-emit-internal":
                        raise ValidationFailure(
                            f"{location}: multiple converted history lost independent pending work"
                        )
            if (
                operation == "checkpoint_step_v2"
                and "processed_legacy_internal_producer_reference" in covers
            ):
                checkpoint_before = artifact(vector["checkpoint_before"]).document
                before_aggregate = checkpoint_before["root_record"]["aggregate_state"]
                before_entry = next(
                    entry
                    for runtime in before_aggregate["runtimes"]
                    for entry in runtime["ready_mailbox"]
                    if "legacy_v1_internal" in entry["envelope"]["source"]
                )
                result_aggregate = result_document["root_record"]["aggregate_state"]
                result_root = next(
                    runtime
                    for runtime in result_aggregate["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                terminal_receipt = next(
                    receipt
                    for receipt in result_document["operation_receipts"]
                    if receipt.get("operation_kind") == "event_terminal"
                    and receipt.get("event_id")
                    == before_entry["envelope"]["event_id"]
                )
                if (
                    result_root["variables"][0]["value"] != ["integer", "6"]
                    or result_aggregate["next_logical_step_sequence"] != "4"
                    or terminal_receipt["outcome"]["disposition"] != "handled"
                    or terminal_receipt["acceptance_sequence"]
                    != before_entry["acceptance_sequence"]
                ):
                    raise ValidationFailure(
                        f"{location}: processed legacy internal event is not exact"
                    )
            if operation == "checkpoint_admit_v2":
                checkpoint_before = artifact(vector["checkpoint_before"]).document
                deliveries = selected["deliveries"]
                replay_evidence = [
                    checkpoint_replay_result(checkpoint_before, delivery)
                    for delivery in deliveries
                ]
                if "compacted_legacy_terminal_replay" in covers:
                    event_id = deliveries[0]["envelope"]["event_id"]
                    if any(
                        receipt["operation_kind"] == "legacy_v1_operation"
                        and receipt["legacy_receipt"].get("event_id") == event_id
                        for receipt in checkpoint_before["operation_receipts"]
                    ) or not any(
                        item["event_id"] == event_id
                        and item["request_digest_domain"]
                        == "determa-inbox-envelope-digest-1"
                        for item in checkpoint_before["event_identity_tombstones"]
                    ):
                        raise ValidationFailure(
                            f"{location}: compacted legacy replay retained its wrapper or lacks tombstone evidence"
                        )
                if covers & {
                    "tombstoned_root_single_replay",
                    "tombstoned_root_batch_replay",
                    "tombstoned_spawned_child_replay",
                    "tombstoned_mixed_runtime_batch_replay",
                } and (
                    checkpoint_before["root_record"]["status"] != "tombstone"
                    or not replay_evidence
                    or any(evidence is None for evidence in replay_evidence)
                ):
                    raise ValidationFailure(
                        f"{location}: tombstoned replay lacks retained exact evidence"
                    )
                if (
                    "tombstoned_spawned_child_replay" in covers
                    and set(deliveries[0]["envelope"]["target"])
                    != {"spawned_instance"}
                ):
                    raise ValidationFailure(
                        f"{location}: historical child replay lacks spawned target"
                    )
                if "tombstoned_mixed_runtime_batch_replay" in covers and {
                    next(iter(delivery["envelope"]["target"]))
                    for delivery in deliveries
                } != {"root", "spawned_instance"}:
                    raise ValidationFailure(
                        f"{location}: mixed replay lacks root and spawned targets"
                    )
                new_deliveries = [
                    delivery
                    for delivery, evidence in zip(
                        deliveries, replay_evidence, strict=True
                    )
                    if evidence is None
                ]

                def admitted_member(
                    checkpoint: dict[str, Any], delivery: dict[str, Any]
                ) -> tuple[dict[str, Any], dict[str, Any]]:
                    event_id = delivery["envelope"]["event_id"]
                    aggregate = checkpoint["root_record"]["aggregate_state"]
                    entry = next(
                        (
                            entry
                            for runtime in aggregate["runtimes"]
                            for mailbox in (
                                runtime["ready_mailbox"],
                                runtime["deferred_mailbox"],
                            )
                            for entry in mailbox
                            if entry["envelope"]["event_id"] == event_id
                        ),
                        None,
                    )
                    receipt = next(
                        (
                            receipt
                            for receipt in checkpoint["operation_receipts"]
                            if receipt.get("operation_kind") == "acceptance"
                            and receipt.get("event_id") == event_id
                        ),
                        None,
                    )
                    if (
                        entry is None
                        or receipt is None
                        or entry["envelope"] != delivery["envelope"]
                        or entry["envelope_digest"] != delivery["envelope_digest"]
                        or receipt["request_digest"] != delivery["envelope_digest"]
                        or receipt["acceptance_sequence"]
                        != entry["acceptance_sequence"]
                        or entry["deferral_count"] != "0"
                    ):
                        raise ValidationFailure(
                            f"{location}: checkpoint admission result is not bound to delivery"
                    )
                    return entry, receipt

                def validate_admission_checkpoint(
                    checkpoint: dict[str, Any],
                ) -> None:
                    before_aggregate = checkpoint_before["root_record"]["aggregate_state"]
                    after_aggregate = checkpoint["root_record"]["aggregate_state"]
                    before_runtimes = {
                        runtime["runtime_id"]: runtime
                        for runtime in before_aggregate["runtimes"]
                    }
                    after_runtimes = {
                        runtime["runtime_id"]: runtime
                        for runtime in after_aggregate["runtimes"]
                    }
                    if before_runtimes.keys() != after_runtimes.keys():
                        raise ValidationFailure(
                            f"{location}: admission changed the runtime set"
                        )
                    for runtime_id, before_runtime in before_runtimes.items():
                        after_runtime = after_runtimes[runtime_id]
                        expected_new = [
                            delivery["envelope"]["event_id"]
                            for delivery in new_deliveries
                            if delivery["envelope"]["target"]
                            == before_runtime["target_identity"]
                        ]
                        before_ready = before_runtime["ready_mailbox"]
                        after_ready = after_runtime["ready_mailbox"]
                        if (
                            after_ready[: len(before_ready)] != before_ready
                            or [
                                entry["envelope"]["event_id"]
                                for entry in after_ready[len(before_ready) :]
                            ]
                            != expected_new
                            or after_runtime["deferred_mailbox"]
                            != before_runtime["deferred_mailbox"]
                        ):
                            raise ValidationFailure(
                                f"{location}: resulting mailbox is not the exact request append"
                            )
                        before_projection = copy.deepcopy(before_runtime)
                        after_projection = copy.deepcopy(after_runtime)
                        for projection in (before_projection, after_projection):
                            projection.pop("ready_mailbox")
                            projection.pop("deferred_mailbox")
                        if before_projection != after_projection:
                            raise ValidationFailure(
                                f"{location}: admission changed non-mailbox runtime state"
                            )
                    unmatched_targets = [
                        delivery["envelope"]["event_id"]
                        for delivery in new_deliveries
                        if not any(
                            delivery["envelope"]["target"]
                            == runtime["target_identity"]
                            for runtime in before_aggregate["runtimes"]
                        )
                    ]
                    if unmatched_targets:
                        raise ValidationFailure(
                            f"{location}: accepted delivery has no exact target runtime"
                        )
                    new_count = len(new_deliveries)
                    expected_revision = str(
                        int(checkpoint_before["revision"]) + (1 if new_count else 0)
                    )
                    expected_receipts = checkpoint_before["operation_receipts"]
                    if (
                        checkpoint["revision"] != expected_revision
                        or after_aggregate["next_acceptance_sequence"]
                        != str(
                            int(before_aggregate["next_acceptance_sequence"])
                            + new_count
                        )
                        or after_aggregate["next_queue_sequence"]
                        != str(int(before_aggregate["next_queue_sequence"]) + new_count)
                        or checkpoint["next_operation_receipt_sequence"]
                        != str(
                            int(checkpoint_before["next_operation_receipt_sequence"])
                            + new_count
                        )
                        or checkpoint["operation_receipts"][: len(expected_receipts)]
                        != expected_receipts
                        or len(checkpoint["operation_receipts"])
                        != len(expected_receipts) + new_count
                    ):
                        raise ValidationFailure(
                            f"{location}: admission counters or receipt history are not exact"
                        )
                    for index, delivery in enumerate(new_deliveries):
                        entry, receipt = admitted_member(checkpoint, delivery)
                        if (
                            entry["acceptance_sequence"]
                            != str(int(before_aggregate["next_acceptance_sequence"]) + index)
                            or entry["queue_sequence"]
                            != str(int(before_aggregate["next_queue_sequence"]) + index)
                            or receipt
                            != {
                                "operation_kind": "acceptance",
                                "receipt_sequence": str(
                                    int(
                                        checkpoint_before[
                                            "next_operation_receipt_sequence"
                                        ]
                                    )
                                    + index
                                ),
                                "event_id": delivery["envelope"]["event_id"],
                                "request_digest": delivery["envelope_digest"],
                                "acceptance_sequence": entry["acceptance_sequence"],
                                "accepted_revision": expected_revision,
                                "delivery_mode": delivery["delivery_mode"],
                            }
                        ):
                            raise ValidationFailure(
                                f"{location}: admitted member allocation is not request-bound"
                            )
                    before_checkpoint_projection = copy.deepcopy(checkpoint_before)
                    after_checkpoint_projection = copy.deepcopy(checkpoint)
                    for projection in (
                        before_checkpoint_projection,
                        after_checkpoint_projection,
                    ):
                        projection.pop("execution_checkpoint_digest")
                        projection.pop("revision")
                        projection.pop("next_operation_receipt_sequence")
                        projection.pop("operation_receipts")
                        aggregate = projection["root_record"]["aggregate_state"]
                        aggregate.pop("aggregate_state_digest")
                        aggregate.pop("next_acceptance_sequence")
                        aggregate.pop("next_queue_sequence")
                        for runtime in aggregate["runtimes"]:
                            runtime.pop("ready_mailbox")
                            runtime.pop("deferred_mailbox")
                    if before_checkpoint_projection != after_checkpoint_projection:
                        raise ValidationFailure(
                            f"{location}: admission changed unrelated checkpoint state"
                        )

                if manifests[result_file]["kind"] == "execution_checkpoint_v2":
                    if any(evidence is not None for evidence in replay_evidence):
                        raise ValidationFailure(
                            f"{location}: checkpoint-only result omits replay evidence"
                        )
                    for delivery in deliveries:
                        admitted_member(result_document, delivery)
                    validate_admission_checkpoint(result_document)
                    if "native_internal_handler_admission" in covers and (
                        deliveries[0]["envelope"]["event"] != "emit_internal"
                    ):
                        raise ValidationFailure(
                            f"{location}: native internal source handler was not admitted"
                        )
                elif result_document["result"] == "batch":
                    members = result_document["members"]
                    result_checkpoint = result_document["checkpoint"]
                    validate_embedded_checkpoint(result_checkpoint, location)
                    if checkpoint_before["root_record"]["status"] == "tombstone":
                        if (
                            new_deliveries
                            or result_checkpoint != checkpoint_before
                        ):
                            raise ValidationFailure(
                                f"{location}: tombstoned all-replay batch mutated checkpoint"
                            )
                    else:
                        validate_admission_checkpoint(result_checkpoint)
                    if len(members) != len(deliveries) or [
                        member["event_id"] for member in members
                    ] != [delivery["envelope"]["event_id"] for delivery in deliveries]:
                        raise ValidationFailure(
                            f"{location}: batch result is not in request order"
                        )
                    new_index = 0
                    for delivery, evidence, member in zip(
                        deliveries, replay_evidence, members, strict=True
                    ):
                        if evidence is not None:
                            if member != {
                                "event_id": delivery["envelope"]["event_id"],
                                "disposition": "replay",
                                "evidence": evidence,
                            }:
                                raise ValidationFailure(
                                    f"{location}: batch replay evidence mismatch"
                                )
                            continue
                        entry, receipt = admitted_member(result_checkpoint, delivery)
                        if member != {
                            "event_id": delivery["envelope"]["event_id"],
                            "disposition": "accepted",
                            "acceptance_sequence": entry["acceptance_sequence"],
                            "queue_sequence": entry["queue_sequence"],
                        }:
                            raise ValidationFailure(
                                f"{location}: batch acceptance evidence mismatch"
                            )
                        expected_acceptance = str(
                            int(
                                checkpoint_before["root_record"]["aggregate_state"][
                                    "next_acceptance_sequence"
                                ]
                            )
                            + new_index
                        )
                        expected_receipt = str(
                            int(checkpoint_before["next_operation_receipt_sequence"])
                            + new_index
                        )
                        if (
                            entry["acceptance_sequence"] != expected_acceptance
                            or receipt["receipt_sequence"] != expected_receipt
                        ):
                            raise ValidationFailure(
                                f"{location}: batch new-member allocation is not contiguous"
                            )
                        new_index += 1
                    if new_index == 0:
                        if result_checkpoint != checkpoint_before:
                            raise ValidationFailure(
                                f"{location}: all-replay batch mutated checkpoint"
                            )
                    elif (
                        result_checkpoint["revision"]
                        != str(int(checkpoint_before["revision"]) + 1)
                    ):
                        raise ValidationFailure(
                            f"{location}: mixed batch did not commit exactly once"
                        )
                else:
                    if len(deliveries) != 1:
                        raise ValidationFailure(
                            f"{location}: multi-member replay lacks ordered evidence"
                        )
                    exact_replay = replay_evidence[0]
                    if exact_replay is None or result_document != exact_replay:
                        raise ValidationFailure(
                            f"{location}: replay result does not match retained evidence"
                        )
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
            if operation == "checkpoint_prune_v2":
                checkpoint_before = artifact(vector["checkpoint_before"]).document
                cutoff = canonical_decimal(
                    selected["cutoff_receipt_sequence"], "pruning cutoff"
                )
                prior_cutoff_value = checkpoint_before["replay_retention"][
                    "pruned_through_receipt_sequence"
                ]
                prior_cutoff = (
                    None
                    if prior_cutoff_value is None
                    else canonical_decimal(
                        prior_cutoff_value, "prior pruning cutoff"
                    )
                )
                if prior_cutoff == cutoff:
                    if result_document != checkpoint_before:
                        raise ValidationFailure(
                            f"{location}: equal pruning cutoff mutated checkpoint"
                        )
                elif result_document != project_bounded_prune(
                    checkpoint_before, cutoff
                ):
                    raise ValidationFailure(
                        f"{location}: bounded pruning result is not the exact "
                        "specification projection"
                    )
                if "version2_native_internal_sequential_pruning" in covers:
                    retained_terminal = next(
                        receipt
                        for receipt in checkpoint_before[
                            "operation_receipts"
                        ]
                        if receipt["receipt_sequence"] == "5"
                    )
                    if (
                        prior_cutoff != 4
                        or cutoff != 5
                        or any(
                            reference.get("event_id")
                            == retained_terminal["event_id"]
                            for receipt in checkpoint_before[
                                "operation_receipts"
                            ]
                            for reference in receipt.get(
                                "emission_references", []
                            )
                        )
                    ):
                        raise ValidationFailure(
                            f"{location}: sequential pruning is not based on "
                            "prior cutoff attestation"
                        )
                if "version2_creation_internal_dependency_retained" in covers:
                    creation = checkpoint_before["operation_receipts"][0]
                    before_entries = [
                        entry
                        for runtime in checkpoint_before["root_record"][
                            "aggregate_state"
                        ]["runtimes"]
                        for entry in runtime["ready_mailbox"]
                    ]
                    after_entries = [
                        entry
                        for runtime in result_document["root_record"][
                            "aggregate_state"
                        ]["runtimes"]
                        for entry in runtime["ready_mailbox"]
                    ]
                    references = creation["legacy_receipt"][
                        "emission_references"
                    ]
                    if (
                        cutoff != 1
                        or len(before_entries) != 1
                        or after_entries != before_entries
                        or len(references) != 1
                        or references[0].get("kind")
                        != "internal_delivery"
                        or references[0].get("event_id")
                        != before_entries[0]["envelope"]["event_id"]
                    ):
                        raise ValidationFailure(
                            f"{location}: creation-owned internal work is not "
                            "distinguishing"
                        )
                if "version2_creation_external_dependency_retained" in covers:
                    creation = checkpoint_before["operation_receipts"][0]
                    before_outbox = checkpoint_before[
                        "pending_outbox_intents"
                    ]
                    references = creation["legacy_receipt"][
                        "emission_references"
                    ]
                    if (
                        cutoff != 1
                        or len(before_outbox) != 1
                        or result_document["pending_outbox_intents"]
                        != before_outbox
                        or len(references) != 1
                        or references[0].get("kind") != "external_outbox"
                        or references[0].get("effect_id")
                        != before_outbox[0]["intent"]["effect_id"]
                    ):
                        raise ValidationFailure(
                            f"{location}: creation-owned external work is not "
                            "distinguishing"
                        )
                if covers & {
                    "version2_creation_internal_dependency_retained",
                    "version2_creation_external_dependency_retained",
                }:
                    if "source_checkpoint_v1" not in vector:
                        raise ValidationFailure(
                            f"{location}: creation-owned work lacks its version-1 source trace"
                        )
                    source_checkpoint = artifact(
                        vector["source_checkpoint_v1"]
                    ).document
                    if upgrade_checkpoint(source_checkpoint) != checkpoint_before:
                        raise ValidationFailure(
                            f"{location}: version-2 checkpoint is not the exact upgrade "
                            "of its bound version-1 host trace"
                        )
                    creation = checkpoint_before["operation_receipts"][0][
                        "legacy_receipt"
                    ]
                    aggregate = checkpoint_before["root_record"][
                        "aggregate_state"
                    ]
                    expected_creation_digest = hash_value(
                        [
                            "determa-creation-request-digest-1",
                            "1",
                            validated_bundle_fingerprint(
                                case / vector["bundle"]
                            ),
                            aggregate["namespace"],
                            aggregate["root_machine_id"],
                            aggregate["root_machine_version"],
                            aggregate["root_instance_id"],
                            aggregate["creation_id"],
                            encode_typed_value(
                                {"input": {}, "external": {}}
                            ),
                        ]
                    )
                    if creation["request_digest"] != expected_creation_digest:
                        raise ValidationFailure(
                            f"{location}: creation-owned work trace has an "
                            "invalid creation request digest"
                        )
                    source_aggregate = source_checkpoint["root_record"][
                        "aggregate_state"
                    ]
                    source_receipts = source_checkpoint["operation_receipts"]
                    if (
                        len(source_receipts) != 2
                        or source_receipts[0]["operation_kind"] != "creation"
                        or source_receipts[1]["operation_kind"] != "delivery"
                        or source_receipts[1]["event_id"]
                        != "creation-unrelated"
                    ):
                        raise ValidationFailure(
                            f"{location}: source trace is not a complete create/delivery history"
                        )
                    root_runtime = next(
                        runtime
                        for runtime in source_aggregate["runtimes"]
                        if runtime["relation"]["kind"] == "root"
                    )
                    expected_root_runtime_id = hash_value(
                        [
                            "determa-root-runtime-identity-2",
                            "1",
                            source_aggregate["validated_bundle_fingerprint"],
                            source_aggregate["namespace"],
                            source_aggregate["root_machine_id"],
                            source_aggregate["root_machine_version"],
                            source_aggregate["root_instance_id"],
                        ]
                    )
                    if root_runtime["runtime_id"] != expected_root_runtime_id:
                        raise ValidationFailure(
                            f"{location}: source root identity does not use the normative operands"
                        )
                    root_index = (
                        "0"
                        if source_aggregate["root_machine_id"]
                        == "internal_creator"
                        else "1"
                    )
                    root_pointer = f"/machines/{root_index}/root"
                    initialization_cause_id = hash_value(
                        [
                            "determa-cause-identity-1",
                            "1",
                            "root_initialization",
                            source_aggregate["root_instance_id"],
                            root_runtime["runtime_id"],
                            root_runtime["runtime_id"],
                            source_aggregate["creation_id"],
                            "0",
                            root_pointer,
                            "0",
                        ]
                    )
                    created_aggregate = copy.deepcopy(source_aggregate)
                    created_aggregate.pop("aggregate_state_digest")
                    created_aggregate["next_logical_step_sequence"] = "1"
                    root_variable = created_aggregate["runtimes"][0][
                        "variables"
                    ][0]
                    root_variable["value"] = ["integer", "0"]
                    created_digest = hash_value(
                        ["determa-aggregate-state-digest-1", created_aggregate]
                    )
                    if (
                        source_receipts[0]["resulting_aggregate_state_digest"]
                        != created_digest
                        or source_receipts[1]["resulting_aggregate_state_digest"]
                        != source_aggregate["aggregate_state_digest"]
                    ):
                        raise ValidationFailure(
                            f"{location}: legacy receipts do not retain exact version-1 "
                            "before/after aggregate digests"
                        )
                    presented_envelope = {
                        "event": "increment",
                        "event_id": "creation-unrelated",
                        "target": copy.deepcopy(root_runtime["target_identity"]),
                        "payload": ["map", []],
                    }
                    expected_delivery_digest = hash_value(
                        [
                            "determa-inbox-envelope-digest-1",
                            "1",
                            source_aggregate["root_instance_id"],
                            "input",
                            presented_envelope,
                        ]
                    )
                    if source_receipts[1]["request_digest"] != expected_delivery_digest:
                        raise ValidationFailure(
                            f"{location}: legacy delivery receipt does not hash the complete envelope"
                        )
                    creation_reference = source_receipts[0][
                        "emission_references"
                    ][0]
                    if source_aggregate["root_machine_id"] == "internal_creator":
                        expected_event_id = hash_value(
                            [
                                "determa-event-identity-1",
                                "1",
                                source_aggregate["root_instance_id"],
                                root_runtime["runtime_id"],
                                root_runtime["runtime_id"],
                                initialization_cause_id,
                                "0",
                                f"{root_pointer}/entry/0/send",
                                "0",
                            ]
                        )
                        pending = source_checkpoint["pending_deliveries"]
                        if (
                            len(pending) != 1
                            or pending[0]["envelope"]["event_id"]
                            != expected_event_id
                            or creation_reference.get("event_id")
                            != expected_event_id
                        ):
                            raise ValidationFailure(
                                f"{location}: internal creation identity/reference is not normative"
                            )
                    else:
                        expected_effect_id = hash_value(
                            [
                                "determa-effect-identity-1",
                                "1",
                                [
                                    source_aggregate["namespace"],
                                    source_aggregate["root_machine_id"],
                                    source_aggregate["root_machine_version"],
                                ],
                                source_aggregate["root_instance_id"],
                                root_runtime["runtime_id"],
                                initialization_cause_id,
                                "0",
                                f"{root_pointer}/entry/0/send",
                                "0",
                            ]
                        )
                        pending = source_checkpoint["pending_outbox_intents"]
                        if (
                            len(pending) != 1
                            or pending[0]["intent"]["effect_id"]
                            != expected_effect_id
                            or creation_reference.get("effect_id")
                            != expected_effect_id
                        ):
                            raise ValidationFailure(
                                f"{location}: external creation identity/reference is not normative"
                            )
        if operation == "checkpoint_prune_v2" and expectation["result"] == "failure":
            checkpoint_before = artifact(vector["checkpoint_before"]).document
            cutoff = canonical_decimal(
                selected["cutoff_receipt_sequence"], "pruning cutoff"
            )
            prior_cutoff_value = checkpoint_before["replay_retention"][
                "pruned_through_receipt_sequence"
            ]
            prior_cutoff = (
                None
                if prior_cutoff_value is None
                else canonical_decimal(prior_cutoff_value, "prior pruning cutoff")
            )
            lower_cutoff_invalid = (
                prior_cutoff is not None and cutoff < prior_cutoff
            )
            skipped_cutoff_invalid = cutoff >= canonical_decimal(
                checkpoint_before["next_operation_receipt_sequence"],
                "next receipt sequence",
            )
            aggregate = checkpoint_before["root_record"].get("aggregate_state")
            live_entries = (
                [
                    entry
                    for runtime in aggregate["runtimes"]
                    for mailbox in (
                        runtime["ready_mailbox"],
                        runtime["deferred_mailbox"],
                    )
                    for entry in mailbox
                ]
                if aggregate is not None
                else []
            )
            live_event_ids = {
                entry["envelope"]["event_id"] for entry in live_entries
            }
            receipts = checkpoint_before["operation_receipts"]
            acceptance_by_event = {
                receipt["event_id"]: receipt
                for receipt in receipts
                if receipt["operation_kind"] == "acceptance"
            }
            terminal_by_event = {
                receipt["event_id"]: receipt
                for receipt in receipts
                if receipt["operation_kind"] == "event_terminal"
            }
            dependency_reasons: set[str] = set()
            if any(
                event_id in live_event_ids
                and canonical_decimal(
                    receipt["receipt_sequence"],
                    "live acceptance receipt sequence",
                )
                <= cutoff
                for event_id, receipt in acceptance_by_event.items()
            ):
                dependency_reasons.add("live_acceptance")
            if any(
                (
                    canonical_decimal(
                        acceptance_by_event[event_id]["receipt_sequence"],
                        "acceptance receipt sequence",
                    )
                    <= cutoff
                )
                != (
                    canonical_decimal(
                        terminal["receipt_sequence"],
                        "terminal receipt sequence",
                    )
                    <= cutoff
                )
                for event_id, terminal in terminal_by_event.items()
                if event_id in acceptance_by_event
            ):
                dependency_reasons.add("terminal_pair")

            retained_event_ids = live_event_ids
            pending_effect_ids = {
                item["intent"]["effect_id"]
                for item in checkpoint_before["pending_outbox_intents"]
            }
            for producer in receipts:
                producer_sequence = canonical_decimal(
                    producer["receipt_sequence"], "producer receipt sequence"
                )
                if producer_sequence == 0 or producer_sequence > cutoff:
                    continue
                references = list(producer.get("emission_references", []))
                legacy = producer.get("legacy_receipt")
                if isinstance(legacy, dict):
                    references.extend(legacy.get("emission_references", []))
                if any(
                    reference.get("event_id") in retained_event_ids
                    for reference in references
                    if reference.get("kind")
                    in {
                        "internal_mailbox",
                        "internal_terminal",
                        "internal_delivery",
                    }
                ):
                    dependency_reasons.add("internal_producer")
                if any(
                    reference.get("effect_id") in pending_effect_ids
                    for reference in references
                    if reference.get("kind") == "external_outbox"
                ):
                    dependency_reasons.add("pending_outbox")
            for entry in live_entries:
                source = entry["envelope"]["source"]
                legacy_origin = source.get("legacy_v1_internal")
                if legacy_origin is not None:
                    producer_sequence = canonical_decimal(
                        legacy_origin["producing_receipt_sequence"],
                        "legacy internal producer sequence",
                    )
                    if 0 < producer_sequence <= cutoff:
                        dependency_reasons.add("internal_producer")
            for receipt in receipts:
                if canonical_decimal(
                    receipt["receipt_sequence"],
                    "retained receipt sequence",
                ) <= cutoff:
                    continue
                legacy_evidence = receipt.get("legacy_v1_delivery")
                if legacy_evidence is None and receipt.get(
                    "operation_kind"
                ) == "legacy_v1_operation":
                    legacy_evidence = receipt.get("legacy_receipt")
                if not isinstance(legacy_evidence, dict):
                    continue
                origin = legacy_evidence.get("origin")
                if (
                    isinstance(origin, dict)
                    and origin.get("kind") == "internal_emission"
                ):
                    producer_sequence = canonical_decimal(
                        origin["producing_receipt_sequence"],
                        "retained legacy origin producer sequence",
                    )
                    if 0 < producer_sequence <= cutoff:
                        dependency_reasons.add("legacy_origin")

            dependency_invalid = bool(dependency_reasons)
            if expectation.get("code") == "invalid_execution_checkpoint":
                if lower_cutoff_invalid or skipped_cutoff_invalid or dependency_invalid:
                    failure_evidence.add("invalid_execution_checkpoint")
                if (
                    "version2_lower_pruning_cutoff_rejected" in covers
                    and not lower_cutoff_invalid
                ):
                    raise ValidationFailure(
                        f"{location}: lower-cutoff rejection is not distinguishing"
                    )
                if (
                    "version2_invalid_pruning_cutoff_rejected" in covers
                    and not skipped_cutoff_invalid
                ):
                    raise ValidationFailure(
                        f"{location}: skipped-cutoff rejection is not distinguishing"
                    )
                if (
                    "version2_dependency_pruning_rejected" in covers
                    and not dependency_invalid
                ):
                    raise ValidationFailure(
                        f"{location}: dependency rejection has no retained producer"
                    )
                if (
                    "version2_legacy_origin_pruning_rejected" in covers
                    and "legacy_origin" not in dependency_reasons
                ):
                    raise ValidationFailure(
                        f"{location}: legacy-origin pruning rejection lacks "
                        "a retained dependency chain"
                    )
                if (
                    "version2_live_acceptance_pruning_rejected" in covers
                    and "live_acceptance" not in dependency_reasons
                ):
                    raise ValidationFailure(
                        f"{location}: live-acceptance pruning rejection lacks "
                        "protected live work"
                    )
                if (
                    "version2_terminal_pair_pruning_rejected" in covers
                    and "terminal_pair" not in dependency_reasons
                ):
                    raise ValidationFailure(
                        f"{location}: terminal-pair pruning rejection is not "
                        "distinguishing"
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
    if run_mutation_probes:
        for index, original_vector in enumerate(test["version2_vectors"]):
            operation = original_vector["operation"]
            original_code = original_vector["expect"].get("code")
            alternative_allowed = sorted(
                operation_failure_codes[operation] - {original_code}
            )
            if operation == "step_v2" or not alternative_allowed:
                relabeled_code = next(
                    entry["code"]
                    for entry in _CLOSED_CODE_REGISTRY["entries"]
                    if entry["code"] not in operation_failure_codes[operation]
                )
            else:
                relabeled_code = alternative_allowed[0]
            relabeled = copy.deepcopy(test)
            relabeled_vector = relabeled["version2_vectors"][index]
            prior_file = relabeled_vector.get(
                "state_before", relabeled_vector.get("checkpoint_before")
            )
            if prior_file is None:
                prior_file = next(
                    item["file"]
                    for item in relabeled["artifacts"]["documents"]
                    if item.get("valid") and item["kind"] != "version2_operation_inputs"
                )
            relabeled_vector["expect"] = {
                "result": "failure",
                "code": relabeled_code,
                "unchanged_file": prior_file,
            }
            try:
                validate_version2_vectors(
                    case,
                    relabeled,
                    bundle_paths,
                    artifact_paths,
                    artifact_overrides=artifact_overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"{case.name}: operation relabel was accepted for "
                f"{original_vector['name']} as {relabeled_code}"
            )
        for index, original_vector in enumerate(test["version2_vectors"]):
            if (
                original_vector["operation"] != "checkpoint_prune_v2"
                or original_vector["expect"]["result"] != "success"
            ):
                continue
            relabeled = copy.deepcopy(test)
            relabeled_vector = relabeled["version2_vectors"][index]
            relabeled_vector["expect"] = {
                "result": "failure",
                "code": "invalid_execution_checkpoint",
                "unchanged_file": relabeled_vector["checkpoint_before"],
            }
            try:
                validate_version2_vectors(
                    case,
                    relabeled,
                    bundle_paths,
                    artifact_paths,
                    artifact_overrides=artifact_overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"{case.name}: successful pruning vector was relabeled as "
                "invalid_execution_checkpoint"
            )
        if case.name == "checkpoint-04-version2-mailboxes":
            for index, original_vector in enumerate(test["version2_vectors"]):
                if not set(original_vector["covers"]) & {
                    "version2_creation_internal_dependency_retained",
                    "version2_creation_external_dependency_retained",
                }:
                    continue
                source_name = original_vector["source_checkpoint_v1"]
                before_name = original_vector["checkpoint_before"]
                result_name = original_vector["expect"]["exact_result_file"]
                source = copy.deepcopy(artifact(source_name).document)
                source["operation_receipts"][1]["request_digest"] = hash_value(
                    [
                        "determa-inbox-envelope-digest-1",
                        "1",
                        source["root_instance_id"],
                        "input",
                        "creation-unrelated",
                    ]
                )
                source.pop("execution_checkpoint_digest")
                source["execution_checkpoint_digest"] = hash_value(
                    ["determa-execution-checkpoint-digest-1", source]
                )
                before = upgrade_checkpoint(source)
                result = project_bounded_prune(before, 1)
                mutated = dict(artifact_overrides)
                mutated.update(
                    {
                        source_name: source,
                        before_name: before,
                        result_name: result,
                    }
                )
                try:
                    validate_version2_vectors(
                        case,
                        test,
                        bundle_paths,
                        artifact_paths,
                        artifact_overrides=mutated,
                        run_mutation_probes=False,
                    )
                except ValidationFailure:
                    pass
                else:
                    raise ValidationFailure(
                        f"{case.name}: self-consistent abbreviated legacy request "
                        f"history was accepted for {original_vector['name']}"
                    )

                source = copy.deepcopy(artifact(source_name).document)
                replacement_id = "sha256:" + "0" * 64
                creation_reference = source["operation_receipts"][0][
                    "emission_references"
                ][0]
                if creation_reference["kind"] == "internal_delivery":
                    creation_reference["event_id"] = replacement_id
                    pending = source["pending_deliveries"][0]
                    pending["envelope"]["event_id"] = replacement_id
                    pending["envelope_digest"] = hash_value(
                        [
                            "determa-inbox-envelope-digest-1",
                            "1",
                            source["root_instance_id"],
                            "internal",
                            pending["envelope"],
                        ]
                    )
                else:
                    creation_reference["effect_id"] = replacement_id
                    source["pending_outbox_intents"][0]["intent"][
                        "effect_id"
                    ] = replacement_id
                source.pop("execution_checkpoint_digest")
                source["execution_checkpoint_digest"] = hash_value(
                    ["determa-execution-checkpoint-digest-1", source]
                )
                before = upgrade_checkpoint(source)
                result = project_bounded_prune(before, 1)
                mutated = dict(artifact_overrides)
                mutated.update(
                    {
                        source_name: source,
                        before_name: before,
                        result_name: result,
                    }
                )
                try:
                    validate_version2_vectors(
                        case,
                        test,
                        bundle_paths,
                        artifact_paths,
                        artifact_overrides=mutated,
                        run_mutation_probes=False,
                    )
                except ValidationFailure:
                    continue
                raise ValidationFailure(
                    f"{case.name}: self-consistent non-normative creation identity "
                    f"was accepted for {original_vector['name']}"
                )
    if run_mutation_probes and case.name == "117-version2-mailboxes":
        def reseal_core_result(result: dict[str, Any]) -> dict[str, Any]:
            mutated = copy.deepcopy(result)
            state = mutated["state"]
            state.pop("aggregate_state_digest", None)
            state["aggregate_state_digest"] = hash_value(
                ["determa-aggregate-state-digest-2", state]
            )
            return mutated

        probes: dict[str, dict[str, Any]] = {
            "creation expectation substitution": {
                "empty-aggregate-v2.json": artifact("base-aggregate.json").document,
            },
            "lifecycle result substitution": {
                "internal-emission-cancelled-result.json": artifact("internal-emission-active-result.json").document,
            },
        }
        self_cause = copy.deepcopy(
            artifact("internal-emission-active-result.json").document
        )
        self_cause_entry = next(
            entry
            for runtime in self_cause["state"]["runtimes"]
            for entry in runtime["ready_mailbox"]
            if entry["delivery_mode"] == "internal"
        )
        self_cause_entry["envelope"]["cause_id"] = self_cause_entry[
            "envelope"
        ]["event_id"]
        self_cause_entry["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                self_cause["state"]["root_instance_id"],
                "internal",
                self_cause_entry["envelope"],
            ]
        )
        probes["internal emission self-cause"] = {
            "internal-emission-active-result.json": reseal_core_result(
                self_cause
            )
        }
        chained_prior = artifact("chained-internal-before.json").document
        chained_bad = copy.deepcopy(
            artifact("chained-internal-result.json").document
        )
        chained_source = next(
            runtime
            for runtime in chained_prior["runtimes"]
            if runtime["relation"].get("component_id") == "left"
        )
        inherited_cause_id = chained_source["ready_mailbox"][0]["envelope"][
            "cause_id"
        ]
        wrong_second_event_id = hash_value(
            [
                "determa-event-identity-1",
                "1",
                chained_prior["root_instance_id"],
                chained_source["runtime_id"],
                chained_source["runtime_id"],
                inherited_cause_id,
                chained_prior["next_logical_step_sequence"],
                "/machines/0/root/states/processing/components/0/root/"
                "states/running/on_events/component_finish/action/0/send",
                "0",
            ]
        )
        wrong_disposed_envelope = {
            "event": "component_work",
            "event_id": wrong_second_event_id,
            "cause_id": inherited_cause_id,
            "source": {"runtime": chained_source["target_identity"]},
            "target": chained_source["target_identity"],
            "payload": ["map", []],
        }
        chained_bad["emissions"][0]["event_id"] = wrong_second_event_id
        chained_bad["lifecycle_dispositions"][0][
            "event_id"
        ] = wrong_second_event_id
        chained_bad["lifecycle_dispositions"][0]["request_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                chained_prior["root_instance_id"],
                "internal",
                wrong_disposed_envelope,
            ]
        )
        chained_result_root = next(
            runtime
            for runtime in chained_bad["state"]["runtimes"]
            if runtime["relation"]["kind"] == "root"
        )
        wrong_completion_event_id = hash_value(
            [
                "determa-event-identity-1",
                "1",
                chained_prior["root_instance_id"],
                chained_source["runtime_id"],
                chained_result_root["runtime_id"],
                inherited_cause_id,
                chained_prior["next_logical_step_sequence"],
                "system:component_completion",
                "0",
            ]
        )
        wrong_completion = chained_result_root["ready_mailbox"][0]
        wrong_completion["envelope"]["event_id"] = wrong_completion_event_id
        wrong_completion["envelope"]["cause_id"] = inherited_cause_id
        wrong_completion["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                chained_prior["root_instance_id"],
                "internal",
                wrong_completion["envelope"],
            ]
        )
        chained_bad["emissions"][1]["event_id"] = wrong_completion_event_id
        probes["chained emission inherited cause substitution"] = {
            "chained-internal-result.json": reseal_core_result(chained_bad)
        }
        numeric_activation = copy.deepcopy(
            artifact("internal-emission-active-result.json").document
        )
        numeric_entry = next(
            entry
            for runtime in numeric_activation["state"]["runtimes"]
            for entry in runtime["ready_mailbox"]
            if "component" in entry["envelope"]["target"]
        )
        numeric_entry["envelope"]["target"]["component"][
            "activation_sequence"
        ] = 0
        numeric_entry["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                numeric_activation["state"]["root_instance_id"],
                "internal",
                numeric_entry["envelope"],
            ]
        )
        probes["numeric emitted component activation"] = {
            "internal-emission-active-result.json": reseal_core_result(
                numeric_activation
            )
        }
        wrong_system_source = copy.deepcopy(
            artifact("internal-emission-runtime-completed-result.json").document
        )
        completion_entry = next(
            entry
            for runtime in wrong_system_source["state"]["runtimes"]
            for entry in runtime["ready_mailbox"]
            if entry["envelope"]["event"] == "determa.component_completed"
        )
        completion_entry["envelope"]["source"] = {
            "runtime": next(
                runtime
                for runtime in wrong_system_source["state"]["runtimes"]
                if runtime["relation"]["kind"] == "component"
                and runtime["relation"]["component_id"] == "left"
            )["target_identity"]
        }
        completion_entry["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                wrong_system_source["state"]["root_instance_id"],
                "internal",
                completion_entry["envelope"],
            ]
        )
        probes["reserved completion wrong system source"] = {
            "internal-emission-runtime-completed-result.json": (
                reseal_core_result(wrong_system_source)
            )
        }
        stepped_unhandled = copy.deepcopy(
            artifact("spawn-isolation-result.json").document
        )
        stepped_unhandled["state"]["next_logical_step_sequence"] = "3"
        probes["unhandled spawned delivery allocated step"] = {
            "spawn-isolation-result.json": reseal_core_result(
                stepped_unhandled
            )
        }
        mutated_inputs = copy.deepcopy(artifact("operation-inputs.json").document)
        mutated_inputs["invalid_runtime_step"]["target_runtime_id"] = artifact("empty-aggregate-v2.json").document["root_runtime_id"]
        probes["fabricated runtime classification"] = {"operation-inputs.json": mutated_inputs}
        admission = artifact("admission-success.json").document
        admission_unknown = copy.deepcopy(admission)
        admission_unknown["accepted"][0]["event_id"] = "not-in-request"
        probes["admission event not in request"] = {
            "admission-success.json": admission_unknown
        }
        admission_sequence = copy.deepcopy(admission)
        admission_sequence["accepted"][0]["acceptance_sequence"] = "999"
        probes["admission acceptance sequence 999"] = {
            "admission-success.json": admission_sequence
        }
        admission_digest = copy.deepcopy(admission)
        admission_digest["state"]["aggregate_state_digest"] = "sha256:" + "0" * 64
        probes["admission all-zero aggregate digest"] = {
            "admission-success.json": admission_digest
        }
        admission_deferral = copy.deepcopy(admission)
        admitted_event_ids = {
            item["event_id"] for item in admission_deferral["accepted"]
        }
        next(
            entry
            for runtime in admission_deferral["state"]["runtimes"]
            for entry in runtime["ready_mailbox"]
            if entry["envelope"]["event_id"] in admitted_event_ids
        )["deferral_count"] = "99"
        admission_deferral["state"].pop("aggregate_state_digest")
        admission_deferral["state"]["aggregate_state_digest"] = hash_value(
            ["determa-aggregate-state-digest-2", admission_deferral["state"]]
        )
        probes["admission nonzero initial deferral count"] = {
            "admission-success.json": admission_deferral
        }
        replay = artifact("replay-success.json").document
        replay_unknown = copy.deepcopy(replay)
        replay_unknown["event_id"] = "not-in-request"
        probes["core replay event not in request"] = {
            "replay-success.json": replay_unknown
        }
        replay_sequence = copy.deepcopy(replay)
        replay_sequence["acceptance_sequence"] = "999"
        probes["core replay acceptance sequence 999"] = {
            "replay-success.json": replay_sequence
        }
        corrected_contract_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        corrected_host = corrected_contract_inputs["host_cause_mismatch"][
            "deliveries"
        ][0]
        corrected_host["envelope"]["cause_id"] = corrected_host["envelope"][
            "event_id"
        ]
        corrected_host["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                artifact("base-aggregate.json").document["root_instance_id"],
                corrected_host["delivery_mode"],
                corrected_host["envelope"],
            ]
        )
        probes["host cause rejection without cause violation"] = {
            "operation-inputs.json": corrected_contract_inputs
        }
        corrected_digest_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        corrected_digest = corrected_digest_inputs["digest_mismatch_batch"][
            "deliveries"
        ][1]
        corrected_digest["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                artifact("base-aggregate.json").document["root_instance_id"],
                corrected_digest["delivery_mode"],
                corrected_digest["envelope"],
            ]
        )
        probes["digest rejection without digest violation"] = {
            "operation-inputs.json": corrected_digest_inputs
        }
        nonduplicate_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        nonduplicate_inputs["duplicate_batch"]["deliveries"][1]["envelope"][
            "event_id"
        ] = "not-a-duplicate"
        probes["duplicate rejection without duplicate identity"] = {
            "operation-inputs.json": nonduplicate_inputs
        }
        undeclared_reserved_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        undeclared_reserved = undeclared_reserved_inputs["reserved_event_admit"][
            "deliveries"
        ][0]
        undeclared_reserved["envelope"]["event"] = "unreserved.lifecycle_event"
        undeclared_reserved["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                artifact("reserved-admission-before.json").document[
                    "root_instance_id"
                ],
                undeclared_reserved["delivery_mode"],
                undeclared_reserved["envelope"],
            ]
        )
        probes["undeclared non-reserved internal event admission"] = {
            "operation-inputs.json": undeclared_reserved_inputs
        }
        probes["running root descendant classified as terminal"] = {
            "faulted-root-retained-component-aggregate.json": artifact(
                "cleanup-rollback-before.json"
            ).document
        }
        unseen_core_conflict_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        unseen_core_conflict = unseen_core_conflict_inputs[
            "conflicting_replay"
        ]["deliveries"][0]
        unseen_core_conflict["envelope"]["event_id"] = "unseen-core-conflict"
        unseen_core_conflict["envelope"]["cause_id"] = "unseen-core-conflict"
        unseen_core_conflict["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                artifact("base-aggregate.json").document["root_instance_id"],
                unseen_core_conflict["delivery_mode"],
                unseen_core_conflict["envelope"],
            ]
        )
        probes["core conflict expectation without retained identity"] = {
            "operation-inputs.json": unseen_core_conflict_inputs
        }
        for probe_name, overrides in probes.items():
            try:
                validate_version2_vectors(
                    case,
                    test,
                    bundle_paths,
                    artifact_paths,
                    artifact_overrides=overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(f"{case.name}: adversarial probe was accepted: {probe_name}")
        for relabeled_code in ("checkpoint_revision_conflict", "invalid_event"):
            reserved_relabel = copy.deepcopy(test)
            reserved_vector = next(
                vector
                for vector in reserved_relabel["version2_vectors"]
                if vector["name"] == "reserved_component_completion_is_admitted"
            )
            reserved_vector["expect"] = {
                "result": "failure",
                "code": relabeled_code,
                "unchanged_file": "reserved-admission-before.json",
                "caller_still_owns_input": True,
            }
            try:
                validate_version2_vectors(
                    case,
                    reserved_relabel,
                    bundle_paths,
                    artifact_paths,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"{case.name}: reserved component admission accepted "
                f"unsupported rejection relabel {relabeled_code}"
            )
    if run_mutation_probes and case.name == "118-version2-persistence":
        descriptor = copy.deepcopy(artifact("descriptor-compatible-v2.json").document)
        wrong_shape = copy.deepcopy(descriptor)
        wrong_shape["base_descriptor"]["source_aggregate_shape_fingerprint"] = "sha256:" + "0" * 64
        source_cycle = copy.deepcopy(descriptor)
        source_cycle["base_descriptor"]["target_validated_bundle_fingerprint"] = (
            source_cycle["base_descriptor"]["source_validated_bundle_fingerprint"]
        )
        source = artifact("base-aggregate-v2.json").document
        probes = {
            "migration shape substitution": {"descriptor-compatible-v2.json": wrong_shape},
            "migration self-cycle substitution": {"descriptor-compatible-v2.json": source_cycle},
            "migration result without target binding or sequence": {
                "migration-preserve-result.json": {
                    "result": "success",
                    "aggregate_state": source,
                    "dispositions": [],
                }
            },
        }
        for probe_name, overrides in probes.items():
            try:
                validate_version2_vectors(
                    case,
                    test,
                    bundle_paths,
                    artifact_paths,
                    artifact_overrides=overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(f"{case.name}: adversarial probe was accepted: {probe_name}")
    if run_mutation_probes and case.name == "checkpoint-04-version2-mailboxes":
        terminal_result = artifact("terminal-replay-result.json").document
        tombstone_result = artifact("tombstone-replay-result.json").document
        all_replay_result = artifact("all-replay-batch-result.json").document
        mixed_result = artifact("mixed-replay-new-batch-result.json").document
        compacted_legacy_result = artifact(
            "compacted-legacy-replay-result.json"
        ).document
        tombstoned_batch_result = artifact(
            "tombstoned-batch-replay-result.json"
        ).document
        probes = {}
        for label, mutation in (
            ("pruning changed aggregate variable", "variable"),
            ("pruning changed logical step counter", "logical_step"),
            ("pruning omitted required replay tombstone", "tombstone"),
        ):
            compact_projection = copy.deepcopy(
                artifact("compact-checkpoint-v2.json").document
            )
            aggregate = compact_projection["root_record"]["aggregate_state"]
            if mutation == "variable":
                aggregate["runtimes"][0]["variables"][0]["value"] = [
                    "integer",
                    "999",
                ]
            elif mutation == "logical_step":
                aggregate["next_logical_step_sequence"] = "999"
            else:
                compact_projection["event_identity_tombstones"] = []
            if mutation != "tombstone":
                aggregate.pop("aggregate_state_digest")
                aggregate["aggregate_state_digest"] = hash_value(
                    ["determa-aggregate-state-digest-2", aggregate]
                )
            compact_projection.pop("execution_checkpoint_digest")
            compact_projection["execution_checkpoint_digest"] = hash_value(
                [
                    "determa-execution-checkpoint-digest-2",
                    compact_projection,
                ]
            )
            probes[label] = {"compact-checkpoint-v2.json": compact_projection}
        for field, value in (
            ("acceptance_sequence", "999"),
            ("request_digest", "sha256:" + "0" * 64),
        ):
            internal_projection = copy.deepcopy(
                artifact(
                    "native-internal-terminal-pruned-checkpoint-v2.json"
                ).document
            )
            internal_event_id = next(
                receipt["event_id"]
                for receipt in artifact(
                    "native-internal-terminal-checkpoint-v2.json"
                ).document["operation_receipts"]
                if receipt["receipt_sequence"] == "5"
            )
            next(
                tombstone
                for tombstone in internal_projection[
                    "event_identity_tombstones"
                ]
                if tombstone["event_id"] == internal_event_id
            )[field] = value
            internal_projection.pop("execution_checkpoint_digest")
            internal_projection["execution_checkpoint_digest"] = hash_value(
                [
                    "determa-execution-checkpoint-digest-2",
                    internal_projection,
                ]
            )
            probes[f"native internal pruning {field}"] = {
                "native-internal-terminal-pruned-checkpoint-v2.json": (
                    internal_projection
                )
            }
        unseen_checkpoint_conflict_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        unseen_checkpoint_conflict = unseen_checkpoint_conflict_inputs[
            "terminal_conflict"
        ]["deliveries"][0]
        unseen_checkpoint_conflict["envelope"]["event_id"] = (
            "unseen-checkpoint-conflict"
        )
        unseen_checkpoint_conflict["envelope"]["cause_id"] = (
            "unseen-checkpoint-conflict"
        )
        unseen_checkpoint_conflict["envelope_digest"] = hash_value(
            [
                "determa-inbox-envelope-digest-2",
                "2",
                artifact("terminal-checkpoint-v2.json").document[
                    "root_instance_id"
                ],
                unseen_checkpoint_conflict["delivery_mode"],
                unseen_checkpoint_conflict["envelope"],
            ]
        )
        probes["checkpoint conflict expectation without retained identity"] = {
            "operation-inputs.json": unseen_checkpoint_conflict_inputs
        }
        for field, sequence in (
            ("acceptance_receipt_sequence", "999"),
            ("terminal_receipt_sequence", "1000"),
        ):
            result = copy.deepcopy(terminal_result)
            result[field] = sequence
            probes[f"terminal replay {field}"] = {
                "terminal-replay-result.json": result
            }
        wrong_disposition = copy.deepcopy(tombstone_result)
        wrong_disposition["terminal_disposition"] = "faulted"
        probes["tombstone replay disposition"] = {
            "tombstone-replay-result.json": wrong_disposition
        }
        unknown_member = copy.deepcopy(all_replay_result)
        unknown_member["members"][0]["event_id"] = "not-in-request"
        probes["all-replay member not in request"] = {
            "all-replay-batch-result.json": unknown_member
        }
        fabricated_member = copy.deepcopy(mixed_result)
        fabricated_member["members"][1]["event_id"] = "not-in-request"
        probes["mixed member not in request"] = {
            "mixed-replay-new-batch-result.json": fabricated_member
        }
        fabricated_sequence = copy.deepcopy(mixed_result)
        fabricated_sequence["members"][1]["acceptance_sequence"] = "999"
        probes["mixed acceptance sequence 999"] = {
            "mixed-replay-new-batch-result.json": fabricated_sequence
        }
        fabricated_queue_sequence = copy.deepcopy(mixed_result)
        fabricated_queue_sequence["members"][1]["queue_sequence"] = "999"
        probes["mixed queue sequence 999"] = {
            "mixed-replay-new-batch-result.json": fabricated_queue_sequence
        }
        mixed_zero_digest = copy.deepcopy(mixed_result)
        mixed_zero_digest["checkpoint"]["execution_checkpoint_digest"] = (
            "sha256:" + "0" * 64
        )
        probes["mixed embedded all-zero checkpoint digest"] = {
            "mixed-replay-new-batch-result.json": mixed_zero_digest
        }
        mixed_deferral = copy.deepcopy(mixed_result)
        mixed_checkpoint = mixed_deferral["checkpoint"]
        mixed_aggregate = mixed_checkpoint["root_record"]["aggregate_state"]
        mixed_event_id = mixed_deferral["members"][1]["event_id"]
        next(
            entry
            for runtime in mixed_aggregate["runtimes"]
            for entry in runtime["ready_mailbox"]
            if entry["envelope"]["event_id"] == mixed_event_id
        )["deferral_count"] = "99"
        mixed_aggregate.pop("aggregate_state_digest")
        mixed_aggregate["aggregate_state_digest"] = hash_value(
            ["determa-aggregate-state-digest-2", mixed_aggregate]
        )
        mixed_checkpoint.pop("execution_checkpoint_digest")
        mixed_checkpoint["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-2", mixed_checkpoint]
        )
        probes["mixed new member deferral count 99"] = {
            "mixed-replay-new-batch-result.json": mixed_deferral
        }
        mutated_legacy_inputs = copy.deepcopy(
            artifact("operation-inputs.json").document
        )
        mutated_legacy_inputs["legacy_terminal_replay"]["deliveries"][0][
            "request_digest_domain"
        ] = "determa-inbox-envelope-digest-2"
        probes["legacy replay digest domain substitution"] = {
            "operation-inputs.json": mutated_legacy_inputs
        }
        compacted_legacy_sequence = copy.deepcopy(compacted_legacy_result)
        compacted_legacy_sequence["acceptance_sequence"] = "999"
        probes["compacted legacy replay acceptance sequence 999"] = {
            "compacted-legacy-replay-result.json": compacted_legacy_sequence
        }
        tombstoned_batch_sequence = copy.deepcopy(tombstoned_batch_result)
        tombstoned_batch_sequence["members"][1]["evidence"][
            "acceptance_sequence"
        ] = "999"
        probes["tombstoned batch replay acceptance sequence 999"] = {
            "tombstoned-batch-replay-result.json": tombstoned_batch_sequence
        }
        tombstoned_batch_digest = copy.deepcopy(tombstoned_batch_result)
        tombstoned_batch_digest["checkpoint"]["execution_checkpoint_digest"] = (
            "sha256:" + "0" * 64
        )
        probes["tombstoned batch embedded checkpoint digest"] = {
            "tombstoned-batch-replay-result.json": tombstoned_batch_digest
        }
        tombstoned_batch_creation = copy.deepcopy(tombstoned_batch_result)
        embedded_checkpoint = tombstoned_batch_creation["checkpoint"]
        embedded_checkpoint["root_record"]["creation_id"] = "different-creation"
        embedded_checkpoint.pop("execution_checkpoint_digest")
        embedded_checkpoint["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-2", embedded_checkpoint]
        )
        probes["tombstoned batch embedded creation identity"] = {
            "tombstoned-batch-replay-result.json": tombstoned_batch_creation
        }
        fabricated_legacy_metadata = copy.deepcopy(
            artifact(
                "multi-pending-upgraded-with-metadata-checkpoint-v2.json"
            ).document
        )
        next(
            receipt
            for receipt in fabricated_legacy_metadata["operation_receipts"]
            if receipt["operation_kind"] == "acceptance"
        )["legacy_v1_delivery"]["envelope_digest"] = "sha256:" + ("0" * 64)
        fabricated_legacy_metadata.pop("execution_checkpoint_digest")
        fabricated_legacy_metadata["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-2", fabricated_legacy_metadata]
        )
        probes["fabricated legacy host acceptance metadata"] = {
            "multi-pending-upgraded-with-metadata-checkpoint-v2.json": (
                fabricated_legacy_metadata
            )
        }
        fabricated_processed_metadata = copy.deepcopy(
            artifact(
                "multi-pending-processed-with-metadata-checkpoint-v2.json"
            ).document
        )
        next(
            receipt
            for receipt in fabricated_processed_metadata["operation_receipts"]
            if receipt.get("operation_kind") == "acceptance"
            and receipt.get("event_id") == "delivery-unhandled"
        )["legacy_v1_delivery"]["envelope_digest"] = "sha256:" + ("0" * 64)
        fabricated_processed_metadata.pop("execution_checkpoint_digest")
        fabricated_processed_metadata["execution_checkpoint_digest"] = hash_value(
            [
                "determa-execution-checkpoint-digest-2",
                fabricated_processed_metadata,
            ]
        )
        probes["fabricated processed legacy host acceptance metadata"] = {
            "multi-pending-processed-with-metadata-checkpoint-v2.json": (
                fabricated_processed_metadata
            )
        }
        for probe_name, overrides in probes.items():
            try:
                validate_version2_vectors(
                    case,
                    test,
                    bundle_paths,
                    artifact_paths,
                    artifact_overrides=overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"{case.name}: adversarial probe was accepted: {probe_name}"
            )
        relabel_probes = (
            ("checkpoint_malformed_delivery_rejection", "invalid_delivery_mode"),
            ("checkpoint_invalid_delivery_mode_rejection", "malformed_delivery"),
            ("checkpoint_terminal_root_precedes_digest_validation", "delivery_digest_mismatch"),
            ("checkpoint_tombstoned_root_precedes_digest_validation", "terminal_root"),
            ("checkpoint_distinct_stale_writer", "tombstoned_root"),
            ("checkpoint_malformed_delivery_rejection", "checkpoint_revision_conflict"),
        )
        for vector_name, relabeled_code in relabel_probes:
            mutated_test = copy.deepcopy(test)
            mutated_vector = next(
                vector
                for vector in mutated_test["version2_vectors"]
                if vector["name"] == vector_name
            )
            mutated_vector["expect"]["code"] = relabeled_code
            try:
                validate_version2_vectors(
                    case,
                    mutated_test,
                    bundle_paths,
                    artifact_paths,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                continue
            raise ValidationFailure(
                f"{case.name}: adversarial expectation relabel was accepted: "
                f"{vector_name} as {relabeled_code}"
            )
    return coverage


def validate_vector_references(
    case: Path,
    test: dict[str, Any],
    bundle_paths: set[Path],
    artifact_paths: set[Path],
) -> None:
    artifact_names = {path.name for path in artifact_paths}
    bundle_names = {path.name for path in bundle_paths}
    artifact_kinds = {
        entry["file"]: entry["kind"] for entry in test["artifacts"]["documents"]
    }
    artifact_manifest = {
        entry["file"]: entry for entry in test["artifacts"]["documents"]
    }
    for entry in test["artifacts"]["documents"]:
        if entry["kind"] != "artifact_resolver" or not entry["valid"]:
            continue
        resolver = analyze_artifact(case / entry["file"]).document
        definition_keys = [
            definition["validated_bundle_fingerprint"]
            for definition in resolver["definitions"]
        ]
        descriptor_keys = [
            descriptor["migration_descriptor_digest"]
            for descriptor in resolver["migration_descriptors"]
        ]
        if len(definition_keys) != len(set(definition_keys)):
            raise ValidationFailure(
                f"{case.name}: resolver {entry['file']} repeats a definition key"
            )
        if len(descriptor_keys) != len(set(descriptor_keys)):
            raise ValidationFailure(
                f"{case.name}: resolver {entry['file']} repeats a descriptor key"
            )
        for definition in resolver["definitions"]:
            bundle_file = definition["bundle_file"]
            if bundle_file not in bundle_names:
                raise ValidationFailure(
                    f"{case.name}: resolver {entry['file']} references undeclared "
                    f"bundle {bundle_file}"
                )
        for descriptor in resolver["migration_descriptors"]:
            descriptor_file = descriptor["descriptor_file"]
            if (
                descriptor_file not in artifact_names
                or artifact_kinds[descriptor_file] != "migration_descriptor"
            ):
                raise ValidationFailure(
                    f"{case.name}: resolver {entry['file']} references undeclared "
                    f"migration descriptor {descriptor_file}"
                )
    for vector in test.get("persistence_vectors", []):
        input_artifact_kinds = {
            "aggregate_state": "aggregate_state",
            "aggregate_state_package": "aggregate_state_package",
            "migration_descriptor": "migration_descriptor",
            "input_envelope": "json_value",
            "resource_limits": "resource_limits",
            "artifact_resolver": "artifact_resolver",
        }
        for field, expected_kind in input_artifact_kinds.items():
            if field in vector and vector[field] not in artifact_names:
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} references undeclared "
                    f"artifact {vector[field]}"
                )
            if (
                field in vector
                and artifact_kinds[vector[field]] != expected_kind
            ):
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} {field} must name "
                    f"a {expected_kind} document"
                )
        for field in ("source_bundle", "target_bundle"):
            if field in vector and vector[field] not in bundle_names:
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} references undeclared "
                    f"bundle {vector[field]}"
                )
        for field in ("definitions",):
            for filename in vector.get(field, []):
                if filename not in bundle_names:
                    raise ValidationFailure(
                        f"{case.name}: vector {vector['name']} references undeclared "
                        f"bundle {filename}"
                    )
        for filename in vector.get("migration_descriptors", []):
            if filename not in artifact_names:
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} references undeclared "
                    f"descriptor {filename}"
                )
            if artifact_kinds[filename] != "migration_descriptor":
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} descriptor must name "
                    "a migration_descriptor document"
                )
        descriptor_error = vector["expect"].get("code")
        descriptor_decoder_errors = frozenset(
            ARTIFACT_FORMAT_FIELDS["migration_descriptor"][4:]
        )
        if vector["operation"] == "decode_selected_migration_descriptor":
            filename = vector["migration_descriptor"]
            manifest = artifact_manifest[filename]
            validate_direct_descriptor_expectation(
                f"{case.name}: vector {vector['name']} selected descriptor "
                f"{filename}",
                vector["expect"],
                manifest,
            )
        elif descriptor_error in descriptor_decoder_errors:
            declared_error_files = [
                filename
                for filename in vector.get("migration_descriptors", [])
                if not artifact_manifest[filename]["valid"]
                and artifact_manifest[filename].get("error") == descriptor_error
            ]
            if declared_error_files:
                request = vector.get("migration_request", vector)
                route = request.get("migration_route", [])
                descriptors_by_digest: dict[str, list[str]] = {}
                for filename in vector.get("migration_descriptors", []):
                    descriptor = analyze_artifact(case / filename).document
                    digest = (
                        descriptor.get("migration_descriptor_digest")
                        if isinstance(descriptor, dict)
                        else None
                    )
                    if isinstance(digest, str):
                        descriptors_by_digest.setdefault(digest, []).append(
                            filename
                        )
                selected_error_files: list[str] = []
                for digest in route:
                    filenames = descriptors_by_digest.get(digest, [])
                    if len(filenames) > 1:
                        raise ValidationFailure(
                            f"{case.name}: vector {vector['name']} ambiguously selects "
                            f"migration descriptor digest {digest}"
                        )
                    if len(filenames) == 1:
                        filename = filenames[0]
                        manifest = artifact_manifest[filename]
                        if (
                            not manifest["valid"]
                            and manifest.get("error") == descriptor_error
                        ):
                            selected_error_files.append(filename)
                if len(selected_error_files) != 1:
                    raise ValidationFailure(
                        f"{case.name}: vector {vector['name']} does not uniquely route "
                        f"to a descriptor declaring {descriptor_error}"
                    )
        expected_artifact_kinds = {
            "aggregate_state_file": "aggregate_state",
            "exact_bytes_file": "aggregate_state",
            "migration_audit_file": "json_value",
            "emissions_file": "json_value",
            "artifact_resolver_file": "artifact_resolver",
        }
        for field, expected_kind in expected_artifact_kinds.items():
            filename = vector["expect"].get(field)
            if filename is not None and filename not in artifact_names:
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} expectation references "
                    f"undeclared artifact {filename}"
                )
            if (
                filename is not None
                and artifact_kinds[filename] != expected_kind
            ):
                raise ValidationFailure(
                    f"{case.name}: vector {vector['name']} {field} must name "
                    f"a {expected_kind} document"
                )
    digest_bypasses = {
        entry["file"]
        for entry in test["artifacts"]["documents"]
        if entry.get("verify_digest") is False
    }
    for filename in digest_bypasses:
        users = [
            vector
            for vector in test["persistence_vectors"]
            if filename
            in {
                vector.get("aggregate_state"),
                vector.get("aggregate_state_package"),
                *vector.get("migration_descriptors", []),
            }
        ]
        if not users or any(
            vector["expect"]["result"] != "failure" for vector in users
        ):
            raise ValidationFailure(
                f"{case.name}: verify_digest false artifact {filename} must be used "
                "only by failure vectors"
            )


def validate_profile_references(
    case: Path,
    test: dict[str, Any],
    artifact_paths: set[Path],
) -> None:
    artifact_names = {path.name for path in artifact_paths}
    profile = test["persistence_profile"]
    references = [profile["initial_store"]]
    for step in profile["steps"]:
        references.extend(
            step[field]
            for field in ("input_envelope", "expect_store", "expect_call_log")
            if field in step
        )
    missing = sorted(set(references) - artifact_names)
    if missing:
        raise ValidationFailure(
            f"{case.name}: persistence profile references undeclared artifacts {missing}"
        )


def validate_execution_checkpoint_profile(
    case: Path,
    test: dict[str, Any],
    artifact_paths: set[Path],
    *,
    artifact_overrides: dict[str, Any] | None = None,
    run_mutation_probes: bool = True,
) -> tuple[set[str], int]:
    artifact_overrides = artifact_overrides or {}
    manifest = {entry["file"]: entry for entry in test["artifacts"]["documents"]}
    artifact_names = {path.name for path in artifact_paths}
    static_names = {
        entry["file"]
        for entry in test["static"]["documents"]
        if entry["valid"]
    }
    bundle_fingerprints: dict[str, str] = {}

    def validate_bundle_binding(
        value: dict[str, Any],
        *,
        file_field: str,
        source_digest_field: str,
        location: str,
    ) -> Path:
        filename = value[file_field]
        if filename not in static_names:
            raise ValidationFailure(
                f"{location}: bundle {filename} is not a valid declared document"
            )
        path = case / filename
        if value[source_digest_field] != hash_bytes(path.read_bytes()):
            raise ValidationFailure(
                f"{location}: bundle source digest does not match {filename}"
            )
        return path

    def bind_bundle_fingerprint(
        filename: str,
        claimed: str,
        authoritative: str | None,
        location: str,
    ) -> None:
        expected = authoritative or bundle_fingerprints.get(filename)
        if expected is not None and claimed != expected:
            raise ValidationFailure(
                f"{location}: validated bundle fingerprint is not bound to {filename}"
            )
        bundle_fingerprints.setdefault(filename, claimed)

    def validate_descriptor_route(
        operation_input: dict[str, Any],
        location: str,
    ) -> None:
        files = operation_input["migration_descriptor_files"]
        route = operation_input["migration_descriptor_digest_route"]
        if len(files) != len(route):
            raise ValidationFailure(
                f"{location}: migration descriptor files and route differ"
            )
        for filename, digest in zip(files, route, strict=True):
            entry = manifest.get(filename)
            if (
                entry is None
                or entry["kind"] != "migration_descriptor"
                or not entry["valid"]
            ):
                raise ValidationFailure(
                    f"{location}: undeclared migration descriptor {filename}"
                )
            descriptor = analyze_artifact(case / filename).document
            if descriptor["migration_descriptor_digest"] != digest:
                raise ValidationFailure(
                    f"{location}: migration descriptor route is not exact"
                )
        if (
            descriptor["target_validated_bundle_fingerprint"]
            != operation_input["target_validated_bundle_fingerprint"]
        ):
            raise ValidationFailure(
                f"{location}: migration target bundle and route are not bound"
            )

    def checkpoint(
        filename: str | None,
        location: str,
    ) -> tuple[dict[str, Any], bytes] | None:
        if filename is None:
            return None
        if filename not in artifact_names:
            raise ValidationFailure(f"{location}: undeclared checkpoint {filename}")
        entry = manifest[filename]
        if entry["kind"] != "execution_checkpoint" or not entry["valid"]:
            raise ValidationFailure(
                f"{location}: {filename} must be a valid execution checkpoint"
            )
        analysis = analyze_artifact(case / filename)
        return analysis.document, analysis.source

    def resolve_ref(
        reference: dict[str, str],
        location: str,
        expected_kind: str,
    ) -> Any:
        filename = reference["file"]
        if filename not in artifact_names:
            raise ValidationFailure(f"{location}: undeclared artifact {filename}")
        entry = manifest[filename]
        if entry["kind"] != expected_kind or not entry["valid"]:
            raise ValidationFailure(
                f"{location}: {filename} must be a valid {expected_kind}"
            )
        value = artifact_overrides.get(
            filename,
            analyze_artifact(case / filename).document,
        )
        for raw_part in reference["pointer"].split("/")[1:]:
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict) and part in value:
                value = value[part]
            elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                value = value[int(part)]
            else:
                raise ValidationFailure(
                    f"{location}: unresolved JSON pointer {reference['pointer']}"
                )
        return value

    input_operations = {
        "create": "create",
        "accept_delivery": "delivery",
        "process_pending_delivery": "delivery",
        "foreground_process_delivery": "delivery",
        "maintenance_migration": "maintenance_migration",
        "update_pending_outbox": "update_pending_outbox",
        "terminalize_outbox": "terminalize_outbox",
        "compact_outbox": "compact_outbox",
        "delete_outbox_record": "delete_outbox_record",
        "update_replay_retention": "update_replay_retention",
        "tombstone_root": "tombstone_root",
        "delete_checkpoint": "delete_checkpoint",
    }
    result_unions = {
        operation: set(outcomes)
        for operation, outcomes in EXECUTION_CHECKPOINT_OPERATION_OUTCOMES.items()
    }
    core_call_unions = {
        "create": {"none", "create"},
        "accept_delivery": {"none"},
        "process_pending_delivery": {"none", "dispatch"},
        "foreground_process_delivery": {"none", "dispatch"},
        "maintenance_migration": {"none", "migrate"},
        "update_pending_outbox": {"none"},
        "terminalize_outbox": {"none"},
        "compact_outbox": {"none"},
        "delete_outbox_record": {"none"},
        "update_replay_retention": {"none"},
        "tombstone_root": {"none"},
        "delete_checkpoint": {"none"},
        "inject_execution_store": {"none"},
        "register_adapter": {"none"},
        "resolve_adapter": {"none"},
        "validate_host_profile": {"none"},
    }

    def validate_input_shape(
        operation: str, value: Any, location: str
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValidationFailure(f"{location}: operation input must be an object")
        expected_operation = input_operations[operation]
        if value.get("operation") != expected_operation:
            raise ValidationFailure(
                f"{location}: input operation is not {expected_operation}"
            )
        cas = {"expected_revision", "expected_checkpoint_digest"}
        if expected_operation == "create":
            required = {
                "operation",
                "bundle_file",
                "bundle_source_digest",
                "validated_bundle_fingerprint",
                "namespace",
                "machine_id",
                "machine_version",
                "root_instance_id",
                "creation_id",
                "bindings",
                "request_digest",
            }
            allowed = required | cas
        elif expected_operation == "delivery":
            if "candidate" in value:
                required = {"operation", "candidate"} | cas
                allowed = required
            else:
                required = {
                    "operation",
                    "root_instance_id",
                    "delivery_mode",
                    "origin",
                    "envelope",
                    "envelope_digest",
                } | cas
                allowed = required | {"dispatch_input"}
        elif expected_operation == "maintenance_migration":
            required = {
                "operation",
                "operation_id",
                "source_aggregate_state_digest",
                "target_bundle_file",
                "target_bundle_source_digest",
                "migration_descriptor_files",
                "target_validated_bundle_fingerprint",
                "migration_descriptor_digest_route",
                "maintenance_mode",
                "request_digest",
            } | cas
            allowed = required
        elif expected_operation == "update_pending_outbox":
            required = {
                "operation",
                "effect_id",
                "desired_pending_state",
            } | cas
            allowed = required
        elif expected_operation == "terminalize_outbox":
            required = {"operation", "effect_id", "terminal_outcome"} | cas
            allowed = required
        elif expected_operation in {"compact_outbox", "delete_outbox_record"}:
            required = {"operation", "effect_id"} | cas
            allowed = required
        elif expected_operation == "update_replay_retention":
            required = {"operation", "target_replay_retention"} | cas
            allowed = required
        elif expected_operation == "tombstone_root":
            required = {"operation", "operation_id"} | cas
            allowed = required
        else:
            required = {"operation"} | cas
            allowed = required
        if not required.issubset(value) or set(value) - allowed:
            raise ValidationFailure(
                f"{location}: input fields do not match {expected_operation}"
            )
        return value

    def aggregate_digest(checkpoint_document: dict[str, Any]) -> str:
        root = checkpoint_document["root_record"]
        if root["status"] != "retained":
            raise ValidationFailure("core operation cannot use a root tombstone")
        return root["aggregate_state"]["aggregate_state_digest"]

    def validate_emissions(
        core_result: dict[str, Any],
        receipt: dict[str, Any],
        after_document: dict[str, Any],
        location: str,
    ) -> None:
        emissions = core_result["emissions"]
        references = receipt["emission_references"]
        if len(emissions) != len(references):
            raise ValidationFailure(
                f"{location}: core emissions and receipt references differ"
            )
        for index, (emission, reference) in enumerate(
            zip(emissions, references, strict=True)
        ):
            if reference["emission_index"] != str(index):
                raise ValidationFailure(f"{location}: emission index drift")
            if emission["kind"] == "internal":
                if (
                    reference["kind"] != "internal_delivery"
                    or reference["event_id"] != emission["event_id"]
                ):
                    raise ValidationFailure(
                        f"{location}: internal core emission linkage drift"
                    )
                pending = next(
                    (
                        item
                        for item in after_document["pending_deliveries"]
                        if item["delivery_sequence"]
                        == reference["delivery_sequence"]
                    ),
                    None,
                )
                if pending is None or pending["envelope"] != {
                    key: emission[key]
                    for key in emission
                    if key not in {"kind"}
                }:
                    raise ValidationFailure(
                        f"{location}: internal core emission was not retained"
                    )
            else:
                if (
                    reference["kind"] != "external_outbox"
                    or reference["effect_id"] != emission["effect_id"]
                ):
                    raise ValidationFailure(
                        f"{location}: external core emission linkage drift"
                    )
                intents = [
                    item["intent"]
                    for item in after_document["pending_outbox_intents"]
                ] + [
                    item["intent"]
                    for item in after_document["terminal_outbox_records"]
                ]
                intent = next(
                    (
                        item
                        for item in intents
                        if item["effect_id"] == emission["effect_id"]
                    ),
                    None,
                )
                expected_intent = {
                    key: emission[key]
                    for key in (
                        "effect_id",
                        "sequence",
                        "event",
                        "payload",
                        "correlation_id",
                    )
                }
                if intent != expected_intent:
                    raise ValidationFailure(
                        f"{location}: external core emission intent drift"
                    )

    def validate_coverage_claim(
        label: str,
        vector: dict[str, Any],
        operation_input: dict[str, Any] | None,
        before_document: dict[str, Any] | None,
        after_document: dict[str, Any] | None,
        core_result: dict[str, Any] | None,
        receipt: dict[str, Any] | None,
        location: str,
    ) -> None:
        (
            operation,
            result,
            code,
            mutation,
            core_call,
            failure_boundary,
            predicate,
        ) = EXECUTION_CHECKPOINT_COVERAGE_RULES[label]
        actual = (
            vector["operation"],
            vector["expect"]["result"],
            vector["expect"].get("code"),
            vector["expect"]["checkpoint_mutation"],
            vector["expect"]["core_call"],
            vector.get("failure_boundary"),
        )
        expected = (
            operation,
            result,
            code,
            mutation,
            core_call,
            failure_boundary,
        )
        if actual != expected:
            raise ValidationFailure(
                f"{location}: coverage {label} does not match behavior"
            )

        advertised = set(vector.get("advertised_capabilities", []))
        requested = set(vector.get("requested_capabilities", []))
        features = set(vector.get("host_features", []))
        profile = vector.get("host_profile")

        def require(condition: bool) -> None:
            if not condition:
                raise ValidationFailure(
                    f"{location}: coverage {label} relational predicate failed"
                )

        if predicate == "creation":
            require(
                operation_input is not None
                and "request_digest" in operation_input
            )
        elif predicate == "creation_conflict":
            require(
                operation_input is not None
                and before_document is not None
                and operation_input["root_instance_id"]
                == before_document["root_instance_id"]
                and operation_input["creation_id"]
                != before_document["operation_receipts"][0]["creation_id"]
            )
        elif predicate == "creation_rejection":
            require(
                before_document is None
                and after_document is None
                and core_result is not None
                and core_result["aggregate_state"] is None
            )
        elif predicate == "pending_acceptance":
            require(
                operation_input is not None
                and after_document is not None
                and any(
                    item["envelope"]["event_id"]
                    == operation_input["envelope"]["event_id"]
                    for item in after_document["pending_deliveries"]
                )
            )
        elif predicate == "input_processing":
            require(
                operation_input is not None
                and operation_input["delivery_mode"] == "input"
                and before_document is not None
                and any(
                    item["envelope"]["event_id"]
                    == operation_input["envelope"]["event_id"]
                    for item in before_document["pending_deliveries"]
                )
            )
        elif predicate == "foreground":
            require(
                operation_input is not None
                and operation_input["delivery_mode"] == "input"
                and receipt is not None
                and receipt["accepted_revision"]
                == receipt["committed_revision"]
            )
        elif predicate == "receipt_replay":
            require(
                operation_input is not None
                and receipt is not None
                and receipt["event_id"]
                == operation_input["envelope"]["event_id"]
            )
        elif predicate in {"revision", "rollback", "response_loss"}:
            require(before_document is not None and after_document is not None)
        elif predicate in {
            "rejected_receipt",
            "faulted_receipt",
            "unhandled_receipt",
        }:
            expected_disposition = predicate.removesuffix("_receipt")
            require(
                receipt is not None
                and receipt["outcome"]["disposition"] == expected_disposition
            )
        elif predicate == "internal_processing":
            require(
                operation_input is not None
                and operation_input["delivery_mode"] == "internal"
            )
        elif predicate == "stale_cas":
            require(
                operation_input is not None
                and before_document is not None
                and (
                    operation_input["expected_revision"]
                    != before_document["revision"]
                    or operation_input["expected_checkpoint_digest"]
                    != before_document["execution_checkpoint_digest"]
                )
            )
        elif predicate == "internal_pending":
            require(
                after_document is not None
                and any(
                    item["delivery_mode"] == "internal"
                    for item in after_document["pending_deliveries"]
                )
            )
        elif predicate == "migration":
            require(
                core_result is not None
                and bool(core_result["audit_records"])
                and receipt is not None
                and bool(receipt["migration_sequences"])
            )
        elif predicate == "migration_replay":
            require(
                operation_input is not None
                and after_document is not None
                and any(
                    item.get("operation_id") == operation_input["operation_id"]
                    and item["request_digest"]
                    == operation_input["request_digest"]
                    for item in after_document["operation_receipts"]
                )
            )
        elif predicate == "migration_conflict":
            require(
                operation_input is not None
                and before_document is not None
                and any(
                    item.get("operation_id") == operation_input["operation_id"]
                    and item["request_digest"]
                    != operation_input["request_digest"]
                    for item in before_document["operation_receipts"]
                )
            )
        elif predicate == "malformed":
            require(
                operation_input is not None
                and operation_input.get("candidate") is None
                and set(operation_input)
                == {
                    "operation",
                    "candidate",
                    "expected_revision",
                    "expected_checkpoint_digest",
                }
            )
        elif predicate == "wrong_root":
            require(
                operation_input is not None
                and before_document is not None
                and operation_input["root_instance_id"]
                != before_document["root_instance_id"]
            )
        elif predicate == "invalid_mode":
            require(
                operation_input is not None
                and before_document is not None
                and operation_input["delivery_mode"] not in {"input", "internal"}
                and operation_input["envelope_digest"]
                == hash_value(
                    [
                        "determa-inbox-envelope-digest-1",
                        "1",
                        operation_input["root_instance_id"],
                        operation_input["delivery_mode"],
                        operation_input["envelope"],
                    ]
                )
                and all(
                    item.get("event_id")
                    != operation_input["envelope"]["event_id"]
                    for item in before_document["operation_receipts"]
                )
                and all(
                    item["envelope"]["event_id"]
                    != operation_input["envelope"]["event_id"]
                    for item in before_document["pending_deliveries"]
                )
            )
        elif predicate == "invalid_origin":
            require(
                operation_input is not None
                and before_document is not None
                and operation_input["origin"].get("kind") == "invalid"
                and operation_input["envelope_digest"]
                == hash_value(
                    [
                        "determa-inbox-envelope-digest-1",
                        "1",
                        operation_input["root_instance_id"],
                        operation_input["delivery_mode"],
                        operation_input["envelope"],
                    ]
                )
                and all(
                    item.get("event_id")
                    != operation_input["envelope"]["event_id"]
                    for item in before_document["operation_receipts"]
                )
                and all(
                    item["envelope"]["event_id"]
                    != operation_input["envelope"]["event_id"]
                    for item in before_document["pending_deliveries"]
                )
            )
        elif predicate == "replay_conflict_before_mode":
            require(
                operation_input is not None
                and before_document is not None
                and operation_input["delivery_mode"] not in {"input", "internal"}
                and operation_input["envelope_digest"]
                == hash_value(
                    [
                        "determa-inbox-envelope-digest-1",
                        "1",
                        operation_input["root_instance_id"],
                        operation_input["delivery_mode"],
                        operation_input["envelope"],
                    ]
                )
                and any(
                    item.get("event_id")
                    == operation_input["envelope"]["event_id"]
                    and item["request_digest"]
                    != operation_input["envelope_digest"]
                    for item in before_document["operation_receipts"]
                )
            )
        elif predicate == "replay_receipt_before_origin":
            require(
                operation_input is not None
                and before_document is not None
                and receipt is not None
                and operation_input["origin"].get("kind") == "invalid"
                and receipt.get("event_id")
                == operation_input["envelope"]["event_id"]
                and receipt["request_digest"]
                == operation_input["envelope_digest"]
            )
        elif predicate == "digest_mismatch":
            require(
                operation_input is not None
                and operation_input["envelope_digest"]
                != hash_value(
                    [
                        "determa-inbox-envelope-digest-1",
                        "1",
                        operation_input["root_instance_id"],
                        operation_input["delivery_mode"],
                        operation_input["envelope"],
                    ]
                )
            )
        elif predicate == "event_conflict":
            require(
                operation_input is not None
                and before_document is not None
                and any(
                    item.get("event_id")
                    == operation_input["envelope"]["event_id"]
                    and item["request_digest"]
                    != operation_input["envelope_digest"]
                    for item in before_document["operation_receipts"]
                )
            )
        elif predicate == "tombstoned_root":
            require(
                before_document is not None
                and before_document["root_record"]["status"] == "tombstone"
            )
        elif predicate == "tombstone":
            require(
                after_document is not None
                and after_document["root_record"]["status"] == "tombstone"
            )
        elif predicate == "permanent_retention":
            require(
                after_document is not None
                and after_document["replay_retention"]["mode"] == "permanent"
            )
        elif predicate == "bounded_retention":
            require(
                operation_input is not None
                and operation_input["target_replay_retention"]["mode"] == "bounded"
                and after_document is not None
                and after_document["replay_retention"]["mode"] == "bounded"
            )
        elif predicate == "dependency_pruning":
            require(
                operation_input is not None
                and operation_input["target_replay_retention"]["mode"] == "bounded"
            )
        elif predicate == "reverse_retention":
            require(
                operation_input is not None
                and before_document is not None
                and before_document["replay_retention"]["mode"] == "bounded"
                and operation_input["target_replay_retention"]["mode"] == "permanent"
            )
        elif predicate == "outbox_not_attempted":
            require(
                after_document is not None
                and any(
                    item["delivery_state"]["status"] == "not_attempted"
                    for item in after_document["pending_outbox_intents"]
                )
            )
        elif predicate in {"pending_retryable", "pending_ambiguous"}:
            expected_status = {
                "pending_retryable": "retryable_failure",
                "pending_ambiguous": "ambiguous",
            }[predicate]
            require(
                operation_input is not None
                and operation_input["desired_pending_state"]["status"]
                == expected_status
            )
        elif predicate.startswith("terminal_"):
            require(
                operation_input is not None
                and operation_input["terminal_outcome"]["status"]
                == predicate.removeprefix("terminal_")
            )
        elif predicate == "compact":
            require(
                operation_input is not None
                and after_document is not None
                and any(
                    item["effect_id"] == operation_input["effect_id"]
                    for item in after_document["outbox_effect_tombstones"]
                )
            )
        elif predicate == "effect_conflict":
            require(operation_input is not None and before_document is not None)
        elif predicate == "referenced_effect":
            require(
                operation_input is not None
                and before_document is not None
                and any(
                    emission.get("effect_id") == operation_input["effect_id"]
                    for item in before_document["operation_receipts"]
                    for emission in item.get("emission_references", [])
                )
            )
        elif predicate == "outbox_linkage":
            require(
                receipt is not None
                and any(
                    item["kind"] == "external_outbox"
                    for item in receipt["emission_references"]
                )
            )
        elif predicate == "direct_injection":
            require("adapter_identifier" not in vector)
        elif predicate == "public_registry":
            require(vector["registration_route"] == "public")
        elif predicate == "invalid_configuration":
            require(not vector["configuration_valid"])
        elif predicate == "capability_mismatch":
            require(
                vector["configuration_valid"]
                and not requested.issubset(advertised)
            )
        elif predicate in {"memory", "file", "sqlite", "postgresql"}:
            require(vector["adapter_identifier"] == predicate)
        elif predicate == "bundled_public":
            require(
                vector["registration_source"] == "bundled"
                and vector["registration_route"] == "public"
            )
        elif predicate == "third_party_public":
            require(
                vector["registration_source"] == "third_party"
                and vector["registration_route"] == "public"
            )
        elif predicate == "root_identity_profile":
            require(
                profile == "strict_durable_outbox"
                and "root_identity_retention" in advertised
            )
        elif predicate == "strict_complete":
            require(
                profile == "strict_durable_outbox"
                and "permanent_outbox_terminal_retention" in advertised
                and {
                    "outbox_worker",
                    "total_outbox_lifecycle",
                    "retain_unresolved_outbox",
                }.issubset(features)
            )
        elif predicate == "compact_complete":
            require(
                profile == "compact_durable_outbox"
                and "compact_effect_identity_retention" in advertised
                and {
                    "outbox_worker",
                    "total_outbox_lifecycle",
                    "retain_referenced_effect_tombstones",
                }.issubset(features)
            )
        elif predicate == "durable_complete":
            require(
                profile == "durable_embedded_processing"
                and bool(
                    advertised & {"durable_single_writer", "durable_concurrent"}
                )
                and "atomic_checkpoint_processing" in features
            )
        elif predicate == "exactly_once_complete":
            require(
                profile == "exactly_once_committed_processing"
                and "permanent_receipt_retention" in advertised
                and vector["checkpoint_retention_mode"] == "permanent"
            )
        elif predicate == "broker_complete":
            require(
                profile == "broker_integrated"
                and {
                    "acknowledge_after_checkpoint_commit",
                    "durable_redelivery",
                    "outbox_worker",
                }.issubset(features)
            )
        elif predicate == "shared_complete":
            require(
                profile == "shared_application_transaction"
                and "shared_application_transaction" in advertised
                and "native_shared_application_transaction" in features
            )
        elif predicate == "missing_durable":
            require(
                profile == "durable_embedded_processing"
                and not advertised
                & {"durable_single_writer", "durable_concurrent"}
            )
        elif predicate == "missing_root_identity":
            require(
                profile == "durable_embedded_processing"
                and "root_identity_retention" not in advertised
            )
        elif predicate == "missing_atomic":
            require(
                profile == "durable_embedded_processing"
                and "atomic_checkpoint_processing" not in features
            )
        elif predicate == "missing_receipt_retention":
            require(
                profile == "exactly_once_committed_processing"
                and "permanent_receipt_retention" not in advertised
            )
        elif predicate == "bounded_exactly_once":
            require(
                profile == "exactly_once_committed_processing"
                and vector["checkpoint_retention_mode"] == "bounded"
            )
        elif predicate == "missing_redelivery":
            require(
                profile == "broker_integrated"
                and "durable_redelivery" not in features
            )
        elif predicate == "missing_ack":
            require(
                profile == "broker_integrated"
                and "acknowledge_after_checkpoint_commit" not in features
            )
        elif predicate == "missing_worker":
            expected_profile = {
                "broker_profile_missing_outbox_worker": "broker_integrated",
                "strict_outbox_missing_worker": "strict_durable_outbox",
                "compact_outbox_missing_worker": "compact_durable_outbox",
            }[label]
            require(
                profile == expected_profile and "outbox_worker" not in features
            )
        elif predicate == "missing_terminal_retention":
            require(
                profile == "strict_durable_outbox"
                and "permanent_outbox_terminal_retention" not in advertised
            )
        elif predicate == "missing_total_lifecycle":
            expected_profile = {
                "strict_outbox_missing_total_lifecycle": "strict_durable_outbox",
                "compact_outbox_missing_total_lifecycle": "compact_durable_outbox",
            }[label]
            require(
                profile == expected_profile
                and "total_outbox_lifecycle" not in features
            )
        elif predicate == "missing_unresolved":
            require(
                profile == "strict_durable_outbox"
                and "retain_unresolved_outbox" not in features
            )
        elif predicate == "missing_compact_retention":
            require(
                profile == "compact_durable_outbox"
                and "compact_effect_identity_retention" not in advertised
            )
        elif predicate == "missing_reference_retention":
            require(
                profile == "compact_durable_outbox"
                and "retain_referenced_effect_tombstones" not in features
            )
        elif predicate == "missing_native":
            require(
                profile == "shared_application_transaction"
                and "native_shared_application_transaction" not in features
            )
        elif predicate == "missing_shared_capability":
            require(
                profile == "shared_application_transaction"
                and "shared_application_transaction" not in advertised
            )
        else:
            raise ValidationFailure(
                f"{location}: unknown coverage predicate {predicate}"
            )

    for entry in test["artifacts"]["documents"]:
        if entry.get("semantic_probe") != "compact_intent_digest":
            continue
        required_probe_fields = {
            "semantic_source",
            "semantic_expected",
            "semantic_input_file",
            "semantic_input_pointer",
        }
        if not required_probe_fields.issubset(entry):
            raise ValidationFailure(
                f"{case.name}: incomplete compact intent semantic probe"
            )
        candidate = analyze_artifact(case / entry["file"]).document
        source = checkpoint(entry["semantic_source"], case.name)[0]
        expected = checkpoint(entry["semantic_expected"], case.name)[0]
        request = resolve_ref(
            {
                "file": entry["semantic_input_file"],
                "pointer": entry["semantic_input_pointer"],
            },
            case.name,
            "execution_checkpoint_inputs",
        )
        effect_id = request["effect_id"]
        source_record = next(
            item
            for item in source["terminal_outbox_records"]
            if item["intent"]["effect_id"] == effect_id
        )
        tombstone = next(
            item
            for item in candidate["outbox_effect_tombstones"]
            if item["effect_id"] == effect_id
        )
        correct_digest = hash_value(
            [
                "determa-outbox-intent-digest-1",
                "1",
                source["root_instance_id"],
                source_record["intent"],
            ]
        )
        if tombstone["intent_digest"] == correct_digest:
            raise ValidationFailure(
                f"{entry['file']}: compact intent digest probe is not negative"
            )
        repaired = copy.deepcopy(candidate)
        repaired_tombstone = next(
            item
            for item in repaired["outbox_effect_tombstones"]
            if item["effect_id"] == effect_id
        )
        repaired_tombstone["intent_digest"] = correct_digest
        without_digest = dict(repaired)
        without_digest.pop("execution_checkpoint_digest")
        repaired["execution_checkpoint_digest"] = hash_value(
            ["determa-execution-checkpoint-digest-1", without_digest]
        )
        if repaired != expected:
            raise ValidationFailure(
                f"{entry['file']}: probe differs beyond compact intent digest"
            )

    names: set[str] = set()
    coverage: set[str] = set()
    all_vectors = test["execution_checkpoint_profile"]["vectors"]
    scope_vectors = [
        vector for vector in all_vectors if "scope_selection" in vector
    ]
    vectors = [
        vector for vector in all_vectors if "scope_selection" not in vector
    ]
    for filename, entry in manifest.items():
        if entry["kind"] != "execution_checkpoint_core_evidence":
            continue
        evidence = analyze_artifact(case / filename).document
        for call_name, core_evidence in evidence["calls"].items():
            evidence_location = f"{case.name} core evidence {call_name}"
            evidence_input = resolve_ref(
                {
                    "file": core_evidence["operation_input_file"],
                    "pointer": core_evidence["operation_input_pointer"],
                },
                evidence_location,
                "execution_checkpoint_inputs",
            )
            expected_operation = {
                "create": "create",
                "dispatch": "delivery",
                "migrate": "maintenance_migration",
            }[core_evidence["core_operation"]]
            if evidence_input["operation"] != expected_operation:
                raise ValidationFailure(
                    f"{evidence_location}: core operation and input differ"
                )
            expected_digest = hash_value(
                [
                    "determa-conformance-execution-checkpoint-operation-input-1",
                    evidence_input,
                ]
            )
            if core_evidence["operation_input_digest"] != expected_digest:
                raise ValidationFailure(
                    f"{evidence_location}: operation-input digest is not exact"
                )
            if core_evidence["core_operation"] == "create":
                validate_bundle_binding(
                    evidence_input,
                    file_field="bundle_file",
                    source_digest_field="bundle_source_digest",
                    location=evidence_location,
                )
                request_digest = hash_value(
                    [
                        "determa-creation-request-digest-1",
                        "1",
                        evidence_input["validated_bundle_fingerprint"],
                        evidence_input["namespace"],
                        evidence_input["machine_id"],
                        evidence_input["machine_version"],
                        evidence_input["root_instance_id"],
                        evidence_input["creation_id"],
                        encode_typed_value(evidence_input["bindings"]),
                    ]
                )
                if evidence_input["request_digest"] != request_digest:
                    raise ValidationFailure(
                        f"{evidence_location}: create request digest is not exact"
                    )
                aggregate = core_evidence["aggregate_state"]
                bind_bundle_fingerprint(
                    evidence_input["bundle_file"],
                    evidence_input["validated_bundle_fingerprint"],
                    (
                        aggregate["validated_bundle_fingerprint"]
                        if aggregate is not None
                        else None
                    ),
                    evidence_location,
                )
                if aggregate is not None and (
                    aggregate["namespace"] != evidence_input["namespace"]
                    or aggregate["root_machine_id"]
                    != evidence_input["machine_id"]
                    or aggregate["root_machine_version"]
                    != evidence_input["machine_version"]
                    or aggregate["root_instance_id"]
                    != evidence_input["root_instance_id"]
                    or aggregate["creation_id"]
                    != evidence_input["creation_id"]
                ):
                    raise ValidationFailure(
                        f"{evidence_location}: create projection identity drift"
                    )
    for index, vector in enumerate(vectors):
        location = f"{case.name} vector {index} ({vector['name']})"
        if vector["name"] in names:
            raise ValidationFailure(f"{case.name}: duplicate vector {vector['name']}")
        names.add(vector["name"])
        duplicate_coverage = coverage & set(vector["covers"])
        if duplicate_coverage:
            raise ValidationFailure(
                f"{location}: duplicate coverage {sorted(duplicate_coverage)}"
            )
        coverage.update(vector["covers"])

        before = checkpoint(vector["checkpoint_before"], location)
        expectation = vector["expect"]
        after = checkpoint(expectation["checkpoint_after"], location)
        operation = vector["operation"]
        result = expectation["result"]
        core_call = expectation["core_call"]
        if result not in result_unions[operation]:
            raise ValidationFailure(
                f"{location}: {result} is not a result of {operation}"
            )
        code = expectation.get("code")
        if code not in EXECUTION_CHECKPOINT_OPERATION_OUTCOMES[operation][result]:
            raise ValidationFailure(
                f"{location}: {code!r} is not a code for {operation}/{result}"
            )
        if core_call not in core_call_unions[operation]:
            raise ValidationFailure(
                f"{location}: {core_call} is not a core call of {operation}"
            )
        operation_input = None
        if operation in input_operations:
            operation_input = validate_input_shape(
                operation,
                resolve_ref(
                    vector["input"],
                    location,
                    "execution_checkpoint_inputs",
                ),
                location,
            )
        core_result = (
            resolve_ref(
                vector["core_result"],
                location,
                "execution_checkpoint_core_evidence",
            )
            if "core_result" in vector
            else None
        )
        if core_call == "none" and core_result is not None:
            raise ValidationFailure(f"{location}: no-core operation has a core result")
        if core_call != "none" and not isinstance(core_result, dict):
            raise ValidationFailure(f"{location}: core call lacks an exact result")
        if operation_input is not None:
            if operation == "create":
                validate_bundle_binding(
                    operation_input,
                    file_field="bundle_file",
                    source_digest_field="bundle_source_digest",
                    location=location,
                )
                expected_request_digest = hash_value(
                    [
                        "determa-creation-request-digest-1",
                        "1",
                        operation_input["validated_bundle_fingerprint"],
                        operation_input["namespace"],
                        operation_input["machine_id"],
                        operation_input["machine_version"],
                        operation_input["root_instance_id"],
                        operation_input["creation_id"],
                        encode_typed_value(operation_input["bindings"]),
                    ]
                )
                if operation_input["request_digest"] != expected_request_digest:
                    raise ValidationFailure(
                        f"{location}: creation request digest is not exact"
                    )
            elif operation == "maintenance_migration":
                validate_bundle_binding(
                    operation_input,
                    file_field="target_bundle_file",
                    source_digest_field="target_bundle_source_digest",
                    location=location,
                )
                validate_descriptor_route(operation_input, location)
                expected_request_digest = hash_value(
                    [
                        "determa-maintenance-migration-request-digest-1",
                        "1",
                        (
                            before[0]["root_instance_id"]
                            if before is not None
                            else ""
                        ),
                        operation_input["operation_id"],
                        operation_input["source_aggregate_state_digest"],
                        operation_input["target_validated_bundle_fingerprint"],
                        operation_input["migration_descriptor_digest_route"],
                        operation_input["maintenance_mode"],
                    ]
                )
                if operation_input["request_digest"] != expected_request_digest:
                    raise ValidationFailure(
                        f"{location}: migration request digest is not exact"
                    )
            if core_result is not None:
                if (
                    core_result["operation_input_file"]
                    != vector["input"]["file"]
                    or core_result["operation_input_pointer"]
                    != vector["input"]["pointer"]
                ):
                    raise ValidationFailure(
                        f"{location}: core evidence cites a different input"
                    )
                expected_input_digest = hash_value(
                    [
                        (
                            "determa-conformance-execution-checkpoint-"
                            "operation-input-1"
                        ),
                        operation_input,
                    ]
                )
                if (
                    core_result["core_operation"] != core_call
                    or core_result["operation_input_digest"]
                    != expected_input_digest
                ):
                    raise ValidationFailure(
                        f"{location}: core evidence is not bound to its exact input"
                    )
            if operation == "create":
                aggregate = (
                    core_result.get("aggregate_state")
                    if core_result is not None
                    else None
                )
                if aggregate is not None:
                    bind_bundle_fingerprint(
                        operation_input["bundle_file"],
                        operation_input["validated_bundle_fingerprint"],
                        aggregate["validated_bundle_fingerprint"],
                        location,
                    )
                    if (
                        aggregate["namespace"] != operation_input["namespace"]
                        or aggregate["root_machine_id"]
                        != operation_input["machine_id"]
                        or aggregate["root_machine_version"]
                        != operation_input["machine_version"]
                        or aggregate["root_instance_id"]
                        != operation_input["root_instance_id"]
                        or aggregate["creation_id"]
                        != operation_input["creation_id"]
                    ):
                        raise ValidationFailure(
                            f"{location}: create result is not bound to its request"
                        )
                else:
                    bind_bundle_fingerprint(
                        operation_input["bundle_file"],
                        operation_input["validated_bundle_fingerprint"],
                        None,
                        location,
                    )
            elif core_call == "dispatch":
                assert before is not None
                dispatch_input = operation_input.get("dispatch_input")
                if not isinstance(dispatch_input, dict):
                    raise ValidationFailure(
                        f"{location}: dispatch core call lacks dispatch_input"
                    )
                validate_bundle_binding(
                    dispatch_input,
                    file_field="bundle_file",
                    source_digest_field="bundle_source_digest",
                    location=location,
                )
                prior_aggregate = before[0]["root_record"]["aggregate_state"]
                bind_bundle_fingerprint(
                    dispatch_input["bundle_file"],
                    dispatch_input["validated_bundle_fingerprint"],
                    prior_aggregate["validated_bundle_fingerprint"],
                    location,
                )
                mode = operation_input["delivery_mode"]
                delivery = dispatch_input["delivery"]
                if set(delivery) != {mode}:
                    raise ValidationFailure(
                        f"{location}: dispatch mode differs from presented delivery"
                    )
                native = delivery[mode]
                envelope = operation_input["envelope"]
                expected_native = {
                    "event": envelope["event"],
                    "event_id": envelope["event_id"],
                    "target": envelope["target"],
                    "payload": decode_typed_value(envelope["payload"]),
                }
                if "correlation_id" in envelope:
                    expected_native["correlation_id"] = envelope["correlation_id"]
                if native != expected_native:
                    raise ValidationFailure(
                        f"{location}: dispatch_input differs from presented envelope"
                    )
            elif operation == "maintenance_migration" and core_result is not None:
                aggregate = core_result["aggregate_state"]
                bind_bundle_fingerprint(
                    operation_input["target_bundle_file"],
                    operation_input["target_validated_bundle_fingerprint"],
                    aggregate["validated_bundle_fingerprint"],
                    location,
                )

        mutation = expectation["checkpoint_mutation"]
        if mutation == "absent":
            if before is not None or after is not None:
                raise ValidationFailure(
                    f"{location}: absent mutation needs no checkpoint"
                )
        elif mutation == "created":
            if before is not None or after is None:
                raise ValidationFailure(
                    f"{location}: created mutation boundary is invalid"
                )
            if after[0]["revision"] != "0":
                raise ValidationFailure(
                    f"{location}: created checkpoint revision is not zero"
                )
        elif mutation == "changed":
            if before is None or after is None:
                raise ValidationFailure(
                    f"{location}: changed mutation needs both checkpoints"
                )
            before_revision = canonical_decimal(
                before[0]["revision"], f"{location} before revision"
            )
            after_revision = canonical_decimal(
                after[0]["revision"], f"{location} after revision"
            )
            if after_revision != before_revision + 1:
                raise ValidationFailure(
                    f"{location}: changed checkpoint must increment revision once"
                )
            if (
                before[0]["execution_checkpoint_digest"]
                == after[0]["execution_checkpoint_digest"]
            ):
                raise ValidationFailure(
                    f"{location}: changed checkpoint kept its digest"
                )
        elif mutation == "unchanged":
            if before is None or after is None or before[1] != after[1]:
                raise ValidationFailure(
                    f"{location}: unchanged checkpoint must preserve exact bytes"
                )

        if result in {"not_accepted", "failure", "unsupported"} and mutation not in {
            "absent",
            "unchanged",
        }:
            raise ValidationFailure(f"{location}: failure mutated the checkpoint")
        if result == "response_lost":
            if mutation != "changed" or vector.get("failure_boundary") != (
                "after_commit_before_response"
            ):
                raise ValidationFailure(
                    f"{location}: response loss must follow a committed change"
                )
        if vector.get("failure_boundary") == "before_commit" and mutation not in {
            "absent",
            "unchanged",
        }:
            raise ValidationFailure(
                f"{location}: pre-commit failure was not rolled back"
            )
        after_document = after[0] if after is not None else None
        before_document = before[0] if before is not None else None
        if before_document is not None and operation in input_operations:
            assert operation_input is not None
            supplied_revision = operation_input.get("expected_revision")
            supplied_digest = operation_input.get("expected_checkpoint_digest")
            matches_read = (
                supplied_revision == before_document["revision"]
                and supplied_digest
                == before_document["execution_checkpoint_digest"]
            )
            if mutation == "changed" and not matches_read:
                raise ValidationFailure(
                    f"{location}: writer lacks the exact checkpoint CAS read"
                )
            if expectation.get("code") == "checkpoint_revision_conflict":
                if matches_read or core_call != "none":
                    raise ValidationFailure(
                        f"{location}: stale writer did not fail before the core call"
                    )

        receipt_sequence = expectation.get("receipt_sequence")
        receipt = None
        if receipt_sequence is not None:
            if after_document is None:
                raise ValidationFailure(f"{location}: receipt has no checkpoint")
            receipt = next(
                (
                    item
                    for item in after_document["operation_receipts"]
                    if item["receipt_sequence"] == receipt_sequence
                ),
                None,
            )
            if receipt is None:
                raise ValidationFailure(
                    f"{location}: missing expected receipt {receipt_sequence}"
                )

        if operation == "create" and result == "committed":
            if receipt is None or receipt["operation_kind"] != "creation":
                raise ValidationFailure(
                    f"{location}: create result lacks creation receipt"
                )
            assert operation_input is not None
            if receipt["creation_id"] != operation_input["creation_id"] or (
                receipt["request_digest"] != operation_input["request_digest"]
            ):
                raise ValidationFailure(
                    f"{location}: creation receipt identity changed"
                )
        if operation == "accept_delivery" and result == "pending":
            assert operation_input is not None
            event_id = operation_input["envelope"]["event_id"]
            pending = next(
                (
                    item
                    for item in after_document["pending_deliveries"]
                    if item["envelope"]["event_id"] == event_id
                ),
                None,
            )
            if pending is None:
                raise ValidationFailure(
                    f"{location}: pending acceptance was not retained"
                )
            if (
                pending["envelope_digest"] != operation_input["envelope_digest"]
                or pending["delivery_mode"] != operation_input["delivery_mode"]
                or pending["origin"] != operation_input["origin"]
                or pending["envelope"] != operation_input["envelope"]
                or pending["delivery_sequence"] != expectation["delivery_sequence"]
                or pending["accepted_revision"] != expectation["accepted_revision"]
            ):
                raise ValidationFailure(
                    f"{location}: pending acceptance result mismatch"
                )
        if operation == "process_pending_delivery" and result in {
            "committed",
            "response_lost",
        }:
            if before_document is None or receipt is None:
                raise ValidationFailure(
                    f"{location}: pending processing boundary is absent"
                )
            assert operation_input is not None
            event_id = operation_input["envelope"]["event_id"]
            pending = next(
                (
                    item
                    for item in before_document["pending_deliveries"]
                    if item["envelope"]["event_id"] == event_id
                ),
                None,
            )
            if (
                pending is None
                or receipt["operation_kind"] != "delivery"
                or receipt["event_id"] != event_id
                or receipt["request_digest"] != pending["envelope_digest"]
                or any(
                    item["envelope"]["event_id"] == event_id
                    for item in after_document["pending_deliveries"]
                )
            ):
                raise ValidationFailure(
                    f"{location}: pending delivery transition mismatch"
                )
        if operation == "foreground_process_delivery" and result in {
            "committed",
            "response_lost",
        }:
            assert operation_input is not None
            if (
                receipt is None
                or receipt["operation_kind"] != "delivery"
                or receipt["event_id"] != operation_input["envelope"]["event_id"]
                or receipt["request_digest"]
                != operation_input["envelope_digest"]
                or receipt["accepted_revision"] != receipt["committed_revision"]
            ):
                raise ValidationFailure(f"{location}: foreground receipt mismatch")
        if operation == "maintenance_migration" and result in {
            "committed",
            "response_lost",
        }:
            assert operation_input is not None
            if (
                receipt is None
                or receipt["operation_kind"] != "maintenance_migration"
                or receipt["operation_id"] != operation_input["operation_id"]
                or receipt["request_digest"] != operation_input["request_digest"]
            ):
                raise ValidationFailure(f"{location}: maintenance receipt mismatch")
        if operation == "update_pending_outbox" and result == "committed":
            assert operation_input is not None
            record = next(
                (
                    item
                    for item in after_document["pending_outbox_intents"]
                    if item["intent"]["effect_id"] == operation_input["effect_id"]
                ),
                None,
            )
            if (
                record is None
                or record["delivery_state"]
                != operation_input["desired_pending_state"]
            ):
                raise ValidationFailure(f"{location}: pending outbox update mismatch")
        if operation == "terminalize_outbox" and result == "committed":
            assert operation_input is not None
            record = next(
                (
                    item
                    for item in after_document["terminal_outbox_records"]
                    if item["intent"]["effect_id"] == operation_input["effect_id"]
                ),
                None,
            )
            if (
                record is None
                or record["outcome"] != operation_input["terminal_outcome"]
            ):
                raise ValidationFailure(f"{location}: terminal outbox result mismatch")
        if operation == "compact_outbox" and result == "committed":
            assert operation_input is not None
            effect_id = operation_input["effect_id"]
            source_record = next(
                (
                    item
                    for item in before_document["terminal_outbox_records"]
                    if item["intent"]["effect_id"] == effect_id
                ),
                None,
            )
            compact_record = next(
                (
                    item
                    for item in after_document["outbox_effect_tombstones"]
                    if item["effect_id"] == effect_id
                ),
                None,
            )
            if source_record is None or compact_record is None:
                raise ValidationFailure(f"{location}: compact tombstone is missing")
            expected_intent_digest = hash_value(
                [
                    "determa-outbox-intent-digest-1",
                    "1",
                    before_document["root_instance_id"],
                    source_record["intent"],
                ]
            )
            if compact_record["intent_digest"] != expected_intent_digest:
                raise ValidationFailure(
                    f"{location}: compact intent digest mismatches source intent"
                )
        if operation == "update_replay_retention" and result == "committed":
            assert operation_input is not None
            if after_document["replay_retention"] != operation_input[
                "target_replay_retention"
            ]:
                raise ValidationFailure(f"{location}: retention result mismatch")
        if operation == "tombstone_root" and result == "tombstoned":
            assert operation_input is not None
            tombstone = after_document["root_record"]
            if (
                tombstone["status"] != "tombstone"
                or tombstone["tombstone_operation_id"]
                != operation_input["operation_id"]
            ):
                raise ValidationFailure(f"{location}: root tombstone mismatch")

        if core_call in {"create", "dispatch"}:
            assert core_result is not None
            if core_call == "create":
                if core_result["prior_aggregate_state_digest"] is not None:
                    raise ValidationFailure(
                        f"{location}: create core result has prior state"
                    )
                if result == "failure":
                    if (
                        core_result["aggregate_state"] is not None
                        or core_result["emissions"]
                        or core_result["status"] != "rejected"
                    ):
                        raise ValidationFailure(
                            f"{location}: rejected create core result drift"
                        )
                else:
                    aggregate = after_document["root_record"]["aggregate_state"]
                    if core_result["aggregate_state"] != aggregate:
                        raise ValidationFailure(
                            f"{location}: created aggregate differs from core"
                        )
                    if (
                        core_result["status"] != receipt["status"]
                        or core_result["fault"] != receipt["fault"]
                    ):
                        raise ValidationFailure(
                            f"{location}: creation receipt differs from core"
                        )
                    validate_emissions(
                        core_result, receipt, after_document, location
                    )
            else:
                if before_document is None:
                    raise ValidationFailure(f"{location}: dispatch has no prior state")
                if core_result["prior_aggregate_state_digest"] != aggregate_digest(
                    before_document
                ):
                    raise ValidationFailure(
                        f"{location}: dispatch prior aggregate digest drift"
                    )
                if mutation == "changed":
                    aggregate = after_document["root_record"]["aggregate_state"]
                    if core_result["aggregate_state"] != aggregate:
                        raise ValidationFailure(
                            f"{location}: committed aggregate differs from core"
                        )
                    if receipt["outcome"] != {
                        "status": core_result["status"],
                        "disposition": core_result["disposition"],
                        "fault": core_result["fault"],
                        "rejection": core_result["rejection"],
                    }:
                        raise ValidationFailure(
                            f"{location}: delivery outcome differs from core"
                        )
                    validate_emissions(
                        core_result, receipt, after_document, location
                    )
        if core_call == "migrate":
            assert core_result is not None
            if (
                core_result["prior_aggregate_state_digest"]
                != aggregate_digest(before_document)
                or core_result["aggregate_state"]
                != after_document["root_record"]["aggregate_state"]
                or core_result["audit_records"]
                != after_document["migration_audit_records"]
                or not core_result["audit_records"]
            ):
                raise ValidationFailure(
                    f"{location}: migration result or audit differs from core"
                )

        for label in vector["covers"]:
            validate_coverage_claim(
                label,
                vector,
                operation_input,
                before_document,
                after_document,
                core_result,
                receipt,
                location,
            )

        if operation in {
            "register_adapter",
            "resolve_adapter",
            "validate_host_profile",
        }:
            advertised = set(vector["advertised_capabilities"])
            requested = set(vector["requested_capabilities"])
            if (
                operation in {"register_adapter", "resolve_adapter"}
                and not vector["configuration_valid"]
            ):
                if (
                    result != "failure"
                    or expectation.get("code")
                    != "invalid_adapter_configuration"
                ):
                    raise ValidationFailure(
                        f"{location}: invalid configuration did not take precedence"
                    )
                continue
            if result == "accepted" and not requested.issubset(advertised):
                raise ValidationFailure(
                    f"{location}: accepted capabilities were not advertised"
                )
            if (
                operation in {"register_adapter", "resolve_adapter"}
                and expectation.get("code") == "invalid_adapter_configuration"
            ):
                raise ValidationFailure(
                    f"{location}: configuration failure used a valid configuration"
                )
            if (
                operation in {"register_adapter", "resolve_adapter"}
                and expectation.get("code") == "adapter_capability_mismatch"
                and requested.issubset(advertised)
            ):
                raise ValidationFailure(
                    f"{location}: adapter capability mismatch has no mismatch"
                )
        if operation in {"register_adapter", "resolve_adapter"}:
            identifier = vector["adapter_identifier"]
            advertised = set(vector["advertised_capabilities"])
            durable = {"durable_single_writer", "durable_concurrent"}
            if identifier == "memory" and advertised != {"ephemeral"}:
                raise ValidationFailure(
                    f"{location}: memory advertised non-ephemeral capability"
                )
            if identifier == "file" and advertised & durable:
                raise ValidationFailure(
                    f"{location}: file implied an unproved durable capability"
                )
            if vector.get("registration_route") != "public":
                raise ValidationFailure(
                    f"{location}: adapter bypasses the public registration route"
                )
        if operation == "validate_host_profile":
            advertised = set(vector["advertised_capabilities"])
            features = set(vector["host_features"])
            profile = vector["host_profile"]
            required_capabilities = {"root_identity_retention"}
            required_features: set[str] = {"atomic_checkpoint_processing"}
            durable = bool(
                advertised & {"durable_single_writer", "durable_concurrent"}
            )
            if profile == "exactly_once_committed_processing":
                required_capabilities.add("permanent_receipt_retention")
            elif profile == "broker_integrated":
                required_features.update(
                    {
                        "acknowledge_after_checkpoint_commit",
                        "durable_redelivery",
                        "outbox_worker",
                    }
                )
            elif profile == "strict_durable_outbox":
                required_capabilities.add(
                    "permanent_outbox_terminal_retention"
                )
                required_features.update(
                    {
                        "outbox_worker",
                        "total_outbox_lifecycle",
                        "retain_unresolved_outbox",
                    }
                )
            elif profile == "compact_durable_outbox":
                required_capabilities.add("compact_effect_identity_retention")
                required_features.update(
                    {
                        "outbox_worker",
                        "total_outbox_lifecycle",
                        "retain_referenced_effect_tombstones",
                    }
                )
            elif profile == "shared_application_transaction":
                required_capabilities.add("shared_application_transaction")
                required_features.add("native_shared_application_transaction")
            conforming = (
                durable
                and required_capabilities.issubset(advertised)
                and required_capabilities.issubset(requested)
                and required_features.issubset(features)
                and not (
                    profile == "exactly_once_committed_processing"
                    and vector["checkpoint_retention_mode"] != "permanent"
                )
            )
            if (result == "accepted") != conforming:
                raise ValidationFailure(
                    f"{location}: composed host-profile result is incorrect"
                )

    def scope_state(
        reference: dict[str, str], location: str
    ) -> tuple[dict[str, Any], bytes]:
        filename = reference["file"]
        entry = manifest.get(filename)
        if (
            entry is None
            or entry["kind"] != "execution_store_scope_state"
            or not entry["valid"]
        ):
            raise ValidationFailure(
                f"{location}: {filename} must be a valid scope state"
            )
        value = resolve_ref(
            reference,
            location,
            "execution_store_scope_state",
        )
        if not isinstance(value, dict):
            raise ValidationFailure(f"{location}: scope state must be an object")
        return value, canonical_json_bytes(value)

    def checkpoint_outbox_records(document: dict[str, Any]) -> list[dict[str, str]]:
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
        return [
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

    def validate_scope_state(
        document: dict[str, Any], location: str
    ) -> dict[str, dict[str, Any]]:
        scopes: dict[str, dict[str, Any]] = {}
        isolation_keys: set[str] = set()
        for scope_document in document["scopes"]:
            identifier = scope_document["logical_scope_id"]
            isolation_key = scope_document["physical_isolation_key"]
            if identifier in scopes or isolation_key in isolation_keys:
                raise ValidationFailure(
                    f"{location}: logical scopes and isolation keys must be unique"
                )
            scopes[identifier] = scope_document
            isolation_keys.add(isolation_key)
            actual_records: list[dict[str, str]] = []
            for root_instance_id, binding in scope_document["checkpoints"].items():
                resolved = checkpoint(binding["file"], location)
                if resolved is None:
                    raise ValidationFailure(
                        f"{location}: missing checkpoint {binding['file']}"
                    )
                checkpoint_document, source = resolved
                if (
                    checkpoint_document["root_instance_id"] != root_instance_id
                    or binding["serialization_digest"]
                    != hash_bytes(canonical_json_bytes(checkpoint_document))
                    or binding["execution_checkpoint_digest"]
                    != checkpoint_document["execution_checkpoint_digest"]
                ):
                    raise ValidationFailure(
                        f"{location}: checkpoint map is not byte-exact"
                    )
                actual_records.extend(
                    checkpoint_outbox_records(checkpoint_document)
                )
            effect_ids = [item["effect_id"] for item in actual_records]
            if (
                len(effect_ids) != len(set(effect_ids))
                or scope_document["outbox_records"] != actual_records
            ):
                raise ValidationFailure(
                    f"{location}: complete outbox-record map is not exact"
                )
        return scopes

    for index, vector in enumerate(scope_vectors):
        location = f"{case.name} scope vector {index} ({vector['name']})"
        if vector["name"] in names:
            raise ValidationFailure(f"{case.name}: duplicate vector {vector['name']}")
        names.add(vector["name"])
        duplicate_coverage = coverage & set(vector["covers"])
        if duplicate_coverage:
            raise ValidationFailure(
                f"{location}: duplicate coverage {sorted(duplicate_coverage)}"
            )
        coverage.update(vector["covers"])

        before_document, before_source = scope_state(
            vector["scope_state_before"], location
        )
        after_document, after_source = scope_state(
            vector["scope_state_after"], location
        )
        before_scopes = validate_scope_state(before_document, location)
        after_scopes = validate_scope_state(after_document, location)
        if (
            before_document["physical_backend_id"]
            != after_document["physical_backend_id"]
            or set(before_scopes) != set(after_scopes)
        ):
            raise ValidationFailure(
                f"{location}: backend or logical scope membership changed"
            )

        selection = vector["scope_selection"]
        classification = selection["classification"]
        requested = selection["requested_scope_id"]
        candidates = selection["candidates"]
        candidate_ids = [item["logical_scope_id"] for item in candidates]
        candidate_keys = [item["physical_isolation_key"] for item in candidates]
        if (
            len(candidate_ids) != len(set(candidate_ids))
            or len(candidate_keys) != len(set(candidate_keys))
        ):
            raise ValidationFailure(f"{location}: scope candidates are not distinct")
        for candidate in candidates:
            candidate_scope = before_scopes.get(candidate["logical_scope_id"])
            if (
                candidate_scope is None
                or candidate_scope["physical_isolation_key"]
                != candidate["physical_isolation_key"]
            ):
                raise ValidationFailure(
                    f"{location}: scope candidate is not bound to store state"
                )
        selected_scope_id: str | None = None
        if classification == "selected":
            if (
                requested is None
                or len(candidates) != 1
                or candidates[0]["logical_scope_id"] != requested
                or not candidates[0]["authorized"]
            ):
                raise ValidationFailure(
                    f"{location}: selected scope is not exact and authorized"
                )
            selected_scope_id = requested
        elif classification == "missing":
            if requested is not None or candidates:
                raise ValidationFailure(f"{location}: missing selection is not empty")
        elif classification == "ambiguous":
            if requested is None or len(candidates) < 2:
                raise ValidationFailure(f"{location}: ambiguous selection is not exact")
        elif classification == "mismatched":
            if (
                requested is None
                or len(candidates) != 1
                or candidates[0]["logical_scope_id"] == requested
                or not candidates[0]["authorized"]
            ):
                raise ValidationFailure(f"{location}: mismatched selection is not exact")
        elif classification == "unauthorized":
            if (
                requested is None
                or len(candidates) != 1
                or candidates[0]["logical_scope_id"] != requested
                or candidates[0]["authorized"]
            ):
                raise ValidationFailure(f"{location}: unauthorized selection is not exact")

        expectation = vector["expect"]
        expected_result = "selected" if selected_scope_id is not None else "rejected"
        if (
            expectation["selection_result"] != expected_result
            or expectation["selected_scope_id"] != selected_scope_id
        ):
            raise ValidationFailure(f"{location}: scope selection result drift")
        state_changed = before_source != after_source
        if (expectation["scope_state_mutation"] == "changed") != state_changed:
            raise ValidationFailure(f"{location}: scope-state mutation drift")

        expected_calls = {
            "resolver": ["resolve_execution_store_scope"],
            "execution_host": (
                ["update_pending_outbox"] if selected_scope_id is not None else []
            ),
            "store": (
                ["load_checkpoint", "compare_and_swap_checkpoint"]
                if selected_scope_id is not None
                else []
            ),
            "core": [],
        }
        if expectation["calls"] != expected_calls:
            raise ValidationFailure(f"{location}: resolver/host/store/core trace drift")

        if selected_scope_id is None:
            if (
                before_source != after_source
                or before_document != after_document
                or expectation["checkpoint_map_mutation"] != "unchanged"
                or expectation["outbox_record_map_mutation"] != "unchanged"
            ):
                raise ValidationFailure(
                    f"{location}: rejected scope selection changed complete store state"
                )
        else:
            for identifier in set(before_scopes) - {selected_scope_id}:
                if before_scopes[identifier] != after_scopes[identifier]:
                    raise ValidationFailure(
                        f"{location}: non-selected scope {identifier} changed"
                    )
            before_scope = before_scopes[selected_scope_id]
            after_scope = after_scopes[selected_scope_id]
            if any(
                before_scope[field] != after_scope[field]
                for field in ("logical_scope_id", "physical_isolation_key")
            ):
                raise ValidationFailure(f"{location}: selected scope metadata changed")
            checkpoint_changed = (
                before_scope["checkpoints"] != after_scope["checkpoints"]
            )
            outbox_changed = (
                before_scope["outbox_records"] != after_scope["outbox_records"]
            )
            if (
                (expectation["checkpoint_map_mutation"] == "changed")
                != checkpoint_changed
                or (expectation["outbox_record_map_mutation"] == "changed")
                != outbox_changed
            ):
                raise ValidationFailure(f"{location}: selected scope mutation drift")
            if set(before_scope["checkpoints"]) != set(after_scope["checkpoints"]):
                raise ValidationFailure(f"{location}: checkpoint map membership changed")
            changed_roots = [
                root_instance_id
                for root_instance_id in before_scope["checkpoints"]
                if before_scope["checkpoints"][root_instance_id]
                != after_scope["checkpoints"][root_instance_id]
            ]
            if len(changed_roots) != 1:
                raise ValidationFailure(
                    f"{location}: host operation must change exactly one checkpoint"
                )
            root_instance_id = changed_roots[0]
            before_checkpoint = checkpoint(
                before_scope["checkpoints"][root_instance_id]["file"], location
            )
            after_checkpoint = checkpoint(
                after_scope["checkpoints"][root_instance_id]["file"], location
            )
            assert before_checkpoint is not None and after_checkpoint is not None
            if (
                canonical_decimal(
                    after_checkpoint[0]["revision"], f"{location} after revision"
                )
                != canonical_decimal(
                    before_checkpoint[0]["revision"], f"{location} before revision"
                )
                + 1
            ):
                raise ValidationFailure(
                    f"{location}: selected checkpoint revision did not advance once"
                )
            before_records = {
                item["effect_id"]: item for item in before_scope["outbox_records"]
            }
            after_records = {
                item["effect_id"]: item for item in after_scope["outbox_records"]
            }
            effect_id = vector["effect_id"]
            if (
                set(before_records) != set(after_records)
                or effect_id not in before_records
                or before_records[effect_id] == after_records[effect_id]
                or any(
                    before_records[key] != after_records[key]
                    for key in set(before_records) - {effect_id}
                )
            ):
                raise ValidationFailure(
                    f"{location}: operation changed the wrong outbox-record map entry"
                )
            updated_record = next(
                (
                    item
                    for item in after_checkpoint[0]["pending_outbox_intents"]
                    if item["intent"]["effect_id"] == effect_id
                ),
                None,
            )
            if (
                updated_record is None
                or updated_record["delivery_state"]
                != vector["desired_pending_state"]
            ):
                raise ValidationFailure(
                    f"{location}: pending-outbox result differs from host input"
                )

        for label in vector["covers"]:
            expected = {
                "scoped_outbox_update_scope_a": ("selected", "scope-a"),
                "scoped_outbox_update_scope_b": ("selected", "scope-b"),
                "missing_scope_rejected": ("missing", None),
                "ambiguous_scope_rejected": ("ambiguous", None),
                "mismatched_scope_rejected": ("mismatched", None),
                "unauthorized_scope_rejected": ("unauthorized", None),
                "portable_state_scope_invariance": ("selected", "scope-b"),
            }[label]
            if (classification, selected_scope_id) != expected:
                raise ValidationFailure(
                    f"{location}: coverage {label} does not match behavior"
                )
        if "portable_state_scope_invariance" in vector["covers"]:
            scope_a = after_scopes["scope-a"]
            scope_b = after_scopes["scope-b"]
            if (
                scope_a["checkpoints"] != scope_b["checkpoints"]
                or scope_a["outbox_records"] != scope_b["outbox_records"]
            ):
                raise ValidationFailure(
                    f"{location}: portable checkpoint bytes, digests, or effects differ"
                )

    if run_mutation_probes:
        def expect_profile_probe_rejection(
            name: str,
            probe_test: dict[str, Any],
            overrides: dict[str, Any] | None = None,
        ) -> None:
            try:
                validate_execution_checkpoint_profile(
                    case,
                    probe_test,
                    artifact_paths,
                    artifact_overrides=overrides,
                    run_mutation_probes=False,
                )
            except ValidationFailure:
                return
            raise ValidationFailure(
                f"{case.name}: self-mutation probe was accepted: {name}"
            )

        def vector_index_for(label: str) -> int | None:
            return next(
                (
                    index
                    for index, vector in enumerate(vectors)
                    if label in vector["covers"]
                ),
                None,
            )

        if scope_vectors:
            rejected = next(
                vector
                for vector in scope_vectors
                if vector["scope_selection"]["classification"] == "missing"
            )
            probe = copy.deepcopy(test)
            probe_vector = next(
                item
                for item in probe["execution_checkpoint_profile"]["vectors"]
                if item["name"] == rejected["name"]
            )
            probe_vector["expect"]["calls"]["execution_host"] = [
                "update_pending_outbox"
            ]
            expect_profile_probe_rejection("host call after rejected scope", probe)

            selected_a = next(
                vector
                for vector in scope_vectors
                if "scoped_outbox_update_scope_a" in vector["covers"]
            )
            probe = copy.deepcopy(test)
            probe_vector = next(
                item
                for item in probe["execution_checkpoint_profile"]["vectors"]
                if item["name"] == selected_a["name"]
            )
            probe_vector["scope_state_after"]["pointer"] = "/snapshots/updated-b"
            expect_profile_probe_rejection("non-selected scope mutation", probe)

        creation_commit_index = vector_index_for("creation_commit")
        creation_replay_index = vector_index_for("creation_replay")
        if creation_commit_index is not None and creation_replay_index is not None:
            probe = copy.deepcopy(test)
            commit_covers = probe["execution_checkpoint_profile"]["vectors"][
                creation_commit_index
            ]["covers"]
            replay_covers = probe["execution_checkpoint_profile"]["vectors"][
                creation_replay_index
            ]["covers"]
            commit_covers[commit_covers.index("creation_commit")] = (
                "creation_replay"
            )
            replay_covers[replay_covers.index("creation_replay")] = (
                "creation_commit"
            )
            expect_profile_probe_rejection("swapped creation coverage", probe)

        dispatch_index = vector_index_for("delayed_processing")
        if dispatch_index is not None:
            dispatch_vector = vectors[dispatch_index]
            input_reference = dispatch_vector["input"]
            core_reference = dispatch_vector["core_result"]
            input_document = copy.deepcopy(
                analyze_artifact(case / input_reference["file"]).document
            )
            core_document = copy.deepcopy(
                analyze_artifact(case / core_reference["file"]).document
            )
            request_name = input_reference["pointer"].split("/")[-1]
            call_name = core_reference["pointer"].split("/")[-1]
            request = input_document["requests"][request_name]
            mode = request["delivery_mode"]
            request["dispatch_input"]["delivery"][mode]["payload"] = {
                "amount": 999
            }
            core_document["calls"][call_name]["operation_input_digest"] = hash_value(
                [
                    "determa-conformance-execution-checkpoint-operation-input-1",
                    request,
                ]
            )
            expect_profile_probe_rejection(
                "dispatch input drift with rebound evidence digest",
                test,
                {
                    input_reference["file"]: input_document,
                    core_reference["file"]: core_document,
                },
            )

            digest_probe = copy.deepcopy(core_document)
            digest_probe["calls"][call_name]["operation_input_digest"] = (
                "sha256:" + ("0" * 64)
            )
            expect_profile_probe_rejection(
                "wrong core operation-input digest",
                test,
                {core_reference["file"]: digest_probe},
            )

        configuration_index = vector_index_for(
            "invalid_adapter_configuration"
        )
        if configuration_index is not None:
            probe = copy.deepcopy(test)
            vector_probe = probe["execution_checkpoint_profile"]["vectors"][
                configuration_index
            ]
            vector_probe["requested_capabilities"] = [
                "durable_concurrent",
                "root_identity_retention",
            ]
            vector_probe["expect"]["code"] = "adapter_capability_mismatch"
            expect_profile_probe_rejection(
                "capability mismatch before invalid configuration",
                probe,
            )

    return coverage, len(all_vectors)


def validate_execution_checkpoint_schema_totality(
    test: dict[str, Any],
    validator: Draft202012Validator,
    case: Path,
) -> None:
    """Prove operation/result/code/core-call unions reject every exclusion."""
    allowed_results = {
        operation: set(outcomes)
        for operation, outcomes in EXECUTION_CHECKPOINT_OPERATION_OUTCOMES.items()
    }
    allowed_core_calls = {
        "create": {"none", "create"},
        "accept_delivery": {"none"},
        "process_pending_delivery": {"none", "dispatch"},
        "foreground_process_delivery": {"none", "dispatch"},
        "maintenance_migration": {"none", "migrate"},
        "update_pending_outbox": {"none"},
        "terminalize_outbox": {"none"},
        "compact_outbox": {"none"},
        "delete_outbox_record": {"none"},
        "update_replay_retention": {"none"},
        "tombstone_root": {"none"},
        "delete_checkpoint": {"none"},
        "inject_execution_store": {"none"},
        "register_adapter": {"none"},
        "resolve_adapter": {"none"},
        "validate_host_profile": {"none"},
    }
    all_results = {
        "committed",
        "accepted",
        "pending",
        "not_accepted",
        "tombstoned",
        "failure",
        "response_lost",
        "unsupported",
    }
    all_codes = {
        code
        for outcomes in EXECUTION_CHECKPOINT_OPERATION_OUTCOMES.values()
        for codes in outcomes.values()
        for code in codes
        if code is not None
    }
    all_core_calls = {"none", "create", "dispatch", "migrate"}
    seen: set[str] = set()
    for index, vector in enumerate(
        test["execution_checkpoint_profile"]["vectors"]
    ):
        if "scope_selection" in vector:
            continue
        operation = vector["operation"]
        if operation in seen:
            continue
        seen.add(operation)
        for result in all_results - allowed_results[operation]:
            probe = copy.deepcopy(test)
            expectation = probe["execution_checkpoint_profile"]["vectors"][index][
                "expect"
            ]
            expectation["result"] = result
            expectation.pop("delivery_sequence", None)
            expectation.pop("accepted_revision", None)
            if result in {"failure", "not_accepted", "response_lost", "unsupported"}:
                expectation["code"] = "invalid_execution_checkpoint"
            else:
                expectation.pop("code", None)
            if result == "pending":
                expectation["delivery_sequence"] = "0"
                expectation["accepted_revision"] = "0"
            if next(validator.iter_errors(probe), None) is None:
                raise ValidationFailure(
                    f"{case.name}: schema accepts impossible {operation}/{result}"
                )
        for result, allowed_codes in (
            EXECUTION_CHECKPOINT_OPERATION_OUTCOMES[operation].items()
        ):
            for code in all_codes - set(allowed_codes):
                probe = copy.deepcopy(test)
                expectation = probe["execution_checkpoint_profile"]["vectors"][
                    index
                ]["expect"]
                expectation["result"] = result
                expectation["code"] = code
                if result == "pending":
                    expectation["delivery_sequence"] = "0"
                    expectation["accepted_revision"] = "0"
                else:
                    expectation.pop("delivery_sequence", None)
                    expectation.pop("accepted_revision", None)
                if next(validator.iter_errors(probe), None) is None:
                    raise ValidationFailure(
                        f"{case.name}: schema accepts impossible "
                        f"{operation}/{result}/{code}"
                    )
        for core_call in all_core_calls - allowed_core_calls[operation]:
            probe = copy.deepcopy(test)
            vector_probe = probe["execution_checkpoint_profile"]["vectors"][index]
            vector_probe["expect"]["core_call"] = core_call
            if core_call == "none":
                vector_probe.pop("core_result", None)
            else:
                vector_probe.setdefault(
                    "core_result",
                    {"file": "core-results.json", "pointer": "/calls/create"},
                )
            if next(validator.iter_errors(probe), None) is None:
                raise ValidationFailure(
                    f"{case.name}: schema accepts impossible "
                    f"{operation}/{core_call} core call"
                )

    scope_vectors = [
        (index, vector)
        for index, vector in enumerate(
            test["execution_checkpoint_profile"]["vectors"]
        )
        if "scope_selection" in vector
    ]
    if scope_vectors:
        index, _ = scope_vectors[0]
        probe = copy.deepcopy(test)
        probe["execution_checkpoint_profile"]["vectors"][index][
            "language_specific"
        ] = True
        if next(validator.iter_errors(probe), None) is None:
            raise ValidationFailure(
                f"{case.name}: scope vector schema accepts extra members"
            )

        probe = copy.deepcopy(test)
        del probe["execution_checkpoint_profile"]["vectors"][index]["effect_id"]
        if next(validator.iter_errors(probe), None) is None:
            raise ValidationFailure(
                f"{case.name}: scope vector accepts no effect identity"
            )


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


def resource_shape_metrics(
    value: Any,
    depth: int = 0,
) -> tuple[int, int, int, int]:
    maximum_depth = depth
    maximum_map_members = 0
    maximum_list_members = 0
    maximum_string_bytes = 0
    if isinstance(value, dict):
        maximum_depth = depth + 1
        maximum_map_members = len(value)
        for key, child in value.items():
            maximum_string_bytes = max(
                maximum_string_bytes,
                len(key.encode("utf-8")),
            )
            child_metrics = resource_shape_metrics(child, depth + 1)
            maximum_depth = max(maximum_depth, child_metrics[0])
            maximum_map_members = max(maximum_map_members, child_metrics[1])
            maximum_list_members = max(maximum_list_members, child_metrics[2])
            maximum_string_bytes = max(maximum_string_bytes, child_metrics[3])
    elif isinstance(value, list):
        maximum_depth = depth + 1
        maximum_list_members = len(value)
        for child in value:
            child_metrics = resource_shape_metrics(child, depth + 1)
            maximum_depth = max(maximum_depth, child_metrics[0])
            maximum_map_members = max(maximum_map_members, child_metrics[1])
            maximum_list_members = max(maximum_list_members, child_metrics[2])
            maximum_string_bytes = max(maximum_string_bytes, child_metrics[3])
    elif isinstance(value, str):
        maximum_string_bytes = len(value.encode("utf-8"))
    return (
        maximum_depth,
        maximum_map_members,
        maximum_list_members,
        maximum_string_bytes,
    )


def validate_case_112(case: Path, test: dict[str, Any]) -> None:
    floor = analyze_artifact(
        case / "minimum-supported-floor-resource-limits.json"
    ).document
    if floor != MINIMUM_RESOURCE_LIMIT_FLOORS:
        raise ValidationFailure(
            f"{case.name}: minimum supported resource floors changed"
        )

    source = analyze_artifact(
        case / "occurrence-source-aggregate-state.json"
    ).document
    descriptor = analyze_artifact(
        case / "occurrence-migration-descriptor.json"
    ).document
    definitions = [
        analyze_source(case / filename).document
        for filename in ("occurrence-machine.yaml", "occurrence-target.yaml")
    ]
    values = [source, descriptor, *definitions]
    shape_metrics = [
        resource_shape_metrics(value)
        for value in values
    ]
    expressions = {
        rule["expression"]
        for rule in descriptor["mappings"]["variables"]
        if "expression" in rule
    }
    actual_use = {
        "definition_bytes": max(
            len(canonical_json_bytes(definition))
            for definition in definitions
        ),
        "json_nesting_depth": max(item[0] for item in shape_metrics),
        "runtimes": len(source["runtimes"]),
        "active_states": max(
            len(runtime["active_state_activations"])
            for runtime in source["runtimes"]
        ),
        "variables": max(
            len(runtime["variables"])
            for runtime in source["runtimes"]
        ),
        "map_members": max(item[1] for item in shape_metrics),
        "list_members": max(item[2] for item in shape_metrics),
        "string_utf8_bytes": max(item[3] for item in shape_metrics),
        "descriptor_rules": sum(
            len(rules) for rules in descriptor["mappings"].values()
        ),
        "cel_expression_length": sum(
            len(expression.encode("utf-8"))
            for expression in expressions
        ),
        # Any non-empty checked expression has at least one AST node.
        "cel_ast_nodes": int(bool(expressions)),
    }
    fields = {
        "definition_bytes": "maximum_definition_bytes",
        "json_nesting_depth": "maximum_json_nesting_depth",
        "runtimes": "maximum_runtimes",
        "active_states": "maximum_active_states_per_runtime",
        "variables": "maximum_variables_per_runtime",
        "map_members": "maximum_map_members",
        "list_members": "maximum_list_members",
        "string_utf8_bytes": "maximum_string_utf8_bytes",
        "descriptor_rules": "maximum_descriptor_rules",
        "cel_expression_length": "maximum_cel_expression_length",
        "cel_ast_nodes": "maximum_cel_ast_nodes",
    }
    for label, field in fields.items():
        if actual_use[label] > int(MINIMUM_RESOURCE_LIMIT_FLOORS[field]):
            raise ValidationFailure(
                f"{case.name}: {label} exceeds its documented minimum floor"
            )
    vectors = {
        vector["name"]: vector for vector in test["persistence_vectors"]
    }
    success_name = "minimum_supported_floors_accept_all_listed_dimensions"
    success = vectors.get(success_name)
    if (
        success is None
        or success.get("resource_limits")
        != "minimum-supported-floor-resource-limits.json"
        or success["expect"]["result"] != "success"
    ):
        raise ValidationFailure(
            f"{case.name}: minimum-floor success vector changed"
        )
    for label, field in fields.items():
        filename = f"configured-{label}-below-use.json"
        limits = analyze_artifact(case / filename).document
        expected = dict(MINIMUM_RESOURCE_LIMIT_FLOORS)
        expected[field] = str(actual_use[label] - 1)
        if limits != expected:
            raise ValidationFailure(
                f"{case.name}: {filename} is not the exact below-use limit"
            )
        vector_name = f"configured_{label}_limit_exceeded"
        vector = vectors.get(vector_name)
        if (
            vector is None
            or vector.get("resource_limits") != filename
            or vector["expect"]
            != {
                "result": "failure",
                "code": "migration_resource_limit_exceeded",
                "caller_still_owns_aggregate": True,
            }
        ):
            raise ValidationFailure(
                f"{case.name}: {vector_name} changed"
            )
    chain = vectors.get("chain_limit_exceeded")
    chain_limits = analyze_artifact(case / "chain-resource-limits.json").document
    if (
        chain is None
        or len(chain["migration_route"]) != 1
        or chain_limits["maximum_chain_length"] != "0"
        or chain["expect"]
        != {
            "result": "failure",
            "code": "migration_resource_limit_exceeded",
            "caller_still_owns_aggregate": True,
        }
    ):
        raise ValidationFailure(
            f"{case.name}: chain length is not exact descriptor count"
        )
    if any("cumulative" in name for name in chain_limits):
        raise ValidationFailure(
            f"{case.name}: cumulative chain resource field is unsupported"
        )


def validate_case_115(case: Path, test: dict[str, Any]) -> None:
    vectors = {
        vector["name"]: vector for vector in test["persistence_vectors"]
    }
    spawned_values = {
        "spawned_machine_version_javascript_safe_maximum":
            "9007199254740991",
        "spawned_machine_version_first_javascript_unsafe":
            "9007199254740992",
        "spawned_machine_version_javascript_rounding_gap":
            "9007199254740993",
        "spawned_machine_version_signed64_maximum":
            "9223372036854775807",
    }
    for name, expected_version in spawned_values.items():
        vector = vectors.get(name)
        if vector is None or vector["expect"]["result"] != "success":
            raise ValidationFailure(f"{case.name}: missing {name}")
        aggregate = analyze_artifact(case / vector["aggregate_state"]).document
        runtime = next(
            item
            for item in aggregate["runtimes"]
            if item["identity_origin"]["kind"] == "owned_spawned_instance"
        )
        if (
            runtime["target_identity"]["spawned_instance"]["machine_version"]
            != expected_version
        ):
            raise ValidationFailure(
                f"{case.name}: {name} does not preserve its decimal string"
            )
        origin = runtime["identity_origin"]
        definition = origin["definition"]["machine"]
        expected_runtime_id = hash_value(
            [
                "determa-spawned-runtime-identity-1",
                "1",
                aggregate["root_instance_id"],
                origin["owner_runtime_id"],
                origin["spawn_action_pointer"],
                origin["spawn_sequence"],
                definition["namespace"],
                definition["machine_id"],
                definition["machine_version"],
            ]
        )
        if (
            runtime["runtime_id"] != expected_runtime_id
            or runtime["target_identity"]["spawned_instance"]["instance_id"]
            != expected_runtime_id
            or runtime["current_definition"]["machine"]["machine_version"]
            != expected_version
            or definition["machine_version"] != expected_version
        ):
            raise ValidationFailure(
                f"{case.name}: {name} is not identity-consistent"
            )

    component_values = {
        "component_activation_javascript_safe_maximum":
            "9007199254740991",
        "component_activation_first_javascript_unsafe":
            "9007199254740992",
        "component_activation_unbounded": (
            "123456789012345678901234567890123456789012345678901234567890"
        ),
    }
    for name, expected_activation in component_values.items():
        vector = vectors.get(name)
        if vector is None or vector["expect"]["result"] != "success":
            raise ValidationFailure(f"{case.name}: missing {name}")
        aggregate = analyze_artifact(case / vector["aggregate_state"]).document
        runtime = next(
            item
            for item in aggregate["runtimes"]
            if item["identity_origin"]["kind"] == "component"
            and item["relation"]["component_id"] == "left"
        )
        target = runtime["target_identity"]["component"]
        if (
            target["activation_sequence"] != expected_activation
            or runtime["identity_origin"]["activation_sequence"]
            != expected_activation
            or runtime["relation"]["activation_sequence"]
            != expected_activation
            or target["component_runtime_id"] != runtime["runtime_id"]
        ):
            raise ValidationFailure(
                f"{case.name}: {name} is not occurrence-consistent"
            )
        origin = runtime["identity_origin"]
        definition = origin["definition"]["machine"]
        expected_runtime_id = hash_value(
            [
                "determa-component-runtime-identity-1",
                "1",
                aggregate["root_instance_id"],
                origin["owner_runtime_id"],
                origin["component_definition_pointer"],
                expected_activation,
                definition["namespace"],
                definition["machine_id"],
                definition["machine_version"],
            ]
        )
        owner = next(
            item
            for item in aggregate["runtimes"]
            if item["runtime_id"] == origin["owner_runtime_id"]
        )
        counter = next(
            item
            for item in owner["next_component_activation_sequences"]
            if item["definition_pointer"]
            == origin["component_definition_pointer"]
        )
        if (
            runtime["runtime_id"] != expected_runtime_id
            or counter["next_sequence"] != str(int(expected_activation) + 1)
        ):
            raise ValidationFailure(
                f"{case.name}: {name} identity or counter changed"
            )

    failure_codes = {
        "spawned_numeric_machine_version_rejected": (
            "spawned-numeric-machine-version.json",
            int,
        ),
        "spawned_machine_version_above_signed64_rejected": (
            "spawned-machine-version-above-signed64.json",
            str,
        ),
        "component_numeric_activation_rejected": (
            "component-numeric-activation.json",
            int,
        ),
    }
    for name, (filename, expected_type) in failure_codes.items():
        vector = vectors.get(name)
        if (
            vector is None
            or vector["aggregate_state"] != filename
            or vector["expect"]
            != {
                "result": "failure",
                "code": "invalid_aggregate_state",
                "caller_still_owns_aggregate": True,
            }
        ):
            raise ValidationFailure(f"{case.name}: {name} changed")
        aggregate = analyze_artifact(case / filename).document
        runtime = next(
            item
            for item in aggregate["runtimes"]
            if item["identity_origin"]["kind"]
            in {"component", "owned_spawned_instance"}
        )
        if runtime["identity_origin"]["kind"] == "component":
            value = runtime["target_identity"]["component"][
                "activation_sequence"
            ]
        else:
            value = runtime["target_identity"]["spawned_instance"][
                "machine_version"
            ]
        if type(value) is not expected_type:
            raise ValidationFailure(
                f"{case.name}: {name} has the wrong wire representation"
            )
    overflow = analyze_artifact(
        case / "spawned-machine-version-above-signed64.json"
    ).document
    overflow_runtime = next(
        item
        for item in overflow["runtimes"]
        if item["identity_origin"]["kind"] == "owned_spawned_instance"
    )
    if (
        overflow_runtime["target_identity"]["spawned_instance"][
            "machine_version"
        ]
        != "9223372036854775808"
    ):
        raise ValidationFailure(
            f"{case.name}: signed-64 overflow boundary changed"
        )


def validate_persistence_profile_02(case: Path) -> None:
    source = analyze_artifact(case / "source-aggregate-state.json").document
    expected = analyze_artifact(case / "expected-aggregate-state.json").document
    envelope = analyze_artifact(case / "input-envelope.json").document
    initial_store = analyze_artifact(case / "initial-store.json").document
    committed_store = analyze_artifact(case / "committed-store.json").document
    descriptor = analyze_artifact(case / "migration-descriptor.json").document

    source_runtime = source["runtimes"][0]
    expected_runtime = expected["runtimes"][0]
    source_target = source_runtime["target_identity"]
    runtime_id = source["root_runtime_id"]
    if not (
        expected["root_runtime_id"] == runtime_id
        and source_runtime["runtime_id"] == runtime_id
        and expected_runtime["runtime_id"] == runtime_id
        and expected_runtime["target_identity"] == source_target
        and envelope["target"] == source_target
        and initial_store["aggregate_state"] == source
        and committed_store["aggregate_state"] == expected
    ):
        raise ValidationFailure(
            f"{case.name}: migration rekeyed the root runtime or target"
        )

    migrated = copy.deepcopy(source)
    target_fingerprint = descriptor["target_validated_bundle_fingerprint"]
    migrated["validated_bundle_fingerprint"] = target_fingerprint
    migrated["migration_sequence"] = str(int(migrated["migration_sequence"]) + 1)
    for runtime in migrated["runtimes"]:
        runtime["current_definition"]["validated_bundle_fingerprint"] = (
            target_fingerprint
        )
    migrated["aggregate_state_digest"] = hash_value(
        [
            "determa-aggregate-state-digest-1",
            {
                key: value
                for key, value in migrated.items()
                if key != "aggregate_state_digest"
            },
        ]
    )
    audits = committed_store["migration_audit"]
    if (
        len(audits) != 1
        or audits[0]["root_runtime_id"] != runtime_id
        or audits[0]["target_aggregate_state_digest"]
        != migrated["aggregate_state_digest"]
    ):
        raise ValidationFailure(
            f"{case.name}: migration audit identity or target digest changed"
        )

    outbox = committed_store["outbox"]
    if (
        initial_store["outbox"] != []
        or len(outbox) != 1
        or outbox[0]["sequence"] != 0
        or expected["next_output_sequence"] != "1"
    ):
        raise ValidationFailure(
            f"{case.name}: deterministic output is not atomically asserted"
        )
    machine = expected_runtime["current_definition"]["machine"]
    effect_id = hash_value(
        [
            "determa-effect-identity-1",
            "1",
            [
                machine["namespace"],
                machine["machine_id"],
                machine["machine_version"],
            ],
            expected["root_instance_id"],
            runtime_id,
            envelope["event_id"],
            str(int(expected["next_logical_step_sequence"]) - 1),
            "/machines/0/root/on_events/work/action/0/send",
            "0",
        ]
    )
    if outbox[0]["effect_id"] != effect_id:
        raise ValidationFailure(
            f"{case.name}: output effect identity does not use the preserved runtime"
        )


def validate_repository(repository_root: Path, spec_root: Path) -> str:
    try:
        registry_categories, registry_entries = validate_registry(repository_root)
    except RegistryValidationError as error:
        raise ValidationFailure(f"closed-code registry: {error}") from error
    validate_direct_descriptor_expectation_probes()
    validate_version1_fault_code_adversarial_probes(repository_root)
    validate_version2_aggregate_adversarial_probes(repository_root)
    validate_version2_checkpoint_adversarial_probes(repository_root)
    validate_all_retained_version1_checkpoint_upgrades(repository_root)
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
        "persistence_vectors": (
            repository_root / "scripts" / "schemas" / "persistence-vectors.schema.json"
        ),
        "persistence_profile": (
            repository_root / "scripts" / "schemas" / "persistence-profile.schema.json"
        ),
        "execution_checkpoint_profile": (
            repository_root
            / "scripts"
            / "schemas"
            / "execution-checkpoint-profile.schema.json"
        ),
        "version2_vectors": (
            repository_root / "scripts" / "schemas" / "version2-vectors.schema.json"
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
    persistence_vector_validator = Draft202012Validator(
        schemas["persistence_vectors"], registry=registry
    )
    persistence_profile_validator = Draft202012Validator(
        schemas["persistence_profile"], registry=registry
    )
    execution_checkpoint_profile_validator = Draft202012Validator(
        schemas["execution_checkpoint_profile"], registry=registry
    )
    version2_vector_validator = Draft202012Validator(
        schemas["version2_vectors"], registry=registry
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
    persistence_vectors = 0
    persistence_profile_steps = 0
    execution_checkpoint_vectors = 0
    execution_checkpoint_coverage: set[str] = set()
    version2_vectors = 0
    version2_coverage: set[str] = set()

    for case in cases:
        test = load_fixture_document(case / "test.yaml")
        validate_driver_markers(test, case.name)
        profile_modes = {
            name
            for name in (
                "persistence_vectors",
                "persistence_profile",
                "execution_checkpoint_profile",
                "version2_vectors",
            )
            if name in test
        }
        if len(profile_modes) > 1:
            raise ValidationFailure(
                f"{case.name}: profile driver modes are mutually exclusive"
            )
        if "persistence_vectors" in test:
            validate_fixture_schema(test, persistence_vector_validator, case)
        if "persistence_profile" in test:
            validate_fixture_schema(test, persistence_profile_validator, case)
        if "execution_checkpoint_profile" in test:
            validate_fixture_schema(
                test, execution_checkpoint_profile_validator, case
            )
            validate_execution_checkpoint_schema_totality(
                test, execution_checkpoint_profile_validator, case
            )
        if "version2_vectors" in test:
            validate_fixture_schema(test, version2_vector_validator, case)
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
        elif "persistence_vectors" in test:
            validate_vector_references(
                case, test, referenced, referenced_artifacts
            )
            persistence_vectors += len(test["persistence_vectors"])
        elif "persistence_profile" in test:
            validate_profile_references(case, test, referenced_artifacts)
            persistence_profile_steps += len(
                test["persistence_profile"]["steps"]
            )
        elif "execution_checkpoint_profile" in test:
            case_coverage, vector_count = validate_execution_checkpoint_profile(
                case, test, referenced_artifacts
            )
            duplicate_coverage = execution_checkpoint_coverage & case_coverage
            if duplicate_coverage:
                raise ValidationFailure(
                    f"{case.name}: execution-checkpoint coverage repeated across "
                    f"cases: {sorted(duplicate_coverage)}"
                )
            execution_checkpoint_coverage.update(case_coverage)
            execution_checkpoint_vectors += vector_count
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
        if case.name == "112-migration-security-limits":
            validate_case_112(case, test)
        if case.name == "115-target-identity-decimal-projections":
            validate_case_115(case, test)
        if case.name == "persistence-02-atomic-aggregate-inbox-outbox-audit":
            validate_persistence_profile_02(case)

    all_test_files = {
        path for root in case_roots if root.is_dir() for path in root.rglob("test.yaml")
    }
    if len(all_test_files) != len(cases):
        raise ValidationFailure("duplicate or nested conformance test discovery")
    if execution_checkpoint_vectors:
        missing_coverage = (
            REQUIRED_EXECUTION_CHECKPOINT_COVERAGE
            - execution_checkpoint_coverage
        )
        unexpected_coverage = (
            execution_checkpoint_coverage
            - REQUIRED_EXECUTION_CHECKPOINT_COVERAGE
        )
        if missing_coverage or unexpected_coverage:
            raise ValidationFailure(
                "execution-checkpoint profile coverage mismatch: "
                f"missing={sorted(missing_coverage)}, "
                f"unexpected={sorted(unexpected_coverage)}"
            )
    if version2_vectors:
        missing_coverage = REQUIRED_VERSION2_COVERAGE - version2_coverage
        unexpected_coverage = version2_coverage - REQUIRED_VERSION2_COVERAGE
        if missing_coverage or unexpected_coverage:
            raise ValidationFailure(
                "version-2 coverage mismatch: "
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
        f"{scenarios} runtime scenarios, {persistence_vectors} persistence vectors, "
        f"{persistence_profile_steps} persistence-profile steps, and "
        f"{execution_checkpoint_vectors} execution-checkpoint vectors, "
        f"{version2_vectors} version-2 vectors"
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
