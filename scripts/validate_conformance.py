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
NON_FINITE_DOUBLE_MARKERS = frozenset(
    {"nan", "positive_infinity", "negative_infinity"}
)
INSTANCE_REFERENCE_FIELDS = frozenset(
    {"root_instance_id", "instance_id", "machine_id", "machine_version"}
)
ARTIFACT_KINDS = {
    "aggregate_state": "aggregate-state.schema.json",
    "migration_descriptor": "migration-descriptor.schema.json",
    "aggregate_state_package": "aggregate-state-package.schema.json",
    "execution_checkpoint": "execution-checkpoint.schema.json",
}
DRIVER_ARTIFACT_KINDS = {
    "artifact_resolver": "artifact-resolver.schema.json",
    "resource_limits": "resource-limits.schema.json",
    "execution_checkpoint_inputs": "execution-checkpoint-inputs.schema.json",
    "execution_checkpoint_core_evidence": (
        "execution-checkpoint-core-evidence.schema.json"
    ),
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
    REQUIRED_EXECUTION_CHECKPOINT_COVERAGE
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
    "migration_descriptor": (
        "migration_descriptor_format",
        "determa.aggregate_migration",
        "migration_descriptor_schema_version",
        1,
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
    "execution_checkpoint": (
        "execution_checkpoint_format",
        "determa.execution_checkpoint",
        "execution_checkpoint_schema_version",
        1,
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


def verify_artifact_digest(kind: str, document: Any, path: Path) -> None:
    if kind == "aggregate_state":
        digest = document.get("aggregate_state_digest")
        without_digest = dict(document)
        without_digest.pop("aggregate_state_digest", None)
        expected = hash_value(
            ["determa-aggregate-state-digest-1", without_digest]
        )
        if digest != expected:
            raise ValidationFailure(
                f"{path}: aggregate_state_digest {digest!r} != {expected!r}"
            )
    elif kind == "migration_descriptor":
        digest = document.get("migration_descriptor_digest")
        without_digest = dict(document)
        without_digest.pop("migration_descriptor_digest", None)
        expected = hash_value(
            ["determa-migration-descriptor-1", without_digest]
        )
        if digest != expected:
            raise ValidationFailure(
                f"{path}: migration_descriptor_digest {digest!r} != {expected!r}"
            )
    elif kind == "aggregate_state_package":
        verify_artifact_digest("aggregate_state", document["aggregate_state"], path)
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
            verify_artifact_digest("migration_descriptor", descriptor, path)
            digest = descriptor["migration_descriptor_digest"]
            if digest in descriptor_digests:
                raise ValidationFailure(
                    f"{path}: duplicate descriptor attachment {digest}"
                )
            descriptor_digests.add(digest)
    elif kind == "execution_checkpoint":
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            verify_artifact_digest(
                "aggregate_state", root_record["aggregate_state"], path
            )
        digest = document.get("execution_checkpoint_digest")
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        expected = hash_value(
            ["determa-execution-checkpoint-digest-1", without_digest]
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
        if aggregate["root_instance_id"] != root_id:
            raise ValidationFailure("checkpoint: retained aggregate root mismatch")
        creation_id = aggregate["creation_id"]
        root_runtime_id = aggregate["root_runtime_id"]
    else:
        creation_id = root_record["creation_id"]
        root_runtime_id = root_record["root_runtime_id"]
    if creation["creation_id"] != creation_id:
        raise ValidationFailure("checkpoint: creation identity mismatch")

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
    if kind == "execution_checkpoint":
        root_record = document["root_record"]
        if root_record["status"] == "retained":
            try:
                verify_artifact_digest(
                    "aggregate_state",
                    root_record["aggregate_state"],
                    Path("<embedded aggregate>"),
                )
            except ValidationFailure:
                return structural_error
        without_digest = dict(document)
        without_digest.pop("execution_checkpoint_digest", None)
        expected_digest = hash_value(
            ["determa-execution-checkpoint-digest-1", without_digest]
        )
        if document["execution_checkpoint_digest"] != expected_digest:
            return "execution_checkpoint_digest_mismatch"
        try:
            validate_execution_checkpoint_semantics(document)
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
    vectors = test["execution_checkpoint_profile"]["vectors"]
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

    return coverage, len(vectors)


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

    for case in cases:
        test = load_fixture_document(case / "test.yaml")
        validate_driver_markers(test, case.name)
        profile_modes = {
            name
            for name in (
                "persistence_vectors",
                "persistence_profile",
                "execution_checkpoint_profile",
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

    return (
        f"validated {len(document_paths)} bundle documents across {len(cases)} "
        f"case directories against spec {spec_version}; "
        f"{artifact_documents} JSON artifacts, "
        f"{source_rejections} expected source rejections, "
        f"{structural_rejections} expected structural rejections, "
        f"{static_schema_passes} schema-valid static documents, and "
        f"{scenarios} runtime scenarios, {persistence_vectors} persistence vectors, "
        f"{persistence_profile_steps} persistence-profile steps, and "
        f"{execution_checkpoint_vectors} execution-checkpoint vectors"
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
