"""Evidence routing for conditional store decisions and native store tests.

These driver rules grant no production capability. Native assertions live in the
reviewed implementation tests, never in caller-supplied capability reports.
"""

from __future__ import annotations

from pathlib import Path


POLICY_OPERATIONS = frozenset({
    "checkpoint_register_adapter_v1",
    "checkpoint_resolve_adapter_v1",
    "checkpoint_validate_capabilities_v1",
})
POLICY_LAYER = "conditional_adapter_policy"
POLICY_INVENTORY = {
    "checkpoint-03-native-retention": frozenset({
        "checkpoint_public_adapter_registry", "checkpoint_capability_composition",
    }),
    "checkpoint-07-complete-host-contract": frozenset({
        "bundled_adapter_registration", "third_party_adapter_registration",
        "vendor_adapter_scheme_registration", "vendor_adapter_scheme_resolution",
        "duplicate_adapter_registration", "unknown_adapter",
        "invalid_adapter_configuration", "adapter_capability_failure",
        "memory_boundary", "file_boundary", "sqlite_boundary", "postgresql_boundary",
        "durable_embedded_positive", "durable_embedded_negative",
        "exactly_once_positive", "exactly_once_negative",
        "broker_positive", "broker_negative",
        "strict_outbox_positive", "strict_outbox_negative",
        "compact_outbox_positive", "compact_outbox_negative",
        "shared_transaction_positive", "shared_transaction_negative",
    }),
}

# This independent inventory is not derived from fixture coverage labels.
# Each value is a required assertion contract for the implementation's native
# tests. Conditional vectors and reported capability flags cannot satisfy it.
OPERATIONAL_GATES = {
    "public_registration": "Bundled and third-party factories use the same public registration, configuration, capabilities and health path; direct injection uses the same verification.",
    "public_selection": "Generic vendor+https URI selection, duplicate registration without replacement, unknown schemes/references, and invalid configuration are exercised through the public API.",
    "executing_source": "Verify the actual executing factory and its transitive source/compiled implementation closure; replacing live executable bindings fails even if descriptor/source-file digests remain equal.",
    "configured_instance": "Bind claims to the actual native instance, exact provider identity and effective configuration read from that instance; wrong instances, sources, configurations and copied reports fail.",
    "current_health": "Changed effective configuration or current health invalidates/recomputes proof before the next requested operation; stale healthy reports cannot grant a capability.",
    "forged_evidence": "Caller-controlled verified/trusted flags and self-asserted claims fail before root load/create/process, using independently observed zero root accesses.",
    "memory_and_file": "Memory claims only ephemeral; actual file writes survive a clean restart without inventing crash durability or concurrency guarantees.",
    "sqlite_transactions": "Actual configured SQLite commit and rollback atomically cover application rows and checkpoints; restart preserves committed bytes and excludes rolled-back bytes.",
    "sqlite_configuration": "SQLite exact physical schema, synchronization, journal and connection topology are checked on the actual database before claiming supported durability.",
    "postgresql_transactions": "A live PostgreSQL service proves native shared application/checkpoint commit and rollback; an absent/unavailable service is unmet, never skipped success.",
    "postgresql_concurrency": "Real independent PostgreSQL sessions prove exactly one concurrent revision/digest winner, loser nonmutation and correct native transaction fate.",
    "postgresql_configuration": "A live PostgreSQL instance proves exact physical schema, isolation, locking and connection topology; incompatible configuration fails before root access.",
    "durable_processing": "Production admission/processing atomically retain complete first responses and equal replay, root no-reuse evidence, and crash-before/after-commit behavior.",
    "permanent_retention": "Actual permanent receipt retention supports exactly-once committed processing; bounded mode cannot satisfy it, and compaction preserves required dependency evidence.",
    "broker_composition": "Actual ingress acknowledges only after checkpoint commit, supports durable redelivery and an actual outbox worker; a store or hypothetical feature list alone fails.",
    "strict_outbox_composition": "Actual worker and store prove total outbox lifecycle, permanent terminal retention and no deletion of unresolved work.",
    "compact_outbox_composition": "Actual worker and store prove total outbox lifecycle and retention of every effect tombstone still referenced by a retained receipt.",
    "shared_transaction_composition": "The application actually uses the same native transaction for rows and checkpoint; store support without application participation cannot satisfy the profile.",
    "return_integrity": "Corrupting actual production policy returns or durable first/replay responses causes the corresponding runtime gate to fail; expected bodies are never reconstructed by the adapter.",
}


class AdapterEvidenceError(ValueError):
    pass


def validate_policy_case(case: Path, vectors: list[dict]) -> None:
    observed = []
    for vector in vectors:
        conditional = vector["operation"] in POLICY_OPERATIONS
        if conditional:
            if vector.get("evidence_layer") != POLICY_LAYER:
                raise AdapterEvidenceError(f"{case.name}: missing conditional adapter policy marker")
            if (vector["expect"]["mutation"] != "none"
                    or vector["expect"]["core_calls"] != 0
                    or vector.get("checkpoint_before") != vector.get("checkpoint_after")):
                raise AdapterEvidenceError(f"{case.name}: conditional policy cannot perform root operations")
            observed.append(vector["name"])
        elif "evidence_layer" in vector:
            raise AdapterEvidenceError(f"{case.name}: production operation cannot be conditional policy")
    if len(observed) != len(set(observed)) or set(observed) != POLICY_INVENTORY.get(case.name, set()):
        raise AdapterEvidenceError(f"{case.name}: exact conditional adapter policy inventory mismatch")


def validate_policy_case_inventory(cases: set[str]) -> None:
    if not set(POLICY_INVENTORY).issubset(cases):
        raise AdapterEvidenceError("missing conditional adapter policy case directory")
