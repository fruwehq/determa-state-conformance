#!/usr/bin/env python3
"""Adversarial tests for durable-host relational validation."""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from validate_conformance import (
    ValidationFailure,
    host_profile_failure_code,
    load_fixture_document,
    normalize_raw_admission_request,
    validate_aggregate_against_bundle,
    validate_checkpoint_derivation,
    validate_cross_scope_pair,
    validate_durable_host_vectors,
    validate_persistence_derivation,
    validate_request_checkpoint_binding,
)
from generate_execution_checkpoint_profile import process

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance" / "profiles" / "execution-checkpoint"
PERSISTENCE_PROFILE = ROOT / "conformance" / "profiles" / "persistence"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def production_input_validator() -> Draft202012Validator:
    configured = os.environ.get("DETERMA_STATE_SPEC_ROOT")
    candidates = [
        Path(configured) if configured else None,
        ROOT / ".determa-state-spec",
        ROOT.parent / "determa-state-spec",
    ]
    spec_root = next(
        (candidate for candidate in candidates if candidate and candidate.is_dir()),
        None,
    )
    if spec_root is None:
        raise RuntimeError(
            "set DETERMA_STATE_SPEC_ROOT or check out the specification at "
            ".determa-state-spec"
        )
    schema_paths = (
        spec_root / "schema/aggregate-state-v2.schema.json",
        ROOT / "scripts/schemas/durable-host-inputs-v2.schema.json",
    )
    schemas = [load(path) for path in schema_paths]
    registry = Registry().with_resources(
        [
            (schema["$id"], Resource.from_contents(schema))
            for schema in schemas
        ]
    )
    return Draft202012Validator(schemas[1], registry=registry)


class DurableHostValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.input_validator = production_input_validator()

    def test_exact_committed_replay_precedes_stale_checkpoint_cas(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        request = load(case / "inputs-v2.json")["requests"]["replay_committed"]
        handled = load(case / "handled-checkpoint-v2.json")
        created = load(case / "created-checkpoint-v2.json")

        validate_request_checkpoint_binding(
            request, handled, {}, "exact replay", created
        )
        non_replay = copy.deepcopy(request)
        non_replay["envelopes"][0]["envelope"]["event_id"] = "not-committed"
        with self.assertRaisesRegex(
            ValidationFailure, "differs from checkpoint_before"
        ):
            validate_request_checkpoint_binding(
                non_replay, handled, {}, "stale non-replay", created
            )
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["replay_committed"]["envelopes"][0][
                "envelope"
            ].update(event_id="not-committed"),
            "differs from checkpoint_before",
        )

    def test_stale_replay_checkpoint_identity_must_be_historical(self) -> None:
        mutations = (
            ("root_instance_id", "unrelated-root"),
            ("revision", "9"),
            ("digest", "sha256:" + "0" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                self._assert_complete_case_mutation_fails(
                    lambda requests, field=field, value=value: requests[
                        "replay_committed"
                    ]["expected_checkpoint"].update({field: value}),
                    "differs from checkpoint_before",
                )
        self._assert_complete_test_mutation_fails(
            lambda test: next(
                vector
                for vector in test["durable_host_vectors"]
                if vector["name"] == "committed_replay_read_only"
            ).update(historical_checkpoint="accepted-checkpoint-v2.json"),
            "differs from checkpoint_before",
        )

    def test_changed_stale_same_identity_reaches_conflict_precedence(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        requests = load(case / "inputs-v2.json")["requests"]
        handled = load(case / "handled-checkpoint-v2.json")
        created = load(case / "created-checkpoint-v2.json")
        validate_request_checkpoint_binding(
            requests["stale_replay_conflict"],
            handled,
            {},
            "stale identity conflict",
            created,
        )

    def test_stale_writer_requires_explicit_current_store_checkpoint(self) -> None:
        case = PROFILE / "checkpoint-01-native-lifecycle"
        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            test = load_fixture_document(mutated_case / "test.yaml")
            vector = next(
                item
                for item in test["durable_host_vectors"]
                if item["name"] == "checkpoint_stale_writer"
            )
            del vector["stored_checkpoint_before"]
            with self.assertRaisesRegex(
                ValidationFailure, "must be declared together"
            ):
                validate_durable_host_vectors(
                    mutated_case,
                    test,
                    set(mutated_case.glob("*.json")),
                    self.input_validator,
                )

    def test_stale_writer_store_identity_is_request_derived(self) -> None:
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["concurrent_loser"][
                "writer_checkpoint_context"
            ].update(
                stored_checkpoint=copy.deepcopy(
                    requests["concurrent_loser"]["writer_checkpoint_context"][
                        "presented_checkpoint"
                    ]
                )
            ),
            "writer checkpoint context does not match",
        )

    def test_stale_tombstone_names_explicit_presented_and_stored_states(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        test = load_fixture_document(case / "test.yaml")
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "stale_tombstone_rejection"
        )
        request = load(case / "inputs-v2.json")["requests"]["stale_tombstone"]
        self.assertEqual(vector["checkpoint_before"], "handled-checkpoint-v2.json")
        self.assertEqual(
            vector["stored_checkpoint_before"], "bounded-checkpoint-v2.json"
        )
        self.assertNotEqual(
            request["writer_checkpoint_context"]["presented_checkpoint"],
            request["writer_checkpoint_context"]["stored_checkpoint"],
        )

    def test_batch_precedence_is_global_across_members(self) -> None:
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["global_batch_precedence"]["envelopes"][1].update(
                delivery_mode="input"
            ),
            "admission failure is not request-derived",
        )

    def test_correlation_requires_presence_not_retained_effect_lookup(self) -> None:
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["invalid_correlation"]["envelopes"][0][
                "envelope"
            ].update(correlation_id="caller-owned-correlation"),
            "admission failure is not request-derived",
        )

    def test_unhandled_delivery_allocates_no_logical_step(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        request = load(case / "inputs-v2.json")["requests"]["unhandled"]
        result = load(case / "results-v2.json")["results"]["committed"]
        before = load(case / "unhandled-accepted-checkpoint-v2.json")
        after = load(case / "unhandled-checkpoint-v2.json")
        after["root_record"]["aggregate_state"]["next_logical_step_sequence"] = "2"
        with self.assertRaisesRegex(ValidationFailure, "logical step count"):
            validate_checkpoint_derivation(
                request,
                result,
                before,
                after,
                "unhandled mutation",
                case / "machine.yaml",
            )

    def test_stale_pruning_must_have_a_newer_cutoff(self) -> None:
        case = PROFILE / "checkpoint-03-native-retention"
        request = load(case / "inputs-v2.json")["requests"]["prune_stale"]
        request["cutoff_receipt_sequence"] = "2"
        result = load(case / "results-v2.json")["results"]["stale"]
        current = load(case / "completed-checkpoint-v2.json")
        with self.assertRaisesRegex(ValidationFailure, "newer mutation"):
            validate_checkpoint_derivation(
                request,
                result,
                current,
                current,
                "stale prune mutation",
                case / "machine.yaml",
            )

    def test_running_root_is_required_for_tombstone_rejection(self) -> None:
        case = PROFILE / "checkpoint-03-native-retention"
        request = load(case / "inputs-v2.json")["requests"]["tombstone_running"]
        result = load(case / "results-v2.json")["results"]["running_root"]
        completed = load(case / "completed-checkpoint-v2.json")
        with self.assertRaisesRegex(ValidationFailure, "running root"):
            validate_checkpoint_derivation(
                request,
                result,
                completed,
                completed,
                "terminal tombstone mutation",
                case / "machine.yaml",
            )

    def test_combined_persistence_transaction_uses_one_revision(self) -> None:
        case = (
            PERSISTENCE_PROFILE
            / "persistence-02-atomic-aggregate-inbox-outbox-audit"
        )
        request = load(case / "inputs-v2.json")["requests"]["process"]
        result = load(case / "results-v2.json")["results"]["committed"]
        before = load(case / "initial-store-v2.json")
        after = load(case / "committed-store-v2.json")
        after["checkpoint"]["revision"] = "2"
        descriptor = load(case / "migration-descriptor-v2.json")
        with self.assertRaisesRegex(ValidationFailure, "exactly once"):
            validate_persistence_derivation(
                request,
                result,
                before,
                after,
                "combined persistence mutation",
                {"migration-descriptor-v2.json": descriptor},
            )

    def test_spawned_completion_disposes_the_child(self) -> None:
        case = PROFILE / "checkpoint-06-terminal-spawned-host-trace"

        def retain_completed_child(document: dict) -> None:
            before = load(case / "spawned-root-pending-checkpoint-v2.json")
            child = next(
                copy.deepcopy(runtime)
                for runtime in before["root_record"]["aggregate_state"]["runtimes"]
                if runtime["relation"]["kind"] == "owned_spawned_instance"
            )
            child["status"] = "completed"
            child["active_leaf_state_definition_pointers"] = []
            child["active_state_activations"] = []
            child["variables"] = []
            child["ready_mailbox"] = []
            document["root_record"]["aggregate_state"]["runtimes"].append(child)

        self._assert_case_artifact_mutation_fails(
            case,
            "spawned-child-terminal-checkpoint-v2.json",
            retain_completed_child,
            "spawned completion disposal",
        )

    def test_instance_reference_machine_version_is_logically_integer(self) -> None:
        case = PROFILE / "checkpoint-06-terminal-spawned-host-trace"
        checkpoint = load(case / "spawned-root-pending-checkpoint-v2.json")
        aggregate = checkpoint["root_record"]["aggregate_state"]
        owner = next(
            runtime
            for runtime in aggregate["runtimes"]
            if runtime["relation"]["kind"] == "root"
        )
        reference = next(
            variable
            for variable in owner["variables"]
            if variable["variable_declaration_pointer"].endswith(
                "/payment_reference"
            )
        )["value"]
        fields = dict(reference[1])
        self.assertEqual(fields["machine_version"], ["integer", "1"])
        fields["machine_version"] = ["string", "1"]
        reference[1] = [[name, fields[name]] for name, _ in reference[1]]
        with self.assertRaisesRegex(
            ValidationFailure, "machine_version is not a canonical positive integer"
        ):
            validate_aggregate_against_bundle(aggregate, case / "machine.yaml")

    def test_every_stale_instance_reference_field_is_validated(self) -> None:
        case = PROFILE / "checkpoint-06-terminal-spawned-host-trace"
        checkpoint = load(case / "spawned-child-terminal-checkpoint-v2.json")
        baseline = checkpoint["root_record"]["aggregate_state"]
        mutations = {
            "root_instance_id": ["integer", "42"],
            "instance_id": ["string", ""],
            "machine_id": ["boolean", True],
            "machine_version": ["integer", "01"],
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                aggregate = copy.deepcopy(baseline)
                owner = next(
                    runtime
                    for runtime in aggregate["runtimes"]
                    if runtime["relation"]["kind"] == "root"
                )
                reference = next(
                    variable
                    for variable in owner["variables"]
                    if variable["variable_declaration_pointer"].endswith(
                        "/payment_reference"
                    )
                )["value"]
                fields = dict(reference[1])
                fields[field] = replacement
                reference[1] = [[name, fields[name]] for name, _ in reference[1]]
                with self.assertRaisesRegex(
                    ValidationFailure, f"instance reference {field}"
                ):
                    validate_aggregate_against_bundle(
                        aggregate, case / "machine.yaml"
                    )

    def test_outbox_effects_are_derived_from_machine_actions(self) -> None:
        case = PROFILE / "checkpoint-02-native-outbox"
        request = load(case / "inputs-v2.json")["requests"]["pending"]
        result = load(case / "results-v2.json")["results"][
            "processing_committed"
        ]
        before = load(case / "accepted-checkpoint-v2.json")
        after = load(case / "pending-checkpoint-v2.json")
        after["pending_outbox_intents"][0]["intent"]["effect_id"] = (
            "sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(
            ValidationFailure, "external effects are not machine-derived"
        ):
            validate_checkpoint_derivation(
                request, result, before, after, "effect mutation", case / "machine.yaml"
            )

    def test_external_effect_derivation_fails_closed_on_guarded_handler(self) -> None:
        case = PROFILE / "checkpoint-02-native-outbox"
        with tempfile.TemporaryDirectory() as temporary:
            machine_path = Path(temporary) / "machine.yaml"
            machine_path.write_text(
                (case / "machine.yaml").read_text(encoding="utf-8").replace(
                    "        emit_outputs:\n",
                    '        emit_outputs:\n          guard: "false"\n',
                    1,
                ),
                encoding="utf-8",
            )
            before = load(case / "accepted-checkpoint-v2.json")
            with self.assertRaisesRegex(RuntimeError, "cannot select guarded"):
                process(before, bundle_path=machine_path)

            request = load(case / "inputs-v2.json")["requests"]["pending"]
            result = load(case / "results-v2.json")["results"][
                "processing_committed"
            ]
            after = load(case / "pending-checkpoint-v2.json")
            with self.assertRaisesRegex(
                ValidationFailure, "handler selection is unsupported"
            ):
                validate_checkpoint_derivation(
                    request,
                    result,
                    before,
                    after,
                    "guard mutation",
                    machine_path,
                )

    def test_deletion_probe_requires_a_retained_referenced_effect(self) -> None:
        case = PROFILE / "checkpoint-02-native-outbox"
        request = load(case / "inputs-v2.json")["requests"]["delete"]
        result = load(case / "results-v2.json")["results"]["deletion_rejected"]
        checkpoint = load(case / "effect-tombstone-checkpoint-v2.json")
        request["target"]["effect_id"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            ValidationFailure, "deletion target is not retained and referenced"
        ):
            validate_checkpoint_derivation(
                request,
                result,
                checkpoint,
                checkpoint,
                "effect deletion mutation",
                case / "machine.yaml",
            )

    def test_deletion_probe_requires_the_checkpoint_root_identity(self) -> None:
        case = PROFILE / "checkpoint-03-native-retention"
        request = load(case / "inputs-v2.json")["requests"]["delete"]
        result = load(case / "results-v2.json")["results"][
            "deletion_unsupported"
        ]
        checkpoint = load(case / "root-tombstone-checkpoint-v2.json")
        request["target"]["root_instance_id"] = "different-root"
        with self.assertRaisesRegex(
            ValidationFailure, "does not identify this checkpoint"
        ):
            validate_checkpoint_derivation(
                request,
                result,
                checkpoint,
                checkpoint,
                "root deletion mutation",
                case / "machine.yaml",
            )

    def test_deletion_probe_operation_identity_cannot_conflict_with_history(self) -> None:
        case = PROFILE / "checkpoint-03-native-retention"
        request = load(case / "inputs-v2.json")["requests"]["delete"]
        result = load(case / "results-v2.json")["results"][
            "deletion_unsupported"
        ]
        checkpoint = load(case / "root-tombstone-checkpoint-v2.json")
        request["request_id"] = "root-tombstone"
        request["deletion_operation_id"] = "root-tombstone"
        with self.assertRaisesRegex(
            ValidationFailure, "conflicts with retained history"
        ):
            validate_checkpoint_derivation(
                request,
                result,
                checkpoint,
                checkpoint,
                "deletion identity mutation",
                case / "machine.yaml",
            )

    def test_completed_transition_allocates_final_state_activation(self) -> None:
        case = PROFILE / "checkpoint-03-native-retention"
        request = load(case / "inputs-v2.json")["requests"]["complete_process"]
        result = load(case / "results-v2.json")["results"][
            "processing_committed"
        ]
        before = load(case / "completion-accepted-checkpoint-v2.json")
        after = load(case / "completed-checkpoint-v2.json")
        runtime = after["root_record"]["aggregate_state"]["runtimes"][0]
        runtime["next_state_activation_sequences"] = [
            item
            for item in runtime["next_state_activation_sequences"]
            if not item["definition_pointer"].endswith("/states/finished")
        ]
        with self.assertRaisesRegex(
            ValidationFailure, "did not allocate its state activation"
        ):
            validate_checkpoint_derivation(
                request,
                result,
                before,
                after,
                "completion mutation",
                case / "machine.yaml",
            )

    def test_raw_malformed_member_precedes_normalized_members(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        test = load_fixture_document(case / "test.yaml")
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        _, malformed = normalize_raw_admission_request(
            vector["raw_admission_request"],
            "raw baseline",
            self.input_validator,
        )
        self.assertTrue(malformed)
        self._assert_complete_test_mutation_fails(
            self._substitute_valid_raw_member,
            "admission failure is not request-derived",
        )

    def test_duplicate_keys_in_raw_member_are_malformed(self) -> None:
        self._assert_raw_member_mutation_is_malformed(
            self._substitute_duplicate_key_raw_member
        )

    def test_escaped_unpaired_surrogate_in_raw_member_is_malformed(self) -> None:
        self._assert_raw_member_mutation_is_malformed(
            self._substitute_unpaired_surrogate_raw_member
        )

    def test_non_finite_number_in_raw_member_is_malformed(self) -> None:
        self._assert_raw_member_mutation_is_malformed(
            self._substitute_non_finite_raw_member
        )

    def test_empty_claimed_capabilities_fail_every_host_profile(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        requests = load(case / "inputs-v2.json")["requests"]
        positives = [
            value
            for name, value in requests.items()
            if name.startswith("profile_") and name.endswith("_positive")
        ]
        self.assertEqual(len(positives), 6)
        for request in positives:
            mutated = copy.deepcopy(request)
            mutated["store_capabilities"] = []
            mutated["host_guarantees"] = []
            self.assertEqual(
                host_profile_failure_code(mutated),
                "adapter_capability_mismatch",
                request["host_profile"],
            )
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["profile_durable_embedded_positive"].update(
                store_capabilities=[], host_guarantees=[]
            ),
            "composed profile result is not request-derived",
        )

    def test_cross_scope_portable_identity_divergence_fails(self) -> None:
        left, right = self._scope_pair()
        right["portable_identity"] = "different-root"
        with self.assertRaisesRegex(ValidationFailure, "portable identities"):
            validate_cross_scope_pair([left, right], "identity mutation")
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["scope_b"].update(
                portable_identity="different-root"
            ),
            "outside the selected authorized scope",
        )

    def test_cross_scope_effect_identity_divergence_fails(self) -> None:
        left, right = self._scope_pair()
        right["effect_id"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValidationFailure, "portable identities"):
            validate_cross_scope_pair([left, right], "effect mutation")
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["scope_b"].update(
                effect_id="sha256:" + "0" * 64
            ),
            "outside the selected authorized scope",
        )

    def test_scope_requests_receive_only_the_selected_scope_record(self) -> None:
        left, right = self._scope_pair()
        for operation in (left, right):
            self.assertEqual(len(operation["store_records"]), 1)
            self.assertEqual(
                operation["store_records"][0]["scope_id"],
                operation["scope"]["scope_id"],
            )
        validate_cross_scope_pair([left, right], "selected-only positive")

    def test_cross_scope_record_exposure_fails(self) -> None:
        left, right = self._scope_pair()
        left["store_records"].append(copy.deepcopy(right["store_records"][0]))
        with self.assertRaisesRegex(ValidationFailure, "relationally isolated"):
            validate_cross_scope_pair([left, right], "exposure mutation")
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["scope_a"]["store_records"].append(
                copy.deepcopy(requests["scope_b"]["store_records"][0])
            ),
            "outside the selected authorized scope",
        )

    def test_unauthorized_scope_receives_no_store_records(self) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        requests = load(case / "inputs-v2.json")["requests"]
        self.assertEqual(requests["scope_unauthorized"]["store_records"], [])
        self._assert_complete_case_mutation_fails(
            lambda values: values["scope_unauthorized"]["store_records"].append(
                copy.deepcopy(values["scope_b"]["store_records"][0])
            ),
            "outside the selected authorized scope",
        )

    def _scope_pair(self) -> tuple[dict, dict]:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        requests = load(case / "inputs-v2.json")["requests"]
        return copy.deepcopy(requests["scope_a"]), copy.deepcopy(requests["scope_b"])

    def _assert_complete_case_mutation_fails(self, mutate, pattern: str) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            inputs_path = mutated_case / "inputs-v2.json"
            inputs = load(inputs_path)
            mutate(inputs["requests"])
            inputs_path.write_text(
                json.dumps(inputs, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            test = load_fixture_document(mutated_case / "test.yaml")
            with self.assertRaisesRegex(ValidationFailure, pattern):
                validate_durable_host_vectors(
                    mutated_case,
                    test,
                    set(mutated_case.glob("*.json")),
                    self.input_validator,
                )

    def _assert_case_artifact_mutation_fails(
        self, case: Path, filename: str, mutate, pattern: str
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            artifact_path = mutated_case / filename
            document = load(artifact_path)
            mutate(document)
            artifact_path.write_text(
                json.dumps(document, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            test = load_fixture_document(mutated_case / "test.yaml")
            with self.assertRaisesRegex(ValidationFailure, pattern):
                validate_durable_host_vectors(
                    mutated_case,
                    test,
                    set(mutated_case.glob("*.json")),
                    self.input_validator,
                )

    def _assert_complete_test_mutation_fails(self, mutate, pattern: str) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            test = load_fixture_document(mutated_case / "test.yaml")
            mutate(test)
            with self.assertRaisesRegex(ValidationFailure, pattern):
                validate_durable_host_vectors(
                    mutated_case,
                    test,
                    set(mutated_case.glob("*.json")),
                    self.input_validator,
                )

    def _assert_complete_test_mutation_passes(self, mutate) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            test = load_fixture_document(mutated_case / "test.yaml")
            mutate(test)
            validate_durable_host_vectors(
                mutated_case,
                test,
                set(mutated_case.glob("*.json")),
                self.input_validator,
            )

    def _assert_raw_member_mutation_is_malformed(self, mutate) -> None:
        case = PROFILE / "checkpoint-07-complete-host-contract"
        test = load_fixture_document(case / "test.yaml")
        mutate(test)
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        _, malformed = normalize_raw_admission_request(
            vector["raw_admission_request"],
            "strict raw mutation",
            self.input_validator,
        )
        self.assertTrue(malformed)
        self._assert_complete_test_mutation_passes(mutate)

    def _substitute_valid_raw_member(self, test: dict) -> None:
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        sources = vector["raw_admission_request"]["ordered_member_sources"]
        replacement = copy.deepcopy(sources[1])
        member = replacement["json_value"]
        member["delivery_mode"] = "input"
        member["envelope"]["event_id"] = "valid-substituted-member"
        member["envelope"]["cause_id"] = "valid-substituted-member"
        sources[0] = {
            "utf8_json": json.dumps(
                member, ensure_ascii=True, separators=(",", ":")
            )
        }
        _, malformed = normalize_raw_admission_request(
            vector["raw_admission_request"],
            "valid substitution",
            self.input_validator,
        )
        if malformed:
            raise AssertionError("valid raw member substitution remained malformed")

    def _substitute_duplicate_key_raw_member(self, test: dict) -> None:
        self._substitute_valid_raw_member(test)
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        source = vector["raw_admission_request"]["ordered_member_sources"][0]
        source["utf8_json"] = source["utf8_json"].replace(
            '{"delivery_mode":"input"',
            '{"delivery_mode":"input","delivery_mode":"input"',
            1,
        )

    def _substitute_unpaired_surrogate_raw_member(self, test: dict) -> None:
        self._substitute_valid_raw_member(test)
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        source = vector["raw_admission_request"]["ordered_member_sources"][0]
        source["utf8_json"] = source["utf8_json"].replace(
            '"event":"increment"', '"event":"\\ud800"', 1
        )

    def _substitute_non_finite_raw_member(self, test: dict) -> None:
        self._substitute_valid_raw_member(test)
        vector = next(
            item
            for item in test["durable_host_vectors"]
            if item["name"] == "malformed_batch"
        )
        source = vector["raw_admission_request"]["ordered_member_sources"][0]
        source["utf8_json"] = source["utf8_json"].replace('"1"', "NaN", 1)


if __name__ == "__main__":
    unittest.main()
