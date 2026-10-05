#!/usr/bin/env python3
"""Adversarial tests for substitution-free version-1 vector validation."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from validate_conformance import (
    ValidationFailure,
    load_fixture_document,
    validate_initial_identity_oracles,
    validate_version1_vectors,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_CASE = ROOT / "conformance/core/120-native-v1-definition-package"
MAILBOX_CASE = ROOT / "conformance/core/117-version1-mailboxes"
MIGRATION_CASE = ROOT / "conformance/core/122-native-v1-migration-execution"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_case(
    case: Path,
    *,
    test: dict | None = None,
    artifact_overrides: dict[str, dict] | None = None,
) -> None:
    test = test or load_fixture_document(case / "test.yaml")
    bundle_paths = {
        case / entry["file"] for entry in test.get("static", {}).get("documents", [])
    }
    artifact_paths = {
        case / entry["file"] for entry in test["artifacts"]["documents"]
    }
    validate_version1_vectors(
        case,
        test,
        bundle_paths,
        artifact_paths,
        artifact_overrides=artifact_overrides,
    )


class Version1ValidatorTests(unittest.TestCase):
    def test_nonfaulting_deferral_cannot_consume_logical_step(self) -> None:
        from generate_version1_vectors import seal_aggregate

        result = load(MAILBOX_CASE / "repeated-deferral-result.json")
        result["state"]["next_logical_step_sequence"] = str(
            int(result["state"]["next_logical_step_sequence"]) + 1
        )
        result["state"] = seal_aggregate(result["state"])
        with self.assertRaisesRegex(ValidationFailure, "deferral consumed a logical-step"):
            validate_case(
                MAILBOX_CASE,
                artifact_overrides={"repeated-deferral-result.json": result},
            )

    def test_old_initialization_hashes_are_rejected(self) -> None:
        for name, old_hash, field in (
            (
                "75-root-initialization-fault",
                "sha256:1fd5180e9f39fdc5eeb458f13c58acf9b70e6cad17c41cd0e4144cfa8084e110",
                "cause",
            ),
            (
                "86-initial-component-completion-order",
                "sha256:c605f731291ed327389d465ebc0b9881c061919e5888fcc6327637af0996a152",
                "event",
            ),
        ):
            with self.subTest(name=name):
                case = ROOT / "conformance/core" / name
                test = load_fixture_document(case / "test.yaml")
                if field == "cause":
                    test["create"]["expect"]["fault"]["cause_id"] = old_hash
                else:
                    test["steps"][0]["expect"]["emissions"][0]["event_id"] = old_hash
                with self.assertRaisesRegex(ValidationFailure, "identit"):
                    validate_initial_identity_oracles(
                        case, test, case / "machine.yaml",
                        f"conformance:{name}:root", f"conformance:{name}:create",
                    )

    def test_wrong_combined_delivery_digest_is_rejected_with_valid_results(self) -> None:
        stale_digests = {
            "migration_then_processing_handled": "sha256:4852e6c0a8c08aaac931556bf767f5d37cf982ca1befa897631c1212a8364a02",
            "migration_then_processing_unhandled": "sha256:f3ee7378c14aee3d99ce24c933f4d4d95e3dfd9e9fb7bd4ef70d2d45fab688a3",
            "migration_then_processing_faulted": "sha256:33e8e85e8d9ff1cb4a8ab99284a4097eef6a4697f4a9c7a39a4f0684cb21d0fa",
            "migration_then_processing_rejected": "sha256:869f263e775656a2bea013bc8473f0075a4835ada36a1d23ba50d94f3b4c5a94",
        }
        for name, stale_digest in stale_digests.items():
            with self.subTest(name=name):
                requests = load(MIGRATION_CASE / "operation-inputs.json")
                requests[name]["delivery"]["envelope_digest"] = stale_digest
                with self.assertRaisesRegex(
                    ValidationFailure, "combined operation envelope digest"
                ):
                    validate_case(
                        MIGRATION_CASE,
                        artifact_overrides={"operation-inputs.json": requests},
                    )

    def test_exact_typed_failure_response_binding(self) -> None:
        responses = load(PACKAGE_CASE / "operation-failures.json")
        key = next(iter(responses["responses"]))
        responses["responses"][key]["code"] = "invalid_aggregate_state"
        with self.assertRaisesRegex(ValidationFailure, "exact typed failure response differs"):
            validate_case(
                PACKAGE_CASE,
                artifact_overrides={"operation-failures.json": responses},
            )

    def test_failure_response_schema_rejects_missing_and_extra_fields(self) -> None:
        schema = load(ROOT / "scripts/schemas/version1-operation-failures.schema.json")
        document = load(PACKAGE_CASE / "operation-failures.json")
        key = next(iter(document["responses"]))
        for mutation in (lambda body: body.pop("code"), lambda body: body.update(unexpected=True)):
            mutated = copy.deepcopy(document)
            mutation(mutated["responses"][key])
            with self.subTest(mutated=mutated["responses"][key]):
                self.assertTrue(list(Draft202012Validator(schema).iter_errors(mutated)))

    def test_schema_valid_result_from_another_request_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationFailure, "replay mutated aggregate"):
            validate_case(
                MAILBOX_CASE,
                artifact_overrides={
                    "admission-success.json": load(MAILBOX_CASE / "replay-success.json")
                },
            )

    def test_schema_valid_request_substitution_is_rejected(self) -> None:
        requests = load(MAILBOX_CASE / "operation-inputs.json")
        requests["admit_two"] = copy.deepcopy(requests["equal_replay"])
        with self.assertRaisesRegex(ValidationFailure, "result count differs from request"):
            validate_case(
                MAILBOX_CASE,
                artifact_overrides={"operation-inputs.json": requests},
            )

    def test_resealed_aggregate_requires_available_definition(self) -> None:
        requests = load(PACKAGE_CASE / "operation-inputs.json")
        requests["matching_definition"]["definition_resolver"]["definitions"] = []
        with self.assertRaisesRegex(ValidationFailure, "unresolved definition"):
            validate_case(
                PACKAGE_CASE,
                artifact_overrides={"operation-inputs.json": requests},
            )

    def test_package_restore_intent_is_required_and_closed(self) -> None:
        schema = load(ROOT / "scripts/schemas/version1-operation-inputs.schema.json")
        requests = load(PACKAGE_CASE / "operation-inputs.json")
        validator = Draft202012Validator(schema)
        self.assertFalse(list(validator.iter_errors(requests)))

        missing = copy.deepcopy(requests)
        del missing["valid_self_contained_package"]["intent"]
        self.assertTrue(list(validator.iter_errors(missing)))

        unknown = copy.deepcopy(requests)
        unknown["valid_self_contained_package"]["intent"] = "restore_by_magic"
        self.assertTrue(list(validator.iter_errors(unknown)))

    def test_package_restore_result_is_derived_from_intent(self) -> None:
        requests = load(PACKAGE_CASE / "operation-inputs.json")
        requests["valid_self_contained_package"]["intent"] = (
            "restore_and_apply_migration_route"
        )
        requests["attachments_seed_empty_resolver_and_drive_route"]["intent"] = (
            "restore_aggregate"
        )
        with self.assertRaisesRegex(
            ValidationFailure, "package restore result is not request-derived"
        ):
            validate_case(
                PACKAGE_CASE,
                artifact_overrides={"operation-inputs.json": requests},
            )

    def test_identical_package_requests_are_rejected_across_pointers(self) -> None:
        requests = load(PACKAGE_CASE / "operation-inputs.json")
        requests["valid_self_contained_package"] = copy.deepcopy(
            requests["attachments_seed_empty_resolver_and_drive_route"]
        )
        test = load_fixture_document(PACKAGE_CASE / "test.yaml")
        vector = next(
            vector
            for vector in test["version1_vectors"]
            if vector["name"] == "valid_self_contained_package"
        )
        vector["expect"]["exact_result_file"] = (
            "package-attachments_seed_empty_resolver_and_drive_route-result.json"
        )
        with self.assertRaisesRegex(
            ValidationFailure, "duplicates executable input"
        ):
            validate_case(
                PACKAGE_CASE,
                test=test,
                artifact_overrides={"operation-inputs.json": requests},
            )

    def test_package_behavior_does_not_depend_on_coverage_labels(self) -> None:
        test = load_fixture_document(PACKAGE_CASE / "test.yaml")
        vectors = {vector["name"]: vector for vector in test["version1_vectors"]}
        left = vectors["valid_self_contained_package"]
        right = vectors["attachments_seed_empty_resolver_and_drive_route"]
        left["covers"], right["covers"] = right["covers"], left["covers"]
        validate_case(PACKAGE_CASE, test=test)

    def test_system_emission_indices_are_lifecycle_operation_local(self) -> None:
        filenames = (
            "chained-internal-result.json",
            "internal-emission-retained-faulted-result.json",
            "internal-emission-runtime-completed-result.json",
        )
        for filename in filenames:
            with self.subTest(filename=filename):
                result = load(MAILBOX_CASE / filename)
                system_emission = next(
                    emission
                    for emission in result["emissions"]
                    if emission["kind"] == "internal_mailbox"
                    and any(
                        entry["envelope"]["event_id"] == emission["event_id"]
                        and "system" in entry["envelope"]["source"]
                        for runtime in result["state"]["runtimes"]
                        for entry in runtime["ready_mailbox"]
                    )
                )
                self.assertEqual(system_emission["emission_index"], "0")
                system_emission["emission_index"] = "1"
                with self.assertRaisesRegex(
                    ValidationFailure, "lifecycle-operation-local"
                ):
                    validate_case(
                        MAILBOX_CASE,
                        artifact_overrides={filename: result},
                    )


if __name__ == "__main__":
    unittest.main()
