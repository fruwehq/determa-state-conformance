#!/usr/bin/env python3
"""Adversarial tests for substitution-free version-2 vector validation."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from validate_conformance import (
    ValidationFailure,
    load_fixture_document,
    validate_version2_vectors,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_CASE = ROOT / "conformance/core/120-native-v2-definition-package"
MAILBOX_CASE = ROOT / "conformance/core/117-version2-mailboxes"


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
    validate_version2_vectors(
        case,
        test,
        bundle_paths,
        artifact_paths,
        artifact_overrides=artifact_overrides,
    )


class Version2ValidatorTests(unittest.TestCase):
    def test_package_restore_intent_is_required_and_closed(self) -> None:
        schema = load(ROOT / "scripts/schemas/version2-operation-inputs.schema.json")
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
            for vector in test["version2_vectors"]
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
        vectors = {vector["name"]: vector for vector in test["version2_vectors"]}
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
