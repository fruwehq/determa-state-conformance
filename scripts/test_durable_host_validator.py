#!/usr/bin/env python3
"""Adversarial tests for durable-host relational validation."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from validate_conformance import (
    ValidationFailure,
    host_profile_failure_code,
    load_fixture_document,
    validate_cross_scope_pair,
    validate_durable_host_vectors,
    validate_request_checkpoint_binding,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance" / "profiles" / "execution-checkpoint"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DurableHostValidatorTests(unittest.TestCase):
    def test_stale_replay_request_cannot_be_swapped_onto_another_before(self) -> None:
        case = PROFILE / "checkpoint-01-native-lifecycle"
        request = load(case / "inputs-v2.json")["requests"]["accept_replay"]
        processed = load(case / "processed-checkpoint-v2.json")
        accepted = load(case / "accepted-checkpoint-v2.json")

        validate_request_checkpoint_binding(request, processed, {}, "baseline")
        with self.assertRaisesRegex(
            ValidationFailure, "differs from checkpoint_before"
        ):
            validate_request_checkpoint_binding(request, accepted, {}, "stale swap")

        with tempfile.TemporaryDirectory() as temporary:
            mutated_case = Path(temporary) / case.name
            shutil.copytree(case, mutated_case)
            inputs_path = mutated_case / "inputs-v2.json"
            inputs = load(inputs_path)
            inputs["requests"]["accept_replay"]["expected_checkpoint"] = {
                "root_instance_id": accepted["root_instance_id"],
                "revision": accepted["revision"],
                "digest": accepted["execution_checkpoint_digest"],
            }
            inputs_path.write_text(
                json.dumps(inputs, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            test = load_fixture_document(mutated_case / "test.yaml")
            with self.assertRaisesRegex(
                ValidationFailure, "differs from checkpoint_before"
            ):
                validate_durable_host_vectors(
                    mutated_case, test, set(mutated_case.glob("*.json"))
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
            "scoped store records are not isolated",
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
            "scoped store records are not isolated",
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
                    mutated_case, test, set(mutated_case.glob("*.json"))
                )


if __name__ == "__main__":
    unittest.main()
