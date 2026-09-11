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
    normalize_raw_admission_request,
    validate_cross_scope_pair,
    validate_durable_host_vectors,
    validate_request_checkpoint_binding,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance" / "profiles" / "execution-checkpoint"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DurableHostValidatorTests(unittest.TestCase):
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

    def test_batch_precedence_is_global_across_members(self) -> None:
        self._assert_complete_case_mutation_fails(
            lambda requests: requests["global_batch_precedence"]["envelopes"][1].update(
                delivery_mode="input"
            ),
            "admission failure is not request-derived",
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
            vector["raw_admission_request"], "raw baseline"
        )
        self.assertTrue(malformed)
        self._assert_complete_test_mutation_fails(
            self._substitute_valid_raw_member,
            "admission failure is not request-derived",
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
                    mutated_case, test, set(mutated_case.glob("*.json"))
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
                    mutated_case, test, set(mutated_case.glob("*.json"))
                )

    @staticmethod
    def _substitute_valid_raw_member(test: dict) -> None:
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
        sources[0] = replacement
        _, malformed = normalize_raw_admission_request(
            vector["raw_admission_request"], "valid substitution"
        )
        if malformed:
            raise AssertionError("valid raw member substitution remained malformed")


if __name__ == "__main__":
    unittest.main()
