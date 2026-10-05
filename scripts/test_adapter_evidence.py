#!/usr/bin/env python3
"""Adversarial evidence routing tests; these do not certify any native adapter."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adapter_evidence import (
    OPERATIONAL_GATES, POLICY_INVENTORY, POLICY_LAYER, AdapterEvidenceError,
    validate_policy_case, validate_policy_case_inventory,
)
from run_adapter_policy_profile import check_observation, run as run_policy
from run_execution_store_gates import read_report, run_mapping, validate_mapping
from validate_conformance import load_fixture_document


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance/profiles/execution-checkpoint"


class PolicyEvidenceTests(unittest.TestCase):
    def test_each_marker_and_exact_vector_is_required(self) -> None:
        count = 0
        for case_name, names in POLICY_INVENTORY.items():
            case = PROFILE / case_name
            rows = load_fixture_document(case / "test.yaml")["durable_host_vectors"]
            validate_policy_case(case, rows)
            for name in names:
                index = next(i for i, row in enumerate(rows) if row["name"] == name)
                for replacement in (None, "configured_instance", True):
                    mutated = copy.deepcopy(rows)
                    if replacement is None:
                        del mutated[index]["evidence_layer"]
                    else:
                        mutated[index]["evidence_layer"] = replacement
                    with self.assertRaisesRegex(AdapterEvidenceError, "marker"):
                        validate_policy_case(case, mutated)
                mutated = copy.deepcopy(rows)
                deleted = mutated.pop(index)
                # Keeping every coverage label elsewhere cannot hide deletion.
                mutated[0]["covers"].extend(deleted["covers"])
                with self.assertRaisesRegex(AdapterEvidenceError, "inventory"):
                    validate_policy_case(case, mutated)
                count += 1
        self.assertEqual(count, 26)

    def test_production_operations_cannot_be_reclassified(self) -> None:
        case = PROFILE / "checkpoint-01-native-lifecycle"
        rows = load_fixture_document(case / "test.yaml")["durable_host_vectors"]
        for index in range(len(rows)):
            mutated = copy.deepcopy(rows)
            mutated[index]["evidence_layer"] = POLICY_LAYER
            with self.assertRaisesRegex(AdapterEvidenceError, "production operation"):
                validate_policy_case(case, mutated)

    def test_case_inventory_cannot_disappear(self) -> None:
        for case_name in POLICY_INVENTORY:
            with self.assertRaisesRegex(AdapterEvidenceError, "case directory"):
                validate_policy_case_inventory(set(POLICY_INVENTORY) - {case_name})

    def test_policy_cannot_access_root_or_create_handle(self) -> None:
        expected = {"kind": "registration", "body": {"version": 1}}
        observed = {"raw_response": expected, "root_accesses": 0,
                    "operational_handles_created": 0}
        check_observation(observed, expected)
        for key in ("root_accesses", "operational_handles_created"):
            for value in (1, False, None):
                with self.assertRaisesRegex(ValueError, "operational work"):
                    check_observation({**observed, key: value}, expected)
        for response in ({}, {"kind": "registration", "body": {"version": True}}):
            with self.assertRaisesRegex(ValueError, "production policy return"):
                check_observation({**observed, "raw_response": response}, expected)

    def test_runner_compares_corrupted_actual_return(self) -> None:
        requests = []

        def corrupted_adapter(command, *, input, **kwargs):
            requests.append(json.loads(input))
            from subprocess import CompletedProcess
            return CompletedProcess(command, 0, json.dumps({
                "raw_response": {"kind": "corrupted_return"},
                "root_accesses": 0, "operational_handles_created": 0,
            }).encode(), b"")

        with patch("run_adapter_policy_profile.subprocess.run", corrupted_adapter):
            with self.assertRaisesRegex(ValueError, "production policy return"):
                run_policy(["reviewed-production-adapter"])
        self.assertEqual(set(requests[0]), {"evidence_layer", "request"})
        self.assertNotIn("expected", requests[0]["request"])
        self.assertNotIn("covers", requests[0]["request"])


class NativeGateRoutingTests(unittest.TestCase):
    def mapping(self, xml: str | None = None) -> dict:
        # Deliberate report producer tests ONLY this runner, not native semantics.
        if xml is None:
            xml = '<testsuite><testcase classname="native" name="assertions"/></testsuite>'
        return {
            "gates": {gate: ["native::assertions"] for gate in OPERATIONAL_GATES},
            "runs": [{
                "command": [sys.executable, "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])",
                    "{report}", xml],
                "report": "native.xml", "required_environment": [],
            }],
        }

    def test_missing_unknown_duplicate_and_unmapped_tests_fail(self) -> None:
        mapping = self.mapping()
        validate_mapping(mapping, ROOT)
        for gate in OPERATIONAL_GATES:
            mutated = copy.deepcopy(mapping)
            del mutated["gates"][gate]
            with self.assertRaisesRegex(AdapterEvidenceError, "gate mapping"):
                validate_mapping(mutated, ROOT)
        mutated = copy.deepcopy(mapping)
        mutated["gates"]["conditional_adapter_policy"] = ["native::assertions"]
        with self.assertRaisesRegex(AdapterEvidenceError, "gate mapping"):
            validate_mapping(mutated, ROOT)
        mutated = copy.deepcopy(mapping)
        mutated["gates"]["public_registration"] *= 2
        with self.assertRaisesRegex(AdapterEvidenceError, "distinct exact"):
            validate_mapping(mutated, ROOT)
        mapping["gates"]["postgresql_transactions"] = ["postgresql::not_executed"]
        with self.assertRaisesRegex(AdapterEvidenceError, "unexecuted mapped"):
            run_mapping(mapping, ROOT)

    def test_fresh_actual_run_and_missing_service(self) -> None:
        self.assertEqual(run_mapping(self.mapping(), ROOT), len(OPERATIONAL_GATES))
        mapping = self.mapping()
        mapping["runs"][0]["required_environment"] = ["DETERMA_TEST_SERVICE"]
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(AdapterEvidenceError, "service configuration"):
                run_mapping(mapping, ROOT)

    def test_skips_errors_failures_unknown_and_empty_reports_fail(self) -> None:
        for body in ('<skipped/>', '<error/>', '<failure/>'):
            xml = f'<testsuite><testcase classname="native" name="assertions">{body}</testcase></testsuite>'
            with self.assertRaisesRegex(AdapterEvidenceError, "unmet"):
                run_mapping(self.mapping(xml), ROOT)
        for xml in ('<testsuite/>', '<passed>true</passed>',
                    '<testsuite skipped="1"><testcase classname="native" name="assertions"/></testsuite>'):
            with self.assertRaises(AdapterEvidenceError):
                run_mapping(self.mapping(xml), ROOT)

    def test_old_report_cannot_satisfy_empty_command(self) -> None:
        mapping = self.mapping()
        mapping["runs"][0]["command"] = [sys.executable, "-c", "pass", "{report}"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "native.xml").write_text('<testsuite><testcase classname="native" name="assertions"/></testsuite>')
            with self.assertRaisesRegex(AdapterEvidenceError, "fresh native test report"):
                run_mapping(mapping, root)
            self.assertTrue((root / "native.xml").exists())

    def test_paths_and_duplicate_reports_fail(self) -> None:
        for path in ("../native.xml", "/tmp/native.xml", "", "."):
            mapping = self.mapping()
            mapping["runs"][0]["report"] = path
            with self.assertRaises(AdapterEvidenceError):
                validate_mapping(mapping, ROOT)
        mapping = self.mapping()
        mapping["runs"].append(copy.deepcopy(mapping["runs"][0]))
        with self.assertRaisesRegex(AdapterEvidenceError, "duplicate operational"):
            validate_mapping(mapping, ROOT)

    def test_duplicate_test_identity_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.xml"
            case = '<testcase classname="native" name="assertions"/>'
            path.write_text('<testsuite>' + case * 2 + '</testsuite>')
            with self.assertRaisesRegex(AdapterEvidenceError, "duplicate executed"):
                read_report(path)


if __name__ == "__main__":
    unittest.main()
