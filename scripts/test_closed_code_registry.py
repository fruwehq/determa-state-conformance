#!/usr/bin/env python3
"""Negative validation tests for the closed-code registry."""

from __future__ import annotations

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from closed_code_registry import (
    REGISTRY_RELATIVE_PATH,
    SCHEMA_RELATIVE_PATH,
    VECTOR_RELATIVE_PATH,
    VECTOR_SCHEMA_RELATIVE_PATH,
    RegistryValidationError,
    load_json,
    render_vectors,
    validate_registry,
)


ROOT = Path(__file__).resolve().parents[1]


class ClosedCodeRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_json(ROOT / REGISTRY_RELATIVE_PATH)

    def assert_invalid(self, registry: dict[str, object], message: str) -> None:
        with self.assertRaisesRegex(RegistryValidationError, message):
            validate_registry(ROOT, registry, check_generated=False)

    def test_duplicate_code_in_category_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["entries"].insert(1, copy.deepcopy(registry["entries"][0]))
        self.assert_invalid(registry, "duplicate code")

    def test_malformed_code_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["code"] = "Not-Portable"
        self.assert_invalid(registry, "does not match")

    def test_unknown_category_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["category"] = "unknown_category"
        self.assert_invalid(registry, "uncategorized code")

    def test_empty_category_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["categories"].append(
            {"id": "unused_category", "description": "Unused test category."}
        )
        self.assert_invalid(registry, "categories without codes")

    def test_missing_required_member_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        del registry["entries"][0]["source"]
        self.assert_invalid(registry, "required property")

    def test_extra_member_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["unexpected"] = True
        self.assert_invalid(registry, "Additional properties")

    def test_stale_generated_vectors_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / REGISTRY_RELATIVE_PATH.parent).mkdir(parents=True)
            (root / SCHEMA_RELATIVE_PATH.parent).mkdir(parents=True)
            shutil.copy(ROOT / "VERSION", root / "VERSION")
            shutil.copy(ROOT / REGISTRY_RELATIVE_PATH, root / REGISTRY_RELATIVE_PATH)
            shutil.copy(ROOT / SCHEMA_RELATIVE_PATH, root / SCHEMA_RELATIVE_PATH)
            shutil.copy(
                ROOT / VECTOR_SCHEMA_RELATIVE_PATH,
                root / VECTOR_SCHEMA_RELATIVE_PATH,
            )
            (root / VECTOR_RELATIVE_PATH).write_bytes(b"{}\n")
            with self.assertRaisesRegex(RegistryValidationError, "stale"):
                validate_registry(root)

    def test_generated_vectors_are_reproducible(self) -> None:
        expected = render_vectors(self.registry)
        self.assertEqual(expected, (ROOT / VECTOR_RELATIVE_PATH).read_bytes())


if __name__ == "__main__":
    unittest.main()
