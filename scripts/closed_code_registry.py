#!/usr/bin/env python3
"""Validate and generate vectors from the authoritative closed-code registry."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


REGISTRY_RELATIVE_PATH = Path("conformance/closed-code-registry/registry.json")
VECTOR_RELATIVE_PATH = Path("conformance/closed-code-registry/vectors.generated.json")
SCHEMA_RELATIVE_PATH = Path("scripts/schemas/closed-code-registry.schema.json")
VECTOR_SCHEMA_RELATIVE_PATH = Path("scripts/schemas/closed-code-vectors.schema.json")


class RegistryValidationError(ValueError):
    """The registry or its generated vector projection is invalid."""


def _reject_duplicate_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryValidationError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_names,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise RegistryValidationError(f"{path}: {error}") from error


def render_vectors(registry: dict[str, Any]) -> bytes:
    canonical_registry = json.dumps(
        registry, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    by_category: dict[str, list[str]] = {
        category["id"]: [] for category in registry["categories"]
    }
    for entry in registry["entries"]:
        by_category[entry["category"]].append(entry["code"])
    vector = {
        "vector_schema_version": 1,
        "registry_sha256": hashlib.sha256(canonical_registry).hexdigest(),
        "categories": [
            {"id": category, "codes": codes}
            for category, codes in by_category.items()
        ],
    }
    return (json.dumps(vector, indent=2, ensure_ascii=True) + "\n").encode()


def validate_registry(
    repository_root: Path,
    registry: dict[str, Any] | None = None,
    *,
    check_generated: bool = True,
) -> tuple[int, int]:
    schema = load_json(repository_root / SCHEMA_RELATIVE_PATH)
    Draft202012Validator.check_schema(schema)
    if registry is None:
        registry = load_json(repository_root / REGISTRY_RELATIVE_PATH)
    if not isinstance(registry, dict):
        raise RegistryValidationError("registry root must be an object")

    errors = sorted(
        Draft202012Validator(schema).iter_errors(registry),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise RegistryValidationError(f"{location}: {error.message}")

    expected_version = (repository_root / "VERSION").read_text().strip()
    if registry["specification_version"] != expected_version:
        raise RegistryValidationError(
            "registry specification_version does not match VERSION"
        )

    category_ids = [category["id"] for category in registry["categories"]]
    if category_ids != sorted(category_ids):
        raise RegistryValidationError("categories must be ordered by id")
    if len(category_ids) != len(set(category_ids)):
        raise RegistryValidationError("duplicate category id")
    category_vocabulary = schema["$defs"]["category"]["enum"]
    missing_categories = set(category_vocabulary) - set(category_ids)
    extra_categories = set(category_ids) - set(category_vocabulary)
    if missing_categories or extra_categories:
        raise RegistryValidationError(
            "category vocabulary mismatch: "
            f"missing={sorted(missing_categories)}, extra={sorted(extra_categories)}"
        )

    declared_categories = set(category_vocabulary)
    used_categories: set[str] = set()
    seen_entries: set[tuple[str, str]] = set()
    entry_keys: list[tuple[str, str]] = []
    for entry in registry["entries"]:
        category = entry["category"]
        code = entry["code"]
        if category not in declared_categories:
            raise RegistryValidationError(
                f"uncategorized code {code!r}: unknown category {category!r}"
            )
        key = (category, code)
        if key in seen_entries:
            raise RegistryValidationError(
                f"duplicate code {code!r} in category {category!r}"
            )
        seen_entries.add(key)
        used_categories.add(category)
        entry_keys.append(key)

    unused_categories = declared_categories - used_categories
    if unused_categories:
        raise RegistryValidationError(
            f"categories without codes: {sorted(unused_categories)}"
        )
    if entry_keys != sorted(entry_keys):
        raise RegistryValidationError("entries must be ordered by category then code")

    if check_generated:
        vector_path = repository_root / VECTOR_RELATIVE_PATH
        try:
            actual = vector_path.read_bytes()
        except OSError as error:
            raise RegistryValidationError(f"{vector_path}: {error}") from error
        expected = render_vectors(registry)
        if actual != expected:
            raise RegistryValidationError(
                "generated closed-code vectors are stale; run "
                "python scripts/closed_code_registry.py"
            )
        vector_schema = load_json(repository_root / VECTOR_SCHEMA_RELATIVE_PATH)
        Draft202012Validator.check_schema(vector_schema)
        vector = load_json(vector_path)
        vector_errors = list(Draft202012Validator(vector_schema).iter_errors(vector))
        if vector_errors:
            raise RegistryValidationError(
                f"generated closed-code vectors: {vector_errors[0].message}"
            )
    return len(category_ids), len(seen_entries)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check the generated vector file instead of updating it",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args()
    root = arguments.repository_root.resolve()
    registry = load_json(root / REGISTRY_RELATIVE_PATH)
    validate_registry(root, registry, check_generated=False)
    expected = render_vectors(registry)
    vector_path = root / VECTOR_RELATIVE_PATH
    if arguments.check:
        if not vector_path.exists() or vector_path.read_bytes() != expected:
            raise SystemExit(
                "generated closed-code vectors are stale; run "
                "python scripts/closed_code_registry.py"
            )
    else:
        vector_path.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
