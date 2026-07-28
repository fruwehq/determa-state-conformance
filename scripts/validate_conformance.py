#!/usr/bin/env python3
"""Validate conformance fixture structure against a checked-out specification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
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
}
DRIVER_ARTIFACT_KINDS = {
    "artifact_resolver": "artifact-resolver.schema.json",
    "resource_limits": "resource-limits.schema.json",
}
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

    for case in cases:
        test = load_fixture_document(case / "test.yaml")
        validate_driver_markers(test, case.name)
        if "persistence_vectors" in test and "persistence_profile" in test:
            raise ValidationFailure(
                f"{case.name}: core vectors and persistence profile are mutually exclusive"
            )
        if "persistence_vectors" in test:
            validate_fixture_schema(test, persistence_vector_validator, case)
        if "persistence_profile" in test:
            validate_fixture_schema(test, persistence_profile_validator, case)
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

        has_persistence_mode = (
            "persistence_vectors" in test or "persistence_profile" in test
        )
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

    all_test_files = {
        path for root in case_roots if root.is_dir() for path in root.rglob("test.yaml")
    }
    if len(all_test_files) != len(cases):
        raise ValidationFailure("duplicate or nested conformance test discovery")

    return (
        f"validated {len(document_paths)} bundle documents across {len(cases)} "
        f"case directories against spec {spec_version}; "
        f"{artifact_documents} JSON artifacts, "
        f"{source_rejections} expected source rejections, "
        f"{structural_rejections} expected structural rejections, "
        f"{static_schema_passes} schema-valid static documents, and "
        f"{scenarios} runtime scenarios, {persistence_vectors} persistence vectors, "
        f"and {persistence_profile_steps} persistence-profile steps"
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
