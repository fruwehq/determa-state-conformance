#!/usr/bin/env python3
"""Validate conformance fixture structure against a checked-out specification."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
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


class ValidationFailure(Exception):
    """One durable validation failure."""


@dataclass(frozen=True)
class SourceAnalysis:
    error: str | None
    document: Any | None


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
    schema_path = spec_root / "schema" / "machine.schema.json"
    if not schema_path.is_file():
        raise ValidationFailure(f"missing specification schema: {schema_path}")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValidationFailure(f"{schema_path}: invalid JSON: {error}") from error
    Draft202012Validator.check_schema(schema)
    schema_validator = Draft202012Validator(schema)

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

    for case in cases:
        test = load_fixture_document(case / "test.yaml")
        if "load" in test and test["load"] != {"valid": True}:
            raise ValidationFailure(f"{case.name}: unsupported load assertion")

        referenced: set[Path] = set()
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

        has_scenario = bool(test.get("steps")) or "create" in test or static is None
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
                send = step.get("send")
                if send is not None:
                    if not isinstance(send, dict):
                        raise ValidationFailure(
                            f"{case.name}: step {index} send is not a map"
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
                        or deliver.get("captured") not in captures
                    ):
                        raise ValidationFailure(
                            f"{case.name}: step {index} references an unavailable capture"
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
        f"{source_rejections} expected source rejections, "
        f"{structural_rejections} expected structural rejections, "
        f"{static_schema_passes} schema-valid static documents, and "
        f"{scenarios} structurally consistent scenario fixtures"
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
