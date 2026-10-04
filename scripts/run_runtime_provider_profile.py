#!/usr/bin/env python3
"""Compare production provider adapter observations with the closed source profile."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import shlex
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

from runtime_provider_validator import CASE_REL, SOURCES, validate_profile


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON value: {value}")


def parse_adapter_response(body: bytes):
    return json.loads(body.decode("utf-8", errors="strict"),
                      object_pairs_hook=_pairs_unique, parse_constant=_reject_constant)


def exact_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (actual.keys() == expected.keys() and
                all(exact_equal(actual[key], value) for key, value in expected.items()))
    if isinstance(expected, list):
        return (len(actual) == len(expected) and
                all(exact_equal(a, e) for a, e in zip(actual, expected)))
    return actual == expected


def validate_adapter_response(response, vector, by_source, closure_digest, observation_validator):
    name = vector["name"]
    if type(response) is not dict or set(response) != {
        "observation", "loaded_source", "loaded_closure_digest",
    }:
        raise ValueError("adapter response must have exactly three fields")
    if type(response["loaded_closure_digest"]) is not str or \
            response["loaded_closure_digest"] != closure_digest:
        raise ValueError("executing closure digest mismatch")
    loaded_source = response["loaded_source"]
    if type(loaded_source) is not dict or any(
        type(path) is not str or path not in by_source or
        type(hash_) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", hash_) or
        by_source[path] != hash_
        for path, hash_ in loaded_source.items()
    ):
        raise ValueError("executing source evidence mismatch")
    if (any(stage in vector["expected"]["stages"] for stage in (
        "evaluate_guard", "evaluate_actions", "invoke_inspect_guard", "compile_region",
    )) or (vector["expected"]["result"] == "accepted" and
            vector["request"]["installed"]["providers"])) and not loaded_source:
        raise ValueError("executing source evidence missing")
    observed = response["observation"]
    errors = list(observation_validator.iter_errors(observed))
    if errors:
        raise ValueError(f"invalid observation: {errors[0].message}")
    if not exact_equal(observed, vector["expected"]):
        raise ValueError(f"production observation differs from oracle: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", required=True,
                        help="production implementation adapter command")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    count = validate_profile(args.spec_root, root)
    case = root / CASE_REL
    document = json.loads((case / "vectors.generated.json").read_text())
    closure = json.loads((case / "provider-closure.json").read_text())
    by_source = {item["path"]: item["sha256"] for item in closure["files"]}
    vector_schema = json.loads((root / "scripts/schemas/runtime-provider-vectors.schema.json").read_text())
    observation_validator = Draft202012Validator({
        "$ref": "#/$defs/observation", "$defs": vector_schema["$defs"],
    })
    closure_digest = document["vectors"][0]["request"]["installed"]["closure_digest"]
    command = shlex.split(args.adapter)
    if not command:
        parser.error("empty adapter command")
    for vector in document["vectors"]:
        # The adapter receives a complete operation and source paths. Case names,
        # expected observations, and normative oracle files are withheld.
        with tempfile.TemporaryDirectory(prefix="determa-runtime-provider-") as temporary:
            inputs = Path(temporary)
            names = {vector["request"]["bundle"], "provider-closure.json", *SOURCES}
            for key in ("source_file", "manifest_file", "generated_bundle_file"):
                name = vector["request"]["arguments"].get(key)
                if name is not None:
                    names.add(name)
            for name in names:
                destination = inputs / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(case / name, destination)
            payload = {"request": vector["request"], "profile_root": str(inputs),
                       "source_files": list(SOURCES), "source_closure_file": "provider-closure.json"}
            completed = subprocess.run(command, input=json.dumps(payload).encode("utf-8"),
                                       capture_output=True, check=False)
        if completed.returncode:
            raise SystemExit(f"{vector['name']}: adapter exited {completed.returncode}: "
                             f"{completed.stderr.decode('utf-8', errors='replace').strip()}")
        try:
            response = parse_adapter_response(completed.stdout)
        except (UnicodeDecodeError, ValueError) as error:
            raise SystemExit(f"{vector['name']}: invalid adapter JSON: {error}") from error
        try:
            validate_adapter_response(response, vector, by_source, closure_digest,
                                      observation_validator)
        except ValueError as error:
            raise SystemExit(f"{vector['name']}: {error}") from error
    print(f"passed {count} runtime provider production adapter vectors")


if __name__ == "__main__":
    main()
