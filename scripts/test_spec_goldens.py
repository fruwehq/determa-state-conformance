#!/usr/bin/env python3
"""Check portable computations against independent normative spec examples."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from validate_conformance import (
    aggregate_shape_fingerprint_for_path,
    hash_value,
    validate_aggregate_v1_semantics,
    validated_bundle_fingerprint,
    verify_artifact_digest,
)


def check(spec_root: Path) -> None:
    examples = spec_root / "examples" / "persistence"
    source = validated_bundle_fingerprint(examples / "source.yaml")
    target = validated_bundle_fingerprint(examples / "target.yaml")
    shape = aggregate_shape_fingerprint_for_path(examples / "source.yaml")
    assert source == "sha256:cf1429c9cc0ecfb62e406bff29c9b537d668fad6601e30f0da0210986b7f6413"
    assert target == "sha256:eeec154ca64b619fe802af811b942073a2bc988b669429d7d08748dd72ab6cfc"
    assert shape == "sha256:2e66cdbbdcfe44dad5a2edd52e5c1693e28c6c60ae590682f4862ee56fe058cc"
    assert aggregate_shape_fingerprint_for_path(examples / "target.yaml") == shape
    root = hash_value([
        "determa-root-runtime-identity-1", "1",
        "sha256:7e48ad82ea5305c24b7730f4fd24c36ec196a0875c982b85eba5b3a5ddcbb92f",
        "example.turnstile", "turnstile", "1", "turnstile-42",
    ])
    assert root == "sha256:d42f331cbd0c491bba66d512c010f89f94c52df12057a80fecde85d3b954592f"
    component = hash_value([
        "determa-component-runtime-identity-1", "1", "turnstile-42", root,
        "/machines/0/root/states/locked/components/0", "0",
        "example.turnstile", "turnstile", "1",
    ])
    assert component == "sha256:b0145e3c9c3d470fda4e59e55fe1585a1a9a7d74e29377062d70bf1789ffeb76"

    schema_names = (
        "aggregate-state-v1", "migration-descriptor-v1", "execution-checkpoint-v1",
    )
    schemas = {
        name: json.loads((spec_root / "schema" / f"{name}.schema.json").read_text())
        for name in schema_names
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    for name, kind in (
        ("aggregate-state-v1", "aggregate_state_v1"),
        ("compatible-migration-v1", "migration_descriptor_v1"),
        ("execution-checkpoint-v1", "execution_checkpoint_v1"),
    ):
        path = examples / f"{name}.json"
        document = json.loads(path.read_text())
        schema_name = "migration-descriptor-v1" if name == "compatible-migration-v1" else name
        Draft202012Validator(schemas[schema_name], registry=registry).validate(document)
        verify_artifact_digest(kind, document, path)
        if kind == "aggregate_state_v1":
            validate_aggregate_v1_semantics(document)

    maintenance = json.loads((examples / "execution-checkpoint-v1-maintenance-cases.json").read_text())
    checkpoint_validator = Draft202012Validator(schemas["execution-checkpoint-v1"], registry=registry)
    for item in maintenance["positive"]:
        checkpoint_validator.validate(item["checkpoint"])
        verify_artifact_digest("execution_checkpoint_v1", item["checkpoint"], examples)
    for item in maintenance["negative"]:
        errors = list(checkpoint_validator.iter_errors(item["checkpoint"]))
        if item["expected"] == "schema_validation":
            assert errors, item["name"]
        else:
            assert not errors, item["name"]
            verify_artifact_digest("execution_checkpoint_v1", item["checkpoint"], examples)
            receipt = item["checkpoint"]["operation_receipts"][-1]
            normative = maintenance["positive"][0]["checkpoint"]["operation_receipts"][-1]
            assert receipt["target_validated_bundle_fingerprint"] != normative["target_validated_bundle_fingerprint"]
    print("verified merged-spec fingerprints, identities, artifacts, and maintenance examples")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    check(parser.parse_args().spec_root)
