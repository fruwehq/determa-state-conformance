"""Validate external helper vectors against pinned normative inputs and artifacts."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from ruamel.yaml import YAML

from generate_timer_helper_profile import CASE, render, artifact
from generate_version1_vectors import canonical, digest


class TimerHelperValidationError(ValueError):
    pass


def validate_profile(spec_root: Path, repository_root: Path) -> int:
    case = repository_root / "conformance/profiles/timer-helper/timer-01-external-helper"
    expected_files = render(spec_root)
    for name, expected in expected_files.items():
        if (case / name).read_bytes() != expected:
            raise TimerHelperValidationError(f"{name}: generated fixture differs from pinned specification")
    document = json.loads(expected_files["vectors.generated.json"])
    resources = []
    spec_schemas = {}
    for path in (spec_root / "schema").glob("*.schema.json"):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        resources.extend(((path.name, resource), (schema["$id"], resource)))
        spec_schemas[path.name] = schema
    schema = json.loads((repository_root / "scripts/schemas/timer-helper-vectors-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    registry = Registry().with_resources(resources)
    errors = list(Draft202012Validator(schema, registry=registry).iter_errors(document))
    if errors:
        raise TimerHelperValidationError(f"driver schema: {errors[0].message}")
    source = json.loads((spec_root / "examples/timers/timer-helper-cases-v1.json").read_text())
    samples = [*source["cases"], *source["early_errors"]]
    if [row["id"] for row in document["cases"]] != [row["name"] for row in samples]:
        raise TimerHelperValidationError("normative coverage changed")
    machine = YAML(typ="safe").load((case / "machine.yaml").read_text())
    setup = YAML(typ="safe").load((case / "test.yaml").read_text())
    if list(Draft202012Validator(spec_schemas["machine.schema.json"], registry=registry).iter_errors(machine)):
        raise TimerHelperValidationError("intent machine invalid")
    if setup["steps"][0]["expect"]["emissions"][0]["event"] != "schedule_requested":
        raise TimerHelperValidationError("machine scheduling intent absent")
    for row, sample in zip(document["cases"], samples):
        name = row["id"]
        if row["request"] != sample["request"] or row["expected_result"] != sample["expected"]:
            raise TimerHelperValidationError(f"{name}: normative request or result changed")
        request, result = row["request"], row["expected_result"]
        if "request_digest" in request and request["request_digest"] != digest([
                "determa-timer-request-1", {key: value for key, value in request.items()
                                              if key != "request_digest"}]):
            raise TimerHelperValidationError(f"{name}: request digest changed")
        if result["status"] == "accepted" and result["result_digest"] != digest([
                "determa-timer-result-1", request["request_digest"],
                {key: value for key, value in result.items() if key != "result_digest"}]):
            raise TimerHelperValidationError(f"{name}: result digest changed")
        for side in ("before", "after"):
            value = row[side]["helper_artifact"]
            if value != artifact(value["records"], value["operation_receipts"]):
                raise TimerHelperValidationError(f"{name}: {side} helper digest changed")
        before, after = row["before"], row["after"]
        if row["expected_result"]["status"] == "rejected" and before != after:
            raise TimerHelperValidationError(f"{name}: rejection mutated state")
        if name in ("schedule_equal_replay", "complete_equal_replay", "read_timer") and before != after:
            raise TimerHelperValidationError(f"{name}: read/replay mutated state")
        if name == "coordinated_fire_commits":
            if after["checkpoint"] == before["checkpoint"] or row["expected_calls"]["admission"] != 1:
                raise TimerHelperValidationError("coordinated fire did not admit atomically")
        elif before["checkpoint"] != after["checkpoint"]:
            raise TimerHelperValidationError(f"{name}: unexpected checkpoint mutation")
    return len(document["cases"])
