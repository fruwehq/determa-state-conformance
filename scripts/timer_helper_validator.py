"""Validate external helper vectors against pinned normative inputs and artifacts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from ruamel.yaml import YAML

from generate_timer_helper_profile import CASE, render, artifact
from generate_version1_vectors import canonical, digest, typed_value, bundle_fingerprint_document
from validate_portable_archive import (ArchiveValidationError, validate_archive_integrity,
                                       validator_registry, schema_valid)


class TimerHelperValidationError(ValueError):
    pass


def validate_profile(spec_root: Path, repository_root: Path) -> tuple[int, int, int, int, int, int]:
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
    clocks = document["clock_cases"]
    expected_clock_names = ([f"valid_absolute_{index}" for index in range(len(clocks["valid_absolute"]))] +
                            [f"valid_duration_{index}" for index in range(len(clocks["valid_duration"]))] +
                            [f"invalid_absolute_{index}" for index in range(len(clocks["invalid_absolute"]))] +
                            [f"invalid_duration_{index}" for index in range(len(clocks["invalid_duration"]))] +
                            [item["name"] for item in clocks["cases"]])
    if [row["id"] for row in document["clock_vectors"]] != expected_clock_names:
        raise TimerHelperValidationError("clock boundary coverage changed")
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
            if value["records"]:
                record = value["records"][0]
                operations = [entry["result"]["operation"] for entry in value["operation_receipts"]]
                if ((record["state"] in ("claimed", "fired") and "claim_fire" not in operations) or
                        (record["state"] == "fired" and "complete_fire" not in operations)):
                    raise TimerHelperValidationError(f"{name}: {side} lost a committed claim/fire receipt")
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
    for row in document["clock_vectors"]:
        request, result = row["request"], row["expected_result"]
        if request["request_digest"] != digest(["determa-timer-request-1",
                {key: value for key, value in request.items() if key != "request_digest"}]):
            raise TimerHelperValidationError(f"{row['id']}: clock request digest changed")
        before, after = row["before"]["helper_artifact"], row["after"]["helper_artifact"]
        if before != artifact() or after != artifact(after["records"], after["operation_receipts"]):
            raise TimerHelperValidationError(f"{row['id']}: clock artifact changed")
        if result["status"] == "accepted":
            if len(after["records"]) != 1 or result["result_digest"] != digest([
                    "determa-timer-result-1", request["request_digest"],
                    {key: value for key, value in result.items() if key != "result_digest"}]):
                raise TimerHelperValidationError(f"{row['id']}: accepted clock outcome changed")
        elif after != before or result["error_code"] not in (
                "invalid_timer_time", "timer_deadline_overflow", "timer_clock_unavailable"):
            raise TimerHelperValidationError(f"{row['id']}: failed clock outcome changed state")
    for index, sample in enumerate(clocks["valid_absolute"]):
        row = document["clock_vectors"][index]
        if row["request"]["arguments"].get("deadline_at") != sample or \
                row["after"]["helper_artifact"]["records"][0]["deadline_at"] != sample or \
                row["expected_calls"]["clock"] != 0:
            raise TimerHelperValidationError("absolute signed-64 clock boundary changed")
    start = len(clocks["valid_absolute"])
    for index, sample in enumerate(clocks["valid_duration"]):
        row = document["clock_vectors"][start + index]
        if row["request"]["arguments"].get("delay_nanoseconds") != sample or \
                row["after"]["helper_artifact"]["records"][0]["deadline_at"] != sample or \
                row["expected_calls"]["clock"] != 1:
            raise TimerHelperValidationError("duration signed-64 clock boundary changed")
    start += len(clocks["valid_duration"])
    for field, samples in (("deadline_at", clocks["invalid_absolute"]),
                           ("delay_nanoseconds", clocks["invalid_duration"])):
        for index, sample in enumerate(samples):
            row = document["clock_vectors"][start + index]
            if row["request"]["arguments"].get(field) != sample or \
                    row["expected_result"]["error_code"] != "invalid_timer_time" or \
                    row["expected_calls"]["clock"] != 0:
                raise TimerHelperValidationError("noncanonical timer time did not fail before clock access")
        start += len(samples)
    for index, sample in enumerate(clocks["cases"]):
        row = document["clock_vectors"][start + index]
        if row["request"]["arguments"]["delay_nanoseconds"] != sample["duration"] or \
                row["trusted_now"] != sample["now"] or \
                row["expected_calls"]["clock"] != 1:
            raise TimerHelperValidationError("trusted duration clock premise changed")
        if "expected_deadline" in sample:
            if row["after"]["helper_artifact"]["records"][0]["deadline_at"] != sample["expected_deadline"] or \
                    int(sample["now"]) + int(sample["duration"]) != int(sample["expected_deadline"]):
                raise TimerHelperValidationError("checked signed-64 duration addition changed")
        elif row["expected_result"]["error_code"] != sample["expected_error"] or \
                row["before"] != row["after"]:
            raise TimerHelperValidationError("overflow or unavailable clock mutated timer state")
    if [row["id"] for row in document["fence_vectors"]] != [
            "complete_at_expiry", "wrong_worker", "changed_fire_event"]:
        raise TimerHelperValidationError("helper claim fence coverage changed")
    for row, error, clock_calls in zip(document["fence_vectors"],
                                       ("timer_stale_fence", "timer_worker_mismatch", "timer_event_conflict"),
                                       (1, 0, 0)):
        request = row["request"]
        if request["request_digest"] != digest(["determa-timer-request-1",
                {key: value for key, value in request.items() if key != "request_digest"}]) or \
                row["expected_result"]["error_code"] != error or \
                row["expected_calls"] != {"clock": clock_calls, "admission": 0} or \
                row["before"] != row["after"] or \
                row["before"]["helper_artifact"]["records"][0]["state"] != "claimed" or \
                row["before"]["checkpoint"] != next(item for item in document["cases"]
                    if item["id"] == "coordinated_fire_commits")["before"]["checkpoint"]:
            raise TimerHelperValidationError("expired, wrong-worker or conflicting fire altered state")
    export = json.loads(expected_files["archive-export.generated.json"])
    stage = json.loads(expected_files["archive-stage.generated.json"])
    archive_schemas = validator_registry(spec_root)
    try:
        schema_valid(archive_schemas["archive-export-request-v1"], export["input_request"],
                     "timer archive export request")
        validate_archive_integrity(export["expected_archive"], archive_schemas)
        for stage_case in stage["cases"]:
            schema_valid(archive_schemas["archive-import-request-v1"], stage_case["input_request"],
                         stage_case["case_id"] + " import request")
            if stage_case["expected_result"]["status"] == "staged":
                validate_archive_integrity(stage_case["input_archive"], archive_schemas)
            else:
                candidate = stage_case["input_archive"]
                schema_valid(archive_schemas["archive-v1"], candidate,
                             stage_case["case_id"] + " resealed archive")
                if candidate["archive_digest"] != digest(["determa-archive-digest-1",
                        {key: value for key, value in candidate.items() if key != "archive_digest"}]):
                    raise TimerHelperValidationError("missing timer refusal is not correctly resealed")
    except (ArchiveValidationError, KeyError) as error:
        raise TimerHelperValidationError(f"timer archive integrity: {error}") from error
    participant = next((part for part in export["expected_archive"]["participants"]
                        if part["participant_id"] == "timer-state"), None)
    timer_record = json.loads((spec_root / "examples/timers/timer-records-v1.json").read_text())
    timer_schema = json.loads((spec_root / "schema/timer-record-v1.schema.json").read_text())
    if participant is None or not participant["required"] or \
            participant["payload"] != typed_value(timer_record) or \
            export["timer_artifact_digest"] != timer_record["timer_artifact_digest"] or \
            participant["participant_schema_digest"] != digest(timer_schema) or \
            export["timer_schema_digest"] != digest(timer_schema) or \
            export["input_request"]["required_participant_ids"] != ["timer-state"]:
        raise TimerHelperValidationError("required timer archive participant is not bound to exact timer artifact")
    if [row["case_id"] for row in stage["cases"]] != ["timer_required_stage", "resealed_missing_required_timer"] or \
            stage["cases"][0]["expected_result"]["status"] != "staged" or \
            stage["cases"][1]["expected_result"]["status"] != "refused" or \
            any(any(value for value in row["expected_host_effects"].values()) for row in stage["cases"]):
        raise TimerHelperValidationError("timer import must stage inertly and refuse omitted required participant")
    lifecycle = json.loads(expected_files["lifecycle.generated.json"])
    lifecycle_schema = json.loads((repository_root / "scripts/schemas/timer-helper-lifecycle-v1.schema.json").read_text())
    Draft202012Validator.check_schema(lifecycle_schema)
    lifecycle_errors = list(Draft202012Validator(lifecycle_schema, registry=registry).iter_errors(lifecycle))
    if lifecycle_errors:
        raise TimerHelperValidationError(f"lifecycle driver schema: {lifecycle_errors[0].message}")
    schedule_payload = lifecycle["expected_intent_emissions"][0]["payload"]
    cancel_payload = lifecycle["expected_cancel_intent_emissions"][-1]["payload"]
    schedule_request = lifecycle["schedule_request"]
    if schedule_payload != {"timer_id": schedule_request["timer_id"],
                            "event_name": schedule_request["arguments"]["event_name"],
                            "delay_nanoseconds": schedule_request["arguments"]["delay_nanoseconds"]} or \
            cancel_payload != {"timer_id": schedule_request["timer_id"]}:
        raise TimerHelperValidationError("declared machine intent does not map to helper commands")
    if lifecycle["cancel_request"]["timer_id"] != schedule_request["timer_id"] or \
            lifecycle["expected_helper_after_cancel"]["records"][0]["state"] != "cancelled" or \
            lifecycle["expected_helper_after_cancel"]["records"][0]["attempt_fence"] != "0":
        raise TimerHelperValidationError("declared cancellation is not bound to preclaim helper state")
    target = YAML(typ="safe").load(expected_files["target-machine.yaml"])
    if list(Draft202012Validator(spec_schemas["machine.schema.json"], registry=registry).iter_errors(target)):
        raise TimerHelperValidationError("timer target machine invalid")
    fingerprint = lifecycle["create_request"]["bundle"]["validated_bundle_fingerprint"]
    if fingerprint != lifecycle["expected_create_checkpoint"]["root_record"]["aggregate_state"]["validated_bundle_fingerprint"]:
        raise TimerHelperValidationError("create request does not identify target definition")
    for source, request in ((expected_files["target-machine.yaml"], lifecycle["create_request"]),
                            (expected_files["machine.yaml"], lifecycle["intent_create_request"]),
                            (expected_files["machine.yaml"], lifecycle["cancel_intent_create_request"])):
        if request["bundle"]["bundle_source_digest"] != "sha256:" + hashlib.sha256(source).hexdigest() or \
                request["bundle"]["validated_bundle_fingerprint"] != bundle_fingerprint_document(YAML(typ="safe").load(source)):
            raise TimerHelperValidationError("create request is not bound to exact format-1 source")
    for label in ("expected_create_checkpoint", "expected_admitted_checkpoint", "expected_after_step_checkpoint"):
        checkpoint = lifecycle[label]
        errors = list(Draft202012Validator(spec_schemas["execution-checkpoint-v1.schema.json"],
                                             registry=registry).iter_errors(checkpoint))
        if errors:
            raise TimerHelperValidationError(f"{label}: {errors[0].message}")
        unsigned = {key: value for key, value in checkpoint.items() if key != "execution_checkpoint_digest"}
        if checkpoint["execution_checkpoint_digest"] != digest(["determa-execution-checkpoint-digest-1", unsigned]):
            raise TimerHelperValidationError(f"{label}: checkpoint digest changed")
        aggregate = checkpoint["root_record"]["aggregate_state"]
        unsigned_aggregate = {key: value for key, value in aggregate.items() if key != "aggregate_state_digest"}
        if aggregate["aggregate_state_digest"] != digest(["determa-aggregate-state-digest-1", unsigned_aggregate]) or \
                "timer_records" in aggregate:
            raise TimerHelperValidationError(f"{label}: aggregate digest or timer boundary changed")
    envelope = lifecycle["expected_fire_envelope"]
    receipt = lifecycle["expected_admitted_checkpoint"]["operation_receipts"][-1]
    if envelope["event_id"] != lifecycle["expected_results"][-1]["event_id"] or \
            receipt["event_id"] != envelope["event_id"] or \
            receipt["request_digest"] != digest(["determa-inbox-envelope-digest-1", "1",
                                                  envelope["target"]["root"]["root_instance_id"],
                                                  "input", envelope]):
        raise TimerHelperValidationError("ordinary event envelope and admission receipt diverge")
    if lifecycle["expected_helper_after_fire"]["records"][0]["admission_receipt_digest"] != \
            digest(["determa-timer-admission-receipt-1", receipt]):
        raise TimerHelperValidationError("timer completion is not bound to committed admission")
    terminal = lifecycle["expected_after_step_checkpoint"]["operation_receipts"][-1]
    if terminal["event_id"] != envelope["event_id"] or \
            terminal["request_digest"] != receipt["request_digest"] or \
            terminal["resulting_aggregate_state_digest"] != lifecycle["expected_after_step_checkpoint"]["root_record"]["aggregate_state"]["aggregate_state_digest"] or \
            terminal["outcome"]["disposition"] != "unhandled":
        raise TimerHelperValidationError("step did not dispose of the fired event")
    installed_lifecycle = json.loads(expected_files["configured-lifecycle.generated.json"])
    installed_errors = list(Draft202012Validator(lifecycle_schema, registry=registry).iter_errors(installed_lifecycle))
    if installed_errors:
        raise TimerHelperValidationError(f"configured timer lifecycle schema: {installed_errors[0].message}")
    installed_schedule = installed_lifecycle["schedule_request"]
    installed_envelope = installed_lifecycle["expected_fire_envelope"]
    installed_checkpoint = installed_lifecycle["expected_admitted_checkpoint"]
    installed_receipt = installed_checkpoint["operation_receipts"][-1]
    installed_fire_id = digest(["determa-timer-fire-event-1", "1",
        installed_schedule["scope_identity"], installed_schedule["root_instance_id"],
        installed_schedule["root_runtime_id"], installed_schedule["timer_id"]])
    for name in ("schedule", "cancel", "claim", "complete"):
        operation = installed_lifecycle[name + "_request"]
        if operation["request_digest"] != digest(["determa-timer-request-1",
                {key: part for key, part in operation.items() if key != "request_digest"}]):
            raise TimerHelperValidationError("configured timer request digest changed")
    for name in ("schedule", "cancel", "claim", "fire"):
        helper = installed_lifecycle["expected_helper_after_" + name]
        if helper != artifact(helper["records"], helper["operation_receipts"]):
            raise TimerHelperValidationError("configured timer helper artifact digest changed")
        for item in helper["operation_receipts"]:
            request_for_item = next((installed_lifecycle[part + "_request"] for part in
                ("schedule", "cancel", "claim", "complete") if
                installed_lifecycle[part + "_request"]["operation_id"] == item["operation_id"]), None)
            if request_for_item is None or item["request_digest"] != request_for_item["request_digest"] or \
                    item["result"]["result_digest"] != digest(["determa-timer-result-1",
                        item["request_digest"], {key: part for key, part in item["result"].items()
                                                 if key != "result_digest"}]):
                raise TimerHelperValidationError("configured timer retained operation result changed")
    installed_aggregate = installed_checkpoint["root_record"]["aggregate_state"]
    installed_step = installed_lifecycle["expected_after_step_checkpoint"]
    installed_terminal = installed_step["operation_receipts"][-1]
    if installed_schedule["scope_identity"] != "effect-scope-1" or \
            installed_envelope["event_id"] != installed_fire_id or \
            installed_envelope["cause_id"] != installed_fire_id or \
            installed_receipt["request_digest"] != digest(["determa-inbox-envelope-digest-1", "1",
                installed_checkpoint["root_instance_id"], "input", installed_envelope]) or \
            installed_checkpoint["execution_checkpoint_digest"] != digest([
                "determa-execution-checkpoint-digest-1",
                {key: part for key, part in installed_checkpoint.items()
                 if key != "execution_checkpoint_digest"}]) or \
            installed_aggregate["aggregate_state_digest"] != digest([
                "determa-aggregate-state-digest-1",
                {key: part for key, part in installed_aggregate.items()
                 if key != "aggregate_state_digest"}]) or \
            installed_step["execution_checkpoint_digest"] != digest([
                "determa-execution-checkpoint-digest-1",
                {key: part for key, part in installed_step.items()
                 if key != "execution_checkpoint_digest"}]) or \
            installed_terminal["event_id"] != installed_fire_id or \
            installed_terminal["request_digest"] != installed_receipt["request_digest"] or \
            installed_lifecycle["expected_helper_after_fire"]["records"][0]["admission_receipt_digest"] != \
                digest(["determa-timer-admission-receipt-1", installed_receipt]):
        raise TimerHelperValidationError("installed timer scope or ordinary admission changed")
    ownership = json.loads(expected_files["source-ownership.generated.json"])
    source_schema = json.loads((repository_root / "scripts/schemas/timer-source-ownership-v1.schema.json").read_text())
    Draft202012Validator.check_schema(source_schema)
    source_errors = list(Draft202012Validator(source_schema, registry=registry).iter_errors(ownership))
    if source_errors:
        raise TimerHelperValidationError(f"timer delivery source schema: {source_errors[0].message}")
    request = ownership["request"]
    source = request["source"]
    expected_source_id = digest(["determa-timer-source-delivery-1",
        installed_schedule["root_instance_id"], installed_schedule["root_runtime_id"],
        installed_schedule["timer_id"]])
    if source["source_scope"] != installed_schedule["scope_identity"] or \
            source["source_delivery_id"] != expected_source_id or \
            source["content"]["content_value"] != typed_value(installed_envelope) or \
            source["source_content_digest"] != digest(["determa-delivery-source-content-digest-1",
                "1", source["source_scope"], source["source_delivery_id"],
                source["content"]["content_kind"], source["content"]["content_value"]]):
        raise TimerHelperValidationError("timer source identity or immutable content changed")
    binding = ownership["admission_binding"]
    if binding["admission_binding_digest"] != digest(["determa-admission-binding-digest-1", "1",
            {key: value for key, value in binding.items() if key != "admission_binding_digest"}]) or \
            binding["source_scope"] != source["source_scope"] or \
            binding["source_delivery_id"] != source["source_delivery_id"] or \
            binding["source_content_digest"] != source["source_content_digest"] or \
            binding["event_id"] != installed_envelope["event_id"] or \
            binding["envelope_digest"] != installed_receipt["request_digest"] or \
            binding["evidence"]["checkpoint"]["execution_checkpoint_digest"] != \
                installed_checkpoint["execution_checkpoint_digest"] or \
            ownership["before_checkpoint"] != installed_lifecycle["expected_create_checkpoint"] or \
            ownership["after_checkpoint"] != installed_checkpoint or \
            ownership["acceptance_receipt"] != installed_receipt or \
            ownership["acknowledge_after_commit"] != {
                "source_scope": source["source_scope"], "source_delivery_id": source["source_delivery_id"]}:
        raise TimerHelperValidationError("timer ingress binding or checkpoint ownership changed")
    delivery_vectors = json.loads(expected_files["timer-delivery.generated.json"])
    delivery_schema = json.loads((repository_root / "scripts/schemas/timer-delivery-v1.schema.json").read_text())
    Draft202012Validator.check_schema(delivery_schema)
    delivery_errors = list(Draft202012Validator(delivery_schema, registry=registry).iter_errors(delivery_vectors))
    if delivery_errors:
        raise TimerHelperValidationError(f"timer delivery driver schema: {delivery_errors[0].message}")
    first_ingest, crashed_ingest, replay_ingest = delivery_vectors["vectors"]
    for vector in delivery_vectors["vectors"]:
        if vector["request"] != request or vector["after"]["bindings"] != [binding] or \
                vector["after"]["checkpoint"] != "after-timer-checkpoint-v1.json":
            raise TimerHelperValidationError("timer delivery source or committed store changed")
    if first_ingest["before"]["bindings"] or first_ingest["before"]["source_acknowledgements"] or \
            crashed_ingest["before"] != first_ingest["before"] or \
            crashed_ingest["after"]["source_acknowledgements"] or \
            replay_ingest["before"] != crashed_ingest["after"] or \
            replay_ingest["after"] != first_ingest["after"] or \
            first_ingest["after"]["source_acknowledgements"] != [ownership["acknowledge_after_commit"]] or \
            crashed_ingest["expected_response"] != {"kind": "no_response"} or \
            crashed_ingest["fault_injection"] != "crash_after_commit_before_ack" or \
            replay_ingest["replay_of"] != crashed_ingest["name"]:
        raise TimerHelperValidationError("timer crash and retained replay trajectory changed")
    admitted = first_ingest["expected_response"]
    if replay_ingest["expected_response"] != admitted or \
            admitted["evidence"] != binding["evidence"] or \
            admitted["admission_binding_digest"] != binding["admission_binding_digest"] or \
            admitted["source_delivery_id"] != source["source_delivery_id"] or \
            admitted["source_content_digest"] != source["source_content_digest"]:
        raise TimerHelperValidationError("timer admitted response differs from source and checkpoint receipt")
    return len(document["cases"]), len(document["clock_vectors"]), len(document["fence_vectors"]), 3, 2, 3
