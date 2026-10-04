#!/usr/bin/env python3
"""Pin the optional external timer helper's complete operation observations."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from ruamel.yaml import YAML
from generate_version1_vectors import canonical, digest, bundle_fingerprint_document, seal_checkpoint

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "conformance/profiles/timer-helper/timer-01-external-helper"
NORM = "examples/timers"


def artifact(records=(), receipts=()):
    value = {"timer_artifact_format": "determa.timer_records",
             "timer_artifact_schema_version": 1, "records": list(records),
             "operation_receipts": list(receipts)}
    value["timer_artifact_digest"] = digest(["determa-timer-artifact-1", value])
    return value


def record_from(request, prior, first):
    first_request = first["request"]
    event_id = first["expected"]["event_id"]
    state = prior.get("record_state", "pending")
    revision = str(prior.get("record_revision", "1"))
    fence = str(prior.get("attempt_fence", "1" if state in ("claimed", "fired") else "0"))
    return {"scope_identity": request["scope_identity"],
            "root_instance_id": request["root_instance_id"],
            "root_runtime_id": request["root_runtime_id"],
            "timer_id": request["timer_id"],
            "schedule_request_digest": first_request["request_digest"],
            "clock_basis": "unix_nanoseconds",
            "deadline_at": prior.get("deadline_at", "110"),
            "event_name": first_request["arguments"]["event_name"],
            "payload": first_request["arguments"]["payload"],
            "correlation_id": first_request["arguments"]["correlation_id"],
            "event_id": event_id, "state": state, "revision": revision,
            "attempt_fence": fence,
            "worker_principal": ("worker-B" if fence == "2" else "worker-A") if state == "claimed" else None,
            "expires_at": prior.get("claim_expires_at", "130") if state == "claimed" else None,
            "admission_receipt_digest": None}


def render(spec_root: Path):
    source = json.loads((spec_root / NORM / "timer-helper-cases-v1.json").read_text())
    clock = json.loads((spec_root / NORM / "timer-clock-cases-v1.json").read_text())
    admission = json.loads((spec_root / NORM / "timer-committed-admission-v1.json").read_text())
    delivery = json.loads((spec_root / "examples/delivery/execution-checkpoint-transfer-v1.json").read_text())
    target_source = (spec_root / "examples/portable-event-deferral.yaml").read_bytes()
    intent_source = (CASE / "machine.yaml").read_bytes()
    first = source["cases"][0]
    intent_test = YAML(typ="safe").load((CASE / "test.yaml").read_text())
    rows = []
    for sample in [*source["cases"], *source["early_errors"]]:
        name = sample["name"]
        prior = sample.get("prior", {})
        request, expected = sample["request"], sample["expected"]
        if name in ("schedule_first", "negative_zero", "fraction", "above_max", "json_number",
                    "duration_overflow", "clock_unavailable") or name in {x["name"] for x in source["early_errors"]}:
            before = artifact()
        else:
            record = record_from(request, prior, first)
            if name == "schedule_equal_replay":
                record["state"] = "claimed"
                record["revision"] = "2"
                record["attempt_fence"] = "1"
                record["worker_principal"] = "worker-A"
                record["expires_at"] = "130"
            if name == "complete_equal_replay":
                record["state"] = "fired"
                record["revision"] = "3"
                record["attempt_fence"] = "1"
                record["admission_receipt_digest"] = admission["admission_receipt_digest"]
            receipts = [{"operation_id": first["request"]["operation_id"],
                         "request_digest": first["request"]["request_digest"],
                         "result": first["expected"]}]
            if name == "complete_equal_replay":
                committed = next(x for x in source["cases"] if x["name"] == "coordinated_fire_commits")
                receipts.append({"operation_id": committed["request"]["operation_id"],
                                 "request_digest": committed["request"]["request_digest"],
                                 "result": committed["expected"]})
            before = artifact([record], receipts)
        after = copy.deepcopy(before)
        if expected["status"] == "accepted" and name not in ("schedule_equal_replay", "complete_equal_replay", "read_timer"):
            if name == "schedule_first":
                after = artifact([record_from(request, {"record_state": "pending", "record_revision": "1"}, first)])
            else:
                after["records"][0]["state"] = ("cancelled" if request["operation"] == "cancel" else
                                                   "claimed" if request["operation"] == "claim_fire" else "fired")
                after["records"][0]["revision"] = expected["record_revision"]
                if request["operation"] == "claim_fire":
                    after["records"][0]["attempt_fence"] = expected["attempt_fence"]
                    after["records"][0]["worker_principal"] = request["arguments"]["worker_principal"]
                    after["records"][0]["expires_at"] = expected["expires_at"]
                if request["operation"] == "complete_fire":
                    after["records"][0]["worker_principal"] = None
                    after["records"][0]["expires_at"] = None
                    after["records"][0]["admission_receipt_digest"] = request["arguments"]["admission_receipt_digest"]
                if request["operation"] == "cancel":
                    after["records"][0]["worker_principal"] = None
                    after["records"][0]["expires_at"] = None
            after["operation_receipts"].append({"operation_id": request["operation_id"],
                                                  "request_digest": request["request_digest"],
                                                  "result": expected})
            after = artifact(after["records"], after["operation_receipts"])
        checkpoint_before = delivery["before_admission"] if name in ("coordinated_fire_commits", "admission_rejected_before_commit") else None
        checkpoint_after = admission["committed_checkpoint"] if name == "coordinated_fire_commits" else checkpoint_before
        rows.append({"id": name, "request": request, "trusted_now": prior.get("trusted_now"),
                     "claim_expires_at": prior.get("lease_expires_at", "151" if name == "uncommitted_fire_recovery" else None),
                     "previous_attempt_fate": prior.get("prior_transaction_fate", prior.get("transaction_fate")),
                     "admission_disposition": prior.get("admission_result", "accepted" if name == "coordinated_fire_commits" else None),
                     "before": {"helper_artifact": before, "checkpoint": checkpoint_before},
                     "expected_result": expected,
                     "after": {"helper_artifact": after, "checkpoint": checkpoint_after},
                     "expected_calls": {"clock": int(name in ("schedule_first", "duration_overflow", "clock_unavailable", "claim_at_deadline", "claim_before_deadline", "uncommitted_fire_recovery", "ambiguous_fire_fate", "coordinated_fire_commits", "admission_rejected_before_commit")),
                                        "admission": int(name == "coordinated_fire_commits")}})
    clock_vectors = []
    def add_clock(label, field, value, now, deadline=None, error=None):
        request = copy.deepcopy(first["request"])
        request["operation_id"] = "clock-" + label
        request["arguments"].pop("delay_nanoseconds", None)
        request["arguments"][field] = value
        request["request_digest"] = digest(["determa-timer-request-1",
            {key: item for key, item in request.items() if key != "request_digest"}])
        result = copy.deepcopy(first["expected"])
        result["operation_id"] = request["operation_id"]
        if error is not None:
            result.update(status="rejected", record_revision=None, event_id=None,
                          error_code=error, result_digest=None)
            after = artifact()
        else:
            result["result_digest"] = digest(["determa-timer-result-1", request["request_digest"],
                {key: item for key, item in result.items() if key != "result_digest"}])
            record = record_from(request, {"record_state": "pending"}, first)
            record.update(schedule_request_digest=request["request_digest"], deadline_at=deadline)
            after = artifact([record], [{"operation_id": request["operation_id"],
                "request_digest": request["request_digest"], "result": result}])
        clock_vectors.append({"id": label, "request": request, "trusted_now": now,
            "claim_expires_at": None, "previous_attempt_fate": None,
            "admission_disposition": None,
            "before": {"helper_artifact": artifact(), "checkpoint": None},
            "expected_result": result,
            "after": {"helper_artifact": after, "checkpoint": None},
            "expected_calls": {"clock": int(field == "delay_nanoseconds" and
                                    error != "invalid_timer_time"), "admission": 0}})
    for index, value_ in enumerate(clock["valid_absolute"]):
        add_clock(f"valid_absolute_{index}", "deadline_at", value_, "0", deadline=value_)
    for index, value_ in enumerate(clock["valid_duration"]):
        add_clock(f"valid_duration_{index}", "delay_nanoseconds", value_, "0", deadline=value_)
    for index, value_ in enumerate(clock["invalid_absolute"]):
        add_clock(f"invalid_absolute_{index}", "deadline_at", value_, "0", error="invalid_timer_time")
    for index, value_ in enumerate(clock["invalid_duration"]):
        add_clock(f"invalid_duration_{index}", "delay_nanoseconds", value_, "0", error="invalid_timer_time")
    for sample in clock["cases"]:
        name = sample["name"]
        deadline = sample.get("expected_deadline")
        add_clock(name, "delay_nanoseconds", sample["duration"], sample["now"],
                  deadline=deadline, error=sample.get("expected_error"))
    value = {"fixture_format": "determa.timer_helper.conformance", "fixture_schema_version": 1,
             "specification_commit": "6207362e879ccca70f709e1eb4cc90448d910c0b",
             "machine_file": "machine.yaml", "setup_test_file": "test.yaml",
             "clock_cases": clock, "clock_vectors": clock_vectors, "cases": rows}
    fire_id = admission["fire_event_id"]
    envelope_digest = admission["envelope_digest"]
    after_step = copy.deepcopy(delivery["after_unhandled"])
    for receipt in after_step["operation_receipts"]:
        if receipt.get("event_id") == "received-1":
            receipt["event_id"] = fire_id
            receipt["request_digest"] = envelope_digest
    after_step = seal_checkpoint(after_step)
    first_row = rows[0]
    claim_row = next(row for row in rows if row["id"] == "claim_at_deadline")
    fire_row = next(row for row in rows if row["id"] == "coordinated_fire_commits")
    cancel_row = next(row for row in rows if row["id"] == "cancel_pending")
    helper_after_fire = copy.deepcopy(claim_row["after"]["helper_artifact"])
    helper_after_fire["records"][0].update(state="fired", revision="3",
        worker_principal=None, expires_at=None,
        admission_receipt_digest=admission["admission_receipt_digest"])
    helper_after_fire["operation_receipts"].append({"operation_id": fire_row["request"]["operation_id"],
        "request_digest": fire_row["request"]["request_digest"], "result": fire_row["expected_result"]})
    helper_after_fire = artifact(helper_after_fire["records"], helper_after_fire["operation_receipts"])
    create = {"operation": "create_v1", "bundle": {"bundle_file": "target-machine.yaml",
              "bundle_source_digest": "sha256:" + hashlib.sha256(target_source).hexdigest(),
              "validated_bundle_fingerprint": bundle_fingerprint_document(YAML(typ="safe").load(target_source))},
              "machine_id": "transaction_server", "machine_version": "1",
              "root_instance_id": "server-1", "creation_id": "create-server-1",
              "bindings": {"input": {}, "external": {}}}
    intent_create = {"operation": "create_v1", "bundle": {"bundle_file": "machine.yaml",
              "bundle_source_digest": "sha256:" + hashlib.sha256(intent_source).hexdigest(),
              "validated_bundle_fingerprint": bundle_fingerprint_document(YAML(typ="safe").load(intent_source))},
              "machine_id": "timer_client", "machine_version": "1",
              "root_instance_id": "timer-intent-main", "creation_id": "create-timer-intent-main",
              "bindings": {"input": {}, "external": {}}}
    cancel_intent_create = copy.deepcopy(intent_create)
    cancel_intent_create["root_instance_id"] = "timer-intent-cancel"
    cancel_intent_create["creation_id"] = "create-timer-intent-cancel"
    lifecycle = {"fixture_format": "determa.timer_helper.lifecycle", "fixture_schema_version": 1,
                 "create_request": create,
                 "intent_create_request": intent_create,
                 "cancel_intent_create_request": cancel_intent_create,
                 "intent_inputs": [intent_test["steps"][0]["send"]],
                 "cancel_intent_inputs": [intent_test["steps"][0]["send"], intent_test["steps"][1]["send"]],
                 "expected_intent_emissions": intent_test["steps"][0]["expect"]["emissions"],
                 "expected_cancel_intent_emissions": [*intent_test["steps"][0]["expect"]["emissions"],
                                                       *intent_test["steps"][1]["expect"]["emissions"]],
                 "schedule_request": first_row["request"],
                 "cancel_request": cancel_row["request"],
                 "claim_request": claim_row["request"],
                 "complete_request": fire_row["request"],
                 "step_request": {"operation": "step_v1", "target_runtime_id":
                                  first_row["request"]["root_runtime_id"]},
                 "trusted_clock_sequence": ["100", "100", "110", "120"],
                 "expected_create_checkpoint": delivery["before_admission"],
                 "expected_helper_after_schedule": first_row["after"]["helper_artifact"],
                 "expected_helper_after_cancel": cancel_row["after"]["helper_artifact"],
                 "expected_helper_after_claim": claim_row["after"]["helper_artifact"],
                 "expected_helper_after_fire": helper_after_fire,
                 "expected_admitted_checkpoint": admission["committed_checkpoint"],
                 "expected_after_step_checkpoint": after_step,
                 "expected_results": [first_row["expected_result"], claim_row["expected_result"], fire_row["expected_result"]],
                 "expected_fire_envelope": admission["committed_checkpoint"]["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]["envelope"]}
    outputs = {"vectors.generated.json": canonical(value) + b"\n",
               "lifecycle.generated.json": canonical(lifecycle) + b"\n",
               "archive-export.generated.json": canonical(json.loads((spec_root / NORM / "timer-archive-export-v1.json").read_text())) + b"\n",
               "archive-stage.generated.json": canonical(json.loads((spec_root / NORM / "timer-archive-stage-v1.json").read_text())) + b"\n",
               "target-machine.yaml": target_source,
               "machine.yaml": (CASE / "machine.yaml").read_bytes(),
               "test.yaml": (CASE / "test.yaml").read_bytes()}
    return outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = render(args.spec_root)
    stale = [name for name, data in outputs.items() if not (CASE / name).exists() or (CASE / name).read_bytes() != data]
    if args.check:
        if stale:
            parser.error("stale timer helper files: " + ", ".join(stale))
    else:
        for name, data in outputs.items():
            (CASE / name).write_bytes(data)
    print(f"{len(outputs)} timer helper files current; {len(json.loads(outputs['vectors.generated.json'])['cases'])} operations")


if __name__ == "__main__":
    main()
