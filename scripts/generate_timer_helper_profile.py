#!/usr/bin/env python3
"""Pin the optional external timer helper's complete operation observations."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from ruamel.yaml import YAML
from generate_version1_vectors import (canonical, digest, typed_value,
                                       bundle_fingerprint_document, normalized_bundle, seal_aggregate,
                                       seal_checkpoint)

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


def configured_lifecycle(original, scope):
    """Reseal an executable timer lifecycle for the installed C/D/H host scope."""
    value = copy.deepcopy(original)
    requests = {}
    for name in ("schedule", "cancel", "claim", "complete"):
        request = value[name + "_request"]
        request["scope_identity"] = scope
        request["request_digest"] = digest(["determa-timer-request-1",
            {key: item for key, item in request.items() if key != "request_digest"}])
        requests[request["operation_id"]] = request
    schedule = value["schedule_request"]
    fire_id = digest(["determa-timer-fire-event-1", "1", scope,
        schedule["root_instance_id"], schedule["root_runtime_id"], schedule["timer_id"]])
    checkpoint = value["expected_admitted_checkpoint"]
    aggregate = checkpoint["root_record"]["aggregate_state"]
    entry = aggregate["runtimes"][0]["ready_mailbox"][0]
    envelope = entry["envelope"]
    envelope["event_id"] = fire_id
    envelope["cause_id"] = fire_id
    envelope_digest = digest(["determa-inbox-envelope-digest-1", "1",
                              checkpoint["root_instance_id"], "input", envelope])
    entry["envelope_digest"] = envelope_digest
    receipt = checkpoint["operation_receipts"][-1]
    receipt["event_id"] = fire_id
    receipt["request_digest"] = envelope_digest
    checkpoint["root_record"]["aggregate_state"] = seal_aggregate(aggregate)
    checkpoint = seal_checkpoint(checkpoint)
    value["expected_admitted_checkpoint"] = checkpoint
    value["expected_fire_envelope"] = envelope
    admission_digest = digest(["determa-timer-admission-receipt-1", receipt])
    complete = value["complete_request"]
    complete["arguments"]["event_id"] = fire_id
    complete["arguments"]["admission_receipt_digest"] = admission_digest
    complete["request_digest"] = digest(["determa-timer-request-1",
        {key: item for key, item in complete.items() if key != "request_digest"}])
    after_step = value["expected_after_step_checkpoint"]
    for terminal in after_step["operation_receipts"]:
        if terminal.get("operation_kind") in ("acceptance", "event_terminal"):
            terminal["event_id"] = fire_id
            terminal["request_digest"] = envelope_digest
    value["expected_after_step_checkpoint"] = seal_checkpoint(after_step)
    for field in ("expected_helper_after_schedule", "expected_helper_after_cancel",
                  "expected_helper_after_claim", "expected_helper_after_fire"):
        helper = value[field]
        record = helper["records"][0]
        record.update(scope_identity=scope, schedule_request_digest=schedule["request_digest"],
                      event_id=fire_id)
        if record["state"] == "fired":
            record["admission_receipt_digest"] = admission_digest
        for item in helper["operation_receipts"]:
            request = requests[item["operation_id"]]
            result = item["result"]
            result["event_id"] = fire_id
            result["scope_identity"] = scope
            result["result_digest"] = digest(["determa-timer-result-1", request["request_digest"],
                {key: part for key, part in result.items() if key != "result_digest"}])
            item["request_digest"] = request["request_digest"]
        value[field] = artifact(helper["records"], helper["operation_receipts"])
    value["expected_results"] = [value["expected_helper_after_schedule"]["operation_receipts"][-1]["result"],
        value["expected_helper_after_claim"]["operation_receipts"][-1]["result"],
        value["expected_helper_after_fire"]["operation_receipts"][-1]["result"]]
    return value


def render(spec_root: Path):
    source = json.loads((spec_root / NORM / "timer-helper-cases-v1.json").read_text())
    clock = json.loads((spec_root / NORM / "timer-clock-cases-v1.json").read_text())
    admission = json.loads((spec_root / NORM / "timer-committed-admission-v1.json").read_text())
    delivery = json.loads((spec_root / "examples/delivery/execution-checkpoint-transfer-v1.json").read_text())
    target_source = (spec_root / "examples/portable-event-deferral.yaml").read_bytes()
    intent_source = (CASE / "machine.yaml").read_bytes()
    first = source["cases"][0]
    first_claim = next(item for item in source["cases"] if item["name"] == "claim_at_deadline")
    first_fire = next(item for item in source["cases"] if item["name"] == "coordinated_fire_commits")
    retry_claim = next(item for item in source["cases"] if item["name"] == "uncommitted_fire_recovery")
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
            if record["state"] in ("claimed", "fired"):
                receipts.append({"operation_id": first_claim["request"]["operation_id"],
                                 "request_digest": first_claim["request"]["request_digest"],
                                 "result": first_claim["expected"]})
            if record["attempt_fence"] == "2":
                receipts.append({"operation_id": retry_claim["request"]["operation_id"],
                                 "request_digest": retry_claim["request"]["request_digest"],
                                 "result": retry_claim["expected"]})
            if record["state"] == "fired":
                receipts.append({"operation_id": first_fire["request"]["operation_id"],
                                 "request_digest": first_fire["request"]["request_digest"],
                                 "result": first_fire["expected"]})
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
                     "expected_calls": {"clock": 2 if name == "coordinated_fire_commits" else int(name in ("schedule_first", "duration_overflow", "clock_unavailable", "claim_at_deadline", "claim_before_deadline", "uncommitted_fire_recovery", "ambiguous_fire_fate", "admission_rejected_before_commit")),
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
             "specification_commit": "77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0",
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
    fence_vectors = []
    for name, error, change, now, clock_calls in (
            ("complete_at_expiry", "timer_stale_fence", {}, "130", 1),
            ("wrong_worker", "timer_worker_mismatch", {"worker_principal": "worker-B"}, "120", 0),
            ("changed_fire_event", "timer_event_conflict",
             {"event_id": "sha256:" + "0" * 64}, "120", 0)):
        request = copy.deepcopy(fire_row["request"])
        request["operation_id"] = name
        request["arguments"].update(change)
        request["request_digest"] = digest(["determa-timer-request-1",
            {key: item for key, item in request.items() if key != "request_digest"}])
        result = copy.deepcopy(fire_row["expected_result"])
        result.update(operation_id=name, status="rejected", record_revision="2",
                      delivery_state="none", error_code=error, result_digest=None)
        before = {"helper_artifact": claim_row["after"]["helper_artifact"],
                  "checkpoint": delivery["before_admission"]}
        fence_vectors.append({"id": name, "request": request, "trusted_now": now,
            "claim_expires_at": None, "previous_attempt_fate": None,
            "admission_disposition": None, "before": before, "expected_result": result,
            "after": copy.deepcopy(before), "expected_calls": {"clock": clock_calls, "admission": 0}})
    for name, error, second_now in (
            ("complete_expires_before_commit", "timer_stale_fence", "130"),
            ("complete_clock_unavailable_before_commit", "timer_clock_unavailable", None)):
        request = copy.deepcopy(fire_row["request"])
        request["operation_id"] = name
        request["request_digest"] = digest(["determa-timer-request-1",
            {key: item for key, item in request.items() if key != "request_digest"}])
        result = copy.deepcopy(fire_row["expected_result"])
        result.update(operation_id=name, status="rejected", record_revision="2",
                      delivery_state="none", error_code=error, result_digest=None)
        before = copy.deepcopy(fire_row["before"])
        fence_vectors.append({"id": name, "request": request, "trusted_now": "120",
            "trusted_clock_sequence": ["120", second_now],
            "claim_expires_at": None, "previous_attempt_fate": None,
            "admission_disposition": "accepted", "before": before, "expected_result": result,
            "after": copy.deepcopy(before), "expected_calls": {"clock": 2, "admission": 1}})
    value["fence_vectors"] = fence_vectors
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
                 "trusted_clock_sequence": ["100", "100", "110", "120", "120"],
                 "expected_create_checkpoint": delivery["before_admission"],
                 "expected_helper_after_schedule": first_row["after"]["helper_artifact"],
                 "expected_helper_after_cancel": cancel_row["after"]["helper_artifact"],
                 "expected_helper_after_claim": claim_row["after"]["helper_artifact"],
                 "expected_helper_after_fire": helper_after_fire,
                 "expected_admitted_checkpoint": admission["committed_checkpoint"],
                 "expected_after_step_checkpoint": after_step,
                 "expected_results": [first_row["expected_result"], claim_row["expected_result"], fire_row["expected_result"]],
                 "expected_fire_envelope": admission["committed_checkpoint"]["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]["envelope"]}
    installed_lifecycle = configured_lifecycle(lifecycle, "effect-scope-1")
    envelope = installed_lifecycle["expected_fire_envelope"]
    source_scope = installed_lifecycle["schedule_request"]["scope_identity"]
    source_delivery_id = digest(["determa-timer-source-delivery-1",
        installed_lifecycle["schedule_request"]["root_instance_id"],
        installed_lifecycle["schedule_request"]["root_runtime_id"],
        installed_lifecycle["schedule_request"]["timer_id"]])
    content = {"content_kind": "canonical_transport_value", "content_value": typed_value(envelope)}
    source_content_digest = digest(["determa-delivery-source-content-digest-1", "1",
        source_scope, source_delivery_id, content["content_kind"], content["content_value"]])
    ingress_request = {"delivery_message_kind": "ingress_request", "source": {
        "source_scope": source_scope, "source_delivery_id": source_delivery_id,
        "source_content_digest": source_content_digest, "content": content},
        "envelope": envelope, "delivery_mode": "input"}
    checkpoint = installed_lifecycle["expected_admitted_checkpoint"]
    acceptance = checkpoint["operation_receipts"][-1]
    evidence = {"operation_kind": "acceptance", "checkpoint": {
        "root_instance_id": checkpoint["root_instance_id"], "checkpoint_revision": checkpoint["revision"],
        "execution_checkpoint_digest": checkpoint["execution_checkpoint_digest"]},
        "receipt_sequence": acceptance["receipt_sequence"],
        "acceptance_sequence": acceptance["acceptance_sequence"],
        "envelope_digest": acceptance["request_digest"]}
    binding = {"delivery_message_kind": "admission_binding", "source_scope": source_scope,
        "source_delivery_id": source_delivery_id, "source_content_digest": source_content_digest,
        "event_id": envelope["event_id"], "envelope_digest": acceptance["request_digest"],
        "evidence": evidence}
    binding["admission_binding_digest"] = digest(["determa-admission-binding-digest-1", "1", binding])
    ownership = {"fixture_format": "determa.timer_helper.source_ownership",
        "fixture_schema_version": 1, "request": ingress_request,
        "before_checkpoint": installed_lifecycle["expected_create_checkpoint"],
        "after_checkpoint": checkpoint, "admission_binding": binding,
        "acceptance_receipt": acceptance,
        "acknowledge_after_commit": {"source_scope": source_scope,
                                     "source_delivery_id": source_delivery_id}}
    admitted = {"delivery_message_kind": "admitted", "source_scope": source_scope,
        "source_delivery_id": source_delivery_id, "source_content_digest": source_content_digest,
        "event_id": envelope["event_id"], "evidence": evidence,
        "retention": {"profile": "permanent", "minimum_replay_until": None},
        "decision_authority": {"kind": "host_profile", "identifier": "orders-host"},
        "acknowledge_source": True,
        "admission_binding_digest": binding["admission_binding_digest"]}
    claimed_timer = installed_lifecycle["expected_helper_after_claim"]
    fired_timer = installed_lifecycle["expected_helper_after_fire"]
    empty = {"checkpoint": "before-timer-checkpoint-v1.json", "bindings": [],
             "dead_letters": [], "source_acknowledgements": [], "provider_dispatches": 0,
             "timer_artifact": claimed_timer}
    committed = {**empty, "checkpoint": "after-timer-checkpoint-v1.json",
        "bindings": [binding], "source_acknowledgements": [ownership["acknowledge_after_commit"]],
        "timer_artifact": fired_timer}
    committed_unacknowledged = {**committed, "source_acknowledgements": []}
    fire_context = {"complete_request": installed_lifecycle["complete_request"],
                    "trusted_now": "120", "expected_prior_fate": "claimed",
                    "helper_provider_interface": "determa.timer_helper"}
    def ingress_vector(name, before, after, expected, fault=None, replay_of=None):
        return {"name": name, "operation": "ingest", "request": ingress_request,
                "timer_fire_context": fire_context,
                "before": before, "after": after, "fault_injection": fault,
                "replay_of": replay_of, "expected_response": expected}
    delivery_vectors = {"fixture_format": "determa.timer_helper.delivery_vectors",
        "fixture_schema_version": 1, "invalid_vectors": [], "vectors": [
            ingress_vector("timer_first_committed_admission", empty, committed, admitted),
            ingress_vector("timer_crash_after_commit_before_ack", empty, committed_unacknowledged,
                           {"kind": "no_response"}, "crash_after_commit_before_ack"),
            ingress_vector("timer_replay_after_commit_crash", committed_unacknowledged, committed, admitted,
                           replay_of="timer_crash_after_commit_before_ack")]}
    raw_export = json.loads((spec_root / NORM / "timer-archive-export-v1.json").read_text())
    live_export = copy.deepcopy(raw_export)
    source_checkpoint = lifecycle["expected_create_checkpoint"]
    source_definition = {"validated_bundle_fingerprint": source_checkpoint["root_record"][
        "aggregate_state"]["validated_bundle_fingerprint"],
        "normalized_bundle": typed_value(normalized_bundle(CASE / "target-machine.yaml"))}
    live_export["source_capture"]["checkpoints"] = [source_checkpoint]
    live_export["source_capture"]["normalized_definitions"] = [source_definition]
    live_export["source_capture"]["inventory_evidence"]["selected_checkpoint_digests"] = [
        source_checkpoint["execution_checkpoint_digest"]]
    archive = live_export["expected_archive"]
    archive["checkpoints"] = [source_checkpoint]
    archive["normalized_definitions"] = [source_definition]
    archive["members"] = [
        {"identity": "checkpoint:" + source_checkpoint["root_instance_id"],
         "digest": digest(source_checkpoint), "byte_length": str(len(canonical(source_checkpoint)))},
        {"identity": "definition:" + source_definition["validated_bundle_fingerprint"],
         "digest": digest(source_definition), "byte_length": str(len(canonical(source_definition)))},
        *[member for member in archive["members"] if member["identity"].startswith("participant:")]]
    archive["archive_digest"] = digest(["determa-archive-digest-1",
        {key: part for key, part in archive.items() if key != "archive_digest"}])
    live_export["expected_result"]["archive_digest"] = archive["archive_digest"]
    outputs = {"vectors.generated.json": canonical(value) + b"\n",
               "lifecycle.generated.json": canonical(lifecycle) + b"\n",
               "configured-lifecycle.generated.json": canonical(installed_lifecycle) + b"\n",
               "source-ownership.generated.json": canonical(ownership) + b"\n",
               "timer-delivery.generated.json": canonical(delivery_vectors) + b"\n",
               "archive-export.generated.json": canonical(json.loads((spec_root / NORM / "timer-archive-export-v1.json").read_text())) + b"\n",
               "archive-operational.generated.json": canonical(live_export) + b"\n",
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
