#!/usr/bin/env python3
"""Pin the optional external timer helper's complete operation observations."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from generate_version1_vectors import canonical, digest

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
    first = source["cases"][0]
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
                     "expected_calls": {"clock": int(name in ("schedule_first", "duration_overflow", "clock_unavailable", "claim_at_deadline", "claim_before_deadline", "uncommitted_fire_recovery", "ambiguous_fire_fate")),
                                        "admission": int(name == "coordinated_fire_commits")}})
    value = {"fixture_format": "determa.timer_helper.conformance", "fixture_schema_version": 1,
             "specification_commit": "6207362e879ccca70f709e1eb4cc90448d910c0b",
             "machine_file": "machine.yaml", "setup_test_file": "test.yaml",
             "clock_cases": clock, "cases": rows}
    outputs = {"vectors.generated.json": canonical(value) + b"\n",
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
