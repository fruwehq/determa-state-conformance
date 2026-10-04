#!/usr/bin/env python3
"""Build closed host-authority driver inputs from pinned §18 examples."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

import rfc8785

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance/profiles/host-authority"
SPEC_PIN = "6bd25e3fcdf068af861aa289903a8489bd8f0139"


def raw(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def request_digest(request: dict) -> str:
    return digest(["determa-host-authority-request-1", {k: v for k, v in request.items() if k != "request_digest"}])


def evidence_digest(request: dict, result: dict) -> str:
    return digest(["determa-host-authority-evidence-1", request["request_digest"],
                   {k: v for k, v in result.items() if k != "evidence_digest"}])


def ledger(epoch: str = "2", generation: str = "4", state: str = "active") -> dict:
    return {"allocated_scope_identities": ["scope-42"], "scope_identity": "scope-42",
            "owner_principal": "owner-1", "authority_epoch": epoch,
            "scope_generation": generation, "state": state, "receipts": [],
            "mutation_bytes": [], "checkpoint_bytes": [], "journal_entries": [],
            "ingress_acknowledgements": [], "active_claims": [],
            "freeze": None, "inventory": [], "retirement_grants": []}


def receipt(request: dict, result: dict) -> dict:
    return {"operation_id": request["operation_id"], "request_digest": request["request_digest"],
            "request_bytes": raw(request), "result_bytes": raw(result),
            "evidence_digest": result["evidence_digest"]}


def render(spec_root: Path) -> bytes:
    source = json.loads((spec_root / "examples/authority/host-authority-cases-v1.json").read_text())
    profiles = json.loads((spec_root / "examples/authority/host-authority-profile-cases-v1.json").read_text())
    clocks = json.loads((spec_root / "examples/authority/host-authority-clock-cases-v1.json").read_text())
    assert (len(source["valid"]), len(source["rejected"])) == (7, 15)
    assert (len(profiles["valid"]), len(profiles["invalid"])) == (4, 2)
    assert (len(clocks["valid"]), len(clocks["invalid"])) == (3, 4)
    vectors = []
    first = {}
    for disposition, rows in source.items():
        for source_case in rows:
            name = source_case["name"]
            request, result = copy.deepcopy(source_case["request"]), copy.deepcopy(source_case["expected"])
            context = source_case["context"]
            proposed = None
            if name in {"retirement_with_known_fate", "retirement_equal_replay"}:
                request["arguments"]["destination_binding_digest"] = profiles["valid"][3]["report"]["destination_binding_digest"]
                request["request_digest"] = request_digest(request)
                result["evidence_digest"] = evidence_digest(request, result)
            if request["operation"] == "guarded_commit":
                # Full native payload, including all bytes the guard must commit.
                proposed = raw({"scope_identity": request["scope_identity"],
                                "operation_id": request["operation_id"],
                                "checkpoint": "checkpoint-for-" + request["operation_id"] + "-" +
                                              source_case["request"]["arguments"]["mutation_digest"][7:15]}).encode()
                request["arguments"]["mutation_digest"] = "sha256:" + hashlib.sha256(proposed).hexdigest()
                request["request_digest"] = request_digest(request)
                if result["status"] == "accepted":
                    result["evidence_digest"] = evidence_digest(request, result)
            before = ledger(generation=result["scope_generation"] or "4", state=result["state"] or "active")
            if name in {"guarded_native_commit", "same_operation_replay"}:
                before = ledger()
                if name == "same_operation_replay":
                    before = copy.deepcopy(first["guarded_native_commit"]["ledger_after"])
                    request = copy.deepcopy(first["guarded_native_commit"]["request"])
                    result = copy.deepcopy(first["guarded_native_commit"]["expected_response"])
                    proposed = first["guarded_native_commit"]["native_mutation_bytes"].encode()
            elif name == "freeze_after_drain":
                before = ledger(generation="5")
                before["receipts"] = copy.deepcopy(first["guarded_native_commit"]["ledger_after"]["receipts"])
                before["mutation_bytes"] = copy.deepcopy(first["guarded_native_commit"]["ledger_after"]["mutation_bytes"])
                before["checkpoint_bytes"] = copy.deepcopy(first["guarded_native_commit"]["ledger_after"]["checkpoint_bytes"])
            elif name in {"retirement_with_known_fate", "retirement_equal_replay", "freeze_request_digest_is_not_committed_proof"}:
                before = copy.deepcopy(first["freeze_after_drain"]["ledger_after"])
                if name == "retirement_equal_replay":
                    before = copy.deepcopy(first["retirement_with_known_fate"]["ledger_after"])
            elif name in {"conflicting_operation_reuse", "replay_evidence_expired"}:
                before = copy.deepcopy(first["guarded_native_commit"]["ledger_after"])
                if name == "replay_evidence_expired":
                    before["receipts"][0] = {"operation_id": request["operation_id"],
                        "request_digest": request["request_digest"], "request_bytes": raw(request),
                        "result_bytes": None, "evidence_digest": None}
            elif name in {"copied_database_relocation", "unsupported_safe_relocation"}:
                before = copy.deepcopy(first["freeze_after_drain"]["ledger_after"])
            elif name == "fence_worker_allocates_new_claim":
                before["scope_generation"] = request["expected_scope_generation"]
                before["journal_entries"] = [{"work_identity": "effect-17", "attempt_fence": "3"}]
            elif name in {"stale_worker_attempt", "worker_principal_mismatch"}:
                before["journal_entries"] = [{"work_identity": "effect-17", "attempt_fence": context["current_attempt_fence"]}]
            elif name == "unknown_native_transaction_fate":
                before["state"] = "active"
            if name in {"unknown_protocol_early_error", "unsupported_version_early_error"}:
                # The deliberately invalid raw envelope must retain the source bytes.
                pass
            elif name == "malformed_request_early_error":
                pass
            else:
                assert request_digest(request) == request["request_digest"], name
            after = copy.deepcopy(before)
            if result["status"] == "accepted" and name not in {"authorized_read", "same_operation_replay", "retirement_equal_replay"}:
                after["scope_generation"] = result["scope_generation"]
                after["state"] = result["state"]
                after["receipts"].append(receipt(request, result))
                if name == "guarded_native_commit":
                    after["mutation_bytes"].append(proposed.decode())
                    after["checkpoint_bytes"].append(proposed.decode())
                elif name == "fence_worker_allocates_new_claim":
                    after["journal_entries"] = [{"work_identity": "effect-17", "attempt_fence": "4"}]
                    after["active_claims"] = [result["claim"]]
                elif name == "freeze_after_drain":
                    after["freeze"] = {"evidence_digest": result["evidence_digest"], "generation": "6"}
                    after["inventory"] = [{"kind": "root", "identity": "root-7"},
                                          {"kind": "receipt", "identity": "commit-1"}]
                elif name == "retirement_with_known_fate":
                    after["retirement_grants"] = [{"destination_binding_digest": request["arguments"]["destination_binding_digest"],
                                                   "consumed": False, "single_use": True}]
            if name == "unknown_native_transaction_fate":
                after["state"] = "transaction_in_doubt"
            if name == "retirement_equal_replay":
                request = copy.deepcopy(first["retirement_with_known_fate"]["request"])
                result = copy.deepcopy(first["retirement_with_known_fate"]["expected_response"])
            # Trusted inputs are complete driver context; source shorthand is not fed to the adapter.
            invocation = {"authenticated_principal": context.get("authenticated_principal", "untrusted"),
                          "authorized_scopes": ["scope-42"] if context.get("scope_authorized") else [],
                          "operation_rights": ["read_authority", "guarded_commit", "freeze_scope", "fence_worker", "prove_retirement"] if context.get("scope_authorized") else [],
                          "assigned_worker_principal": context.get("assigned_worker_principal"),
                          "trusted_clock_now": "1759999999999999999", "clock_available": True}
            fault = {"native_transaction_fate": context.get("native_transaction_fate", "known"),
                     "injection": "disconnect_before_fate_resolution" if name == "unknown_native_transaction_fate" else "none",
                     "epoch_check_separate_from_commit": name == "separate_epoch_check_and_root_cas"}
            profile_report = profiles["valid"][3 if name in {"retirement_with_known_fate", "retirement_equal_replay", "copied_database_relocation"} else
                                                2 if request["operation"] == "fence_worker" else 0]["report"]
            extension = profile_report["extension_report"]
            vector = {"id": name, "source_disposition": disposition, "request": request,
                      "request_bytes": raw(request), "expected_response": result,
                      "expected_response_bytes": raw(result), "invocation": invocation,
                      "native_mutation_bytes": proposed.decode() if proposed is not None else None,
                      "ledger_before": before, "ledger_after": after,
                      "fault": fault, "replay_of": "guarded_native_commit" if name == "same_operation_replay" else
                      "retirement_with_known_fate" if name == "retirement_equal_replay" else None,
                      "configuration": {"topology": profile_report["topology"],
                                        "source_binding_digest": profile_report["source_binding_digest"],
                                        "destination_binding_digest": request.get("arguments", {}).get("destination_binding_digest"),
                                        "required_participants": profile_report["required_participants"],
                                        "extension_requirement": {"category": extension["category"],
                                            "provider_reference": extension["provider_reference"],
                                            "instance_id": extension["instance_id"],
                                            "required_claims": extension["claims"]}}}
            vectors.append(vector)
            first[name] = vector
    profile_vectors = [{"id": row["name"], "source_disposition": disposition,
                        "configured_facts": {"topology": row["report"]["topology"],
                                             "extension_requirement": None if row["report"]["extension_report"] is None else
                                                {"category": row["report"]["extension_report"]["category"],
                                                 "provider_reference": row["report"]["extension_report"]["provider_reference"],
                                                 "instance_id": row["report"]["extension_report"]["instance_id"],
                                                 "required_claims": row["report"]["extension_report"]["claims"]},
                                             "storage_boundary": row["report"]["authority_storage_boundary"],
                                             "source_binding_digest": row["report"]["source_binding_digest"],
                                             "destination_binding_digest": row["report"]["destination_binding_digest"],
                                             "required_participants": row["report"]["required_participants"],
                                             "requested_guarantees": row["report"]["guarantees"]},
                        "expected_report": row["report"], "expected_report_bytes": raw(row["report"]),
                        "expected_outcome": {"status": "accepted", "report_bytes": raw(row["report"])} if disposition == "valid" else
                                            {"status": "rejected", "code": "host_capability_mismatch"},
                        "expected_support": row.get("expected")}
                       for disposition, rows in profiles.items() for row in rows]
    clock_vectors = [{"id": f"clock_{disposition}_{index}", "source_disposition": disposition,
                      "value": row["value"]} for disposition in ("valid", "invalid") for rows in (clocks[disposition],)
                     for index, row in enumerate(rows)]
    claim = first["fence_worker_allocates_new_claim"]["expected_response"]["claim"]
    worker_checks = []
    def check(name: str, phase: str, now: str | None, *, candidate: dict | None = None,
              principal: str = "worker-1", valid: bool = False):
        worker_checks.append({"id": name, "input": {"phase": phase, "claim": candidate or claim,
             "authenticated_principal": principal, "trusted_clock_now": now,
             "current_authority_epoch": "2", "current_attempt_fence": "4",
             "scope_state": "active"}, "expected": {"accepted": valid}})
    check("dispatch_before_expiry", "dispatch", "1759999999999999999", valid=True)
    check("dispatch_at_expiry", "dispatch", claim["expires_at"])
    check("result_at_expiry", "result", claim["expires_at"])
    check("clock_unavailable", "dispatch", None)
    stale_epoch = copy.deepcopy(claim)
    stale_epoch["scope_authority_epoch"] = "1"
    check("old_epoch", "result", "1759999999999999999", candidate=stale_epoch)
    stale_attempt = copy.deepcopy(claim)
    stale_attempt["attempt_fence"] = "3"
    check("old_attempt", "result", "1759999999999999999", candidate=stale_attempt)
    check("principal_mismatch", "dispatch", "1759999999999999999", principal="other")
    def step(row: dict, *, fault: str = "none", response: str | None = "expected",
             after: dict | None = None) -> dict:
        return {"call": {"request_bytes": row["request_bytes"], "invocation": row["invocation"],
                         "native_mutation_bytes": row["native_mutation_bytes"], "fault": fault},
                "expected_response_bytes": row["expected_response_bytes"] if response == "expected" else response,
                "expected_ledger_after": copy.deepcopy(after if after is not None else row["ledger_after"])}
    commit = first["guarded_native_commit"]
    freeze = first["freeze_after_drain"]
    race_request = copy.deepcopy(commit["request"])
    race_request["operation_id"] = "commit-race-2"
    race_bytes = raw({"scope_identity": "scope-42", "operation_id": "commit-race-2", "checkpoint": "race-2"})
    race_request["arguments"]["mutation_digest"] = "sha256:" + hashlib.sha256(race_bytes.encode()).hexdigest()
    race_request["request_digest"] = request_digest(race_request)
    race_response = copy.deepcopy(commit["expected_response"])
    race_response.update(operation_id="commit-race-2", status="rejected", evidence_digest=None,
                         error_code="scope_generation_conflict")
    native_traces = [
        {"id": "precommit_rollback", "required_guarantee": "guarded_local_writes",
         "setup": commit["ledger_before"], "schedule": "one_attempt_then_observe",
         "steps": [step(commit, fault="precommit_abort", response=None, after=commit["ledger_before"])]},
        {"id": "postcommit_lost_response_replay", "required_guarantee": "guarded_local_writes",
         "setup": commit["ledger_before"], "schedule": "restart_between_steps",
         "steps": [step(commit, fault="drop_response_after_commit", response=None), step(commit, after=commit["ledger_after"])]},
        {"id": "race_second_writer", "required_guarantee": "guarded_local_writes",
         "setup": commit["ledger_before"], "schedule": "pause_first_inside_native_guard_start_second_then_commit_first",
         "steps": [step(commit), {"call": {"request_bytes": raw(race_request), "invocation": commit["invocation"],
                                      "native_mutation_bytes": race_bytes, "fault": "none"},
                                  "expected_response_bytes": raw(race_response),
                                  "expected_ledger_after": copy.deepcopy(commit["ledger_after"])}]},
        {"id": "freeze_waits_for_writer", "required_guarantee": "guarded_local_writes",
         "setup": commit["ledger_before"], "schedule": "pause_commit_inside_native_guard_start_freeze_release_commit_then_freeze",
         "steps": [step(commit), step(freeze)]},
        {"id": "unknown_fate_blocks_freeze", "required_guarantee": "guarded_local_writes",
         "setup": first["unknown_native_transaction_fate"]["ledger_before"],
         "schedule": "disconnect_writer_before_fate_proof_then_attempt_freeze",
         "steps": [step(first["unknown_native_transaction_fate"], fault="commit_unknown_disconnect")]},
        {"id": "incomplete_inventory_blocks_retirement", "required_guarantee": "complete_scope_inventory",
         "setup": first["retirement_with_known_fate"]["ledger_before"],
         "schedule": "omit_authoritative_receipt_from_frozen_enumeration",
         "steps": [{"call": {"request_bytes": first["retirement_with_known_fate"]["request_bytes"],
                              "invocation": first["retirement_with_known_fate"]["invocation"],
                              "native_mutation_bytes": None, "fault": "omit_receipt_from_inventory"},
                    "expected_response_bytes": raw({**first["retirement_with_known_fate"]["expected_response"],
                        "status": "rejected", "state": "frozen", "scope_generation": "6",
                        "evidence_digest": None, "error_code": "scope_fence_unproven"}),
                    "expected_ledger_after": copy.deepcopy(first["retirement_with_known_fate"]["ledger_before"])}]},
        {"id": "copied_database_cannot_relocate", "required_guarantee": "safe_relocation",
         "setup": first["copied_database_relocation"]["ledger_before"], "schedule": "one_attempt_then_observe",
         "steps": [step(first["copied_database_relocation"])]},
        {"id": "unsupported_relocation_inactive_destination", "required_guarantee": "none",
         "setup": first["unsupported_safe_relocation"]["ledger_before"], "schedule": "one_attempt_then_observe",
         "steps": [step(first["unsupported_safe_relocation"])]}
    ]
    return (json.dumps({"format": "determa.host-authority-driver-v1", "schema_version": 1,
                       "specification_commit": SPEC_PIN, "operations": vectors,
                       "profiles": profile_vectors, "clocks": clock_vectors, "worker_checks": worker_checks,
                       "native_traces": native_traces,
                       "runtime_probes": ["expiry_equal_rejected", "clock_unavailable_rejected",
                                          "race_second_writer_with_freeze", "precommit_rollback",
                                          "commit_unknown_restart", "postcommit_lost_response_replay",
                                          "stale_worker_dispatch_and_result", "incomplete_frozen_inventory",
                                          "unsupported_relocation_inactive_destination"]}, indent=2) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=Path("../determa-state-spec"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = render(args.spec_root)
    path = PROFILE / "vectors.generated.json"
    if args.check:
        if not path.exists() or path.read_bytes() != payload:
            raise SystemExit("host authority vectors are stale")
    else:
        path.write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
