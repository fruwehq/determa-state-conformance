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
            "roots": ["root-7"], "tombstones": [], "pending_intents": [],
            "terminal_intents": [], "definition_references": ["definition-7"],
            "migration_references": [], "required_participant_records": [],
            "freeze": None, "inventory": [], "retirement_grants": [],
            "destination_activations": []}


def inventory_of(snapshot: dict) -> list[dict]:
    members = []
    for field, kind in (("roots", "root"), ("tombstones", "tombstone"),
                        ("pending_intents", "pending_intent"), ("terminal_intents", "terminal_intent"),
                        ("definition_references", "definition"), ("migration_references", "migration")):
        members.extend({"kind": kind, "identity": item} for item in snapshot[field])
    members.extend({"kind": "receipt", "identity": item["operation_id"]} for item in snapshot["receipts"])
    members.extend({"kind": "checkpoint", "identity": str(index)} for index, _ in enumerate(snapshot["checkpoint_bytes"]))
    members.extend({"kind": "journal", "identity": item["work_identity"]} for item in snapshot["journal_entries"])
    members.extend({"kind": "participant", "identity": item} for item in snapshot["required_participant_records"])
    return sorted(members, key=lambda item: (item["kind"], item["identity"]))


def frozen_inventory_digest(evidence: str, inventory: list[dict]) -> str:
    # Driver binding of the committed freeze receipt to its exact storage snapshot.
    return digest(["determa-host-authority-frozen-inventory-1", evidence, inventory])


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
                before["required_participant_records"] = ["journal:journal-1", "worker:worker-1"]
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
                    after["inventory"] = inventory_of(after)
                    after["freeze"] = {"evidence_digest": result["evidence_digest"], "generation": "6",
                                       "inventory_digest": frozen_inventory_digest(result["evidence_digest"], after["inventory"]),
                                       "required_participants": copy.deepcopy(after["required_participant_records"])}
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
            profile_report = profiles["valid"][3 if name in {"freeze_after_drain", "retirement_with_known_fate", "retirement_equal_replay", "freeze_request_digest_is_not_committed_proof", "copied_database_relocation"} else
                                                2 if request["operation"] == "fence_worker" else 0]["report"]
            extension = profile_report["extension_report"]
            vector = {"id": name, "source_disposition": disposition, "request": request,
                      "execution_tier": "i2_conditional" if name in {"retirement_with_known_fate",
                          "retirement_equal_replay", "copied_database_relocation"} else "native_c",
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
    hypothetical_atoms = {
        "guarded_local_scope_without_relocation": ["scope_guard_through_native_commit", "frozen_authoritative_inventory"],
        "application_owned_transaction": [],
        "guarded_local_worker_fencing": ["scope_guard_through_native_commit", "frozen_authoritative_inventory",
                                         "guarded_journal_claim", "authenticated_worker_checks"],
        "proved_same_authority_local_relocation_support": ["scope_guard_through_native_commit",
            "frozen_authoritative_inventory", "guarded_journal_claim", "authenticated_worker_checks",
            "same_authority_transfer_proof"],
        "unproved_safe_relocation_claim": ["scope_guard_through_native_commit", "frozen_authoritative_inventory"],
        "missing_authority_cannot_claim_guarded_writes": [],
    }
    profile_vectors = [{"id": row["name"], "source_disposition": disposition,
                        "fixture_layer": "hypothetical_common_rule",
                        "hypothetical_verification": {"source_context": row.get("context"),
                            "proved_predicates": hypothetical_atoms[row["name"]]},
                        "configured_facts": {"topology": row["report"]["topology"],
                                             "extension_requirement": None if row["report"]["extension_report"] is None else
                                                {"category": row["report"]["extension_report"]["category"],
                                                 "provider_reference": row["report"]["extension_report"]["provider_reference"],
                                                 "instance_id": row["report"]["extension_report"]["instance_id"],
                                                 "required_claims": row["report"]["extension_report"]["claims"]},
                                             "storage_boundary": row["report"]["authority_storage_boundary"],
                                             "source_binding_digest": row["report"]["source_binding_digest"],
                                             "destination_binding_digest": row["report"]["destination_binding_digest"],
                                             "required_participants": row["report"]["required_participants"]},
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
    worker_ledger = copy.deepcopy(first["fence_worker_allocates_new_claim"]["ledger_after"])
    def check(name: str, phase: str, now: str | None, *, candidate: dict | None = None,
              principal: str = "worker-1", valid: bool = False):
        worker_checks.append({"id": name, "input": {"phase": phase, "claim": candidate or claim,
             "authenticated_principal": principal, "trusted_clock_now": now,
             "current_authority_epoch": "2", "current_attempt_fence": "4",
             "scope_state": "active", "ledger_before": copy.deepcopy(worker_ledger)},
             "expected": {"accepted": valid, "ledger_after": copy.deepcopy(worker_ledger),
                          "host_mutation_count": 0,
                          "external_dispatch_count": 1 if valid and phase == "dispatch" else 0}})
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
         "steps": [step(commit, fault="commit_unknown_disconnect", response=None,
                        after=first["unknown_native_transaction_fate"]["ledger_after"]),
                   step(first["unknown_native_transaction_fate"],
                        after=first["unknown_native_transaction_fate"]["ledger_after"])]},
        {"id": "incomplete_frozen_inventory_refuses_freeze", "required_guarantee": "complete_scope_inventory",
         "setup": first["freeze_after_drain"]["ledger_before"],
         "schedule": "omit_authoritative_receipt_from_frozen_enumeration",
         "steps": [{"call": {"request_bytes": first["freeze_after_drain"]["request_bytes"],
                              "invocation": first["freeze_after_drain"]["invocation"],
                              "native_mutation_bytes": None, "fault": "omit_receipt_from_inventory"},
                    "expected_response_bytes": raw({**first["freeze_after_drain"]["expected_response"],
                        "status": "rejected", "state": "active", "scope_generation": "5",
                        "evidence_digest": None, "error_code": "scope_fence_unproven"}),
                    "expected_ledger_after": copy.deepcopy(first["freeze_after_drain"]["ledger_before"])}]},
        {"id": "copied_database_cannot_relocate", "required_guarantee": "safe_relocation",
         "setup": first["copied_database_relocation"]["ledger_before"], "schedule": "one_attempt_then_observe",
         "steps": [step(first["copied_database_relocation"])]},
        {"id": "unsupported_relocation_inactive_destination", "required_guarantee": "none",
         "setup": first["unsupported_safe_relocation"]["ledger_before"], "schedule": "one_attempt_then_observe",
         "steps": [step(first["unsupported_safe_relocation"])]}
    ]
    copied_without_capability = copy.deepcopy(first["copied_database_relocation"])
    copied_without_capability["expected_response"]["error_code"] = "host_capability_mismatch"
    copied_without_capability["expected_response_bytes"] = raw(copied_without_capability["expected_response"])
    native_traces.append({"id": "copied_database_without_relocation_capability",
        "required_guarantee": "none", "setup": copied_without_capability["ledger_before"],
        "schedule": "one_attempt_then_observe", "steps": [step(copied_without_capability)]})
    def control(action: str, session: str | None = None, step_index: int | None = None,
                barrier: str | None = None) -> dict:
        return {"action": action, "session": session, "step": step_index, "barrier": barrier}
    def event(kind: str, session: str | None = None, response: str | None = None,
              snapshot: dict | None = None, fate: str | None = None,
              barrier: str | None = None, old_session_fenced: bool | None = None) -> dict:
        return {"event": kind, "session": session, "response_bytes": response,
                "ledger": copy.deepcopy(snapshot), "fate": fate, "barrier": barrier,
                "old_session_fenced": old_session_fenced}
    for trace in native_traces:
        name, steps = trace["id"], trace["steps"]
        trace.pop("schedule")
        if name == "precommit_rollback":
            controls = [control("invoke", "writer", 0, "before_native_commit"),
                        control("observe_native_fate", "writer"), control("observe_storage")]
            events = [event("response", "writer", None), event("native_fate", "writer", fate="rolled_back"),
                      event("storage", snapshot=steps[0]["expected_ledger_after"])]
        elif name == "postcommit_lost_response_replay":
            controls = [control("invoke", "writer", 0), control("observe_native_fate", "writer"),
                        control("observe_storage"), control("restart_authority"),
                        control("invoke", "writer", 1), control("observe_storage")]
            events = [event("response", "writer", None), event("native_fate", "writer", fate="committed"),
                      event("storage", snapshot=steps[0]["expected_ledger_after"]),
                      event("restarted", snapshot=steps[0]["expected_ledger_after"]),
                      event("response", "writer", steps[1]["expected_response_bytes"]),
                      event("storage", snapshot=steps[1]["expected_ledger_after"])]
        elif name in {"race_second_writer", "freeze_waits_for_writer"}:
            rival_barrier = "guard_waiting" if name == "race_second_writer" else "freeze_waiting_for_known_fate"
            controls = [control("start_call", "writer", 0, "guard_held_before_native_commit"),
                        control("start_call", "rival", 1, rival_barrier),
                        control("release_barrier", "writer", barrier="guard_held_before_native_commit"),
                        control("observe_native_fate", "writer"), control("observe_storage"),
                        control("release_barrier", "rival", barrier=rival_barrier),
                        control("observe_storage")]
            events = [event("barrier_reached", "writer", barrier="guard_held_before_native_commit"),
                      event("barrier_reached", "rival", barrier=rival_barrier),
                      event("response", "writer", steps[0]["expected_response_bytes"]),
                      event("native_fate", "writer", fate="committed"),
                      event("storage", snapshot=steps[0]["expected_ledger_after"]),
                      event("response", "rival", steps[1]["expected_response_bytes"]),
                      event("storage", snapshot=steps[1]["expected_ledger_after"])]
        elif name == "unknown_fate_blocks_freeze":
            controls = [control("start_call", "writer", 0, "commit_outcome_unknown"),
                        control("disconnect_session", "writer"),
                        control("observe_native_fate", "writer"), control("observe_storage"),
                        control("invoke", "freezer", 1), control("observe_storage"),
                        control("resolve_fate_from_storage", "writer"),
                        control("fence_old_session", "writer"), control("observe_storage")]
            events = [event("barrier_reached", "writer", barrier="commit_outcome_unknown"),
                      event("response", "writer", None),
                      event("native_fate", "writer", fate="unknown"),
                      event("storage", snapshot=steps[0]["expected_ledger_after"]),
                      event("response", "freezer", steps[1]["expected_response_bytes"]),
                      event("storage", snapshot=steps[1]["expected_ledger_after"]),
                      event("native_fate", "writer", fate="rolled_back"),
                      event("old_session_fenced", "writer", old_session_fenced=True),
                      event("storage", snapshot=trace["setup"])]
        else:
            controls = [control("invoke", "writer", 0), control("observe_storage")]
            events = [event("response", "writer", steps[0]["expected_response_bytes"]),
                      event("storage", snapshot=steps[0]["expected_ledger_after"])]
        trace["control_plan"] = controls
        trace["expected_events"] = events
    deleted_checkpoint_ledger = copy.deepcopy(commit["ledger_after"])
    deleted_checkpoint_ledger["checkpoint_bytes"] = []
    allocation_checks = [{"id": "scope_id_permanent_after_checkpoint_deletion",
        "input": {"ledger_before": commit["ledger_after"], "delete_portable_checkpoint": True,
                  "requested_scope_identity": "scope-42"},
        "expected": {"allocated": False, "ledger_after": deleted_checkpoint_ledger}}]
    base_core_checks = [{"id": "no_authority_" + operation,
         "input": {"request_bytes": first[name]["request_bytes"],
                   "configured_authority": None, "core_checkpoint_bytes": "portable-core-state"},
         "expected": {"status": "rejected", "code": "host_capability_mismatch",
                      "authority_result": None, "core_checkpoint_bytes": "portable-core-state",
                      "host_mutation_count": 0}}
        for operation, name in (("guarded_commit", "guarded_native_commit"),
                                ("freeze_scope", "freeze_after_drain"),
                                ("fence_worker", "fence_worker_allocates_new_claim"),
                                ("prove_retirement", "retirement_with_known_fate"))]
    unclaimed_guarantee_checks = []
    for name, guarantee in (("guarded_native_commit", "guarded_local_writes"),
                            ("freeze_after_drain", "guarded_local_writes"),
                            ("fence_worker_allocates_new_claim", "worker_fencing"),
                            ("retirement_with_known_fate", "safe_relocation")):
        original = first[name]
        before = ledger(generation=original["request"]["expected_scope_generation"])
        response = copy.deepcopy(original["expected_response"])
        response.update(status="rejected", scope_generation=before["scope_generation"],
                        state=before["state"], evidence_digest=None,
                        error_code="host_capability_mismatch", claim=None)
        unclaimed_guarantee_checks.append({"id": "unclaimed_" + original["request"]["operation"],
            "required_guarantee": guarantee, "request_bytes": original["request_bytes"],
            "invocation": original["invocation"], "native_mutation_bytes": original["native_mutation_bytes"],
            "fault": original["fault"], "ledger_before": before,
            "expected_response_bytes": raw(response), "ledger_after": copy.deepcopy(before),
            "effects_before": {"host_mutation_count": 0, "external_dispatch_count": 0,
                               "core_call_count": 0, "claim_allocation_count": 0},
            "effects_after": {"host_mutation_count": 0, "external_dispatch_count": 0,
                              "core_call_count": 0, "claim_allocation_count": 0}})
    production_scenarios = []
    for profile_index, scenario_name in ((0, "guarded_sqlite"), (2, "worker_sqlite")):
        configured = profiles["valid"][profile_index]["report"]
        participants = [item["role"] + ":" + item["instance_id"]
                        for item in configured["required_participants"]]
        def adapt_ledger(value: dict) -> dict:
            observed = copy.deepcopy(value)
            observed["required_participant_records"] = participants.copy()
            if observed["freeze"] is not None:
                observed["inventory"] = inventory_of(observed)
                observed["freeze"]["required_participants"] = participants.copy()
                observed["freeze"]["inventory_digest"] = frozen_inventory_digest(
                    observed["freeze"]["evidence_digest"], observed["inventory"])
            return observed
        scenario_operations = []
        for original in vectors:
            if original["execution_tier"] != "native_c":
                continue
            if scenario_name == "guarded_sqlite" and original["request"]["operation"] == "fence_worker":
                continue
            row = copy.deepcopy(original)
            row["ledger_before"] = adapt_ledger(row["ledger_before"])
            row["ledger_after"] = adapt_ledger(row["ledger_after"])
            scenario_operations.append(row)
        scenario_traces = []
        for original in native_traces:
            if original["required_guarantee"] == "safe_relocation":
                continue
            row = copy.deepcopy(original)
            row["setup"] = adapt_ledger(row["setup"])
            for native_step in row["steps"]:
                native_step["expected_ledger_after"] = adapt_ledger(native_step["expected_ledger_after"])
            for event_row in row["expected_events"]:
                if event_row["ledger"] is not None:
                    event_row["ledger"] = adapt_ledger(event_row["ledger"])
            scenario_traces.append(row)
        scenario_checks = []
        if scenario_name == "worker_sqlite":
            for original in worker_checks:
                row = copy.deepcopy(original)
                row["input"]["ledger_before"] = adapt_ledger(row["input"]["ledger_before"])
                row["expected"]["ledger_after"] = adapt_ledger(row["expected"]["ledger_after"])
                scenario_checks.append(row)
        scenario_allocation = copy.deepcopy(allocation_checks[0])
        scenario_allocation["input"]["ledger_before"] = adapt_ledger(
            scenario_allocation["input"]["ledger_before"])
        scenario_allocation["expected"]["ledger_after"] = adapt_ledger(
            scenario_allocation["expected"]["ledger_after"])
        production_scenarios.append({"id": scenario_name,
            "applicability": {"topology_identifier": configured["topology"]["identifier"],
                              "required_participants": configured["required_participants"]},
            "operations": scenario_operations, "worker_checks": scenario_checks,
            "native_traces": scenario_traces, "allocation_check": scenario_allocation})
    return (json.dumps({"format": "determa.host-authority-driver-v1", "schema_version": 1,
                       "specification_commit": SPEC_PIN, "operations": vectors,
                       "profiles": profile_vectors, "clocks": clock_vectors, "worker_checks": worker_checks,
                       "native_traces": native_traces, "allocation_checks": allocation_checks,
                       "base_core_checks": base_core_checks,
                       "unclaimed_guarantee_checks": unclaimed_guarantee_checks,
                       "production_scenarios": production_scenarios,
                       "transfer_suite_obligation": {"profile": "safe_relocation", "certified_by_this_profile": False,
                           "required_suite": "I2 same-authority transfer operational suite",
                           "required_native_observations": ["committed_source_retirement", "known_native_fate",
                               "old_session_cannot_commit", "exact_destination_binding", "single_use_grant_consumption",
                               "complete_participant_import", "inactive_destination_on_refusal"]}},
                       indent=2) + "\n").encode()


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
