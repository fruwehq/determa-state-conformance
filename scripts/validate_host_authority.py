"""Independent source, schema and cross-artifact checks for hosted authority vectors."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from generate_host_authority_profile import PROFILE, SPEC_PIN, render


class AuthorityValidationError(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise AuthorityValidationError(message)


def unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key}")
        result[key] = value
    return result


def load(path: Path) -> dict:
    return json.loads(path.read_text(), object_pairs_hook=unique)


def compact(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def inventory_of(snapshot: dict) -> list[dict]:
    categories = (("roots", "root"), ("tombstones", "tombstone"),
                  ("pending_intents", "pending_intent"), ("terminal_intents", "terminal_intent"),
                  ("definition_references", "definition"), ("migration_references", "migration"))
    members = [{"kind": kind, "identity": identity} for field, kind in categories
               for identity in snapshot[field]]
    members += [{"kind": "receipt", "identity": row["operation_id"]} for row in snapshot["receipts"]]
    members += [{"kind": "checkpoint", "identity": str(index)}
                for index in range(len(snapshot["checkpoint_bytes"]))]
    members += [{"kind": "journal", "identity": row["work_identity"]} for row in snapshot["journal_entries"]]
    members += [{"kind": "participant", "identity": identity}
                for identity in snapshot["required_participant_records"]]
    return sorted(members, key=lambda row: (row["kind"], row["identity"]))


def frozen_inventory_digest(evidence: str, inventory: list[dict]) -> str:
    return hash_value(["determa-host-authority-frozen-inventory-1", evidence, inventory])


def schema_validators(spec_root: Path) -> tuple[Draft202012Validator, Draft202012Validator]:
    paths = [spec_root / "schema/host-authority-operation-v1.schema.json",
             spec_root / "schema/host-authority-profile-report-v1.schema.json",
             spec_root / "schema/extension-capability-report-v1.schema.json",
             spec_root / "schema/provider-reference-v1.schema.json"]
    schemas = [load(path) for path in paths]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    return (Draft202012Validator(schemas[0], registry=registry),
            Draft202012Validator(schemas[1], registry=registry))


def validate_document(document: dict, spec_root: Path) -> tuple[int, int, int, int, int, int]:
    request_schema, profile_schema = schema_validators(spec_root)
    source = load(spec_root / "examples/authority/host-authority-cases-v1.json")
    profile_source = load(spec_root / "examples/authority/host-authority-profile-cases-v1.json")
    clock_source = load(spec_root / "examples/authority/host-authority-clock-cases-v1.json")
    require(set(document) == {"format", "schema_version", "specification_commit", "operations", "profiles", "clocks", "worker_checks", "native_traces", "allocation_checks", "base_core_checks", "unclaimed_guarantee_checks", "production_scenarios", "transfer_suite_obligation"}, "manifest fields")
    require(document["format"] == "determa.host-authority-driver-v1" and document["schema_version"] == 1
            and document["specification_commit"] == SPEC_PIN, "format or spec pin")
    expected_names = {row["name"]: (disposition, row) for disposition in ("valid", "rejected") for row in source[disposition]}
    require(len(expected_names) == 22 and len(document["operations"]) == 22, "operation coverage")
    operations = {}
    for vector in document["operations"]:
        require(set(vector) == {"id", "source_disposition", "execution_tier", "request", "request_bytes", "expected_response",
                                "expected_response_bytes", "invocation", "native_mutation_bytes", "ledger_before",
                                "ledger_after", "fault", "replay_of", "configuration"}, "operation driver fields")
        name = vector["id"]
        require(name in expected_names and name not in operations, f"unknown or repeated operation {name}")
        disposition, example = expected_names[name]
        require(vector["source_disposition"] == disposition, f"{name}: disposition")
        require(vector["execution_tier"] == ("i2_conditional" if name in {
            "retirement_with_known_fate", "retirement_equal_replay", "copied_database_relocation"} else
            "native_c"), f"{name}: operational tier")
        request, response = vector["request"], vector["expected_response"]
        require(vector["request_bytes"] == compact(request) and vector["expected_response_bytes"] == compact(response), f"{name}: raw bytes")
        require(not list(request_schema.iter_errors(response)), f"{name}: response schema")
        early = name in {"malformed_request_early_error", "unknown_protocol_early_error", "unsupported_version_early_error"}
        require(bool(list(request_schema.iter_errors(request))) == early, f"{name}: request schema")
        if not early:
            require(request["request_digest"] == hash_value(["determa-host-authority-request-1",
                {key: value for key, value in request.items() if key != "request_digest"}]), f"{name}: request digest")
        require(response["status"] == example["expected"]["status"] and
                response["error_code"] == example["expected"]["error_code"], f"{name}: source outcome")
        require({key: value for key, value in response.items() if key != "evidence_digest"} ==
                {key: value for key, value in example["expected"].items() if key != "evidence_digest"},
                f"{name}: source response fields")
        source_request = example["request"]
        request_exclusions = {"request_digest"}
        if request["operation"] == "guarded_commit":
            request_exclusions.add("arguments")
        if name in {"retirement_with_known_fate", "retirement_equal_replay"}:
            request_exclusions.add("arguments")
        require({key: value for key, value in request.items() if key not in request_exclusions} ==
                {key: value for key, value in source_request.items() if key not in request_exclusions},
                f"{name}: source request fields")
        if response["status"] == "accepted":
            require(response["evidence_digest"] == hash_value(["determa-host-authority-evidence-1",
                request["request_digest"], {key: value for key, value in response.items() if key != "evidence_digest"}]), f"{name}: evidence digest")
        if response["claim"] is not None:
            claim = response["claim"]
            require(len(claim) == 10 and re.fullmatch(r"0|-?[1-9][0-9]*", claim["expires_at"]) is not None
                    and -(2**63) <= int(claim["expires_at"]) < 2**63, f"{name}: claim clock")
        mutation = vector["native_mutation_bytes"]
        if request["operation"] == "guarded_commit":
            require(isinstance(mutation, str) and request["arguments"]["mutation_digest"] ==
                    "sha256:" + hashlib.sha256(mutation.encode()).hexdigest(), f"{name}: native mutation bytes")
            require(mutation == compact({"scope_identity": request["scope_identity"],
                    "operation_id": request["operation_id"], "checkpoint": "checkpoint-for-" + request["operation_id"] + "-" +
                    example["request"]["arguments"]["mutation_digest"][7:15]}) or name == "same_operation_replay" and
                    mutation == operations["guarded_native_commit"]["native_mutation_bytes"],
                    f"{name}: native payload binding")
        else:
            require(mutation is None, f"{name}: unrelated native mutation")
        require(set(vector["invocation"]) == {"authenticated_principal", "authorized_scopes", "operation_rights",
                                               "assigned_worker_principal", "trusted_clock_now", "clock_available"}, f"{name}: trusted invocation")
        before, after = vector["ledger_before"], vector["ledger_after"]
        ledger_keys = {"allocated_scope_identities", "scope_identity", "owner_principal", "authority_epoch",
                       "scope_generation", "state", "receipts", "mutation_bytes", "checkpoint_bytes",
                       "journal_entries", "ingress_acknowledgements", "active_claims", "freeze", "inventory",
                       "retirement_grants", "destination_activations", "roots", "tombstones", "pending_intents", "terminal_intents",
                       "definition_references", "migration_references", "required_participant_records"}
        require(set(before) == ledger_keys and set(after) == ledger_keys, f"{name}: ledger fields")
        require(before["allocated_scope_identities"] == after["allocated_scope_identities"] == ["scope-42"], f"{name}: scope no-reuse")
        if response["status"] == "rejected":
            permitted = dict(before)
            if name == "unknown_native_transaction_fate":
                permitted["state"] = "transaction_in_doubt"
            require(after == permitted, f"{name}: rejected operation changed authority storage")
        elif name == "authorized_read" or vector["replay_of"]:
            require(after == before, f"{name}: read or replay mutation")
        else:
            require(int(after["scope_generation"]) == int(before["scope_generation"]) + 1,
                    f"{name}: generation advance")
            receipt = after["receipts"][-1]
            require(receipt == {"operation_id": request["operation_id"], "request_digest": request["request_digest"],
                                "request_bytes": vector["request_bytes"], "result_bytes": vector["expected_response_bytes"],
                                "evidence_digest": response["evidence_digest"]}, f"{name}: committed receipt")
            require(len(after["receipts"]) == len(before["receipts"]) + 1, f"{name}: receipt count")
        if name == "guarded_native_commit":
            require(after["mutation_bytes"] == before["mutation_bytes"] + [mutation] and
                    after["checkpoint_bytes"] == before["checkpoint_bytes"] + [mutation], "native mutation not atomic with receipt")
        if name == "freeze_after_drain":
            require(after["freeze"]["evidence_digest"] == response["evidence_digest"] and
                    after["inventory"] == inventory_of(after) and
                    after["freeze"]["inventory_digest"] == frozen_inventory_digest(
                        response["evidence_digest"], after["inventory"]) and
                    after["freeze"]["required_participants"] == after["required_participant_records"] ==
                        before["required_participant_records"], "complete freeze evidence and inventory")
        if name == "fence_worker_allocates_new_claim":
            require(after["active_claims"] == [response["claim"]] and
                    response["claim"]["scope_authority_epoch"] == after["authority_epoch"] and
                    response["claim"]["attempt_fence"] == after["journal_entries"][0]["attempt_fence"],
                    "fenced worker claim and journal")
        if request["operation"] == "prove_retirement" and response["status"] == "accepted":
            require(after["freeze"] is not None and request["arguments"]["freeze_evidence_digest"] == after["freeze"]["evidence_digest"], "retirement freeze proof")
        if name == "unauthorized_scope":
            require(response["scope_identity"] is None and response["authority_epoch"] is None and
                    response["scope_generation"] is None and response["state"] is None and before == after,
                    "unauthorized scope disclosure")
        if name == "replay_evidence_expired":
            require(before["receipts"][0]["operation_id"] == request["operation_id"] and
                    before["receipts"][0]["request_digest"] == request["request_digest"] and
                    before["receipts"][0]["result_bytes"] is None, "expired matching receipt")
        if name == "conflicting_operation_reuse":
            require(before["receipts"][0]["operation_id"] == request["operation_id"] and
                    before["receipts"][0]["request_digest"] != request["request_digest"], "conflicting operation key")
        if name == "retirement_with_known_fate":
            require(before == operations["freeze_after_drain"]["ledger_after"],
                    "retirement must resolve exact committed frozen storage record")
            require(vector["configuration"]["destination_binding_digest"] ==
                    profile_source["valid"][3]["report"]["destination_binding_digest"] and
                    "safe_relocation" in vector["configuration"]["extension_requirement"]["required_claims"],
                    "retirement topology and exact destination")
            require(before["inventory"] == inventory_of(before) and
                    before["required_participant_records"] == before["freeze"]["required_participants"] ==
                    ["journal:journal-1", "worker:worker-1"] and
                    before["freeze"]["inventory_digest"] == frozen_inventory_digest(
                        before["freeze"]["evidence_digest"], before["inventory"]) and
                    any(item["operation_id"] == "freeze-1" and item["evidence_digest"] ==
                        before["freeze"]["evidence_digest"] for item in before["receipts"]),
                    "retirement participant closure")
        if name == "retirement_equal_replay":
            require(before == operations["retirement_with_known_fate"]["ledger_after"],
                    "retirement replay storage record")
        operations[name] = vector
    for name, first_name in (("same_operation_replay", "guarded_native_commit"),
                             ("retirement_equal_replay", "retirement_with_known_fate")):
        replay, first = operations[name], operations[first_name]
        require(replay["request_bytes"] == first["request_bytes"] and
                replay["expected_response_bytes"] == first["expected_response_bytes"] and
                replay["ledger_before"] == first["ledger_after"] and replay["replay_of"] == first_name,
                f"{name}: exact retained replay")
    require(operations["freeze_request_digest_is_not_committed_proof"]["request"]["arguments"]["freeze_evidence_digest"]
            != operations["freeze_after_drain"]["expected_response"]["evidence_digest"], "freeze request used as proof")
    profile_names = {row["name"]: (disposition, row) for disposition in ("valid", "invalid") for row in profile_source[disposition]}
    require(len(profile_names) == len(document["profiles"]) == 6, "profile coverage")
    seen = set()
    for vector in document["profiles"]:
        require(set(vector) == {"id", "source_disposition", "fixture_layer", "hypothetical_verification", "configured_facts", "expected_report", "expected_report_bytes", "expected_outcome", "expected_support"}, "profile fields")
        name = vector["id"]
        require(name in profile_names and name not in seen, f"profile name {name}")
        seen.add(name)
        disposition, example = profile_names[name]
        require(vector["fixture_layer"] == "hypothetical_common_rule", f"{name}: profile source layer")
        atoms = {
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
        require(vector["hypothetical_verification"] == {"source_context": example.get("context"),
                "proved_predicates": atoms[name]}, f"{name}: source-only hypothetical premises")
        report = vector["expected_report"]
        require(vector["source_disposition"] == disposition and report == example["report"] and
                vector["expected_report_bytes"] == compact(report), f"{name}: source profile report")
        require(bool(list(profile_schema.iter_errors(report))) == (disposition == "invalid"), f"{name}: profile schema")
        require(vector["expected_outcome"] == ({"status": "accepted", "report_bytes": compact(report)} if disposition == "valid" else
                {"status": "rejected", "code": "host_capability_mismatch"}), f"{name}: profile refusal")
        facts = vector["configured_facts"]
        expected_requirement = None if report["extension_report"] is None else {
            "category": report["extension_report"]["category"],
            "provider_reference": report["extension_report"]["provider_reference"],
            "instance_id": report["extension_report"]["instance_id"],
            "required_claims": report["extension_report"]["claims"]}
        require(facts["topology"] == report["topology"] and facts["extension_requirement"] == expected_requirement and
                facts["source_binding_digest"] == report["source_binding_digest"] and
                facts["destination_binding_digest"] == report["destination_binding_digest"] and
                facts["required_participants"] == report["required_participants"], f"{name}: configured facts")
    clock_rows = [(kind, item["value"]) for kind in ("valid", "invalid") for item in clock_source[kind]]
    require(len(document["clocks"]) == len(clock_rows) == 7, "clock coverage")
    for vector, (disposition, value) in zip(document["clocks"], clock_rows):
        require(vector["source_disposition"] == disposition and vector["value"] == value, "source clock")
        valid = bool(re.fullmatch(r"0|-?[1-9][0-9]*", value)) and -(2**63) <= int(value.split(".")[0]) < 2**63
        require(valid == (disposition == "valid"), "signed 64-bit canonical clock")
    claim = operations["fence_worker_allocates_new_claim"]["expected_response"]["claim"]
    checks = document["worker_checks"]
    require([item["id"] for item in checks] == ["dispatch_before_expiry", "dispatch_at_expiry",
            "result_at_expiry", "clock_unavailable", "old_epoch", "old_attempt", "principal_mismatch"],
            "worker check coverage")
    for item in checks:
        require(set(item) == {"id", "input", "expected"} and
                set(item["input"]) == {"phase", "claim", "authenticated_principal",
                    "trusted_clock_now", "current_authority_epoch", "current_attempt_fence", "scope_state",
                    "ledger_before"} and
                set(item["expected"]) == {"accepted", "ledger_after", "host_mutation_count",
                    "external_dispatch_count"}, "closed worker check")
        candidate = item["input"]["claim"]
        now = item["input"]["trusted_clock_now"]
        valid = (candidate["scope_authority_epoch"] == item["input"]["current_authority_epoch"] and
                 candidate["attempt_fence"] == item["input"]["current_attempt_fence"] and
                 candidate["worker_principal"] == item["input"]["authenticated_principal"] and
                 item["input"]["scope_state"] == "active" and now is not None and
                 int(now) < int(candidate["expires_at"]))
        require(candidate["scope_identity"] == claim["scope_identity"] and
                item["expected"]["accepted"] is valid and
                item["input"]["ledger_before"] == item["expected"]["ledger_after"] ==
                    operations["fence_worker_allocates_new_claim"]["ledger_after"] and
                item["expected"]["host_mutation_count"] == 0 and
                item["expected"]["external_dispatch_count"] ==
                    (1 if valid and item["input"]["phase"] == "dispatch" else 0),
                "worker expiry/fence and mutation expectation")
    traces = document["native_traces"]
    require([item["id"] for item in traces] == ["precommit_rollback", "postcommit_lost_response_replay",
            "race_second_writer", "freeze_waits_for_writer", "unknown_fate_blocks_freeze",
            "incomplete_frozen_inventory_refuses_freeze", "copied_database_cannot_relocate",
            "unsupported_relocation_inactive_destination", "copied_database_without_relocation_capability"], "native trace coverage")
    for trace in traces:
        require(set(trace) == {"id", "required_guarantee", "setup", "steps", "control_plan", "expected_events"}, "native trace fields")
        require(trace["setup"]["allocated_scope_identities"] == ["scope-42"] and trace["steps"], "native trace setup")
        for step in trace["steps"]:
            require(set(step) == {"call", "expected_response_bytes", "expected_ledger_after"} and
                    set(step["call"]) == {"request_bytes", "invocation", "native_mutation_bytes", "fault"},
                    "native trace step fields")
            require(step["expected_ledger_after"]["allocated_scope_identities"] == ["scope-42"],
                    "native trace scope allocation")
        for control in trace["control_plan"]:
            require(set(control) == {"action", "session", "step", "barrier"} and
                    control["action"] in {"invoke", "start_call", "release_barrier", "observe_native_fate",
                        "observe_storage", "restart_authority", "disconnect_session",
                        "resolve_fate_from_storage", "fence_old_session"} and
                    (control["step"] is None or type(control["step"]) is int and
                     0 <= control["step"] < len(trace["steps"])), "closed native control")
            if control["action"] in {"invoke", "start_call"}:
                require(type(control["step"]) is int and type(control["session"]) is str,
                        "native call must select an exact step and session")
            else:
                require(control["step"] is None, "non-call control cannot select a request")
            if control["action"] in {"start_call", "release_barrier"}:
                require(type(control["barrier"]) is str and control["barrier"], "native barrier identity")
        require(sorted(item["step"] for item in trace["control_plan"] if item["action"] in
                       {"invoke", "start_call"}) == list(range(len(trace["steps"]))),
                "every native trace call must execute exactly once")
        started = {(item["session"], item["barrier"]) for item in trace["control_plan"]
                   if item["action"] == "start_call"}
        require(all((item["session"], item["barrier"]) in started for item in trace["control_plan"]
                    if item["action"] == "release_barrier"), "release of unstarted native barrier")
        for observed_event in trace["expected_events"]:
            require(set(observed_event) == {"event", "session", "response_bytes", "ledger", "fate",
                                             "barrier", "old_session_fenced"}, "closed native event")
        require({(item["session"], item["barrier"]) for item in trace["expected_events"]
                 if item["event"] == "barrier_reached"} == started and
                sum(item["event"] == "storage" for item in trace["expected_events"]) ==
                sum(item["action"] == "observe_storage" for item in trace["control_plan"]) and
                sum(item["event"] == "restarted" for item in trace["expected_events"]) ==
                sum(item["action"] == "restart_authority" for item in trace["control_plan"]) and
                sum(item["event"] == "native_fate" for item in trace["expected_events"]) ==
                sum(item["action"] in {"observe_native_fate", "resolve_fate_from_storage"}
                    for item in trace["control_plan"]),
                "native control events must be observed")
        responses = [item["response_bytes"] for item in trace["expected_events"] if item["event"] == "response"]
        snapshots = [item["ledger"] for item in trace["expected_events"] if item["event"] == "storage"]
        require(responses == [item["expected_response_bytes"] for item in trace["steps"]] and
                snapshots[:len(trace["steps"])] == [item["expected_ledger_after"] for item in trace["steps"]],
                f"{trace['id']}: native responses and storage events")
    expected_controls = {
        "precommit_rollback": ["invoke", "observe_native_fate", "observe_storage"],
        "postcommit_lost_response_replay": ["invoke", "observe_native_fate", "observe_storage",
            "restart_authority", "invoke", "observe_storage"],
        "race_second_writer": ["start_call", "start_call", "release_barrier",
            "observe_native_fate", "observe_storage", "release_barrier", "observe_storage"],
        "freeze_waits_for_writer": ["start_call", "start_call", "release_barrier",
            "observe_native_fate", "observe_storage", "release_barrier", "observe_storage"],
        "unknown_fate_blocks_freeze": ["start_call", "disconnect_session", "observe_native_fate",
            "observe_storage", "invoke", "observe_storage", "resolve_fate_from_storage",
            "fence_old_session", "observe_storage"],
        "incomplete_frozen_inventory_refuses_freeze": ["invoke", "observe_storage"],
        "copied_database_cannot_relocate": ["invoke", "observe_storage"],
        "unsupported_relocation_inactive_destination": ["invoke", "observe_storage"],
        "copied_database_without_relocation_capability": ["invoke", "observe_storage"],
    }
    for trace in traces:
        require([item["action"] for item in trace["control_plan"]] == expected_controls[trace["id"]],
                f"{trace['id']}: native control sequence")
        require([item["barrier"] for item in trace["control_plan"] if item["action"] == "start_call"] ==
                (["guard_held_before_native_commit", "guard_waiting"] if trace["id"] == "race_second_writer" else
                 ["guard_held_before_native_commit", "freeze_waiting_for_known_fate"] if
                 trace["id"] == "freeze_waits_for_writer" else
                 ["commit_outcome_unknown"] if trace["id"] == "unknown_fate_blocks_freeze" else []),
                f"{trace['id']}: native barrier")
    commit = operations["guarded_native_commit"]
    freeze = operations["freeze_after_drain"]
    precommit, lost, race, waiting, unknown, inventory, copied, unsupported, copied_unsupported = traces
    require(precommit["setup"] == commit["ledger_before"] and len(precommit["steps"]) == 1 and
            precommit["steps"][0]["expected_response_bytes"] is None and
            precommit["steps"][0]["expected_ledger_after"] == commit["ledger_before"],
            "precommit rollback trace")
    require(lost["setup"] == commit["ledger_before"] and len(lost["steps"]) == 2 and
            lost["steps"][0]["expected_response_bytes"] is None and
            lost["steps"][0]["expected_ledger_after"] == commit["ledger_after"] and
            lost["steps"][1]["call"]["request_bytes"] == commit["request_bytes"] and
            lost["steps"][1]["expected_response_bytes"] == commit["expected_response_bytes"] and
            lost["steps"][1]["expected_ledger_after"] == commit["ledger_after"],
            "postcommit lost response and exact replay trace")
    require(race["steps"][0]["expected_ledger_after"] == commit["ledger_after"] and
            json.loads(race["steps"][1]["expected_response_bytes"])["error_code"] == "scope_generation_conflict" and
            race["steps"][1]["expected_ledger_after"] == commit["ledger_after"],
            "second writer race trace")
    require(waiting["steps"][0]["expected_ledger_after"] == commit["ledger_after"] and
            waiting["steps"][1]["call"]["request_bytes"] == freeze["request_bytes"] and
            waiting["steps"][1]["expected_ledger_after"] == freeze["ledger_after"],
            "freeze waits for guarded writer trace")
    for trace, row in ((copied, operations["copied_database_relocation"]),
                       (unsupported, operations["unsupported_safe_relocation"])):
        require(trace["steps"][0]["call"]["request_bytes"] == row["request_bytes"] and
                trace["steps"][0]["expected_response_bytes"] == row["expected_response_bytes"] and
                trace["steps"][0]["expected_ledger_after"] == row["ledger_after"],
                f"{trace['id']}: source binding")
    require(unknown["steps"][0]["call"]["request_bytes"] == commit["request_bytes"] and
            unknown["steps"][0]["call"]["native_mutation_bytes"] == commit["native_mutation_bytes"] and
            unknown["steps"][1]["call"]["request_bytes"] ==
                operations["unknown_native_transaction_fate"]["request_bytes"] and
            unknown["steps"][1]["expected_response_bytes"] ==
                operations["unknown_native_transaction_fate"]["expected_response_bytes"],
            "unknown writer and blocked freeze exact calls")
    require(not copied["steps"][0]["expected_ledger_after"]["destination_activations"] and
            not unsupported["steps"][0]["expected_ledger_after"]["destination_activations"] and
            not copied_unsupported["steps"][0]["expected_ledger_after"]["destination_activations"] and
            copied_unsupported["steps"][0]["call"]["request_bytes"] ==
                operations["copied_database_relocation"]["request_bytes"] and
            json.loads(copied_unsupported["steps"][0]["expected_response_bytes"])["error_code"] ==
                "host_capability_mismatch",
            "refused relocation must leave destination inactive")
    require(inventory["steps"][0]["expected_ledger_after"] ==
            operations["freeze_after_drain"]["ledger_before"] and
            inventory["steps"][0]["call"]["request_bytes"] == freeze["request_bytes"] and
            json.loads(inventory["steps"][0]["expected_response_bytes"])["error_code"] == "scope_fence_unproven",
            "incomplete frozen inventory trace")
    require([item["fate"] for item in unknown["expected_events"] if item["event"] == "native_fate"] ==
            ["unknown", "rolled_back"] and
            unknown["expected_events"][-2]["event"] == "old_session_fenced" and
            unknown["expected_events"][-2]["old_session_fenced"] is True and
            unknown["expected_events"][-1]["ledger"] == unknown["setup"],
            "unknown fate must resolve from storage and fence old session")
    allocation = document["allocation_checks"]
    require(len(allocation) == 1 and allocation[0]["id"] == "scope_id_permanent_after_checkpoint_deletion" and
            allocation[0]["input"] == {"ledger_before": commit["ledger_after"],
                "delete_portable_checkpoint": True, "requested_scope_identity": "scope-42"} and
            allocation[0]["expected"] == {"allocated": False,
                "ledger_after": {**commit["ledger_after"], "checkpoint_bytes": []}},
            "permanent scope identity allocation after checkpoint deletion")
    base_names = {"no_authority_guarded_commit": "guarded_native_commit",
                  "no_authority_freeze_scope": "freeze_after_drain",
                  "no_authority_fence_worker": "fence_worker_allocates_new_claim",
                  "no_authority_prove_retirement": "retirement_with_known_fate"}
    require(len(document["base_core_checks"]) == len(base_names), "no-authority refusal coverage")
    for row in document["base_core_checks"]:
        require(set(row) == {"id", "input", "expected"} and row["id"] in base_names and
                set(row["input"]) == {"request_bytes", "configured_authority", "core_checkpoint_bytes"} and
                row["input"]["request_bytes"] == operations[base_names[row["id"]]]["request_bytes"] and
                row["input"]["configured_authority"] is None and
                row["expected"] == {"status": "rejected", "code": "host_capability_mismatch",
                    "authority_result": None, "core_checkpoint_bytes": row["input"]["core_checkpoint_bytes"],
                    "host_mutation_count": 0}, "base core must refuse hosted authority without mutation")
    unsupported_names = (("guarded_native_commit", "guarded_local_writes"),
                         ("freeze_after_drain", "guarded_local_writes"),
                         ("fence_worker_allocates_new_claim", "worker_fencing"),
                         ("retirement_with_known_fate", "safe_relocation"))
    unsupported = document["unclaimed_guarantee_checks"]
    require(len(unsupported) == len(unsupported_names), "unclaimed guarantee refusal coverage")
    for row, (name, guarantee) in zip(unsupported, unsupported_names):
        original = operations[name]
        before = json.loads(json.dumps(operations["guarded_native_commit"]["ledger_before"]))
        before["scope_generation"] = original["request"]["expected_scope_generation"]
        result = json.loads(json.dumps(original["expected_response"]))
        result.update(status="rejected", scope_generation=before["scope_generation"],
                      state=before["state"], evidence_digest=None,
                      error_code="host_capability_mismatch", claim=None)
        zero = {key: 0 for key in ("host_mutation_count", "external_dispatch_count",
                                   "core_call_count", "claim_allocation_count")}
        require(row == {"id": "unclaimed_" + original["request"]["operation"],
            "required_guarantee": guarantee, "request_bytes": original["request_bytes"],
            "invocation": original["invocation"],
            "native_mutation_bytes": original["native_mutation_bytes"], "fault": original["fault"],
            "ledger_before": before, "expected_response_bytes": compact(result),
            "ledger_after": before, "effects_before": zero, "effects_after": zero},
            f"{name}: configured unclaimed guarantee must refuse without any effect")
    scenarios = document["production_scenarios"]
    require([row["id"] for row in scenarios] == ["guarded_sqlite", "worker_sqlite"],
            "exact configured production scenario coverage")
    for scenario, source_index in zip(scenarios, (0, 2)):
        source_report = profile_source["valid"][source_index]["report"]
        require(set(scenario) == {"id", "applicability", "operations", "worker_checks",
                                  "native_traces", "allocation_check"} and
                scenario["applicability"] == {"topology_identifier": source_report["topology"]["identifier"],
                    "required_participants": source_report["required_participants"]},
                "production scenario applicability")
        participants = [item["role"] + ":" + item["instance_id"]
                        for item in source_report["required_participants"]]
        def adapted(snapshot: dict) -> dict:
            value = json.loads(json.dumps(snapshot))
            value["required_participant_records"] = participants.copy()
            if value["freeze"] is not None:
                value["inventory"] = inventory_of(value)
                value["freeze"]["required_participants"] = participants.copy()
                value["freeze"]["inventory_digest"] = frozen_inventory_digest(
                    value["freeze"]["evidence_digest"], value["inventory"])
            return value
        source_operations = [row for row in document["operations"] if row["execution_tier"] == "native_c" and
            (scenario["id"] == "worker_sqlite" or row["request"]["operation"] != "fence_worker")]
        require(len(scenario["operations"]) == len(source_operations), "scenario operation coverage")
        for row, original in zip(scenario["operations"], source_operations):
            expected = json.loads(json.dumps(original))
            expected["ledger_before"] = adapted(original["ledger_before"])
            expected["ledger_after"] = adapted(original["ledger_after"])
            require(row == expected, f"{scenario['id']}: operation topology/participants mismatch")
        source_traces = [row for row in traces if row["required_guarantee"] != "safe_relocation"]
        require(len(scenario["native_traces"]) == len(source_traces) == 8, "scenario trace coverage")
        for row, original in zip(scenario["native_traces"], source_traces):
            expected = json.loads(json.dumps(original))
            expected["setup"] = adapted(original["setup"])
            for item in expected["steps"]:
                item["expected_ledger_after"] = adapted(item["expected_ledger_after"])
            for item in expected["expected_events"]:
                if item["ledger"] is not None:
                    item["ledger"] = adapted(item["ledger"])
            require(row == expected, f"{scenario['id']}: native trace topology/participants mismatch")
        require(len(scenario["worker_checks"]) == (7 if scenario["id"] == "worker_sqlite" else 0),
                "scenario worker checks")
        if scenario["id"] == "worker_sqlite":
            for row, original in zip(scenario["worker_checks"], checks):
                expected = json.loads(json.dumps(original))
                expected["input"]["ledger_before"] = adapted(expected["input"]["ledger_before"])
                expected["expected"]["ledger_after"] = adapted(expected["expected"]["ledger_after"])
                require(row == expected, "scenario worker storage observation")
        expected_allocation = json.loads(json.dumps(allocation[0]))
        expected_allocation["input"]["ledger_before"] = adapted(
            expected_allocation["input"]["ledger_before"])
        expected_allocation["expected"]["ledger_after"] = adapted(
            expected_allocation["expected"]["ledger_after"])
        require(scenario["allocation_check"] == expected_allocation,
                "scenario permanent allocation observation")
    require(document["transfer_suite_obligation"] == {"profile": "safe_relocation",
        "certified_by_this_profile": False, "required_suite": "I2 same-authority transfer operational suite",
        "required_native_observations": ["committed_source_retirement", "known_native_fate",
            "old_session_cannot_commit", "exact_destination_binding", "single_use_grant_consumption",
            "complete_participant_import", "inactive_destination_on_refusal"]},
        "safe relocation must remain conditional on I2 operational evidence")
    return (len(operations), len(seen), len(clock_rows), len(checks), len(traces),
            len(document["base_core_checks"]))


def validate_profile(spec_root: Path, profile: Path = PROFILE) -> tuple[int, int, int, int, int, int]:
    document = load(profile / "vectors.generated.json")
    driver_schema = load(Path(__file__).resolve().parent / "schemas/host-authority-driver-v1.schema.json")
    require(not list(Draft202012Validator(driver_schema).iter_errors(document)), "closed driver schema")
    counts = validate_document(document, spec_root)
    require((profile / "vectors.generated.json").read_bytes() == render(spec_root),
            "generated authority vectors differ from pinned examples")
    return counts
