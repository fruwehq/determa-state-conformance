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


def schema_validators(spec_root: Path) -> tuple[Draft202012Validator, Draft202012Validator]:
    paths = [spec_root / "schema/host-authority-operation-v1.schema.json",
             spec_root / "schema/host-authority-profile-report-v1.schema.json",
             spec_root / "schema/extension-capability-report-v1.schema.json",
             spec_root / "schema/provider-reference-v1.schema.json"]
    schemas = [load(path) for path in paths]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    return (Draft202012Validator(schemas[0], registry=registry),
            Draft202012Validator(schemas[1], registry=registry))


def validate_document(document: dict, spec_root: Path) -> tuple[int, int, int]:
    request_schema, profile_schema = schema_validators(spec_root)
    source = load(spec_root / "examples/authority/host-authority-cases-v1.json")
    profile_source = load(spec_root / "examples/authority/host-authority-profile-cases-v1.json")
    clock_source = load(spec_root / "examples/authority/host-authority-clock-cases-v1.json")
    require(set(document) == {"format", "schema_version", "specification_commit", "operations", "profiles", "clocks", "worker_checks", "native_traces", "runtime_probes"}, "manifest fields")
    require(document["format"] == "determa.host-authority-driver-v1" and document["schema_version"] == 1
            and document["specification_commit"] == SPEC_PIN, "format or spec pin")
    expected_names = {row["name"]: (disposition, row) for disposition in ("valid", "rejected") for row in source[disposition]}
    require(len(expected_names) == 22 and len(document["operations"]) == 22, "operation coverage")
    operations = {}
    for vector in document["operations"]:
        require(set(vector) == {"id", "source_disposition", "request", "request_bytes", "expected_response",
                                "expected_response_bytes", "invocation", "native_mutation_bytes", "ledger_before",
                                "ledger_after", "fault", "replay_of", "configuration"}, "operation driver fields")
        name = vector["id"]
        require(name in expected_names and name not in operations, f"unknown or repeated operation {name}")
        disposition, example = expected_names[name]
        require(vector["source_disposition"] == disposition, f"{name}: disposition")
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
                       "retirement_grants"}
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
            require(after["freeze"]["evidence_digest"] == response["evidence_digest"] and after["inventory"], "freeze evidence")
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
            require(vector["configuration"]["destination_binding_digest"] ==
                    profile_source["valid"][3]["report"]["destination_binding_digest"] and
                    "safe_relocation" in vector["configuration"]["extension_requirement"]["required_claims"],
                    "retirement topology and exact destination")
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
        require(set(vector) == {"id", "source_disposition", "configured_facts", "expected_report", "expected_report_bytes", "expected_outcome", "expected_support"}, "profile fields")
        name = vector["id"]
        require(name in profile_names and name not in seen, f"profile name {name}")
        seen.add(name)
        disposition, example = profile_names[name]
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
                facts["required_participants"] == report["required_participants"] and
                facts["requested_guarantees"] == report["guarantees"], f"{name}: configured facts")
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
                    "trusted_clock_now", "current_authority_epoch", "current_attempt_fence", "scope_state"} and
                set(item["expected"]) == {"accepted"}, "closed worker check")
        candidate = item["input"]["claim"]
        now = item["input"]["trusted_clock_now"]
        valid = (candidate["scope_authority_epoch"] == item["input"]["current_authority_epoch"] and
                 candidate["attempt_fence"] == item["input"]["current_attempt_fence"] and
                 candidate["worker_principal"] == item["input"]["authenticated_principal"] and
                 item["input"]["scope_state"] == "active" and now is not None and
                 int(now) < int(candidate["expires_at"]))
        require(candidate["scope_identity"] == claim["scope_identity"] and
                item["expected"]["accepted"] is valid, "worker expiry/fence expectation")
    traces = document["native_traces"]
    require([item["id"] for item in traces] == ["precommit_rollback", "postcommit_lost_response_replay",
            "race_second_writer", "freeze_waits_for_writer", "unknown_fate_blocks_freeze",
            "incomplete_inventory_blocks_retirement", "copied_database_cannot_relocate",
            "unsupported_relocation_inactive_destination"], "native trace coverage")
    for trace in traces:
        require(set(trace) == {"id", "required_guarantee", "setup", "schedule", "steps"}, "native trace fields")
        require(trace["setup"]["allocated_scope_identities"] == ["scope-42"] and trace["steps"], "native trace setup")
        for step in trace["steps"]:
            require(set(step) == {"call", "expected_response_bytes", "expected_ledger_after"} and
                    set(step["call"]) == {"request_bytes", "invocation", "native_mutation_bytes", "fault"},
                    "native trace step fields")
            require(step["expected_ledger_after"]["allocated_scope_identities"] == ["scope-42"],
                    "native trace scope allocation")
    commit = operations["guarded_native_commit"]
    freeze = operations["freeze_after_drain"]
    precommit, lost, race, waiting, unknown, inventory, copied, unsupported = traces
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
    for trace, row in ((unknown, operations["unknown_native_transaction_fate"]),
                       (copied, operations["copied_database_relocation"]),
                       (unsupported, operations["unsupported_safe_relocation"])):
        require(trace["steps"][0]["call"]["request_bytes"] == row["request_bytes"] and
                trace["steps"][0]["expected_response_bytes"] == row["expected_response_bytes"] and
                trace["steps"][0]["expected_ledger_after"] == row["ledger_after"],
                f"{trace['id']}: source binding")
    require(inventory["steps"][0]["expected_ledger_after"] ==
            operations["retirement_with_known_fate"]["ledger_before"] and
            json.loads(inventory["steps"][0]["expected_response_bytes"])["error_code"] == "scope_fence_unproven",
            "incomplete frozen inventory trace")
    required_probes = {"expiry_equal_rejected", "clock_unavailable_rejected", "race_second_writer_with_freeze",
                       "precommit_rollback", "commit_unknown_restart", "postcommit_lost_response_replay",
                       "stale_worker_dispatch_and_result", "incomplete_frozen_inventory",
                       "unsupported_relocation_inactive_destination"}
    require(set(document["runtime_probes"]) == required_probes and len(document["runtime_probes"]) == len(required_probes), "native proof probes")
    return len(operations), len(seen), len(clock_rows)


def validate_profile(spec_root: Path, profile: Path = PROFILE) -> tuple[int, int, int]:
    document = load(profile / "vectors.generated.json")
    driver_schema = load(Path(__file__).resolve().parent / "schemas/host-authority-driver-v1.schema.json")
    require(not list(Draft202012Validator(driver_schema).iter_errors(document)), "closed driver schema")
    counts = validate_document(document, spec_root)
    require((profile / "vectors.generated.json").read_bytes() == render(spec_root),
            "generated authority vectors differ from pinned examples")
    return counts
