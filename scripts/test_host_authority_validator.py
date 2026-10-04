#!/usr/bin/env python3
"""Cross-binding attacks against valid host authority fixtures."""

from __future__ import annotations

import copy
import base64
import hashlib
import sys
from pathlib import Path

from validate_host_authority import AuthorityValidationError, PROFILE, compact, hash_value, load, validate_document
from run_host_authority_profile import (AdapterOutputError, adapter_call, common_rule_input,
                                        select_production_scenario, verify_configured_profile)


def main() -> int:
    spec = Path(__file__).resolve().parents[2] / "determa-state-spec"
    baseline = load(PROFILE / "vectors.generated.json")
    assert validate_document(baseline, spec) == (22, 6, 7, 7, 9, 4)
    by_name = {row["id"]: index for index, row in enumerate(baseline["operations"])}
    attacks = []
    def attack(name, edit):
        document = copy.deepcopy(baseline)
        edit(document)
        attacks.append((name, document))
    attack("scope swap", lambda d: d["operations"][by_name["authorized_read"]]["request"].update(scope_identity="other"))
    attack("operation swap", lambda d: d["operations"][by_name["authorized_read"]]["request"].update(operation_id="other"))
    attack("generation swap", lambda d: d["operations"][by_name["guarded_native_commit"]]["ledger_after"].update(scope_generation="6"))
    attack("response swap", lambda d: d["operations"][by_name["guarded_native_commit"]].update(expected_response_bytes="{}"))
    attack("mutation bytes swap", lambda d: d["operations"][by_name["guarded_native_commit"]].update(native_mutation_bytes="other"))
    def reseal_mutation(document):
        row = document["operations"][by_name["guarded_native_commit"]]
        row["native_mutation_bytes"] = "other"
        import hashlib
        row["request"]["arguments"]["mutation_digest"] = "sha256:" + hashlib.sha256(b"other").hexdigest()
        row["request"]["request_digest"] = hash_value(["determa-host-authority-request-1",
            {key: value for key, value in row["request"].items() if key != "request_digest"}])
        row["request_bytes"] = compact(row["request"])
        row["expected_response"]["evidence_digest"] = hash_value(["determa-host-authority-evidence-1",
            row["request"]["request_digest"],
            {key: value for key, value in row["expected_response"].items() if key != "evidence_digest"}])
        row["expected_response_bytes"] = compact(row["expected_response"])
        row["ledger_after"]["mutation_bytes"] = ["other"]
        row["ledger_after"]["checkpoint_bytes"] = ["other"]
        row["ledger_after"]["receipts"][0] = {"operation_id": row["request"]["operation_id"],
            "request_digest": row["request"]["request_digest"], "request_bytes": row["request_bytes"],
            "result_bytes": row["expected_response_bytes"], "evidence_digest": row["expected_response"]["evidence_digest"]}
    attack("mutation bytes resealed", reseal_mutation)
    attack("no retained response", lambda d: d["operations"][by_name["guarded_native_commit"]]["ledger_after"]["receipts"][0].update(result_bytes=None))
    attack("freeze request is proof", lambda d: d["operations"][by_name["freeze_request_digest_is_not_committed_proof"]]["request"]["arguments"].update(freeze_evidence_digest=d["operations"][by_name["freeze_after_drain"]]["expected_response"]["evidence_digest"]))
    attack("copied database grants retirement", lambda d: d["operations"][by_name["copied_database_relocation"]]["ledger_after"]["retirement_grants"].append({"copied": True}))
    attack("omitted inventory", lambda d: d["operations"][by_name["freeze_after_drain"]]["ledger_after"].update(inventory=[]))
    attack("omitted participant", lambda d: d["operations"][by_name["retirement_with_known_fate"]]["ledger_before"].update(required_participant_records=[]))
    attack("stale claim", lambda d: d["operations"][by_name["fence_worker_allocates_new_claim"]]["ledger_after"]["active_claims"][0].update(scope_authority_epoch="1"))
    attack("unauthorized leak", lambda d: d["operations"][by_name["unauthorized_scope"]]["expected_response"].update(scope_identity="scope-42"))
    attack("clock overflow", lambda d: d["operations"][by_name["fence_worker_allocates_new_claim"]]["expected_response"]["claim"].update(expires_at="9223372036854775808"))
    attack("extra claim field", lambda d: d["operations"][by_name["fence_worker_allocates_new_claim"]]["expected_response"]["claim"].update(clock_basis="unix_nanoseconds"))
    attack("invalid clock classification", lambda d: d["clocks"][0].update(source_disposition="invalid"))
    attack("safe relocation false report", lambda d: d["profiles"][0]["expected_report"]["guarantees"].update(safe_relocation=True))
    attack("lost response commits twice", lambda d: d["native_traces"][1]["steps"][1]["expected_ledger_after"].update(scope_generation="6"))
    attack("scope identity reused", lambda d: d["allocation_checks"][0]["expected"].update(allocated=True))
    def reseal_postfreeze_participant(document):
        row = document["operations"][by_name["retirement_with_known_fate"]]["ledger_before"]
        row["required_participant_records"] = ["journal:journal-1", "worker:other"]
        row["inventory"] = [{**member, "identity": "worker:other"} if member ==
                            {"kind": "participant", "identity": "worker:worker-1"} else member
                            for member in row["inventory"]]
        row["freeze"]["required_participants"] = row["required_participant_records"]
        row["freeze"]["inventory_digest"] = hash_value(["determa-host-authority-frozen-inventory-1",
            row["freeze"]["evidence_digest"], row["inventory"]])
    attack("resealed post-freeze participant", reseal_postfreeze_participant)
    attack("missing native barrier", lambda d: d["native_traces"][2]["control_plan"].pop(1))
    attack("unknown fate accepted without resolution", lambda d: d["native_traces"][4]["control_plan"].pop(4))
    attack("rejected worker mutates journal", lambda d: d["worker_checks"][1]["expected"]["ledger_after"]["journal_entries"].append({"bad": True}))
    for name, document in attacks:
        try:
            validate_document(document, spec)
        except AuthorityValidationError:
            continue
        raise AssertionError(f"validator accepted {name}")
    for name, payload, expected in [
        ("duplicate response member", b'{"accepted":false,"accepted":false}', {"accepted": False}),
        ("nonfinite", b'{"accepted":NaN}', {"accepted": False}),
        ("invalid UTF-8", b'{"accepted":"\xff"}', {"accepted": False}),
        ("boolean as integer", b'{"accepted":0}', {"accepted": False}),
        ("extra body member", b'{"accepted":false,"extra":null}', {"accepted": False}),
        ("missing body member", b'{}', {"accepted": False}),
        ("missing native event", b'{"events":[]}', {"events": [{"event": "storage"}]}),
    ]:
        child = [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({payload!r})"]
        try:
            adapter_call(child, {}, expected, name)
        except AdapterOutputError:
            pass
        else:
            raise AssertionError(f"runner accepted {name}")
    no_authority = next(row for row in baseline["profiles"] if row["id"] == "application_owned_transaction")
    verify_configured_profile({"report_bytes": no_authority["expected_report_bytes"],
                               "installation_evidence": None}, spec, set())
    assert len(baseline["profiles"]) == 6
    for row in baseline["profiles"]:
        call = common_rule_input(row)
        assert set(call) == {"kind", "configured_facts", "hypothetical_verification"}
        assert "requested_guarantees" not in call["configured_facts"]
        assert "expected" not in call and "report_bytes" not in call
        wrong = b'{"status":"accepted","report_bytes":"{}"}' if row["source_disposition"] == "invalid" else \
                b'{"status":"rejected","code":"host_capability_mismatch"}'
        child = [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({wrong!r})"]
        try:
            adapter_call(child, call, row["expected_outcome"], row["id"])
        except AdapterOutputError:
            pass
        else:
            raise AssertionError(f"common-rule seam accepted wrong outcome for {row['id']}")
    guarded_report = next(row for row in baseline["profiles"] if row["id"] ==
                          "guarded_local_scope_without_relocation")["expected_report"]
    assert select_production_scenario(baseline, guarded_report)["id"] == "guarded_sqlite"
    worker_report = next(row for row in baseline["profiles"] if row["id"] ==
                         "guarded_local_worker_fencing")["expected_report"]
    assert select_production_scenario(baseline, worker_report)["id"] == "worker_sqlite"
    wrong_participant = copy.deepcopy(worker_report)
    wrong_participant["required_participants"][0]["instance_id"] = "other-journal"
    try:
        select_production_scenario(baseline, wrong_participant)
    except AdapterOutputError:
        pass
    else:
        raise AssertionError("runner accepted a claim for an untested participant topology")
    for name, profile_id, installation in [
        ("fabricated safe relocation", "proved_same_authority_local_relocation_support", None),
        ("healthy report without installed closure", "guarded_local_scope_without_relocation", None),
        ("wrong installed closure", "guarded_local_scope_without_relocation",
         {"closure_bytes_base64": "Yg==", "configuration_bytes_base64": "Yg==",
          "observed_health": "healthy", "native_proof_ids": []}),
    ]:
        vector = next(row for row in baseline["profiles"] if row["id"] == profile_id)
        try:
            verify_configured_profile({"report_bytes": vector["expected_report_bytes"],
                                       "installation_evidence": installation}, spec, set())
        except AdapterOutputError:
            pass
        else:
            raise AssertionError(f"public profile gate accepted {name}")
    guarded = copy.deepcopy(next(row for row in baseline["profiles"] if row["id"] ==
                            "guarded_local_scope_without_relocation")["expected_report"])
    closure_bytes, configuration_bytes = b"installed authority closure", b"native authority configuration"
    guarded["extension_report"]["provider_reference"]["content_digest"] = "sha256:" + hashlib.sha256(closure_bytes).hexdigest()
    guarded["topology"]["configuration_digest"] = "sha256:" + hashlib.sha256(configuration_bytes).hexdigest()
    needed_proofs = {"precommit_rollback", "postcommit_lost_response_replay", "race_second_writer",
                     "freeze_waits_for_writer", "freeze_after_drain", "incomplete_frozen_inventory_refuses_freeze"}
    installation = {"closure_bytes_base64": base64.b64encode(closure_bytes).decode(),
                    "configuration_bytes_base64": base64.b64encode(configuration_bytes).decode(),
                    "observed_health": "healthy", "participant_installations": [],
                    "native_proof_ids": sorted(needed_proofs)}
    verify_configured_profile({"report_bytes": compact(guarded), "installation_evidence": installation},
                              spec, needed_proofs)
    try:
        verify_configured_profile({"report_bytes": compact(guarded),
            "installation_evidence": {**installation, "native_proof_ids": []}}, spec, needed_proofs)
    except AdapterOutputError:
        pass
    else:
        raise AssertionError("public profile gate accepted a native claim without passed proofs")
    worker = copy.deepcopy(next(row for row in baseline["profiles"] if row["id"] ==
                           "guarded_local_worker_fencing")["expected_report"])
    worker["extension_report"]["provider_reference"]["content_digest"] = guarded[
        "extension_report"]["provider_reference"]["content_digest"]
    worker["topology"]["configuration_digest"] = guarded["topology"]["configuration_digest"]
    participant_installations = []
    for participant in worker["required_participants"]:
        participant_bytes = participant["role"].encode()
        participant["provider_reference"]["content_digest"] = "sha256:" + hashlib.sha256(
            participant_bytes).hexdigest()
        participant_installations.append({"participant": copy.deepcopy(participant),
            "closure_bytes_base64": base64.b64encode(participant_bytes).decode(),
            "observed_health": "healthy"})
    worker_installation = {**installation, "participant_installations": participant_installations}
    verify_configured_profile({"report_bytes": compact(worker), "installation_evidence": worker_installation},
                              spec, set(), require_native_proof=False)
    corrupted = copy.deepcopy(worker_installation)
    corrupted["participant_installations"][0]["closure_bytes_base64"] = "Yg=="
    try:
        verify_configured_profile({"report_bytes": compact(worker), "installation_evidence": corrupted},
                                  spec, set(), require_native_proof=False)
    except AdapterOutputError:
        pass
    else:
        raise AssertionError("public profile gate accepted wrong installed participant")
    print(f"rejected {len(attacks)} adversarial host authority substitutions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
