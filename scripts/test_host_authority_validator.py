#!/usr/bin/env python3
"""Cross-binding attacks against valid host authority fixtures."""

from __future__ import annotations

import copy
from pathlib import Path

from validate_host_authority import AuthorityValidationError, PROFILE, compact, hash_value, load, validate_document


def main() -> int:
    spec = Path(__file__).resolve().parents[2] / "determa-state-spec"
    baseline = load(PROFILE / "vectors.generated.json")
    assert validate_document(baseline, spec) == (22, 6, 7)
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
    for name, document in attacks:
        try:
            validate_document(document, spec)
        except AuthorityValidationError:
            continue
        raise AssertionError(f"validator accepted {name}")
    print(f"rejected {len(attacks)} adversarial host authority substitutions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
