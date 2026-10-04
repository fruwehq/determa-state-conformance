#!/usr/bin/env python3
"""Materialize the closed §11.5 public extension negotiation driver vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "conformance/profiles/extension-negotiation"
SPEC_CASES = "examples/extensions/capability-cases-v1.json"
SPEC_PIN = "6bd25e3fcdf068af861aa289903a8489bd8f0139"


def render(spec_root: Path, profile: Path = PROFILE) -> bytes:
    source = json.loads((spec_root / SPEC_CASES).read_text())
    assert source["schema_version"] == 1 and len(source["cases"]) == 13
    closure_files = ["provider/test_provider.py", "provider/test_provider.rs"]
    closure_hash = hashlib.sha256(b"determa-test-provider-closure-1\0")
    for relative in closure_files:
        payload = (profile / relative).read_bytes()
        closure_hash.update(len(relative.encode()).to_bytes(8, "big"))
        closure_hash.update(relative.encode())
        closure_hash.update(len(payload).to_bytes(8, "big"))
        closure_hash.update(payload)
    digest = "sha256:" + closure_hash.hexdigest()
    vectors = []
    for case in source["cases"]:
        original = copy.deepcopy(case)
        name = original.pop("name")
        outcome = original.pop("expected")
        original.pop("reason")
        def bind(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "provider_reference":
                        item["content_digest"] = ("sha256:" + "b" * 64) if item["content_digest"] == "sha256:" + "b" * 64 else digest
                    else:
                        bind(item)
            elif isinstance(value, list):
                for item in value:
                    bind(item)
        bind(original)
        registrations = original.pop("registered", None)
        if registrations is None:
            registrations = [original["descriptor"]] if "descriptor" in original else [
                participant["descriptor"] for participant in original.get("participants", [])
            ]
        registrations = list({(d["category"], d["provider_reference"]["identifier"], d["provider_reference"]["version"]): d for d in registrations}.values()) if name != "duplicate_registration" else registrations
        reports = [original["report"]] if "report" in original else [
            p["report"] for p in original.get("participants", [])
        ]
        configurations = [
            {"category": report["category"], "provider_reference": report["provider_reference"],
             "configuration": {"instance_id": report["instance_id"], "claims": report["claims"], "health": report["health"]}}
            for report in reports
        ]
        requirements = [original["requirement"]] if "requirement" in original else []
        if name == "missing_provider":
            configurations = []
        if name == "unrecognized_requirement":
            registrations = [copy.deepcopy(source["cases"][0]["descriptor"])]
            bind(registrations)
        if outcome == "schema_invalid":
            outcome = "invalid_extension_descriptor"
        expected = {"status": "accepted", "reports": reports,
                    "effective": original.get("effective", {})} if outcome == "accept" else {
                        "status": "rejected", "code": outcome}
        if name == "healthy_report_omits_io_hazard":
            expected = {"status": "rejected", "code": "extension_capability_mismatch"}
        vectors.append({
            "id": name, "source_case": name, "registrations": registrations,
            "registration_bytes": [json.dumps(d, sort_keys=True, separators=(",", ":")) for d in registrations],
            "configurations": configurations, "requirements": requirements,
            "lookup_uri": original.get("lookup_uri"),
            "operation": {
                "kind": "compose" if "participants" in original else "negotiate",
                "requested_profile": original.get("requested_profile"),
                "projection": list(original.get("effective", {})),
            },
            # Hypothetical premises for the normative common-rule examples.
            # They never authorize an actual configured instance's claims.
            "hypothetical_verification": {
                "proofs": [
                    {"category": r["category"], "provider_reference": r["provider_reference"],
                     "instance_id": r["instance_id"], "configuration_digest":
                         "sha256:" + hashlib.sha256(json.dumps(c["configuration"], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                     "claims": r["claims"]}
                    for r, c in zip(reports, configurations)
                ],
                "host_guarantees": {key: True for key in
                    ("deterministic", "pure", "portable", "semantically_introspectable", "process_contained")},
                "weak_profile_opt_in": name == "composition_all_and_any",
            },
            "expected": expected,
            "expected_core_mutations": 0,
        })
    # Additional exact-identity and instance-binding attacks omitted by the source examples.
    base = copy.deepcopy(vectors[0])
    for name, mutate, code in [
        ("changed_exact_version", lambda v: v["requirements"][0]["provider_reference"].update(version="1.2.4"), "extension_identity_mismatch"),
        ("changed_exact_digest", lambda v: v["requirements"][0]["provider_reference"].update(content_digest="sha256:"+"f"*64), "extension_identity_mismatch"),
        ("changed_instance", lambda v: v["requirements"][0].update(instance_id="other"), "extension_capability_mismatch"),
        ("changed_category", lambda v: v["requirements"][0].update(category="projection", capability="lossless_projection"), "unknown_extension"),
        ("changed_health", lambda v: v["configurations"][0]["configuration"].update(health="degraded"), "extension_capability_mismatch"),
        ("invalid_configuration", lambda v: v["configurations"][0]["configuration"].update(secret="unexpected"), "invalid_extension_configuration"),
    ]:
        vector = copy.deepcopy(base)
        vector["id"] = name
        vector["source_case"] = None
        mutate(vector)
        vector["registration_bytes"] = [json.dumps(d, sort_keys=True, separators=(",", ":")) for d in vector["registrations"]]
        vector["expected"] = {"status": "rejected", "code": code}
        vectors.append(vector)
    all_guarantees = ("deterministic", "pure", "portable", "semantically_introspectable", "process_contained")
    composition = copy.deepcopy(next(v for v in vectors if v["id"] == "composition_all_and_any"))
    composition["id"] = "composition_all_guarantees"
    composition["source_case"] = None
    composition["operation"]["projection"] = list(all_guarantees) + ["external_io_capable", "weak_profile_opt_in_required"]
    composition["hypothetical_verification"]["weak_profile_opt_in"] = False
    for descriptor in composition["registrations"]:
        descriptor["supported_capabilities"] = list(all_guarantees) + ["external_io_capable"]
    composition["registration_bytes"] = [json.dumps(d, sort_keys=True, separators=(",", ":")) for d in composition["registrations"]]
    for configured, proof in zip(composition["configurations"], composition["hypothetical_verification"]["proofs"]):
        configured["configuration"]["claims"] = list(all_guarantees)
        proof["claims"] = list(all_guarantees)
        proof["configuration_digest"] = "sha256:" + hashlib.sha256(json.dumps(configured["configuration"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    composition["expected"]["reports"] = [
        {"category": c["category"], "provider_reference": c["provider_reference"],
         "instance_id": c["configuration"]["instance_id"], "health": "healthy", "claims": list(all_guarantees)}
        for c in composition["configurations"]]
    composition["expected"]["effective"] = {key: True for key in all_guarantees} | {
        "external_io_capable": False, "weak_profile_opt_in_required": False}
    vectors.append(composition)
    unknown_io = copy.deepcopy(next(v for v in vectors if v["id"] == "healthy_report_omits_io_hazard"))
    unknown_io["id"] = "unknown_health_is_possible_io"
    unknown_io["source_case"] = None
    unknown_io["configurations"][0]["configuration"]["health"] = "unknown"
    unknown_io["hypothetical_verification"]["proofs"][0]["configuration_digest"] = "sha256:" + hashlib.sha256(json.dumps(unknown_io["configurations"][0]["configuration"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    vectors.append(unknown_io)
    descriptor = {"category": "execution_store",
                  "provider_reference": {"identifier": "conformance.provider", "version": "1.0.0", "content_digest": digest},
                  "interface_version": 1, "supported_capabilities": ["durable_single_writer"]}
    configuration = {"instance_id": "primary", "claims": [], "health": "healthy"}
    report = {"category": descriptor["category"], "provider_reference": descriptor["provider_reference"],
              "instance_id": "primary", "health": "healthy", "claims": []}
    requirement = {"category": descriptor["category"], "provider_reference": descriptor["provider_reference"],
                   "instance_id": "primary", "capability": "durable_single_writer"}
    public_vectors = []
    def public_case(name, *, registered=True, configured=True, requested=False,
                    candidate=None, change=None, code=None):
        entry = {"id": name, "installation": "register",
                 "registration": copy.deepcopy(descriptor) if registered else None,
                 "configuration": copy.deepcopy(configuration) if configured else None,
                 "requirement": copy.deepcopy(requirement) if requested else None,
                 "untrusted_candidate_report": copy.deepcopy(candidate),
                 "lookup_uri": None,
                 "expected": {"status": "rejected", "code": code} if code else
                    {"status": "accepted", "report": copy.deepcopy(report)},
                 "expected_core_mutations": 0}
        if change:
            change(entry)
        registered_value = entry["registration"]
        entry["registration_bytes"] = [json.dumps(d, sort_keys=True, separators=(",", ":"))
                                       for d in (registered_value if isinstance(registered_value, list) else
                                                 ([registered_value] if registered_value else []))]
        stages = []
        for index, descriptor_bytes in enumerate(entry["registration_bytes"]):
            registration_error = ("invalid_extension_descriptor" if code == "invalid_extension_descriptor" else
                                  "duplicate_extension_registration" if code == "duplicate_extension_registration" and index > 0 else None)
            stages.append({"operation": "register" if entry["installation"] == "register" else "direct_injection",
                           "input": descriptor_bytes,
                           "output": {"status": "rejected", "code": registration_error} if registration_error else
                                     {"status": "accepted", "value": None}})
            if registration_error:
                break
        if not stages or stages[-1]["output"]["status"] == "accepted":
            if entry["registration"] is not None and entry["configuration"] is not None:
                config_error = code == "invalid_extension_configuration"
                stages.append({"operation": "validate_configuration", "input": entry["configuration"],
                               "output": {"status": "rejected", "code": code} if config_error else
                                         {"status": "accepted", "value": None}})
                if not config_error:
                    stages.append({"operation": "capabilities", "input": entry["configuration"]["instance_id"],
                                   "output": entry["configuration"]["claims"]})
                    stages.append({"operation": "health", "input": entry["configuration"]["instance_id"],
                                   "output": entry["configuration"]["health"]})
        if not stages or not isinstance(stages[-1]["output"], dict) or stages[-1]["output"].get("status") != "rejected":
            stages.append({"operation": "negotiate", "input": {"requirement": entry["requirement"],
                            "lookup_uri": entry["lookup_uri"]}, "output": entry["expected"]})
        entry["expected_stages"] = stages
        public_vectors.append(entry)
    public_case("loaded_provider_no_claim")
    public_case("direct_injection_no_claim", change=lambda e: e.update(installation="direct_injection"))
    public_case("unproved_claim_refused", requested=True, code="extension_capability_mismatch")
    hostile = copy.deepcopy(report)
    hostile["claims"] = ["durable_single_writer"]
    public_case("self_asserted_claim_refused", requested=True, candidate=hostile,
                change=lambda e: e["configuration"].update(claims=["durable_single_writer"]),
                code="extension_capability_mismatch")
    public_case("unknown_provider_refused", registered=False, configured=False, requested=True, code="unknown_extension")
    public_case("version_fallback_refused", requested=True,
                change=lambda e: e["requirement"]["provider_reference"].update(version="1.0.1"),
                code="extension_identity_mismatch")
    public_case("digest_fallback_refused", requested=True,
                change=lambda e: e["requirement"]["provider_reference"].update(content_digest="sha256:" + "f" * 64),
                code="extension_identity_mismatch")
    public_case("instance_swap_refused", requested=True,
                change=lambda e: e["requirement"].update(instance_id="other"),
                code="extension_capability_mismatch")
    public_case("health_downgrade_refused", requested=True,
                change=lambda e: e["configuration"].update(health="degraded"),
                code="extension_capability_mismatch")
    public_case("uri_hint_refused", requested=True,
                change=lambda e: e.update(lookup_uri="store://conformance.provider"),
                code="extension_capability_mismatch")
    public_case("invalid_configuration_refused", requested=True,
                change=lambda e: e["configuration"].update(unexpected=True),
                code="invalid_extension_configuration")
    public_case("duplicate_registration_refused", requested=False,
                change=lambda e: e.update(registration=[copy.deepcopy(descriptor),
                    {**copy.deepcopy(descriptor), "provider_reference": {**descriptor["provider_reference"],
                        "content_digest": "sha256:" + "f" * 64}}]),
                code="duplicate_extension_registration")
    public_case("malformed_descriptor_refused", requested=False,
                change=lambda e: e["registration"].update(interface_version=2),
                code="invalid_extension_descriptor")
    public_case("category_swap_refused", requested=True,
                change=lambda e: e["requirement"].update(category="projection", capability="lossless_projection"),
                code="unknown_extension")
    return (json.dumps({"format": "determa.extension-negotiation-v1", "schema_version": 1,
        "specification_commit": SPEC_PIN,
        "provider_closure": {"content_digest": digest,
                             "closure_files": closure_files},
        "driver_operations": ["register", "validate_configuration", "capabilities", "health", "negotiate"],
        "vectors": vectors, "public_vectors": public_vectors}, indent=2) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, default=Path("../determa-state-spec"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = render(args.spec_root)
    path = PROFILE / "vectors.generated.json"
    if args.check:
        if not path.exists() or path.read_bytes() != output:
            raise SystemExit("extension negotiation vectors are stale")
    else:
        path.write_bytes(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
