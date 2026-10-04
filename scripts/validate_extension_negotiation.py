"""Independent structural and relational checks for the optional §11.5 driver."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from generate_extension_negotiation_profile import PROFILE, SPEC_CASES, SPEC_PIN, render


class ExtensionValidationError(ValueError):
    pass


def _unique_members(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, member in pairs:
        require(key not in value, f"duplicate JSON member {key!r}")
        value[key] = member
    return value


def _invalid_constant(value: str) -> None:
    raise ExtensionValidationError(f"non-JSON numeric constant {value}")


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_members,
                      parse_constant=_invalid_constant)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ExtensionValidationError(message)


def strict_keys(value: object, keys: set[str], where: str) -> None:
    require(isinstance(value, dict) and set(value) == keys, f"{where}: fields mismatch")


def closure_digest(profile: Path, files: list[str]) -> str:
    require(files == ["provider/test_provider.py", "provider/test_provider.rs"], "provider closure list mismatch")
    actual = {path.relative_to(profile).as_posix() for path in (profile / "provider").rglob("*") if path.is_file()}
    require(actual == set(files), "unlisted provider closure file")
    digest = hashlib.sha256(b"determa-test-provider-closure-1\0")
    for relative in files:
        require(not (profile / relative).is_symlink(), "provider closure symlink")
        payload = (profile / relative).read_bytes()
        name = relative.encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def validators(spec_root: Path) -> dict[str, Draft202012Validator]:
    names = {
        "descriptor": "extension-descriptor-v1.schema.json",
        "report": "extension-capability-report-v1.schema.json",
        "requirement": "extension-capability-requirement-v1.schema.json",
    }
    resources = []
    schemas = {}
    for kind, name in names.items():
        schema = json.loads((spec_root / "schema" / name).read_text())
        Draft202012Validator.check_schema(schema)
        schemas[kind] = schema
        resources.extend([(name, Resource.from_contents(schema)), (schema["$id"], Resource.from_contents(schema))])
    registry = Registry().with_resources(resources)
    return {kind: Draft202012Validator(schema, registry=registry) for kind, schema in schemas.items()}


def valid(validator: Draft202012Validator, value: object) -> bool:
    return not list(validator.iter_errors(value))


def outcome(vector: dict, checks: dict[str, Draft202012Validator], digest: str) -> dict:
    registrations = vector["registrations"]
    configurations = vector["configurations"]
    requirements = vector["requirements"]
    for descriptor in registrations:
        if not valid(checks["descriptor"], descriptor):
            return {"status": "rejected", "code": "invalid_extension_descriptor"}
    for requirement in requirements:
        if not valid(checks["requirement"], requirement):
            return {"status": "rejected", "code": "invalid_extension_descriptor"}
    seen = set()
    for descriptor in registrations:
        ref = descriptor["provider_reference"]
        key = (descriptor["category"], ref["identifier"], ref["version"])
        if key in seen:
            return {"status": "rejected", "code": "duplicate_extension_registration"}
        seen.add(key)
    for descriptor in registrations:
        if descriptor["provider_reference"]["content_digest"] != digest:
            return {"status": "rejected", "code": "extension_identity_mismatch"}
    for configured in configurations:
        strict_keys(configured, {"category", "provider_reference", "configuration"}, "configured instance")
        config = configured["configuration"]
        if not isinstance(config, dict) or set(config) != {"instance_id", "claims", "health"}:
            return {"status": "rejected", "code": "invalid_extension_configuration"}
        if not isinstance(config["instance_id"], str) or not isinstance(config["claims"], list) or config["health"] not in ("healthy", "degraded", "unavailable", "unknown"):
            return {"status": "rejected", "code": "invalid_extension_configuration"}
    for configured in configurations:
        ref = configured["provider_reference"]
        same_name = [d for d in registrations if d["category"] == configured["category"] and d["provider_reference"]["identifier"] == ref["identifier"]]
        if same_name and not any(d["provider_reference"] == ref for d in same_name):
            return {"status": "rejected", "code": "extension_identity_mismatch"}
    reports = []
    for configured in configurations:
        config = configured["configuration"]
        report = {"category": configured["category"], "provider_reference": configured["provider_reference"],
                  "instance_id": config["instance_id"], "health": config["health"], "claims": config["claims"]}
        if not valid(checks["report"], report):
            return {"status": "rejected", "code": "invalid_extension_configuration"}
        reports.append(report)
    for requirement in requirements:
        ref = requirement["provider_reference"]
        matching_name = [d for d in registrations if d["category"] == requirement["category"] and d["provider_reference"]["identifier"] == ref["identifier"]]
        if not matching_name:
            return {"status": "rejected", "code": "unknown_extension"}
        matching_ref = [d for d in matching_name if d["provider_reference"] == ref]
        if not matching_ref:
            return {"status": "rejected", "code": "extension_identity_mismatch"}
        matching_report = [r for r in reports if r["category"] == requirement["category"] and r["provider_reference"] == ref and r["instance_id"] == requirement["instance_id"]]
        if not matching_report:
            return {"status": "rejected", "code": "extension_capability_mismatch"}
        claim = requirement["capability"]
        configuration = next((c["configuration"] for c in configurations
                              if c["category"] == requirement["category"] and
                              c["provider_reference"] == ref and
                              c["configuration"]["instance_id"] == requirement["instance_id"]), None)
        config_digest = "sha256:" + hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if configuration else None
        policy_claim = [p for p in vector["hypothetical_verification"]["proofs"]
                        if p["category"] == requirement["category"] and
                        p["provider_reference"] == ref and
                        p["instance_id"] == requirement["instance_id"] and
                        p["configuration_digest"] == config_digest]
        if not (matching_report[0]["health"] == "healthy" and claim in matching_report[0]["claims"] and claim in matching_ref[0]["supported_capabilities"] and policy_claim and claim in policy_claim[0]["claims"]):
            return {"status": "rejected", "code": "extension_capability_mismatch"}
    effective = {}
    if vector["operation"]["kind"] == "compose":
        guarantees = ("deterministic", "pure", "portable", "semantically_introspectable", "process_contained")
        proofs = vector["hypothetical_verification"]["proofs"]
        def proved(report, guarantee):
            configuration = next((c["configuration"] for c in configurations
                                  if c["category"] == report["category"] and
                                  c["provider_reference"] == report["provider_reference"] and
                                  c["configuration"]["instance_id"] == report["instance_id"]), None)
            config_digest = "sha256:" + hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if configuration else None
            return any(p["category"] == report["category"] and
                       p["provider_reference"] == report["provider_reference"] and
                       p["instance_id"] == report["instance_id"] and
                       p["configuration_digest"] == config_digest and
                       guarantee in p["claims"] for p in proofs)
        for guarantee in guarantees:
            effective[guarantee] = vector["hypothetical_verification"]["host_guarantees"][guarantee] and all(
                r["health"] == "healthy" and guarantee in r["claims"] and proved(r, guarantee)
                for r in reports)
        effective["external_io_capable"] = any(
            r["health"] != "healthy" or "external_io_capable" in r["claims"] or
            (not ("pure" in r["claims"] and proved(r, "pure") and
                  vector["hypothetical_verification"]["host_guarantees"]["pure"]))
            for r in reports
        )
        effective["weak_profile_opt_in_required"] = effective["external_io_capable"]
        if vector["operation"]["requested_profile"] == "automatic_retry_without_external_io" and effective["external_io_capable"]:
            return {"status": "rejected", "code": "extension_capability_mismatch"}
        if effective["weak_profile_opt_in_required"] and not vector["hypothetical_verification"]["weak_profile_opt_in"]:
            return {"status": "rejected", "code": "extension_capability_mismatch"}
        effective = {key: effective[key] for key in vector["operation"]["projection"]}
    return {"status": "accepted", "reports": reports, "effective": effective}


def public_outcome(vector: dict, checks: dict[str, Draft202012Validator], digest: str) -> dict:
    registration = vector["registration"]
    registrations = registration if isinstance(registration, list) else ([registration] if registration else [])
    if any(not valid(checks["descriptor"], descriptor) for descriptor in registrations):
        return {"status": "rejected", "code": "invalid_extension_descriptor"}
    if len(registrations) != len({(d["category"], d["provider_reference"]["identifier"], d["provider_reference"]["version"]) for d in registrations}):
        return {"status": "rejected", "code": "duplicate_extension_registration"}
    if any(d["provider_reference"]["content_digest"] != digest for d in registrations):
        return {"status": "rejected", "code": "extension_identity_mismatch"}
    configuration = vector["configuration"]
    if configuration is not None and (not isinstance(configuration, dict) or set(configuration) != {"instance_id", "claims", "health"}):
        return {"status": "rejected", "code": "invalid_extension_configuration"}
    if configuration is not None and (not isinstance(configuration["instance_id"], str) or
                                      not isinstance(configuration["claims"], list) or
                                      configuration["health"] not in ("healthy", "degraded", "unavailable", "unknown")):
        return {"status": "rejected", "code": "invalid_extension_configuration"}
    requirement = vector["requirement"]
    if requirement is not None:
        if not valid(checks["requirement"], requirement):
            return {"status": "rejected", "code": "invalid_extension_descriptor"}
        by_name = [d for d in registrations if d["category"] == requirement["category"] and d["provider_reference"]["identifier"] == requirement["provider_reference"]["identifier"]]
        if not by_name:
            return {"status": "rejected", "code": "unknown_extension"}
        if not any(d["provider_reference"] == requirement["provider_reference"] for d in by_name):
            return {"status": "rejected", "code": "extension_identity_mismatch"}
        if configuration is None or configuration["instance_id"] != requirement["instance_id"] or configuration["health"] != "healthy":
            return {"status": "rejected", "code": "extension_capability_mismatch"}
        # The loaded fixture proves no execution-store guarantee. Its returned
        # claims and any supplied candidate report cannot create host proof.
        return {"status": "rejected", "code": "extension_capability_mismatch"}
    require(bool(registrations) and configuration is not None, "accepted public vector needs an installed instance")
    descriptor = registrations[0]
    return {"status": "accepted", "report": {
        "category": descriptor["category"], "provider_reference": descriptor["provider_reference"],
        "instance_id": configuration["instance_id"], "health": configuration["health"],
        "claims": [],
    }}


def public_stages(vector: dict, checks: dict[str, Draft202012Validator], digest: str) -> list[dict]:
    result = public_outcome(vector, checks, digest)
    registered_value = vector["registration"]
    descriptors = registered_value if isinstance(registered_value, list) else ([registered_value] if registered_value else [])
    stages = []
    registered_keys = set()
    for descriptor, source in zip(descriptors, vector["registration_bytes"]):
        error = None
        if not valid(checks["descriptor"], descriptor):
            error = "invalid_extension_descriptor"
        else:
            ref = descriptor["provider_reference"]
            key = (descriptor["category"], ref["identifier"], ref["version"])
            if key in registered_keys:
                error = "duplicate_extension_registration"
            elif ref["content_digest"] != digest:
                error = "extension_identity_mismatch"
            registered_keys.add(key)
        stages.append({"operation": vector["installation"], "input": source,
                       "output": {"status": "rejected", "code": error} if error else
                                 {"status": "accepted", "value": None}})
        if error:
            return stages
    configuration = vector["configuration"]
    if descriptors and configuration is not None:
        config_error = result["status"] == "rejected" and result["code"] == "invalid_extension_configuration"
        stages.append({"operation": "validate_configuration", "input": configuration,
                       "output": {"status": "rejected", "code": "invalid_extension_configuration"} if config_error else
                                 {"status": "accepted", "value": None}})
        if config_error:
            return stages
        stages.append({"operation": "capabilities", "input": configuration["instance_id"],
                       "output": configuration["claims"]})
        stages.append({"operation": "health", "input": configuration["instance_id"],
                       "output": configuration["health"]})
    stages.append({"operation": "negotiate", "input": {"requirement": vector["requirement"],
                   "lookup_uri": vector["lookup_uri"]}, "output": result})
    return stages


def validate_document(document: dict, spec_root: Path, profile: Path = PROFILE, *, compare_generated: bool = True) -> int:
    strict_keys(document, {"format", "schema_version", "specification_commit", "provider_closure", "driver_operations", "vectors", "public_vectors"}, "manifest")
    require(document["format"] == "determa.extension-negotiation-v1" and type(document["schema_version"]) is int and document["schema_version"] == 1, "format mismatch")
    require(document["specification_commit"] == SPEC_PIN, "specification pin mismatch")
    strict_keys(document["provider_closure"], {"closure_files", "content_digest"}, "provider closure")
    digest = closure_digest(profile, document["provider_closure"]["closure_files"])
    require(document["provider_closure"]["content_digest"] == digest, "provider closure digest mismatch")
    require(document["driver_operations"] == ["register", "validate_configuration", "capabilities", "health", "negotiate"], "driver operations mismatch")
    source = json.loads((spec_root / SPEC_CASES).read_text())
    required = {case["name"] for case in source["cases"]}
    require(len(required) == 13, "normative source coverage changed")
    seen = set()
    covered = set()
    checks = validators(spec_root)
    for vector in document["vectors"]:
        strict_keys(vector, {"id", "source_case", "registrations", "registration_bytes", "configurations", "requirements", "lookup_uri", "operation", "hypothetical_verification", "expected", "expected_core_mutations"}, "vector")
        name = vector["id"]
        require(isinstance(name, str) and name not in seen, "duplicate vector id")
        seen.add(name)
        if vector["source_case"] is not None:
            require(vector["source_case"] == name and name in required, f"{name}: invalid source case")
            covered.add(name)
        require(type(vector["expected_core_mutations"]) is int and vector["expected_core_mutations"] == 0, f"{name}: core mutation")
        require(isinstance(vector["registrations"], list) and isinstance(vector["configurations"], list) and isinstance(vector["requirements"], list), f"{name}: operation arrays")
        require(vector["registration_bytes"] == [json.dumps(d, sort_keys=True, separators=(",", ":")) for d in vector["registrations"]], f"{name}: descriptor bytes mismatch")
        strict_keys(vector["operation"], {"kind", "requested_profile", "projection"}, f"{name}: operation")
        require(vector["operation"]["kind"] in {"compose", "negotiate"}, f"{name}: operation kind")
        require(vector["operation"]["requested_profile"] in {None, "automatic_retry_without_external_io"}, f"{name}: requested profile")
        require(isinstance(vector["operation"]["projection"], list) and
                len(set(vector["operation"]["projection"])) == len(vector["operation"]["projection"]) and
                set(vector["operation"]["projection"]) <= {"deterministic", "pure", "portable", "semantically_introspectable", "process_contained", "external_io_capable", "weak_profile_opt_in_required"}, f"{name}: projection")
        strict_keys(vector["hypothetical_verification"], {"proofs", "host_guarantees", "weak_profile_opt_in"}, f"{name}: verification premise")
        require(set(vector["hypothetical_verification"]["host_guarantees"]) == {"deterministic", "pure", "portable", "semantically_introspectable", "process_contained"} and
                all(type(value) is bool for value in vector["hypothetical_verification"]["host_guarantees"].values()) and
                type(vector["hypothetical_verification"]["weak_profile_opt_in"]) is bool, f"{name}: host verification policy")
        for claim in vector["hypothetical_verification"]["proofs"]:
            strict_keys(claim, {"category", "provider_reference", "instance_id", "configuration_digest", "claims"}, f"{name}: proof")
            require(isinstance(claim["claims"], list) and
                    isinstance(claim["configuration_digest"], str) and
                    len(claim["configuration_digest"]) == 71 and
                    claim["configuration_digest"].startswith("sha256:"), f"{name}: proof shape")
        computed = outcome(vector, checks, digest)
        require(computed == vector["expected"], f"{name}: expected {vector['expected']!r}, computed {computed!r}")
    require(covered == required, f"normative coverage mismatch: {sorted(required - covered)}")
    require(len(seen) == 21, "extension vector coverage mismatch")
    public_seen = set()
    for vector in document["public_vectors"]:
        strict_keys(vector, {"id", "installation", "registration", "registration_bytes", "configuration", "requirement", "untrusted_candidate_report", "lookup_uri", "expected", "expected_stages", "expected_core_mutations"}, "public vector")
        name = vector["id"]
        require(isinstance(name, str) and name not in public_seen, "duplicate public vector")
        public_seen.add(name)
        require(vector["installation"] in {"register", "direct_injection"}, f"{name}: installation mode")
        registered_value = vector["registration"]
        registrations = registered_value if isinstance(registered_value, list) else ([registered_value] if registered_value else [])
        require(vector["registration_bytes"] == [json.dumps(d, sort_keys=True, separators=(",", ":")) for d in registrations], f"{name}: public descriptor bytes mismatch")
        require(vector["expected_core_mutations"] == 0 and type(vector["expected_core_mutations"]) is int, f"{name}: core mutation")
        candidate = vector["untrusted_candidate_report"]
        if candidate is not None:
            require(valid(checks["report"], candidate), f"{name}: invalid candidate report")
        computed = public_outcome(vector, checks, digest)
        require(vector["expected"] == computed, f"{name}: public result mismatch")
        require(vector["expected_stages"] == public_stages(vector, checks, digest), f"{name}: public stage trace mismatch")
    require(len(public_seen) == 14, "public registration coverage mismatch")
    if compare_generated:
        require((json.dumps(document, indent=2) + "\n").encode() == render(spec_root, profile), "generated vectors differ from normative source")
        extras = {p.relative_to(profile).as_posix() for p in profile.rglob("*.json")}
        require(extras == {"vectors.generated.json"}, "unreferenced extension JSON document")
    return len(seen) + len(public_seen)


def validate_profile(spec_root: Path, profile: Path = PROFILE) -> int:
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=spec_root,
                              text=True, capture_output=True, check=True).stdout.strip()
    require(revision == SPEC_PIN, f"specification checkout is {revision}, expected {SPEC_PIN}")
    document = load_manifest(profile / "vectors.generated.json")
    return validate_document(document, spec_root, profile)
