#!/usr/bin/env python3
"""Adversarial swaps across otherwise valid extension negotiation vectors."""

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from validate_extension_negotiation import (
    ExtensionValidationError, PROFILE, exact_json_equal, public_outcome,
    validate_document, validators,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    original = json.loads((PROFILE / "vectors.generated.json").read_text())
    # The original drift was a descriptor-only transport capability. Exercise
    # the cross-schema guard for every category and each of the three inputs.
    schema_fields = (
        ("extension-descriptor-v1.schema.json", "supported_capabilities", True),
        ("extension-capability-report-v1.schema.json", "claims", True),
        ("extension-capability-requirement-v1.schema.json", "capability", False),
    )
    with tempfile.TemporaryDirectory() as directory:
        spec_copy = Path(directory)
        (spec_copy / "schema").mkdir()
        for filename, _, _ in schema_fields:
            (spec_copy / "schema" / filename).write_bytes((args.spec_root / "schema" / filename).read_bytes())
        (spec_copy / "schema/provider-reference-v1.schema.json").write_bytes(
            (args.spec_root / "schema/provider-reference-v1.schema.json").read_bytes())
        for filename, field, is_array in schema_fields:
            path = spec_copy / "schema" / filename
            pristine = json.loads(path.read_text())
            for branch in pristine["allOf"]:
                altered = copy.deepcopy(pristine)
                category = branch["if"]["properties"]["category"]["const"]
                target = next(part for part in altered["allOf"]
                              if part["if"]["properties"]["category"]["const"] == category)
                capability = target["then"]["properties"][field]
                values = capability["items"]["enum"] if is_array else capability["enum"]
                if values:
                    values.pop()
                else:
                    values.append("invented_capability")
                path.write_text(json.dumps(altered))
                try:
                    validators(spec_copy)
                except ExtensionValidationError:
                    pass
                else:
                    raise AssertionError(f"{filename}: missing {category} capability accepted")
            path.write_text(json.dumps(pristine))
    # A schema-valid transport claim on the inert public provider cannot use
    # the common-rule hypothetical proof to satisfy a production requirement.
    source_order = next(v for v in original["vectors"]
                        if v["id"] == "configured_transport_source_order_satisfied")
    descriptor = copy.deepcopy(source_order["registrations"][0])
    descriptor["provider_reference"]["content_digest"] = original["provider_closure"]["content_digest"]
    configured = {"instance_id": "primary", "health": "healthy", "claims": ["source_ordered"]}
    requirement = {"category": "transport", "provider_reference": descriptor["provider_reference"],
                   "instance_id": "primary", "capability": "source_ordered"}
    public_probe = {"installation": "register", "registration": descriptor,
                    "configuration": configured, "requirement": requirement}
    if public_outcome(public_probe, validators(args.spec_root), original["provider_closure"]["content_digest"]) != \
            {"status": "rejected", "code": "extension_capability_mismatch"}:
        raise AssertionError("unproved public source-order claim accepted")
    provider_namespace = {}
    provider_source = PROFILE / "provider/test_provider.py"
    exec(compile(provider_source.read_bytes(), str(provider_source), "exec"), provider_namespace)
    valid_provider_configuration = {"instance_id": "primary", "claims": [], "health": "healthy"}
    if provider_namespace["validate_configuration"](valid_provider_configuration) != valid_provider_configuration:
        raise AssertionError("loaded Python provider rejected valid configuration")
    for bad in (
        {**valid_provider_configuration, "instance_id": ""},
        {**valid_provider_configuration, "instance_id": "Primary"},
        {**valid_provider_configuration, "claims": [7]},
        {**valid_provider_configuration, "claims": ["durable_single_writer"] * 2},
        {**valid_provider_configuration, "health": 7},
        {**valid_provider_configuration, "unexpected": True},
    ):
        try:
            provider_namespace["validate_configuration"](bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"loaded Python provider accepted malformed configuration {bad!r}")
    checked_configuration_rows = 0
    for vector in original["public_vectors"]:
        configuration = vector["configuration"]
        stage = next((item for item in vector["expected_stages"]
                      if item["operation"] == "validate_configuration"), None)
        if stage is None:
            continue
        checked_configuration_rows += 1
        expected_valid = stage["output"]["status"] == "accepted"
        try:
            configured_instance = provider_namespace["validate_configuration"](configuration)
        except ValueError:
            actual_valid = False
        else:
            actual_valid = True
            if configured_instance != configuration:
                raise AssertionError(f"{vector['id']}: provider changed configuration")
            capabilities = next(item["output"] for item in vector["expected_stages"]
                                if item["operation"] == "capabilities")
            health = next(item["output"] for item in vector["expected_stages"]
                          if item["operation"] == "health")
            if provider_namespace["capabilities"](configured_instance) != capabilities or \
               provider_namespace["health"](configured_instance) != health:
                raise AssertionError(f"{vector['id']}: provider result differs from public stage")
        if actual_valid != expected_valid:
            raise AssertionError(f"{vector['id']}: installed Python provider configuration result differs")
    if checked_configuration_rows < 15:
        raise AssertionError("public provider configuration coverage unexpectedly shrank")
    rustc = os.environ.get("DETERMA_TEST_RUSTC") or shutil.which("rustc")
    if not rustc:
        raise AssertionError("Rust compiler is required for executing provider configuration rows")
    rust_rows = 0
    rust_json_rejections = set()
    if rustc:
        rust_lines = [
            f"#[path = {json.dumps(str(PROFILE / 'provider/test_provider.rs'))}] mod provider;",
            "fn main() {",
        ]
        for vector in original["public_vectors"]:
            configuration = vector["configuration"]
            stage = next((item for item in vector["expected_stages"]
                          if item["operation"] == "validate_configuration"), None)
            if stage is None:
                continue
            if set(configuration) != {"instance_id", "claims", "health"} or \
               type(configuration["instance_id"]) is not str or \
               type(configuration["health"]) is not str or \
               not isinstance(configuration["claims"], list) or \
               not all(type(claim) is str for claim in configuration["claims"]):
                if stage["output"] != {"status": "rejected", "code": "invalid_extension_configuration"}:
                    raise AssertionError(f"{vector['id']}: unrepresentable Rust configuration was not rejected")
                rust_json_rejections.add(vector["id"])
                continue  # The public host rejects JSON before the typed Rust provider is called.
            rust_rows += 1
            claims = ", ".join(f"{json.dumps(claim)}.to_string()" for claim in configuration["claims"])
            expected_valid = "true" if stage["output"]["status"] == "accepted" else "false"
            rust_lines.extend([
                "{",
                f"let c = provider::Configuration {{ instance_id: {json.dumps(configuration['instance_id'])}.to_string(), claims: vec![{claims}], health: {json.dumps(configuration['health'])}.to_string() }};",
                f"assert_eq!(provider::validate_configuration(&c).is_ok(), {expected_valid}, {json.dumps(vector['id'])});",
            ])
            if expected_valid == "true":
                rust_lines.extend([
                    "assert_eq!(provider::capabilities(&c), c.claims);",
                    "assert_eq!(provider::health(&c), c.health);",
                ])
            rust_lines.append("}")
        rust_lines.append("}")
        if rust_rows < 12:
            raise AssertionError("Rust provider configuration coverage unexpectedly shrank")
        if rust_json_rejections != {"invalid_configuration_refused", "non_string_claim_refused", "non_string_health_refused"}:
            raise AssertionError(f"unexpected Rust JSON rejection rows: {sorted(rust_json_rejections)}")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "provider_rows.rs"
            binary = Path(directory) / "provider_rows"
            source.write_text("\n".join(rust_lines) + "\n")
            compiled = subprocess.run([rustc, "--edition=2021", str(source), "-o", str(binary)],
                                      text=True, capture_output=True)
            if compiled.returncode:
                raise AssertionError(f"Rust provider failed to compile: {compiled.stderr}")
            ran = subprocess.run([str(binary)], text=True, capture_output=True)
            if ran.returncode:
                raise AssertionError(f"Rust provider row mismatch: {ran.stderr}")
    if exact_json_equal({"stages": [{"output": {"healthy": False}}]},
                        {"stages": [{"output": {"healthy": 0}}]}):
        raise AssertionError("nested stage Boolean accepted as integer")
    vectors = {v["id"]: v for v in original["vectors"]}
    attacks = []
    def attack(label, change):
        document = copy.deepcopy(original)
        selected = {v["id"]: v for v in document["vectors"]}
        change(document, selected)
        attacks.append((label, document))
    attack("category", lambda d, v: v["configured_capability_satisfied"]["requirements"][0].update(category="projection", capability="lossless_projection"))
    attack("instance", lambda d, v: v["configured_capability_satisfied"]["requirements"][0].update(instance_id="other"))
    attack("version", lambda d, v: v["configured_capability_satisfied"]["requirements"][0]["provider_reference"].update(version="1.2.4"))
    attack("digest", lambda d, v: v["configured_capability_satisfied"]["requirements"][0]["provider_reference"].update(content_digest="sha256:"+"f"*64))
    attack("claim", lambda d, v: v["configured_capability_satisfied"]["configurations"][0]["configuration"].update(claims=[]))
    attack("health", lambda d, v: v["configured_capability_satisfied"]["configurations"][0]["configuration"].update(health="degraded"))
    attack("policy", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0].update(claims=[]))
    attack("proof reference", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0]["provider_reference"].update(version="1.2.4"))
    attack("proof configuration", lambda d, v: v["configured_capability_satisfied"]["hypothetical_verification"]["proofs"][0].update(configuration_digest="sha256:"+"f"*64))
    attack("composition policy", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"]["host_guarantees"].update(deterministic=False))
    attack("composition participant", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"]["proofs"][1].update(claims=[]))
    attack("missing weak profile opt in", lambda d, v: v["composition_all_and_any"]["hypothetical_verification"].update(weak_profile_opt_in=False))
    attack("uri fallback", lambda d, v: v["uri_no_privilege"].update(expected={"status":"accepted", "reports":[], "effective":{}}))
    attack("version fallback", lambda d, v: v["changed_exact_version"].update(expected={"status":"accepted", "reports":[], "effective":{}}))
    attack("missing case", lambda d, v: d["vectors"].remove(v["missing_provider"]))
    attack("unlisted case", lambda d, v: d["vectors"].append(copy.deepcopy(v["missing_provider"])))
    attack("mutable closure digest", lambda d, v: d["provider_closure"].update(content_digest="sha256:"+"f"*64))
    attack("core mutation", lambda d, v: v["unhealthy_instance"].update(expected_core_mutations=1))
    attack("public false claim", lambda d, v: d["public_vectors"][0]["expected"]["report"].update(claims=["durable_single_writer"]))
    attack("public self assertion", lambda d, v: d["public_vectors"][4].update(expected={"status":"accepted", "report": d["public_vectors"][4]["untrusted_candidate_report"]}))
    attack("public URI fallback", lambda d, v: d["public_vectors"][10].update(expected={"status":"accepted", "report": d["public_vectors"][0]["expected"]["report"]}))
    attack("skipped health call", lambda d, v: d["public_vectors"][0]["expected_stages"].pop(-2))
    attack("fabricated capabilities", lambda d, v: d["public_vectors"][0]["expected_stages"][-3].update(output=["durable_single_writer"]))
    attack("swapped instance report", lambda d, v: d["public_vectors"][0]["expected"]["report"].update(instance_id="other"))
    attack("descriptor source bytes", lambda d, v: d["public_vectors"][0]["registration_bytes"].append("{}"))
    def unregistered_without_requirement(document, selected):
        vector = selected["configured_capability_satisfied"]
        vector["registrations"] = []
        vector["registration_bytes"] = []
        vector["requirements"] = []
        vector["expected"] = {"status": "accepted", "reports": vector["expected"]["reports"], "effective": {}}
    attack("resealed unregistered report", unregistered_without_requirement)
    def unsupported_without_requirement(document, selected):
        vector = selected["configured_capability_satisfied"]
        vector["requirements"] = []
        vector["configurations"][0]["configuration"]["claims"].append("shared_application_transaction")
        vector["expected"]["reports"][0]["claims"].append("shared_application_transaction")
    attack("resealed unsupported claim", unsupported_without_requirement)
    attack("Boolean effective changed to integer", lambda d, v: v["composition_all_and_any"]["expected"]["effective"].update(pure=0))
    for label, document in attacks:
        try:
            validate_document(document, args.spec_root, compare_generated=False)
        except ExtensionValidationError:
            continue
        raise AssertionError(f"adversarial {label} swap accepted")
    with tempfile.TemporaryDirectory() as directory:
        profile = Path(directory)
        (profile / "provider").mkdir()
        for source in (PROFILE / "provider").iterdir():
            (profile / "provider" / source.name).write_bytes(source.read_bytes())
        with (profile / "provider/test_provider.py").open("ab") as stream:
            stream.write(b"\n# changed after report\n")
        try:
            validate_document(original, args.spec_root, profile, compare_generated=False)
        except ExtensionValidationError:
            pass
        else:
            raise AssertionError("changed provider closure accepted")
    with tempfile.TemporaryDirectory() as directory:
        child = Path(directory) / "adapter.py"
        child.write_text("""import json, sys
request = json.load(sys.stdin)
mode = sys.argv[1]
if mode == 'duplicate':
    print('{"decision":{},"decision":{},"core_mutations":0}')
elif mode == 'nonfinite':
    print('{"decision":NaN,"core_mutations":0}')
elif mode == 'invalid_utf8':
    sys.stdout.buffer.write(b'\\xff')
else:
    with open(request['profile_path'] + '/vectors.generated.json') as source:
        decision = json.load(source)['vectors'][0]['expected']
    if mode == 'nested_type':
        decision['reports'][0]['instance_id'] = 0
    print(json.dumps({'decision': decision, 'core_mutations': False if mode == 'bool_counter' else 0}))
""")
        runner = Path(__file__).with_name("run_extension_negotiation_profile.py")
        for mode in ("duplicate", "nonfinite", "invalid_utf8", "bool_counter", "nested_type"):
            completed = subprocess.run(
                [sys.executable, str(runner), "--spec-root", str(args.spec_root),
                 "--adapter", sys.executable, str(child), mode],
                text=True, capture_output=True,
            )
            if completed.returncode == 0:
                raise AssertionError(f"runtime adapter {mode} substitution accepted")
            if "adapter returned invalid JSON" not in completed.stderr and "observed decision or core mutation mismatch" not in completed.stderr:
                raise AssertionError(f"runtime adapter {mode} failed for wrong reason: {completed.stderr}")
    print(f"rejected {len(attacks) + 6} adversarial extension substitutions; "
          f"executed {checked_configuration_rows} Python and {rust_rows} Rust provider configuration rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
