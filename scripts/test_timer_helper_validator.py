#!/usr/bin/env python3
"""Reject substitution and malformed child responses for timer helper vectors."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from timer_helper_validator import TimerHelperValidationError, validate_profile
from generate_version1_vectors import canonical, digest, typed_value
from run_timer_helper_profile import (loaded_closure_digest, operation_input,
                                      strict_json, verify_configured, verify_native_composition,
                                      trusted_bridge_registration, verify_archive_capture,
                                      run_timer_operation, lifecycle_call)
from run_lossless_delivery_profile import run as run_delivery_case, CASE as DELIVERY_CASE
from validate_portable_archive import validate_archive_integrity, validator_registry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assert validate_profile(args.spec_root, root) == (24, 25, 3, 4, 2, 3)
    try:
        trusted_bridge_registration(["/tmp/decoy-adapter"], root / "no-registration.json")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted unreviewed timer bridge")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        bridge_source = directory / "bridge.py"
        engine_source = directory / "engine.py"
        dependency = directory / "dependency.py"
        build_input = directory / "Cargo.lock"
        for path, body in ((bridge_source, b"# reviewed test bridge\n"),
                           (engine_source, b"# installed test engine\n"),
                           (dependency, b"# dependency\n"),
                           (build_input, b"# build input\n")):
            path.write_bytes(body)
        file_item = lambda path: {"path": path.name,
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()}
        manifest = {"format": "determa.conformance.timer_helper.installation",
            "schema_version": 1, "language": "python", "production_factory": "engine:factory",
            "public_timer_entrypoint": "engine:timer", "public_archive_entrypoint": "engine:archive",
            "native_observer_entrypoint": "bridge:observer", "source_closure": [file_item(engine_source)],
            "dependency_files": [file_item(dependency)], "build_inputs": [file_item(build_input)],
            "features": [], "toolchain": "python-3.13", "effective_configuration": {"scope": "fixture"},
            "configured_provider_content_digest": "sha256:" + "a" * 64,
            "configured_scope_identity": "fixture", "configured_topology_identifier": "local",
            "configured_storage_binding": "sqlite"}
        manifest["effective_configuration_digest"] = digest(manifest["effective_configuration"])
        manifest["dependency_inventory_digest"] = digest(manifest["dependency_files"])
        manifest["build_anchor_digest"] = digest({key: manifest[key] for key in
            ("build_inputs", "features", "toolchain")})
        manifest_path = directory / "installation.json"
        manifest_path.write_bytes(canonical(manifest))
        registration = {key: manifest[key] for key in (
            "language", "production_factory", "public_timer_entrypoint",
            "public_archive_entrypoint", "native_observer_entrypoint",
            "effective_configuration_digest", "dependency_inventory_digest",
            "build_anchor_digest", "configured_provider_content_digest",
            "configured_scope_identity", "configured_topology_identifier",
            "configured_storage_binding")}
        command = [sys.executable, "-I", "-S", str(bridge_source)]
        registration.update(format="determa.conformance.timer_helper.bridge_registration",
            schema_version=1, command=command, bridge_root=str(directory),
            bridge_source_path=bridge_source.name, bridge_source_sha256=file_item(bridge_source)["sha256"],
            installation_root=str(directory), installation_manifest_path=manifest_path.name,
            installation_manifest_sha256=file_item(manifest_path)["sha256"])
        registration_path = directory / "registration.json"
        registration_path.write_bytes(canonical(registration))
        assert trusted_bridge_registration(command, registration_path)["factory_identity"] == "engine:factory"
        for path in (bridge_source, engine_source, dependency, build_input):
            original = path.read_bytes()
            path.write_bytes(original + b"drift")
            try:
                trusted_bridge_registration(command, registration_path)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted reviewed source or build drift in {path.name}")
            path.write_bytes(original)
        for field, value in (("production_factory", "other:factory"),
                             ("configured_scope_identity", "other-scope"),
                             ("build_anchor_digest", "sha256:" + "b" * 64)):
            altered = {**registration, field: value}
            registration_path.write_bytes(canonical(altered))
            try:
                trusted_bridge_registration(command, registration_path)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted changed reviewed {field}")
    first = json.loads((root / "conformance/profiles/timer-helper/timer-01-external-helper/vectors.generated.json").read_text())["cases"][0]
    timer_case = root / "conformance/profiles/timer-helper/timer-01-external-helper"
    with tempfile.TemporaryDirectory() as temporary:
        delivery_case = Path(temporary)
        timer_delivery = json.loads((timer_case / "timer-delivery.generated.json").read_text())
        first_ingress = timer_delivery["vectors"][0]
        timer_delivery["vectors"] = [first_ingress]
        (delivery_case / "delivery-vectors-v1.json").write_text(json.dumps(timer_delivery))
        ownership_artifact = json.loads((timer_case / "source-ownership.generated.json").read_text())
        for filename, value in (("before-timer-checkpoint-v1.json", ownership_artifact["before_checkpoint"]),
                                ("after-timer-checkpoint-v1.json", ownership_artifact["after_checkpoint"])):
            (delivery_case / filename).write_text(json.dumps(value))
        shutil.copyfile(timer_case / "target-machine.yaml", delivery_case / "machine.yaml")
        shutil.copyfile(DELIVERY_CASE / "outbox-machine.yaml", delivery_case / "outbox-machine.yaml")
        after = json.loads(json.dumps(first_ingress["after"]))
        after["checkpoint"] = json.loads((delivery_case / after["checkpoint"]).read_text())
        for mode in ("no_helper", "replaced_raw_return"):
            fake_ingress = delivery_case / "fake_ingress.py"
            fake_ingress.write_text(
                "import json,sys\nfrom pathlib import Path\n"
                f"sys.path.insert(0,{str(root / 'scripts')!r})\n"
                "from run_lossless_delivery_profile import store_call,digest\n"
                "from validate_conformance import canonical_json_bytes\n"
                "r=json.load(sys.stdin)\n"
                "host=Path(r['host_store_database_path'])\n"
                + ("i=r['trusted_timer_invocation']\n"
                   "store_call(host,'timer_invocation_start',run_id=r['run_id'],"
                   "invocation_id=i['invocation_id'],request_digest=i['request_digest'],"
                   "factory_identity=i['factory_identity'],public_request=i['public_request'])\n"
                   if mode == "replaced_raw_return" else "") +
                "store_call(host,'commit',run_id=r['run_id'],operation_id=r['operation_id'],"
                "expected_before_digest=digest(canonical_json_bytes(r['before'])),"
                f"after={after!r}" +
                (",timer_invocation_receipt={'invocation_id':i['invocation_id'],'raw_return':{}}"
                 if mode == "replaced_raw_return" else "") + ")\n"
                f"sys.stdout.buffer.write(canonical_json_bytes({{'response':{first_ingress['expected_response']!r},"
                f"'after':{after!r},'native_evidence':{{}}}}))\n")
            try:
                run_delivery_case([sys.executable, str(fake_ingress)], delivery_case,
                                  timer_bridge_anchor={"factory_identity": "reviewed:timer"})
            except AssertionError as error:
                if "reviewed complete_fire return is not in the same native transaction" not in str(error):
                    raise AssertionError(f"{mode}: wrong rejection: {error}") from error
            else:
                raise AssertionError(f"accepted {mode} with native C/D/H bytes but no real complete_fire")
    export = json.loads((timer_case / "archive-operational.generated.json").read_text())
    lifecycle = json.loads((timer_case / "lifecycle.generated.json").read_text())
    captured = {"checkpoint": lifecycle["expected_create_checkpoint"],
                "timer_artifact": lifecycle["expected_helper_after_schedule"]}
    verify_archive_capture(captured, export, export["expected_archive"])
    for missing in ("records", "operation_receipts"):
        altered = json.loads(json.dumps(export["expected_archive"]))
        participant = next(item for item in altered["participants"]
                           if item["participant_id"] == "timer-state")
        helper = json.loads(json.dumps(captured["timer_artifact"]))
        helper[missing] = []
        helper["timer_artifact_digest"] = digest(["determa-timer-artifact-1",
            {key: item for key, item in helper.items() if key != "timer_artifact_digest"}])
        participant["payload"] = typed_value(helper)
        participant["payload_digest"] = digest(["determa-archive-payload-1", "timer-state",
            participant["participant_schema_digest"], participant["payload"]])
        member = next(item for item in altered["members"]
                      if item["identity"] == "participant:timer-state")
        member["digest"] = digest(participant)
        member["byte_length"] = str(len(canonical(participant)))
        altered["archive_digest"] = digest(["determa-archive-digest-1",
            {key: item for key, item in altered.items() if key != "archive_digest"}])
        validate_archive_integrity(altered, validator_registry(args.spec_root))
        try:
            verify_archive_capture(captured, export, altered)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted resealed archive missing live {missing}")
    submitted = operation_input(first, "target source")
    assert set(submitted) == {"kind", "machine_source", "before", "request", "trusted_now",
                              "claim_expires_at", "previous_attempt_fate", "admission_disposition"}
    assert "expected_result" not in submitted and "after" not in submitted and "id" not in submitted
    with tempfile.TemporaryDirectory() as temporary:
        fake = Path(temporary) / "echo_result.py"
        fake.write_text("import sys\nsys.stdout.write(" + repr(json.dumps({
            "result": first["expected_result"], "calls": first["expected_calls"]})) + ")\n")
        try:
            run_timer_operation([sys.executable, str(fake)], first, "target source")
        except ValueError:
            pass
        else:
            raise AssertionError("accepted helper result without a native store commit")
        forged = Path(temporary) / "forged_commit.py"
        forged.write_text(
            "import json,subprocess,sys\n"
            "body=json.load(sys.stdin)\n"
            "provider=body['host_store_provider']\n"
            "before=body['before']\n"
            "import hashlib\n"
            "import rfc8785\n"
            "prior={'timer_artifact':before['helper_artifact'],'checkpoint':before['checkpoint']}\n"
            "after=json.loads(" + repr(json.dumps({
                "timer_artifact": first["after"]["helper_artifact"],
                "checkpoint": first["after"]["checkpoint"]})) + ")\n"
            "request={'kind':'commit','database_path':provider['database_path'],"
            "'run_id':provider['run_id'],'operation_id':provider['operation_id'],"
            "'expected_before_digest':'sha256:'+hashlib.sha256(rfc8785.dumps(prior)).hexdigest(),"
            "'after':after}\n"
            "subprocess.run(provider['command'],input=rfc8785.dumps(request),check=True,"
            "capture_output=True)\n"
            "sys.stdout.write(" + repr(json.dumps({
                "result": first["expected_result"], "calls": first["expected_calls"]})) + ")\n")
        try:
            run_timer_operation([sys.executable, str(forged)], first, "target source")
        except ValueError:
            pass
        else:
            raise AssertionError("accepted forged native bytes without reviewed invocation journal")
        machine = (timer_case / "machine.yaml").read_text()
        target = (timer_case / "target-machine.yaml").read_text()
        try:
            lifecycle_call([sys.executable, str(fake)], lifecycle, machine, target,
                           "fabricated_lifecycle")
        except ValueError:
            pass
        else:
            raise AssertionError("accepted fabricated lifecycle without staged native commits")
    with tempfile.TemporaryDirectory() as temporary:
        copy = Path(temporary)
        case = copy / "conformance/profiles/timer-helper/timer-01-external-helper"
        case.mkdir(parents=True)
        original = root / "conformance/profiles/timer-helper/timer-01-external-helper"
        for name in ("vectors.generated.json", "lifecycle.generated.json",
                     "configured-lifecycle.generated.json",
                     "source-ownership.generated.json", "timer-delivery.generated.json",
                     "archive-export.generated.json", "archive-operational.generated.json",
                     "archive-stage.generated.json",
                     "target-machine.yaml", "machine.yaml", "test.yaml"):
            shutil.copyfile(original / name, case / name)
        document = json.loads((case / "vectors.generated.json").read_text())
        for name, mutate in (
            ("request substitution", lambda d: d["cases"][0]["request"].update(operation_id="other")),
            ("golden substitution", lambda d: d["cases"][0]["expected_result"].update(record_revision="9")),
            ("helper mutation", lambda d: d["cases"][0]["after"]["helper_artifact"]["records"][0].update(state="fired")),
            ("checkpoint mutation", lambda d: d["cases"][0]["after"].update(checkpoint={})),
            ("coverage deletion", lambda d: d["cases"].pop()),
        ):
            changed = json.loads(json.dumps(document))
            mutate(changed)
            (case / "vectors.generated.json").write_text(json.dumps(changed))
            try:
                validate_profile(args.spec_root, copy)
            except TimerHelperValidationError:
                pass
            else:
                raise AssertionError(f"accepted {name}")
        shutil.copyfile(original / "vectors.generated.json", case / "vectors.generated.json")
        for file_name, edit in (
            ("lifecycle.generated.json", lambda d: d["expected_fire_envelope"].update(event_id="wrong")),
            ("configured-lifecycle.generated.json", lambda d: d["schedule_request"].update(scope_identity="wrong")),
            ("archive-export.generated.json", lambda d: d["input_request"].update(required_participant_ids=[])),
            ("archive-operational.generated.json", lambda d: d["source_capture"]["participant_captures"][0].update(payload=["map", []])),
            ("archive-stage.generated.json", lambda d: d["cases"][0].update(expected_staged_archive=None)),
            ("source-ownership.generated.json", lambda d: d["request"]["source"].update(source_delivery_id="other")),
            ("timer-delivery.generated.json", lambda d: d["vectors"][1]["after"].update(bindings=[])),
        ):
            changed = json.loads((original / file_name).read_text())
            edit(changed)
            (case / file_name).write_text(json.dumps(changed))
            try:
                validate_profile(args.spec_root, copy)
            except TimerHelperValidationError:
                pass
            else:
                raise AssertionError(f"accepted {file_name} substitution")
            shutil.copyfile(original / file_name, case / file_name)
    for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\xff"}'):
        try:
            strict_json(payload)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError("accepted malformed child reply")
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "installed_helper.py"
        source.write_bytes(b"def timer_command(request): pass\n")
        closure_files = [{"logical_path": "installed_helper.py", "absolute_path": str(source),
                          "bytes_base64": base64.b64encode(source.read_bytes()).decode()}]
        reference = {"identifier": "example.timer", "version": "1.0.0",
                     "content_digest": loaded_closure_digest(closure_files, [str(source)])}
        report = {"category": "timer", "provider_reference": reference,
                  "instance_id": "installed-timer", "health": "healthy",
                  "claims": ["durable_timer_helper", "coordinated_timer_admission"]}
        config = b"storage=fixture;scope=scope-archive-example"
        installation = {"loaded_closure_files": closure_files,
                        "loaded_module_paths": [str(source)],
                        "configuration_bytes_base64": base64.b64encode(config).decode(),
                        "configuration_digest": "sha256:" + hashlib.sha256(config).hexdigest(),
                        "scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                        "storage_binding": "test-storage"}
        proof = {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                 "configuration_digest": installation["configuration_digest"],
                 "storage_binding": installation["storage_binding"],
                 "provider_reference": reference, "claims": report["claims"],
                 "observed_request_digests": [first["request"]["request_digest"]],
                 "authority": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                               "storage_binding": "test-storage", "receipt_digests": [reference["content_digest"]]},
                 "delivery": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                              "storage_binding": "test-storage", "receipt_digests": [reference["content_digest"]]},
                 "effects": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                             "storage_binding": "test-storage", "receipt_digests": [reference["content_digest"]]}}
        observed = {"report": report, "installation": installation, "operational_proof": proof}
        anchor = {"factory_identity": "test.public_registry:timer_factory",
                  "provider_digest": reference["content_digest"],
                  "scope_identity": installation["scope_identity"],
                  "topology_identity": installation["topology_identity"],
                  "storage_binding": installation["storage_binding"],
                  "installed_files": [{"path": source.name,
                                       "sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()}]}
        attestation = {"factory_identity": anchor["factory_identity"],
                       "factory_path": str(source), "callable_path": str(source),
                       "loaded_files": [{"absolute_path": str(source),
                                         "sha256": anchor["installed_files"][0]["sha256"]}],
                       "observed_request_digests": [first["request"]["request_digest"]],
                       "native_transaction_ids": [],
                       "configuration_digest": installation["configuration_digest"],
                       "scope_identity": installation["scope_identity"],
                       "topology_identity": installation["topology_identity"],
                       "storage_binding": installation["storage_binding"],
                       "provider_reference": reference}
        def check(value, bridge=attestation, build=anchor):
            return verify_configured(value, args.spec_root, {first["request"]["request_digest"]},
                                     bridge, build, Path(temporary))
        try:
            verify_configured(observed, args.spec_root, {first["request"]["request_digest"]})
        except ValueError:
            pass
        else:
            raise AssertionError("accepted configured helper without reviewed live bridge")
        check(observed)
        for name, mutate in (
            ("wrong source", lambda d: d["installation"]["loaded_closure_files"][0].update(bytes_base64=base64.b64encode(b"other").decode())),
            ("omitted dependency", lambda d: d["installation"].update(loaded_module_paths=[str(source), "/abs/other.py"])),
            ("false claim", lambda d: d["report"].update(claims=["coordinated_timer_admission"])),
            ("independent claim for coordinated runner", lambda d: d["report"].update(claims=["durable_timer_helper", "independent_timer_delivery"])),
            ("missing execution", lambda d: d["operational_proof"].update(observed_request_digests=[])),
            ("wrong topology", lambda d: d["operational_proof"]["delivery"].update(topology_identity="other")),
        ):
            bad = json.loads(json.dumps(observed))
            mutate(bad)
            try:
                check(bad)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted {name}")
        real = Path(temporary) / "real_helper.py"
        real.write_bytes(b"def real_timer_factory(): pass\n")
        decoy_anchor = {**anchor,
                        "installed_files": [{"path": real.name,
                                             "sha256": "sha256:" + hashlib.sha256(real.read_bytes()).hexdigest()}]}
        decoy_attestation = {**attestation, "factory_path": str(real),
                             "callable_path": str(real),
                             "loaded_files": [{"absolute_path": str(real),
                                               "sha256": decoy_anchor["installed_files"][0]["sha256"]}]}
        try:
            check(observed, decoy_attestation, decoy_anchor)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted decoy child closure that was not loaded by bridge")
        ownership = json.loads((root / "conformance/profiles/timer-helper/timer-01-external-helper/source-ownership.generated.json").read_text())
        scope = ownership["request"]["source"]["source_scope"]
        native_id = "sha256:" + "1" * 64
        other_id = "sha256:" + "2" * 64
        third_id = "sha256:" + "3" * 64
        installation["scope_identity"] = scope
        installation["topology_identity"] = "native-topology"
        installation["storage_binding"] = "native-store-config"
        for category in ("authority", "delivery", "effects"):
            proof[category]["scope_identity"] = scope
            proof[category]["topology_identity"] = "native-topology"
            proof[category]["storage_binding"] = "native-store-config"
        proof["scope_identity"] = scope
        proof["topology_identity"] = "native-topology"
        proof["storage_binding"] = "native-store-config"
        proof["authority"]["receipt_digests"] = [native_id]
        proof["effects"]["receipt_digests"] = [other_id]
        proof["delivery"]["receipt_digests"] = [third_id]
        summary = {"configured_delivery_profile": {
            "host_scope_identity": scope, "host_topology_identifier": "native-topology",
            "host_storage_configuration_digest": "native-store-config"},
            "authority_effect_summary": {"scope_identity": scope,
                "topology_identifier": "native-topology", "native_proof_ids": [other_id],
                "authority_summary": {"scope_identity": scope, "native_proof_ids": [native_id]}},
            "delivery_operations": [{"host_store_proof_id": third_id}],
            "effect_integrations": []}
        timer_ops = [{"host_store_proof_id": None}]
        verify_native_composition(observed, summary, timer_ops, ownership)
        proof["delivery"]["receipt_digests"] = [native_id]
        try:
            verify_native_composition(observed, summary, timer_ops, ownership)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted copied delivery proof identity")
    print("timer helper substitution and strict child JSON checks passed")


if __name__ == "__main__":
    main()
