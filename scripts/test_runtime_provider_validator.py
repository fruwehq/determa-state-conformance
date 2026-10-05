#!/usr/bin/env python3
"""Tamper probes and executable source checks for the runtime provider profile."""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime_provider_validator import (CASE_REL, RuntimeProviderValidationError,
                                        validate_positive_semantics, validate_profile)
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    assert validate_profile(args.spec_root, ROOT) == 41
    case = ROOT / CASE_REL
    with tempfile.TemporaryDirectory() as temporary:
        clone = Path(temporary)
        fixture = clone / CASE_REL
        fixture.parent.mkdir(parents=True)
        shutil.copytree(case, fixture)
        schema = clone / "scripts/schemas"
        schema.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/schemas/runtime-provider-vectors.schema.json", schema)

        def probe(relative: str, transform) -> None:
            path = fixture / relative
            original = path.read_bytes()
            path.write_bytes(transform(original))
            try:
                validate_profile(args.spec_root, clone)
            except (RuntimeProviderValidationError, KeyError, ValueError):
                pass
            else:
                raise AssertionError(f"tampering accepted: {relative}")
            finally:
                path.write_bytes(original)

        probe("provider/test_provider.py", lambda body: body + b"\n# changed bytes\n")
        probe("provider-closure.json", lambda body: body.replace(b"sha256:", b"sha256:0", 1))
        probe("norm-mixed-cel-native.source", lambda body: body + b"\n")
        probe("machine.yaml", lambda body: body.replace(b"example.native-review", b"example.native-alias"))
        probe("source-package.json", lambda body: body.replace(b"event.payload.approved", b"false"))
        probe("source-manifest.json", lambda body: body.replace(b"source_artifact_digest", b"wrong_source_digest"))
        probe("vectors.generated.json", lambda body: body.replace(b"compare_and_swap_conflict", b"retry"))
        def change_operational(name, transform):
            def mutate(body):
                document = json.loads(body)
                vector = next(item for item in document["vectors"] if item["name"] == name)
                transform(vector)
                return json.dumps(document, separators=(",", ":")).encode()
            return mutate

        probe("vectors.generated.json", change_operational("native_repeated_sends_commit_and_replay",
              lambda vector: vector["expected"]["value"]["retained_effect_references"][1].update(effect_id="sha256:" + "0" * 64)))
        probe("vectors.generated.json", change_operational("native_repeated_sends_commit_and_replay",
              lambda vector: vector["expected"]["value"]["pending_outbox_entries"][1]["intent"].update(effect_id="sha256:" + "0" * 64)))
        probe("vectors.generated.json", change_operational("native_mixed_sends_have_separate_ordinals",
              lambda vector: vector["expected"]["value"]["emission_identities"][1].update(emission_index="1")))
        probe("norm-invalid-action-output.json", lambda body: b'{"actions":[]}')
        probe("norm-multiple-send-identities.json", lambda body: body.replace(b'"emission_index":"1"', b'"emission_index":"0"'))
        probe("norm-invalid-multiple-send-identities.json", lambda body: (fixture / "norm-multiple-send-identities.json").read_bytes())
        probe("norm-invalid-missing-correlation-action-output.json", lambda body: b'{"actions":[]}')

    machine = YAML(typ="safe").load((case / "machine.yaml").read_text())
    output = json.loads((case / "norm-action-output.json").read_text())
    validate_positive_semantics(machine, output)
    missing_cel = copy.deepcopy(machine)
    del missing_cel["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"][1]["action"][1]["send"]["correlation_id"]
    missing_typed = copy.deepcopy(output)
    del missing_typed["actions"][1]["send"]["correlation_id"]
    unreachable = copy.deepcopy(machine)
    unreachable["machines"][0]["root"]["states"]["complete"] = {"type": "final"}
    for changed_machine, changed_output in (
        (missing_cel, output), (machine, missing_typed), (unreachable, output)
    ):
        try:
            validate_positive_semantics(changed_machine, changed_output)
        except RuntimeProviderValidationError:
            pass
        else:
            raise AssertionError("invalid positive provider semantics accepted")

    source = case / "provider/test_provider.py"
    spec = importlib.util.spec_from_file_location("runtime_profile_test_provider", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    provider = module.Provider()
    snapshot = {"event": {"payload": ["map", [["approved", ["boolean", False]]]]},
                "variables": ["map", [["accepted", ["boolean", False]]]]}
    snapshot_before = json.dumps(snapshot, sort_keys=True)
    assert provider.evaluate_guard(snapshot, guard_override=True) is True
    result = provider.evaluate_actions(snapshot)
    assert result == json.loads((case / "norm-action-output.json").read_text())
    assert provider.guard_snapshot == snapshot
    assert provider.evaluate_actions(snapshot, repeat_send=True) == json.loads((case / "norm-multiple-send-action-output.json").read_text())
    assert provider.action_snapshot == snapshot
    assert provider.evaluate_actions(snapshot, invalid=True) == json.loads(
        (case / "norm-invalid-action-output.json").read_text())
    mixed_provider = module.Provider()
    mixed_output = mixed_provider.evaluate_actions(snapshot, mixed_send=True)
    assert [item.get("send", {}).get("event") for item in mixed_output["actions"]] == [None, "accepted", "notice", "accepted", "notice"]
    assert mixed_provider.action_calls == 1
    safe_provider = module.Provider()
    provider_before_inspection = copy.deepcopy(safe_provider.__dict__)
    host_inspection_calls = 0
    assert safe_provider.inspect_guard(snapshot, 1, 2) == (False, 1, 2)
    host_inspection_calls += 1
    assert safe_provider.__dict__ == provider_before_inspection
    try:
        safe_provider.inspect_guard(snapshot, 1, 1)
    except ValueError as error:
        assert str(error) == "inspection_limit_exceeded"
    else:
        raise AssertionError("inspection budget accepted")
    host_inspection_calls += 1
    assert safe_provider.__dict__ == provider_before_inspection
    unsafe_provider = module.Provider()
    unsafe_before = copy.deepcopy(unsafe_provider.__dict__)
    # Host preflight refuses the unsafe binding before either evaluator is entered.
    assert unsafe_provider.__dict__ == unsafe_before
    assert host_inspection_calls == 2
    try:
        provider.evaluate_actions(snapshot, fail=True, external_io=True)
    except ValueError as error:
        assert str(error) == "action_fault"
    else:
        raise AssertionError("action failure missing")
    assert provider.external_calls == provider.irreversible_effects == 1
    assert provider.external_effect_log == [{"effect_id": "fixture-io-1",
                                             "kind": "external_write", "phase": "before_commit"}]
    assert json.dumps(snapshot, sort_keys=True) == snapshot_before
    assert module.compile_region("event.payload.approved") == "event.payload.approved"
    try:
        module.compile_region("invalid expression")
    except ValueError as error:
        assert str(error) == "language_compilation_failed"
    else:
        raise AssertionError("invalid compiler input accepted")

    with tempfile.TemporaryDirectory() as temporary:
        wrapper = Path(temporary) / "provider_source_rows.rs"
        wrapper.write_text(f'''include!(r#"{case / "provider/test_provider.rs"}"#);
fn main() {{
    let mut provider = Provider::default();
    assert_eq!(provider.evaluate_guard(false, Some(true), false, false), Ok(true));
    assert_eq!(provider.evaluate_guard(false, None, false, false), Ok(false));
    println!("{{}}", provider.evaluate_actions(false, false, false).unwrap());
    println!("{{}}", provider.evaluate_actions(true, false, false).unwrap());
    println!("{{}}", provider.evaluate_actions_repeated(false, false, false, true).unwrap());
    let mut mixed = Provider::default();
    println!("{{}}", mixed.evaluate_actions_mixed(false, false, false, true).unwrap());
    assert_eq!(mixed.action_calls, 1);
    assert_eq!(provider.evaluate_actions(false, true, true), Err("action_fault"));
    assert_eq!(provider.external_calls, 1);
    assert_eq!(provider.irreversible_effects, 1);
    assert_eq!(provider.external_effect_log, vec!["fixture-io-1:external_write:before_commit"]);
    let mut recorded = Provider::default();
    let snapshot = r#"{{"event":{{"cause_id":"distinct-cause","source":{{"host":true}}}},"variables":["map",[]]}}"#;
    assert_eq!(recorded.evaluate_guard_snapshot(snapshot, false, Some(true), false, false), Ok(true));
    recorded.evaluate_actions_snapshot(snapshot, false, false, false, true).unwrap();
    assert_eq!(recorded.guard_snapshot.as_deref(), Some(snapshot));
    assert_eq!(recorded.action_snapshot.as_deref(), Some(snapshot));
    assert_eq!((recorded.guard_calls, recorded.action_calls), (1, 1));
    let safe = Provider::default();
    let before = safe.clone();
    assert_eq!(safe.inspect_guard(true, 1, 2), Ok((true, 1, 2)));
    assert_eq!(safe, before);
    assert_eq!(safe.inspect_guard(true, 1, 1), Err("inspection_limit_exceeded"));
    assert_eq!(safe, before);
    assert_eq!(compile_region("event.payload.approved"), Ok("event.payload.approved"));
    assert_eq!(compile_region("invalid expression"), Err("language_compilation_failed"));
}}
''')
        for toolchain in ("1.86.0", "stable"):
            executable = Path(temporary) / f"provider-{toolchain}"
            command = ["rustc", f"+{toolchain}", "-o", str(executable), str(wrapper)]
            subprocess.run(command, check=True, capture_output=True)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
            outputs = [json.loads(line) for line in result.stdout.splitlines()]
            assert outputs == [json.loads((case / "norm-action-output.json").read_text()),
                               json.loads((case / "norm-invalid-action-output.json").read_text()),
                               json.loads((case / "norm-multiple-send-action-output.json").read_text()), mixed_output]
    with tempfile.TemporaryDirectory() as temporary:
        location = Path(temporary)
        adapter = location / "reject_adapter.py"
        capture = location / "request.json"
        adapter.write_text(
            "import json, pathlib, sys\n"
            "request = json.load(sys.stdin)\n"
            "files = sorted(str(p.relative_to(request['profile_root'])) for p in "
            "pathlib.Path(request['profile_root']).rglob('*') if p.is_file())\n"
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({'request': request, 'files': files}))\n"
            "sys.stdout.buffer.write(pathlib.Path(sys.argv[2]).read_bytes() if len(sys.argv) > 2 "
            "else b'{}')\n"
        )
        run = subprocess.run([
            sys.executable, str(ROOT / "scripts/run_runtime_provider_profile.py"),
            "--spec-root", str(args.spec_root),
            "--adapter", f"{sys.executable} {adapter} {capture}",
        ], capture_output=True, text=True)
        assert run.returncode != 0 and "exactly three fields" in run.stderr
        recorded = json.loads(capture.read_text())
        assert set(recorded["request"]) == {"request", "profile_root", "source_files",
                                             "source_closure_file"}
        assert "vectors.generated.json" not in recorded["files"]
        assert "expected" not in recorded["request"] and "name" not in recorded["request"]
        fixture_vectors = json.loads((case / "vectors.generated.json").read_text())["vectors"]
        first = fixture_vectors[0]
        closure = first["request"]["installed"]["closure_digest"]
        source_evidence = json.loads((case / "provider-closure.json").read_text())["files"]
        valid = {"observation": first["expected"],
                 "loaded_source": {source_evidence[0]["path"]: source_evidence[0]["sha256"]},
                 "loaded_closure_digest": closure}
        variants = {
            "duplicate": b'{"observation":{},"observation":{}}',
            "nonfinite": json.dumps(valid).replace('"irreversible_side_effects": 0',
                                                  '"irreversible_side_effects": NaN').encode(),
            "boolean_counter": json.dumps({**valid, "observation": {
                **first["expected"], "irreversible_side_effects": False}}).encode(),
            "integer_boolean": json.dumps({**valid, "observation": {
                **first["expected"], "determa_state_committed": 0}}).encode(),
            "nested_boolean_counter": json.dumps({**valid, "observation": {
                **first["expected"], "calls": {**first["expected"]["calls"],
                                                "guard": False}}}).encode(),
            "invalid_utf8": b"\xff",
        }
        for variant, raw in variants.items():
            response_file = location / f"{variant}.json"
            response_file.write_bytes(raw)
            rejected = subprocess.run([
                sys.executable, str(ROOT / "scripts/run_runtime_provider_profile.py"),
                "--spec-root", str(args.spec_root),
                "--adapter", f"{sys.executable} {adapter} {capture} {response_file}",
            ], capture_output=True, text=True)
            assert rejected.returncode != 0, f"malformed child output accepted: {variant}"
            assert ("invalid adapter JSON" in rejected.stderr or
                    "invalid observation" in rejected.stderr), rejected.stderr
    print("runtime provider relational tamper probes and Python/Rust source checks passed")


if __name__ == "__main__":
    main()
