#!/usr/bin/env python3
"""Tamper probes and executable source checks for the runtime provider profile."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime_provider_validator import CASE_REL, RuntimeProviderValidationError, validate_profile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    assert validate_profile(args.spec_root, ROOT) == 30
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
        probe("norm-invalid-action-output.json", lambda body: b'{"actions":[]}')

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
    assert provider.evaluate_actions(snapshot, invalid=True) == json.loads(
        (case / "norm-invalid-action-output.json").read_text())
    assert provider.inspect_guard(snapshot, 1, 2) == (False, 1, 2)
    try:
        provider.inspect_guard(snapshot, 1, 1)
    except ValueError as error:
        assert str(error) == "inspection_limit_exceeded"
    else:
        raise AssertionError("inspection budget accepted")
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
        for toolchain in ("1.86.0", "stable"):
            command = ["rustc", f"+{toolchain}", "--crate-type", "lib", "--emit", "metadata",
                       "-o", str(Path(temporary) / f"provider-{toolchain}.rmeta"),
                       str(case / "provider/test_provider.rs")]
            subprocess.run(command, check=True, capture_output=True)
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
            "print('{}')\n"
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
    print("runtime provider relational tamper probes and Python/Rust source checks passed")


if __name__ == "__main__":
    main()
