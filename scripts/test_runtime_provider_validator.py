#!/usr/bin/env python3
"""Tamper probes and executable source checks for the runtime provider profile."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from runtime_provider_validator import CASE_REL, RuntimeProviderValidationError, validate_profile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    assert validate_profile(args.spec_root, ROOT) == 22
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
    snapshot = {"event": {"payload": {"approved": False}}, "variables": {"accepted": False}}
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
    print("runtime provider relational tamper probes and Python/Rust source checks passed")


if __name__ == "__main__":
    main()
