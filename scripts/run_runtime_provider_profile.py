#!/usr/bin/env python3
"""Compare production provider adapter observations with the closed source profile."""
from __future__ import annotations

import argparse
import json
import shutil
import shlex
import subprocess
import tempfile
from pathlib import Path

from runtime_provider_validator import CASE_REL, SOURCES, validate_profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    parser.add_argument("--adapter", required=True,
                        help="production implementation adapter command")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    count = validate_profile(args.spec_root, root)
    case = root / CASE_REL
    document = json.loads((case / "vectors.generated.json").read_text())
    closure = json.loads((case / "provider-closure.json").read_text())
    by_source = {item["path"]: item["sha256"] for item in closure["files"]}
    closure_digest = document["vectors"][0]["request"]["installed"]["closure_digest"]
    command = shlex.split(args.adapter)
    if not command:
        parser.error("empty adapter command")
    for vector in document["vectors"]:
        # The adapter receives a complete operation and source paths. Case names,
        # expected observations, and normative oracle files are withheld.
        with tempfile.TemporaryDirectory(prefix="determa-runtime-provider-") as temporary:
            inputs = Path(temporary)
            names = {vector["request"]["bundle"], "provider-closure.json", *SOURCES}
            for key in ("source_file", "manifest_file", "generated_bundle_file"):
                name = vector["request"]["arguments"].get(key)
                if name is not None:
                    names.add(name)
            for name in names:
                destination = inputs / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(case / name, destination)
            payload = {"request": vector["request"], "profile_root": str(inputs),
                       "source_files": list(SOURCES), "source_closure_file": "provider-closure.json"}
            completed = subprocess.run(command, input=json.dumps(payload), text=True,
                                       capture_output=True, check=False)
        if completed.returncode:
            raise SystemExit(f"{vector['name']}: adapter exited {completed.returncode}: "
                             f"{completed.stderr.strip()}")
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise SystemExit(f"{vector['name']}: invalid adapter JSON: {error}") from error
        if set(response) != {"observation", "loaded_source", "loaded_closure_digest"}:
            raise SystemExit(f"{vector['name']}: adapter response must have exactly three fields")
        if response["loaded_closure_digest"] != closure_digest:
            raise SystemExit(f"{vector['name']}: executing closure digest mismatch")
        loaded_source = response["loaded_source"]
        if not isinstance(loaded_source, dict) or any(
            name not in by_source or by_source[name] != hash_
            for name, hash_ in loaded_source.items()
        ):
            raise SystemExit(f"{vector['name']}: executing source evidence mismatch")
        if (any(stage in vector["expected"]["stages"] for stage in (
            "evaluate_guard", "evaluate_actions", "invoke_inspect_guard", "compile_region",
        )) or (vector["expected"]["result"] == "accepted" and
                vector["request"]["installed"]["providers"])) and not loaded_source:
            raise SystemExit(f"{vector['name']}: executing source evidence missing")
        if response["observation"] != vector["expected"]:
            raise SystemExit(f"{vector['name']}: production observation differs from oracle: "
                             f"{json.dumps(response['observation'], sort_keys=True)}")
    print(f"passed {count} runtime provider production adapter vectors")


if __name__ == "__main__":
    main()
