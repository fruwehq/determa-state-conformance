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
from run_timer_helper_profile import strict_json, verify_configured


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assert validate_profile(args.spec_root, root) == (24, 25, 3)
    with tempfile.TemporaryDirectory() as temporary:
        copy = Path(temporary)
        case = copy / "conformance/profiles/timer-helper/timer-01-external-helper"
        case.mkdir(parents=True)
        original = root / "conformance/profiles/timer-helper/timer-01-external-helper"
        for name in ("vectors.generated.json", "lifecycle.generated.json",
                     "archive-export.generated.json", "archive-stage.generated.json",
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
            ("archive-export.generated.json", lambda d: d["input_request"].update(required_participant_ids=[])),
            ("archive-stage.generated.json", lambda d: d["cases"][0].update(expected_staged_archive=None)),
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
        reference = {"identifier": "example.timer", "version": "1.0.0",
                     "content_digest": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()}
        report = {"category": "timer", "provider_reference": reference,
                  "instance_id": "installed-timer", "health": "healthy",
                  "claims": ["durable_timer_helper", "coordinated_timer_admission"]}
        config = b"storage=fixture;scope=scope-archive-example"
        installation = {"loaded_source_path": str(source),
                        "loaded_source_bytes_base64": base64.b64encode(source.read_bytes()).decode(),
                        "configuration_bytes_base64": base64.b64encode(config).decode(),
                        "configuration_digest": "sha256:" + hashlib.sha256(config).hexdigest(),
                        "scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                        "storage_binding": "test-storage"}
        proof = {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                 "configuration_digest": installation["configuration_digest"],
                 "storage_binding": installation["storage_binding"],
                 "provider_reference": reference, "claims": report["claims"],
                 "passed_case_ids": ["schedule_first"],
                 "authority": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                               "storage_binding": "test-storage", "passed_case_ids": ["guarded_commit"]},
                 "delivery": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                              "storage_binding": "test-storage", "passed_case_ids": ["source_ack"]},
                 "effects": {"scope_identity": "scope-archive-example", "topology_identity": "local-fixture",
                             "storage_binding": "test-storage", "passed_case_ids": ["journal_commit"]}}
        observed = {"report": report, "installation": installation, "operational_proof": proof}
        verify_configured(observed, args.spec_root, {"schedule_first"})
        for name, mutate in (
            ("wrong source", lambda d: d["installation"].update(loaded_source_bytes_base64=base64.b64encode(b"other").decode())),
            ("false claim", lambda d: d["report"].update(claims=["coordinated_timer_admission"])),
            ("missing execution", lambda d: d["operational_proof"].update(passed_case_ids=[])),
            ("wrong topology", lambda d: d["operational_proof"]["delivery"].update(topology_identity="other")),
        ):
            bad = json.loads(json.dumps(observed))
            mutate(bad)
            try:
                verify_configured(bad, args.spec_root, {"schedule_first"})
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted {name}")
    print("timer helper substitution and strict child JSON checks passed")


if __name__ == "__main__":
    main()
