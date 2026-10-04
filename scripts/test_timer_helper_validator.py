#!/usr/bin/env python3
"""Reject substitution and malformed child responses for timer helper vectors."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from timer_helper_validator import TimerHelperValidationError, validate_profile
from run_timer_helper_profile import strict_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-root", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assert validate_profile(args.spec_root, root) == 24
    with tempfile.TemporaryDirectory() as temporary:
        copy = Path(temporary)
        case = copy / "conformance/profiles/timer-helper/timer-01-external-helper"
        case.mkdir(parents=True)
        original = root / "conformance/profiles/timer-helper/timer-01-external-helper"
        for name in ("vectors.generated.json", "machine.yaml", "test.yaml"):
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
    for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\xff"}'):
        try:
            strict_json(payload)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError("accepted malformed child reply")
    print("timer helper substitution and strict child JSON checks passed")


if __name__ == "__main__":
    main()
