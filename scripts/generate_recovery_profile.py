#!/usr/bin/env python3
"""Pin the complete §24 raw examples to an explicit specification checkout."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from validate_recovery_profile import CASE


def generated(spec_root: Path) -> dict[str, bytes]:
    source = spec_root / 'examples/recovery'
    cases = (source / 'recovery-cases-v1.json').read_bytes()
    fixture = json.loads(cases)
    manifest = {
        'title': 'strict quarantine, fresh-scope takeover, clone, and conditional local transfer',
        'recovery_vectors': {
            'early': [case['case_id'] for case in fixture['early_cases']],
            'cases': [case['case_id'] for case in fixture['cases']],
        },
    }
    return {
        'recovery-cases-v1.json': cases,
        'archive-local-transfer-v1.json': (source / 'archive-local-transfer-v1.json').read_bytes(),
        'test.yaml': (json.dumps(manifest, indent=2) + '\n').encode(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    CASE.mkdir(parents=True, exist_ok=True)
    for name, contents in generated(args.spec_root).items():
        target = CASE / name
        if args.check:
            if target.read_bytes() != contents:
                raise SystemExit(f'{name}: differs from pinned specification')
        else:
            target.write_bytes(contents)
    print('42 recovery source cases checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
