#!/usr/bin/env python3
"""Copy the immutable §22 normative raw vectors from an explicit specification pin."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from validate_portable_archive import CASE, FILES


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    source = args.spec_root / 'examples/archives'
    for name in FILES:
        expected = (source / name).read_bytes()
        target = CASE / name
        if args.check:
            if target.read_bytes() != expected:
                raise SystemExit(f'{name}: generated archive fixture differs from pinned specification')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(expected)
    export = json.loads((source / 'export-cases-v1.json').read_bytes())
    stage = json.loads((source / 'stage-cases-v1.json').read_bytes())
    manifest = ('title: complete portable archive export and inert staging\n'
                'archive_vectors:\n  export: ' +
                json.dumps([case['case_id'] for case in export['cases']]) +
                '\n  stage: ' +
                json.dumps([case['case_id'] for case in stage['cases']]) + '\n')
    if args.check:
        if (CASE / 'test.yaml').read_text(encoding='utf-8') != manifest:
            raise SystemExit('archive driver manifest differs from pinned cases')
    else:
        (CASE / 'test.yaml').write_text(manifest, encoding='utf-8')
    print(f'{len(export["cases"])} export and {len(stage["cases"])} stage vectors checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
