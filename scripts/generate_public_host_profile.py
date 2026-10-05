"""Copy exact immutable §25 specification golden bytes into the public profile."""
from __future__ import annotations

import argparse
from pathlib import Path

from validate_public_host import CASE, SOURCES


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for local, source in SOURCES.items():
        expected = (args.spec_root / source).read_bytes()
        target = CASE / local
        if args.check:
            if target.read_bytes() != expected:
                raise SystemExit(f'{local}: pinned public spec source differs')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(expected)
    print(f'{len(SOURCES)} public host source documents checked')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
