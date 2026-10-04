#!/usr/bin/env python3
"""Run complete §22 vectors against a production archive adapter.

The adapter command receives one JSON object on stdin and writes one JSON object to
stdout.  Each invocation is independent.  Case names and expected data are withheld.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from validate_portable_archive import CASE, canonical, parse_json_bytes, read_json, validate_profile

CALLS = ('core_create', 'core_admit', 'core_step', 'core_migration',
         'worker_claim', 'effect_dispatch', 'timer_poll', 'clock_read',
         'authority_grant', 'credentials_create')
STATE = ('active_scopes', 'authority_grants', 'credentials', 'staged_archives')


def require_equal(actual, expected, label: str) -> None:
    if canonical(actual) != canonical(expected):
        raise ValueError(f'{label}: complete canonical response differs')


def run_case(command: list[str], kind: str, case: dict) -> None:
    if kind == 'export':
        request = {'operation': 'export', 'request': case['input_request'],
                   'source_capture': case['source_capture']}
    else:
        request = {'operation': 'stage', 'request': case['input_request'],
                   'input_archive': case['input_archive'],
                   'configured_import': case['configured_import']}
    completed = subprocess.run(command, input=canonical(request), capture_output=True,
                               check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{case["case_id"]}: adapter exited {completed.returncode}: '
                         f'{completed.stderr.decode("utf-8", "replace")[:500]}')
    response = parse_json_bytes(completed.stdout, case['case_id'] + ' adapter response')
    if set(response) != {'result', 'archive', 'staged_archive', 'before', 'after', 'calls'}:
        raise ValueError(f'{case["case_id"]}: incomplete adapter response')
    require_equal(response['result'], case['expected_result'], case['case_id'] + ' result')
    require_equal(response['archive'], case['expected_archive'] if kind == 'export' else None,
                  case['case_id'] + ' archive')
    require_equal(response['staged_archive'],
                  case['expected_staged_archive'] if kind == 'stage' else None,
                  case['case_id'] + ' staged archive')
    calls = response['calls']
    if set(calls) != set(CALLS) or any(type(calls[k]) is not int or calls[k] != 0 for k in CALLS):
        raise ValueError(f'{case["case_id"]}: archive operation invoked active host work')
    before, after = response['before'], response['after']
    if set(before) != set(STATE) or set(after) != set(STATE):
        raise ValueError(f'{case["case_id"]}: incomplete host state observation')
    if any(before[key] != after[key] for key in STATE if key != 'staged_archives'):
        raise ValueError(f'{case["case_id"]}: archive operation changed active host state')
    if kind == 'export' or case['expected_result']['status'] == 'refused':
        require_equal(after, before, case['case_id'] + ' unchanged state')
    else:
        staged = after['staged_archives']
        previous = before['staged_archives']
        if not isinstance(staged, list) or not isinstance(previous, list) or len(staged) != len(previous) + 1:
            raise ValueError(f'{case["case_id"]}: one inert stage record required')
        require_equal(staged[:-1], previous, case['case_id'] + ' prior stages')
        require_equal(staged[-1], {'staging_identity': case['input_request']['staging_identity'],
                                   'archive': case['expected_staged_archive']},
                      case['case_id'] + ' staged bytes')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER,
                        help='adapter executable and arguments after --')
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('adapter command required after --')
    validate_profile(args.spec_root)
    count = 0
    for kind in ('export', 'stage'):
        fixture = read_json(CASE / (kind + '-cases-v1.json'))
        for case in fixture['cases']:
            run_case(command, kind, case)
            count += 1
    print(f'{count} portable archive vectors passed')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'archive profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
