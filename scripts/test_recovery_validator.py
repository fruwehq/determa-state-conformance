#!/usr/bin/env python3
"""Adversarial static and production-response checks for §24."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from unittest.mock import patch

from validate_portable_archive import ArchiveValidationError, canonical, read_json
from validate_recovery_profile import CASE, validate_profile
from run_recovery_profile import CALLS, STATE, input_for, run_case


def rejected(label, fn):
    try:
        fn()
    except (ArchiveValidationError, ValueError):
        return
    raise AssertionError(label + ': invalid result accepted')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    args = parser.parse_args()
    assert validate_profile(args.spec_root) == 42
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    case = next(c for c in fixture['cases'] if c['case_id'] == 'standalone_takeover')
    sent = input_for(case, fixture)
    assert not any(key.startswith('expected_') or key == 'case_id' for key in sent)
    assert sent['request'] == case['request'] and sent['setup_requests'] == []
    assert len(sent['source_archive']['checkpoints']) == 4
    response = {'result': case['expected_result'], 'record': case['expected_record'],
                'transfer_proof': None, 'before': {}, 'after': {}, 'calls': {},
                'caller_response_kind': 'recovery_result',
                'caller_response_body': case['expected_result'], 'mutation_paths': [],
                'setup_responses': []}
    class Completed:
        returncode = 0
        stderr = b''
        stdout = canonical(response)
    captured = []
    def fake_run(command, *, input, **kwargs):
        captured.append(json.loads(input))
        return Completed()
    with patch('run_recovery_profile.subprocess.run', fake_run):
        rejected('incomplete actual observations', lambda: run_case(['adapter'], case, fixture))
    assert captured == [sent]
    response['caller_response_body'] = {'status': 'succeeded'}
    with patch('run_recovery_profile.subprocess.run', return_value=Completed()):
        rejected('partial literal caller body', lambda: run_case(['adapter'], case, fixture))
    response['caller_response_body'] = case['expected_result']
    response['result'] = {'status': 'succeeded'}
    with patch('run_recovery_profile.subprocess.run', return_value=Completed()):
        rejected('partial result', lambda: run_case(['adapter'], case, fixture))
    response['result'] = case['expected_result']
    response['before'] = {key: [] for key in STATE}
    response['after'] = {key: [] for key in STATE}
    response['calls'] = {key: 0 for key in CALLS}
    with patch('run_recovery_profile.subprocess.run', return_value=Completed()):
        rejected('missing durable record', lambda: run_case(['adapter'], case, fixture))
    response['after']['recovery_records'] = [case['expected_record']]
    with patch('run_recovery_profile.subprocess.run', return_value=Completed()):
        rejected('false mutation footprint', lambda: run_case(['adapter'], case, fixture))
    print('42 recovery source cases and 5 adversarial driver substitutions passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
