#!/usr/bin/env python3
"""Adversarial static and production-response checks for §24."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from unittest.mock import patch

from validate_portable_archive import (ArchiveValidationError, canonical, digest, read_json,
                                       validate_archive_integrity, validator_registry, without, ROOT)
from validate_recovery_profile import CASE, validate_profile, validate_owned_definition_closure
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
    assert validate_profile(args.spec_root) == 48
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    case = next(c for c in fixture['cases'] if c['case_id'] == 'standalone_takeover')
    sent = input_for(case, fixture)
    assert not any(key.startswith('expected_') or key == 'case_id' for key in sent)
    assert sent['request'] == case['request'] and sent['setup_requests'] == []
    assert len(sent['source_archive']['checkpoints']) == 4
    assert 'stage_receipt' not in sent and 'expected_result' not in sent
    missing_helper = next(item for item in fixture['cases']
                          if item['case_id'] == 'required_helper_missing')
    missing_input = input_for(missing_helper, fixture)
    assert missing_input['stage_request']['staging_identity'] == \
        missing_helper['request']['arguments']['staging_identity']
    assert missing_input['stage_archive']['participants'] == []
    assert missing_input['source_archive']['participants'] != []
    owned = read_json(CASE / 'recovery-two-root-archive-v1.json')
    validators = validator_registry(args.spec_root)
    broken = copy.deepcopy(owned)
    broken['normalized_definitions'].pop()
    broken['members'] = [member for member in broken['members']
                         if not member['identity'].startswith('definition:') or
                         member['identity'] == 'definition:' + broken['normalized_definitions'][0]['validated_bundle_fingerprint']]
    broken['archive_digest'] = digest(['determa-archive-digest-1', without(broken, 'archive_digest')])
    validate_archive_integrity(broken, validators)
    rejected('resealed missing real definition', lambda: validate_owned_definition_closure(
        broken, CASE / 'recovery-owned-machine.yaml',
        ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-machine.yaml'))
    missing_component = copy.deepcopy(owned)
    nested = missing_component['checkpoints'][0]['root_record']['aggregate_state']
    nested['runtimes'] = [runtime for runtime in nested['runtimes']
                          if runtime['relation']['kind'] != 'component']
    rejected('removed nested component runtime', lambda: validate_owned_definition_closure(
        missing_component, CASE / 'recovery-owned-machine.yaml',
        ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-machine.yaml'))
    response = {'result': case['expected_result'], 'record': case['expected_record'],
                'transfer_proof': None, 'before': {}, 'after': {}, 'calls': {},
                'caller_response_kind': 'recovery_result',
                'caller_response_body': case['expected_result'], 'mutation_paths': [],
                'setup_responses': [], 'stage_setup_result': fixture['stage_receipt']}
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
    local = next(item for item in fixture['cases'] if item['case_id'] == 'local_prepare')
    local_input = input_for(local, fixture)
    stage = {'staging_identity': local_input['stage_request']['staging_identity'],
             'archive': local_input['source_archive']}
    before = {key: [] for key in STATE}
    before['staged_archives'] = [stage]
    after = copy.deepcopy(before)
    after['transfer_proofs'] = [local['expected_transfer_proof']]
    local_response = {
        'result': local['expected_result'], 'record': None,
        'transfer_proof': local['expected_transfer_proof'],
        'before': before, 'after': after, 'calls': {key: 0 for key in CALLS},
        'caller_response_kind': 'recovery_result',
        'caller_response_body': local['expected_result'],
        'mutation_paths': ['/transfer_proofs/0'], 'setup_responses': [],
        'stage_setup_result': fixture['local_transfer_stage_result'],
    }
    class ForgedProof:
        returncode = 0
        stderr = b''
        stdout = canonical(local_response)
    with patch('run_recovery_profile.subprocess.run', return_value=ForgedProof()):
        rejected('copied transfer proof without native frozen inventory',
                 lambda: run_case(['adapter'], local, fixture))
    print('42 normative and 6 real two-root recovery cases; 8 adversarial substitutions passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
