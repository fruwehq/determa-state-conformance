#!/usr/bin/env python3
"""Adversarial checks for closed §22 source, member, and driver validation."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from unittest.mock import patch

from validate_portable_archive import (ArchiveValidationError, CASE, digest, parse_json_bytes, read_json,
                                       validate_archive_integrity, validate_profile,
                                       validator_registry, without)
from run_portable_archive_profile import run_case


def rejected(label, operation) -> None:
    try:
        operation()
    except (ArchiveValidationError, ValueError):
        return
    raise AssertionError(f'{label}: adversarial substitution accepted')


def reseal(archive: dict) -> None:
    objects = {
        **{'checkpoint:' + x['root_instance_id']: x for x in archive['checkpoints']},
        **{'definition:' + x['validated_bundle_fingerprint']: x for x in archive['normalized_definitions']},
        **{'migration_descriptor:' + x['migration_descriptor_digest']: x for x in archive['migration_descriptors']},
        **{'participant:' + x['participant_id']: x for x in archive['participants']},
    }
    archive['members'] = [member for member in archive['members'] if member['identity'] in objects]
    for member in archive['members']:
        value = objects[member['identity']]
        member['digest'] = digest(value)
        from validate_portable_archive import canonical
        member['byte_length'] = str(len(canonical(value)))
    archive['archive_digest'] = digest(['determa-archive-digest-1',
                                        without(archive, 'archive_digest')])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    args = parser.parse_args()
    assert validate_profile(args.spec_root) == 54
    validators = validator_registry(args.spec_root)
    original = read_json(CASE / 'archive-v1.json')
    probes = [
        ('outer digest', lambda a: a.update(archive_digest='sha256:' + '0' * 64), False),
        ('missing member', lambda a: a['members'].pop(), True),
        ('missing checkpoint', lambda a: a['checkpoints'].pop(), True),
        ('required capability', lambda a: a['required_determa_capabilities'].pop(), True),
        ('wrong provider requiredness', lambda a: a['participants'][0].update(required=False), True),
        ('typed payload', lambda a: a['participants'][0]['payload'][1][0][1].__setitem__(1, '8'), True),
    ]
    for label, mutate, seal in probes:
        archive = copy.deepcopy(original)
        mutate(archive)
        if seal: reseal(archive)
        rejected(label, lambda a=archive: validate_archive_integrity(a, validators))
    archive = copy.deepcopy(original)
    archive['members'][0]['byte_length'] = '1'
    archive['archive_digest'] = digest(['determa-archive-digest-1',
                                        without(archive, 'archive_digest')])
    rejected('resealed member length', lambda: validate_archive_integrity(archive, validators))
    archive = copy.deepcopy(original)
    checkpoint = next(x for x in archive['checkpoints'] if x['root_instance_id'] == 'server-1')
    checkpoint['operation_receipts'].pop()
    checkpoint['execution_checkpoint_digest'] = digest([
        'determa-execution-checkpoint-digest-1',
        without(checkpoint, 'execution_checkpoint_digest')])
    reseal(archive)
    rejected('resealed missing receipt', lambda: validate_archive_integrity(archive, validators))
    stage_case = read_json(CASE / 'stage-cases-v1.json')['cases'][0]
    class Result:
        returncode = 0
        stderr = b''
        stdout = b'{}'
    captured = []
    def fake_run(command, *, input, **kwargs):
        captured.append(json.loads(input))
        return Result()
    with patch('run_portable_archive_profile.subprocess.run', fake_run):
        rejected('incomplete actual response', lambda: run_case(['adapter'], 'stage', stage_case))
    assert set(captured[0]) == {'operation', 'request', 'input_archive', 'configured_import'}
    assert 'case_id' not in captured[0] and 'expected_result' not in captured[0]
    owned = read_json(CASE / 'owned-component-vectors-v1.json')['stage_case']
    dropped = copy.deepcopy(owned['expected_staged_archive'])
    nested = next(item for item in dropped['checkpoints']
                  if item['root_instance_id'] == 'component-migration-root')
    nested['root_record']['aggregate_state']['runtimes'] = [
        runtime for runtime in nested['root_record']['aggregate_state']['runtimes']
        if runtime['relation']['kind'] != 'component']
    observation = {key: [] for key in ('active_scopes', 'authority_grants',
                                       'credentials', 'checkpoints', 'host_journals',
                                       'participant_storage', 'staged_archives')}
    response = {'result': owned['expected_result'], 'archive': None,
                'staged_archive': dropped, 'before': observation,
                'after': {**observation, 'staged_archives': [{
                    'staging_identity': owned['input_request']['staging_identity'],
                    'archive': dropped}]},
                'calls': {key: 0 for key in ('core_create', 'core_admit', 'core_step',
                    'core_migration', 'worker_claim', 'effect_dispatch', 'timer_poll',
                    'clock_read', 'authority_grant', 'credentials_create')}}
    class DroppedResult:
        returncode = 0
        stderr = b''
        stdout = json.dumps(response).encode()
    with patch('run_portable_archive_profile.subprocess.run', return_value=DroppedResult()):
        rejected('adapter dropped nested component',
                 lambda: run_case(['adapter'], 'stage', owned))
    raw_probes = (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                  b'{"x":"\\ud800"}', b'{"x":9223372036854775808}')
    for index, raw in enumerate(raw_probes):
        rejected(f'raw JSON {index}', lambda raw=raw: parse_json_bytes(raw, 'probe'))
    print(f'rejected {len(probes) + 4 + len(raw_probes)} archive and driver substitutions')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
