#!/usr/bin/env python3
"""Run §19 vectors through a production host adapter with withheld oracles."""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path

import rfc8785

from committed_native_effects_validator import CASE, exact, strict_json, validate_profile


def canonical(value):
    return rfc8785.dumps(value)


def check_observation(vector, observation, artifacts):
    if type(observation) is not dict or set(observation) != {
        'response_utf8', 'checkpoint_before_utf8', 'checkpoint_after_utf8',
        'journal_before_utf8', 'journal_after_utf8', 'provider_calls', 'core_calls',
        'new_claims', 'loaded_machine_sha256', 'loaded_handler_source',
    }:
        raise ValueError('adapter observation has missing or extra fields')
    request = vector['request']
    expected = vector['expected']
    for side in ('before', 'after'):
        for kind in ('checkpoint', 'journal'):
            key = f'{kind}_{side}_utf8'
            value = observation[key]
            if type(value) is not str:
                raise ValueError(f'{key} must be a UTF-8 JSON string')
            parsed = strict_json(value.encode('utf-8'))
            if value.encode('utf-8') != canonical(parsed):
                raise ValueError(f'{key} must contain canonical normalized bytes')
            fixture = artifacts[request[f'{kind}_before'] if side == 'before' else expected[f'{kind}_after']]
            if value.encode('utf-8') != canonical(fixture):
                raise ValueError(f'{key} differs from complete fixture')
        # Every rejected operation must preserve both artifacts byte for byte.
        if expected['checkpoint_after'] == request['checkpoint_before'] and \
                expected['journal_after'] == request['journal_before'] and \
                (observation['checkpoint_before_utf8'] != observation['checkpoint_after_utf8'] or
                 observation['journal_before_utf8'] != observation['journal_after_utf8']):
            raise ValueError('unchanged operation mutated checkpoint or journal bytes')
    response = observation['response_utf8']
    if type(response) is not str:
        raise ValueError('response_utf8 must be a UTF-8 JSON string')
    parsed_response = strict_json(response.encode('utf-8'))
    if response.encode('utf-8') != canonical(parsed_response):
        raise ValueError('response is not canonical normalized JSON')
    expected_response = expected['response']
    if expected_response is not None and response.encode('utf-8') != canonical(artifacts[expected_response]):
        raise ValueError('full public response differs from oracle')
    if type(observation['loaded_machine_sha256']) is not str or observation['loaded_machine_sha256'] != \
            'sha256:' + hashlib.sha256((CASE / 'machine.yaml').read_bytes()).hexdigest():
        raise ValueError('loaded machine source digest mismatch')
    loaded = observation['loaded_handler_source']
    handlers = {str(path.relative_to(CASE)): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted((CASE / 'handler').glob('test_handler.*'))}
    if type(loaded) is not dict or any(type(path) is not str or path not in handlers or
                                       type(value) is not str or value != handlers[path]
                                       for path, value in loaded.items()) or \
            (expected['counts']['provider_calls'] > 0 and len(loaded) != 1) or \
            (expected['counts']['provider_calls'] == 0 and loaded):
        raise ValueError('actual loaded handler source evidence differs from closure')
    for field in ('provider_calls', 'core_calls', 'new_claims'):
        calls = observation[field]
        if type(calls) is not list or len(calls) != expected['counts'][field]:
            raise ValueError(f'{field} count differs from oracle')
        if any(type(call) is not dict or not call for call in calls):
            raise ValueError(f'{field} needs concrete call evidence')
    if parsed_response.get('status') == 'rejected' and (observation['provider_calls'] or observation['core_calls']):
        raise ValueError('rejected request called provider or core')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--adapter', required=True, help='production host adapter command')
    args = parser.parse_args()
    count = validate_profile(args.spec_root)
    manifest = strict_json((CASE / 'data/vectors.json').read_bytes())
    artifacts = {path.name: strict_json(path.read_bytes()) for path in CASE.glob('*checkpoint.json')}
    artifacts.update({'data/' + path.name: strict_json(path.read_bytes())
                      for path in (CASE / 'data').glob('*.json') if path.name != 'vectors.json'})
    command = shlex.split(args.adapter)
    if not command:
        parser.error('empty adapter command')
    for vector in manifest['vectors']:
        request = vector['request']
        payload = {'operation': request['operation'],
                   'checkpoint_before': artifacts[request['checkpoint_before']],
                   'journal_before': artifacts[request['journal_before']],
                   'claim': None if request['claim'] is None else artifacts[request['claim']],
                   'auth_context': request['auth_context'],
                   'host_configuration': request['host_configuration'],
                   'arguments': request['arguments'], 'fault': request['fault'],
                   'machine_source_utf8': (CASE / 'machine.yaml').read_text(encoding='utf-8'),
                   'handler_source_files': {str(path.relative_to(CASE)): path.read_text(encoding='utf-8')
                                            for path in sorted((CASE / 'handler').glob('test_handler.*'))}}
        # A fresh process receives only inputs; vector name, coverage and expected IDs,
        # output checkpoint/journal, responses and example/oracle files stay hidden.
        completed = subprocess.run(command, input=canonical(payload), capture_output=True, check=False)
        if completed.returncode:
            raise SystemExit(f"{vector['name']}: adapter exited {completed.returncode}: "
                             f"{completed.stderr.decode('utf-8', errors='replace').strip()}")
        try:
            actual = strict_json(completed.stdout)
            check_observation(vector, actual, artifacts)
        except (ValueError, UnicodeDecodeError) as error:
            raise SystemExit(f"{vector['name']}: {error}") from error
    print(f'passed {count} committed native effect production adapter vectors')


if __name__ == '__main__':
    main()
