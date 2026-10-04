#!/usr/bin/env python3
"""Run §21 vectors through a production adapter command, withholding all oracles."""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'


def strict_document(source: bytes, label: str) -> dict:
    analysis = analyze_json_artifact_source(source)
    if analysis.error or not isinstance(analysis.document, dict):
        raise ValueError(f'{label}: invalid strict UTF-8 JSON: {analysis.error}')
    return analysis.document


def expanded(store: dict, checkpoints: dict[str, dict]) -> dict:
    return {**store, 'checkpoint': checkpoints[store['checkpoint']]}


def verify_configured_delivery_profile(command: list[str]) -> None:
    completed = subprocess.run(command, input=canonical_json_bytes({
        'kind': 'configured_delivery_profile'}), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise ValueError('configured delivery profile call failed')
    report = strict_document(completed.stdout, 'configured delivery profile')
    if report != {
            'format': 'determa.conformance.lossless_delivery.configured_profile',
            'schema_version': 1, 'source_ordering': 'unordered',
            'transport_claims': []}:
        raise ValueError('unproved public source_ordered or transport claim')


def run(command: list[str], case: Path = CASE) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    checkpoints = {path.name: strict_document(path.read_bytes(), path.name)
                   for path in case.glob('*-checkpoint-v1.json')}
    machines = {'ingress': (case / 'machine.yaml').read_text(encoding='utf-8'),
                'outbound': (case / 'outbox-machine.yaml').read_text(encoding='utf-8')}
    count = 0
    for vector in manifest['vectors'] + manifest['invalid_vectors']:
        if vector.get('premise_kind') == 'hypothetical_common_rule':
            continue
        negative = 'candidate' in vector
        request = {'operation': vector['operation'],
                   'input': vector['candidate'] if negative else vector['request'],
                   'before': expanded(vector['before'], checkpoints),
                   'fault_injection': None if negative else vector['fault_injection'],
                   'machine_source': machines}
        if 'authority_context' in vector:
            request['authority_context'] = vector['authority_context']
        if 'ordering_context' in vector:
            request['ordering_context'] = vector['ordering_context']
        completed = subprocess.run(command, input=canonical_json_bytes(request),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        expected_response = ({'kind': 'typed_failure',
                              'code': vector['expected_failure'],
                              'acknowledge_source': False}
                             if negative else vector['expected_response'])
        if expected_response == {'kind': 'no_response'}:
            if completed.stdout or completed.returncode == 0:
                raise AssertionError(f'{vector["name"]}: crash cut returned a response')
            count += 1
            continue
        if completed.returncode:
            raise AssertionError(f'{vector["name"]}: adapter exited {completed.returncode}')
        observed = strict_document(completed.stdout, vector['name'])
        if set(observed) != {'response', 'after'}:
            raise AssertionError(f'{vector["name"]}: adapter must return response and complete after store')
        expected = {'response': expected_response,
                    'after': expanded(vector['after'], checkpoints)}
        if canonical_json_bytes(observed) != canonical_json_bytes(expected):
            raise AssertionError(f'{vector["name"]}: response or complete store differs')
        count += 1
    return count


def run_integrations(command: list[str], case: Path = CASE) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    effects = ROOT / 'conformance/profiles/committed-native-effects/effect-01-result'
    machine = (effects / 'machine.yaml').read_text(encoding='utf-8')
    handlers = {str(path.relative_to(effects)): path.read_text(encoding='utf-8')
                for path in sorted((effects / 'handler').glob('test_handler.*'))}
    count = 0
    for vector in manifest['integration']['integration_vectors']:
        request = vector['request']
        payload = {
            'operation': request['operation'],
            'checkpoint_before': vector['checkpoint_before'],
            'journal_before': vector['journal_before'],
            'claim': None if request['claim'] is None else
                strict_document((effects / request['claim']).read_bytes(), request['claim']),
            'host_configuration': request['host_configuration'],
            'auth_context': request['auth_context'],
            'arguments': request['arguments'], 'fault': request['fault'],
            'machine_source_utf8': machine, 'handler_source_files': handlers,
            'delivery_observation_requested': True,
        }
        completed = subprocess.run(command, input=canonical_json_bytes(payload),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        if completed.returncode:
            raise AssertionError(f'{vector["name"]}: composed adapter failed')
        observed = strict_document(completed.stdout, vector['name'])
        if set(observed) != {'response_utf8', 'checkpoint_after_utf8',
                             'journal_after_utf8', 'source_acknowledgements',
                             'provider_calls', 'core_calls'}:
            raise AssertionError(f'{vector["name"]}: incomplete composed delivery observation')
        response_file = vector['expected']['response']
        response = (None if response_file is None else
                    canonical_json_bytes(strict_document((effects / response_file).read_bytes(),
                                                         response_file)).decode('utf-8'))
        if (observed['response_utf8'] != response or
            observed['checkpoint_after_utf8'] !=
                canonical_json_bytes(vector['checkpoint_after']).decode('utf-8') or
            observed['journal_after_utf8'] !=
                canonical_json_bytes(vector['journal_after']).decode('utf-8') or
            observed['source_acknowledgements'] != [] or
            type(observed['provider_calls']) is not list or
            type(observed['core_calls']) is not list or
            len(observed['provider_calls']) != vector['expected']['counts']['provider_calls'] or
            len(observed['core_calls']) != vector['expected']['counts']['core_calls']):
            raise AssertionError(f'{vector["name"]}: host-owned delivery evidence differs')
        if observed['core_calls']:
            receipt = vector['checkpoint_after']['operation_receipts'][-1]
            expected_core = {
                'event_id': receipt['event_id'],
                'operation_kind': 'admit' if receipt['operation_kind'] == 'acceptance' else 'step',
                'target': vector['checkpoint_after']['root_record']['aggregate_state']['runtimes'][0]['target_identity'],
            }
            if observed['core_calls'] != [expected_core]:
                raise AssertionError(f'{vector["name"]}: core call bypassed pinned result envelope')
        count += 1
    return count


def run_core_observability(command: list[str], case: Path = CASE) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    count = 0
    for vector in manifest['core_observability_vectors']:
        payload = {
            'operation': vector['operation'], 'request': vector['request'],
            'machine_source': vector['machine_source'],
            'before_state': vector['before_state'],
            'descriptor': vector['descriptor'],
            'target_machine_source': vector['target_machine_source'],
            'delivery_observation_requested': True,
        }
        completed = subprocess.run(command, input=canonical_json_bytes(payload),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        if completed.returncode:
            raise AssertionError(f'{vector["name"]}: core adapter failed')
        observed = strict_document(completed.stdout, vector['name'])
        expected = {'result': vector['expected_result'], 'source_acknowledgements': []}
        if canonical_json_bytes(observed) != canonical_json_bytes(expected):
            raise AssertionError(f'{vector["name"]}: core result lost a disposition or emission')
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--adapter', required=True,
                        help='command that reads one strict JSON request on stdin')
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--authority-adapter',
                        help='same configured host authority installation used by the effect adapter')
    parser.add_argument('--base-only', action='store_true',
                        help='run the weaker delivery-only claim without §18/§19 native proof')
    args = parser.parse_args()
    command = shlex.split(args.adapter)
    if not command:
        parser.error('empty adapter command')
    verify_configured_delivery_profile(command)
    if args.base_only and args.authority_adapter:
        parser.error('--base-only cannot claim an authority adapter')
    if not args.base_only:
        if not args.authority_adapter:
            parser.error('full lossless delivery claim requires --authority-adapter')
        # The effect runner checks the installed handler/destination closure,
        # complete §19 operations, and the §18 native worker scenario against
        # this exact same production adapter command. A profile report alone
        # does not certify a broker or a durable destination.
        completed = subprocess.run([
            sys.executable, str(ROOT / 'scripts/run_committed_native_effects_profile.py'),
            '--spec-root', str(args.spec_root), '--adapter', args.adapter,
            '--authority-adapter', args.authority_adapter],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            raise SystemExit('§18/§19 configured native proof failed: ' +
                             completed.stderr.decode('utf-8', errors='replace').strip())
    count = run(command)
    core = run_core_observability(command)
    if args.base_only:
        print(f'passed {count + core} base lossless delivery vectors; no §18/§19 claim')
    else:
        integrations = run_integrations(command)
        print(f'passed {count + core + integrations} production lossless delivery vectors under one configured host')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
