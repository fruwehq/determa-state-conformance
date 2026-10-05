#!/usr/bin/env python3
"""Exercise §25 vectors through an actual public client/reference-host adapter.

The adapter must invoke the production public client/host. It receives no case name,
expected response, or expected error. The surrounding test deployment supplies the
fixture's scopes, endpoints, rights, roots, journals and participants. Its independent
observer reports before/after host state and actual call counts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import uuid
import subprocess
import sys
from pathlib import Path

from validate_portable_archive import canonical, parse_json_bytes
from validate_public_host import CASE, load, validate_profile

FINGERPRINT = re.compile(r'^sha256:[0-9a-f]{64}$')
PROOF_KEYS = {'run_id', 'scope_binding_identity', 'source_digest', 'provider_digest',
              'configuration_digest', 'instance_identity', 'store_digest',
              'authority_digest', 'topology_digest', 'claim_proofs'}
CLAIM_KEYS = {'run_id', 'proof_id', 'source_digest', 'provider_digest',
              'configuration_digest', 'scope_binding_identity', 'instance_identity',
              'store_digest', 'authority_digest', 'topology_digest'}

STATE_LISTS = ('active_scopes', 'authority_grants', 'credentials', 'checkpoints',
               'host_journals', 'participant_storage', 'staged_archives',
               'public_operation_receipts', 'scope_aliases', 'endpoint_authorities',
               'timer_records')

CALLS = ('core_create', 'core_admit', 'core_step', 'effect_dispatch', 'timer_poll',
         'authority_mutation', 'archive_stage', 'recovery_mutation')


def verify_proof(proof: dict, request: dict, response: dict | None, run_id: str) -> None:
    if type(proof) is not dict or set(proof) != PROOF_KEYS or proof['run_id'] != run_id:
        raise ValueError('missing or stale same-run native composition proof')
    binding = request['scope_binding_identity']
    if binding is None and response is not None and response['status'] == 'committed':
        binding = response['value']['result']['scope_binding_identity']
    if proof['scope_binding_identity'] != binding:
        raise ValueError('proof belongs to foreign scope binding')
    for key in ('source_digest', 'provider_digest', 'configuration_digest',
                'store_digest', 'authority_digest', 'topology_digest'):
        if type(proof[key]) is not str or not FINGERPRINT.fullmatch(proof[key]):
            raise ValueError(f'proof lacks exact {key}')
    if type(proof['instance_identity']) is not str or not proof['instance_identity']:
        raise ValueError('proof lacks host instance identity')
    claims = proof['claim_proofs']
    if type(claims) is not dict or not claims:
        raise ValueError('native claim proof set absent')
    required = {request['operation']}
    if request['operation'] == 'scope_operation':
        required.add(request['arguments']['action'])
    if request['operation'] == 'timer_command':
        required.add(request['arguments']['timer_request']['operation'])
    if response is not None and response['status'] == 'committed' and request['operation'] == 'capabilities':
        report = response['value']['result']
        required.update(report['supported_operations'])
        required.update(report['supported_scope_actions'])
        required.update(report['supported_timer_commands'])
        required.update(report['supported_determa_capabilities'])
        required.update(k for k, v in report['guarantees'].items() if v is True)
        for extension in report['extension_reports']:
            required.update(extension['claims'])
    if not required <= set(claims):
        raise ValueError(f'native proof omits advertised claims: {required - set(claims)}')
    for claim, evidence in claims.items():
        if type(claim) is not str or type(evidence) is not dict or set(evidence) != CLAIM_KEYS:
            raise ValueError('incomplete native claim evidence')
        if type(evidence['proof_id']) is not str or not evidence['proof_id']:
            raise ValueError('native proof ID absent')
        for key in PROOF_KEYS - {'claim_proofs'}:
            if evidence[key] != proof[key]:
                raise ValueError(f'{claim}: foreign native proof {key}')


def read_only(request: dict) -> bool:
    operation, arguments = request['operation'], request['arguments']
    return (operation in ('read', 'inspect', 'capabilities', 'receipt')
            or (operation == 'timer_command'
                and arguments['timer_request']['operation'] == 'read_timer')
            or (operation == 'scope_operation' and arguments['action'] == 'authority'
                and arguments['authority_request']['operation'] == 'read_authority'))


def run_case(command: list[str], case: dict, negative: bool, run_id: str, *,
             replay: bool = False, previous_after: dict | None = None) -> tuple[bytes | None, dict]:
    name = case['name']
    invocation = {'run_id': run_id, 'request': case['request'],
                  'transport_context': case.get('transport_context'),
                  'client_context': case.get('client_context')}
    completed = subprocess.run(command, input=canonical(invocation), capture_output=True,
                               check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{name}: adapter exited {completed.returncode}: '
                         f'{completed.stderr.decode("utf-8", "replace")[:500]}')
    observed = parse_json_bytes(completed.stdout, name + ' adapter output')
    if type(observed) is not dict or set(observed) != {'response', 'response_bytes_base64', 'transport_error', 'before', 'after', 'calls', 'native_proof', 'transport_attempts'}:
        raise ValueError(f'{name}: incomplete adapter observation')
    encoded = observed['response_bytes_base64']
    if observed['response'] is None:
        if encoded is not None:
            raise ValueError(f'{name}: bytes supplied without protocol response')
        response_bytes = None
    else:
        if type(encoded) is not str:
            raise ValueError(f'{name}: raw production response bytes absent')
        try:
            response_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError(f'{name}: invalid response bytes encoding') from error
        if canonical(parse_json_bytes(response_bytes, name + ' raw production response')) != canonical(observed['response']):
            raise ValueError(f'{name}: raw response differs from parsed response')
    attempts = observed['transport_attempts']
    if type(attempts) is not list:
        raise ValueError(f'{name}: transport attempt trace absent')
    for attempt in attempts:
        if type(attempt) is not dict or set(attempt) != {'endpoint_authority',
                'scope_binding_identity', 'operation_id', 'request_digest'}:
            raise ValueError(f'{name}: incomplete transport attempt')
        if attempt['operation_id'] != case['request']['operation_id'] or \
                attempt['request_digest'] != case['request_digest']:
            raise ValueError(f'{name}: transport changed saved operation identity')
        if case['request']['scope_binding_identity'] is not None and \
                attempt['scope_binding_identity'] != case['request']['scope_binding_identity']:
            raise ValueError(f'{name}: transport retargeted scope binding')
    if not negative or case.get('expected_response') is not None or case.get('expected_error') in (
            'transport_access_denied', 'transport_outcome_unknown'):
        if not attempts:
            raise ValueError(f'{name}: expected public endpoint was not invoked')
    client = case.get('client_context')
    if client is not None:
        if client['decision'] == 'refuse_retarget_before_transport' and attempts:
            raise ValueError(f'{name}: alias change caused transport')
        if client['decision'] == 'query_saved_endpoint_only_and_report_unknown_fate' and (
                not attempts or any(attempt['endpoint_authority'] != client['saved_endpoint_authority']
                                    or attempt['scope_binding_identity'] != client['saved_scope_binding_identity']
                                    for attempt in attempts)):
            raise ValueError(f'{name}: lost response retargeted endpoint')
    verify_proof(observed['native_proof'], case['request'], observed['response'], run_id)
    calls = observed['calls']
    if type(calls) is not dict or set(calls) != set(CALLS) or any(
            type(calls[key]) is not int or calls[key] < 0 for key in CALLS):
        raise ValueError(f'{name}: incomplete actual call counts')
    for phase in ('before', 'after'):
        state = observed[phase]
        if type(state) is not dict or set(state) != {*STATE_LISTS, 'composition'} or any(
                type(state[key]) is not list for key in STATE_LISTS):
            raise ValueError(f'{name}: complete independent {phase} observation required')
        composition = state['composition']
        proof = observed['native_proof']
        if type(composition) is not dict or set(composition) != PROOF_KEYS - {'run_id', 'claim_proofs'} or any(
                composition[key] != proof[key] for key in composition):
            raise ValueError(f'{name}: observed composition differs from native proof')
    request = case['request']
    if replay and (previous_after is None or
                   canonical(previous_after) != canonical(observed['before'])):
        raise ValueError(f'{name}: replay is not continuous with the committed host state')
    if any(type(item) is not dict for item in observed['before']['checkpoints']):
        raise ValueError(f'{name}: malformed independent checkpoint observation')
    if name == 'unauthorized_scope_precedes_existence':
        if not any(item.get('root_instance_id') == request['target']['root_instance_id']
                   for item in observed['before']['checkpoints']):
            raise ValueError('unauthorized existing-root premise absent')
    if name == 'unauthorized_absent_root_indistinguishable':
        if any(item.get('root_instance_id') == request['target']['root_instance_id']
               for item in observed['before']['checkpoints']):
            raise ValueError('unauthorized absent-root premise false')
    expected = case['expected_response'] if negative else case['response']
    if canonical(observed['response']) != canonical(expected):
        raise ValueError(f'{name}: complete production response differs')
    expected_transport = case['expected_error'] if negative and expected is None else None
    if observed['transport_error'] != expected_transport:
        raise ValueError(f'{name}: transport/client outcome differs')
    request = case['request']
    if read_only(request) or negative or replay:
        if canonical(observed['before']) != canonical(observed['after']):
            raise ValueError(f'{name}: observational/refused operation changed host state')
    if (negative or read_only(request) or replay) and any(calls.values()):
        raise ValueError(f'{name}: refused/read/replay operation invoked active work')
    if expected is not None and expected['status'] == 'committed' and expected['receipt'] is not None:
        retained = {
            'scope_binding_identity': expected['receipt']['scope_binding_identity'],
            'operation_id': request['operation_id'],
            'request_digest': case['request_digest'],
            'response_bytes_base64': encoded,
        }
        matches = [item for item in observed['after']['public_operation_receipts']
                   if isinstance(item, dict) and item.get('operation_id') == request['operation_id']
                   and item.get('scope_binding_identity') == retained['scope_binding_identity']]
        if len(matches) != 1 or canonical(matches[0]) != canonical(retained):
            raise ValueError(f'{name}: committed response lacks exact retained native receipt')
        checkpoint = expected['value']['result'].get('checkpoint')
        if checkpoint is not None:
            matches = [item for item in observed['after']['checkpoints']
                       if isinstance(item, dict) and item.get('root_instance_id') == checkpoint['root_instance_id']]
            if len(matches) != 1 or canonical(matches[0]) != canonical(checkpoint):
                raise ValueError(f'{name}: committed checkpoint differs from observed native checkpoint')
        core_call = {'create': 'core_create', 'admit': 'core_admit', 'process': 'core_step'}.get(request['operation'])
        if not replay and core_call is not None and calls[core_call] != 1:
            raise ValueError(f'{name}: committed operation lacks its actual core call')
    if not replay and expected is not None and expected['status'] == 'committed' and expected['receipt'] is not None:
        if canonical(observed['before']) == canonical(observed['after']):
            raise ValueError(f'{name}: committed receipt lacks observed host change')
    return response_bytes, observed['after']


def run_invalid_response(command: list[str], case: dict, run_id: str) -> None:
    # This separate adapter mode must call the production client response decoder.
    invocation = {'run_id': run_id, 'candidate_response': case['response']}
    completed = subprocess.run(command, input=canonical(invocation), capture_output=True,
                               check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{case["name"]}: client decoder adapter exited {completed.returncode}')
    result = parse_json_bytes(completed.stdout, case['name'] + ' client decoder output')
    if result != {'accepted': False, 'error_code': case['expected_error']}:
        raise ValueError(f'{case["name"]}: production client accepted malformed response')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('production adapter command required after --')
    validate_profile(args.spec_root)
    positive = load(CASE / 'positive-v1.json')['cases']
    negative_fixture = load(CASE / 'negative-v1.json')
    negative = negative_fixture['cases']
    run_id = str(uuid.uuid4())
    replay_count = 0
    for case in positive:
        first_bytes, first_after = run_case(command, case, False, run_id)
        response = case['response']
        if response['status'] == 'committed' and response['receipt'] is not None:
            replay_bytes, _ = run_case(command, case, False, run_id, replay=True,
                                       previous_after=first_after)
            if first_bytes != replay_bytes:
                raise ValueError(f'{case["name"]}: replay changed saved first response bytes')
            replay_count += 1
    for case in negative:
        run_case(command, case, True, run_id)
    for case in negative_fixture['invalid_responses']:
        run_invalid_response(command, case, run_id)
    print(f'{len(positive)} positive, {len(negative)} negative and {replay_count} replay protocol observations; {len(negative_fixture["invalid_responses"])} client response refusals passed')
    print('Configured native capability certification remains unmet until separate reviewed operational gates pass.')
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'public host profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
