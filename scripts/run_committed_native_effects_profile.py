#!/usr/bin/env python3
"""Run §19 vectors through a production host adapter with withheld oracles."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import tempfile
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

import rfc8785

from committed_native_effects_validator import CASE, exact, strict_json, validate_profile, schema_registry, validate_schema
from run_host_authority_profile import verify_configured_profile as verify_authority_profile, select_production_scenario
from validate_host_authority import PROFILE as AUTHORITY_PROFILE, load as load_authority_profile


def canonical(value):
    return rfc8785.dumps(value)


def sha256_bytes(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def closure_bytes():
    preimage = bytearray(b'determa-effect-handler-closure-1\0')
    for path in sorted((CASE / 'handler').glob('test_handler.*')):
        name = str(path.relative_to(CASE)).encode('utf-8')
        source = path.read_bytes()
        preimage += len(name).to_bytes(8, 'big') + name
        preimage += len(source).to_bytes(8, 'big') + source
    return bytes(preimage)


def verified_profile(observed, artifacts, spec_root, *, expected_run_id, expected_proofs):
    if type(observed) is not dict or set(observed) != {'report_bytes', 'installation_evidence'} or \
            type(observed['report_bytes']) is not str:
        raise ValueError('configured profile must have complete report and installation evidence')
    report_bytes = observed['report_bytes'].encode('utf-8')
    report = strict_json(report_bytes)
    if report_bytes != canonical(report) or type(report) is not dict or set(report) != {
            'format', 'schema_version', 'scope_identity', 'handler_reference',
            'destination_binding_digest', 'idempotency_policy', 'authority_report_bytes'}:
        raise ValueError('configured effect report is not closed canonical JSON')
    pinned = artifacts['data/unclaimed-journal.json']['effect_records'][0]
    if report['format'] != 'determa.committed_native_effects.configured_profile' or \
            type(report['schema_version']) is not int or report['schema_version'] != 1 or \
            report['scope_identity'] != artifacts['data/unclaimed-journal.json']['scope_identity'] or \
            report['handler_reference'] != pinned['handler_reference'] or \
            report['destination_binding_digest'] != pinned['destination_binding_digest'] or \
            report['idempotency_policy'] != 'destination_deduplicates':
        raise ValueError('configured effect report differs from actual pinned route')
    authority_bytes = report['authority_report_bytes']
    if type(authority_bytes) is not str:
        raise ValueError('authority report bytes absent')
    authority = strict_json(authority_bytes.encode('utf-8'))
    if authority_bytes.encode('utf-8') != canonical(authority):
        raise ValueError('authority report is not canonical')
    validate_schema(authority, spec_root, 'host-authority-profile-report-v1.schema.json',
                    schema_registry(spec_root))
    guarantees = authority['guarantees']
    if authority['scope_identity'] != report['scope_identity'] or \
            authority['authority_epoch'] != '3' or \
            authority['topology']['identifier'] != 'single-sqlite-database' or \
            not guarantees['guarded_local_writes'] or not guarantees['worker_fencing'] or \
            guarantees['safe_relocation'] or \
            {item['role'] for item in authority['required_participants']} != {'journal', 'worker'}:
        raise ValueError('actual authority report lacks required guarded worker topology')
    installation = observed['installation_evidence']
    if type(installation) is not dict or set(installation) != {
            'run_id', 'handler_closure_bytes_base64', 'destination_configuration_bytes_base64',
            'executing_source_path', 'loaded_source_sha256', 'observed_health',
            'authority_closure_bytes_base64', 'authority_configuration_bytes_base64',
            'participant_installations', 'native_proof_ids', 'destination_deduplication_proof'}:
        raise ValueError('configured installation evidence is incomplete')
    def decoded(name):
        value = installation[name]
        if type(value) is not str:
            raise ValueError(f'{name} must be base64 text')
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f'{name} is invalid base64') from None
    closure = decoded('handler_closure_bytes_base64')
    destination = decoded('destination_configuration_bytes_base64')
    authority_closure = decoded('authority_closure_bytes_base64')
    authority_configuration = decoded('authority_configuration_bytes_base64')
    source = installation['executing_source_path']
    sources = artifacts['data/handler-closure.json']['files']
    source_hashes = {item['path']: item['sha256'] for item in sources}
    if installation['run_id'] != expected_run_id or closure != closure_bytes() or \
            sha256_bytes(closure) != report['handler_reference']['content_digest'] or \
            destination != canonical(artifacts['data/destination-configuration.json']) or \
            sha256_bytes(destination) != report['destination_binding_digest'] or \
            source not in source_hashes or installation['loaded_source_sha256'] != source_hashes[source] or \
            installation['observed_health'] != 'healthy' or \
            not authority_closure or not authority_configuration or \
            sha256_bytes(authority_closure) != authority['extension_report']['provider_reference']['content_digest'] or \
            sha256_bytes(authority_configuration) != authority['topology']['configuration_digest']:
        raise ValueError('actual loaded handler, destination or authority installation differs')
    participants = installation['participant_installations']
    required = authority['required_participants']
    if type(participants) is not list or len(participants) != len(required):
        raise ValueError('authority participant installations incomplete')
    for item, reference in zip(participants, required):
        if type(item) is not dict or set(item) != {'participant', 'closure_bytes_base64', 'observed_health'} or \
                item['participant'] != reference or item['observed_health'] != 'healthy':
            raise ValueError('authority participant installation differs')
        try:
            participant_bytes = base64.b64decode(item['closure_bytes_base64'], validate=True)
        except (TypeError, binascii.Error, ValueError):
            raise ValueError('invalid participant closure bytes') from None
        if not participant_bytes or sha256_bytes(participant_bytes) != reference['provider_reference']['content_digest']:
            raise ValueError('authority participant closure digest differs')
    dedupe = installation['destination_deduplication_proof']
    if expected_proofs:
        pinned_effect = artifacts['data/unclaimed-journal.json']['effect_records'][0]['effect_id']
        if type(dedupe) is not dict or set(dedupe) != {
                'scope_identity', 'effect_id', 'destination_binding_digest',
                'first_attempt_receipt_bytes_base64', 'repeat_attempt_receipt_bytes_base64'} or \
                dedupe['scope_identity'] != report['scope_identity'] or \
                dedupe['effect_id'] != pinned_effect or \
                dedupe['destination_binding_digest'] != report['destination_binding_digest']:
            raise ValueError('destination deduplication lacks scoped actual receipt evidence')
        try:
            first = base64.b64decode(dedupe['first_attempt_receipt_bytes_base64'], validate=True)
            repeat = base64.b64decode(dedupe['repeat_attempt_receipt_bytes_base64'], validate=True)
        except (TypeError, binascii.Error, ValueError):
            raise ValueError('invalid destination receipt bytes') from None
        if not first or first != repeat:
            raise ValueError('destination did not return one retained receipt for scoped retry')
    elif dedupe is not None:
        raise ValueError('pre-run destination proof cannot be credited')
    proofs = installation['native_proof_ids']
    if type(proofs) is not list or any(type(item) is not str for item in proofs) or \
            len(proofs) != len(set(proofs)) or set(proofs) != expected_proofs:
        raise ValueError('configured native proof IDs are absent, stale, or unobserved')
    return {'report_digest': sha256_bytes(report_bytes),
            'authority_report_digest': sha256_bytes(authority_bytes.encode('utf-8')),
            'topology_identifier': authority['topology']['identifier'],
            'scope_identity': report['scope_identity'], 'authority_epoch': authority['authority_epoch'],
            'handler_reference': report['handler_reference'],
            'destination_binding_digest': report['destination_binding_digest'],
            'executing_source_path': source, 'loaded_source_sha256': source_hashes[source],
            'run_id': expected_run_id, 'authority_report': authority}


def bind_to_proved_authority(configured, authority):
    observed = configured['authority_report']
    if observed['topology'] != authority['topology'] or \
            observed['authority_storage_boundary'] != authority['authority_storage_boundary'] or \
            observed['extension_report'] != authority['extension_report'] or \
            observed['required_participants'] != authority['required_participants'] or \
            observed['guarantees'] != authority['guarantees']:
        raise ValueError('effect host authority installation differs from proved §18 topology')


def native_proof_id(payload, run_id):
    return sha256_bytes(canonical(['determa-effect-native-proof-1', run_id,
                                   {key: payload[key] for key in (
                                       'operation', 'checkpoint_before', 'journal_before',
                                       'claim', 'auth_context', 'host_configuration',
                                       'arguments', 'fault')}]))


def verify_retry_safety_evidence(vector, evidence, artifacts, configured):
    """Require retained native receipt evidence, never a worker/configuration assertion."""
    request, expected = vector['request'], vector['expected']
    response = artifacts[expected['response']] if expected['response'] is not None else None
    before = artifacts[request['journal_before']]['effect_records']
    required = bool(response and response.get('status') == 'report_recorded'
                    and response.get('attempt_report', {}).get('report_kind') == 'retryable_failure')
    required = required or bool(request['operation'] == 'claim' and expected['counts']['new_claims']
                               and before
                               and before[0]['attempt_fence'] != '0')
    if not required:
        if evidence is not None:
            raise ValueError('retry safety evidence credited without a safe retry decision')
        return
    fields = {'kind', 'scope_identity', 'root_instance_id', 'effect_id', 'operation_token',
              'attempt_fence', 'handler_reference', 'destination_binding_digest',
              'first_attempt_receipt_bytes_base64', 'repeat_attempt_receipt_bytes_base64'}
    if type(evidence) is not dict or set(evidence) != fields:
        raise ValueError('safe retry lacks independently verified native receipt evidence')
    record = before[0]
    pins = {key: record[key] for key in ('effect_id', 'operation_token', 'attempt_fence',
                                      'handler_reference', 'destination_binding_digest')}
    pins.update(kind='destination_deduplication', scope_identity=configured['scope_identity'],
                root_instance_id=artifacts[request['checkpoint_before']]['root_instance_id'])
    if any(not exact(evidence[key], value) for key, value in pins.items()):
        raise ValueError('safe retry evidence differs from original scoped invocation')
    try:
        first = base64.b64decode(evidence['first_attempt_receipt_bytes_base64'], validate=True)
        repeat = base64.b64decode(evidence['repeat_attempt_receipt_bytes_base64'], validate=True)
    except (TypeError, binascii.Error, ValueError):
        raise ValueError('safe retry native receipts are invalid') from None
    if not first or first != repeat:
        raise ValueError('safe retry destination receipts differ or are empty')


def verify_native_evidence(vector, observation, artifacts, configured, payload):
    evidence = observation['native_evidence']
    if type(evidence) is not dict or set(evidence) != {
            'proof_id', 'run_id', 'report_digest', 'authority_report_digest',
            'topology_identifier', 'scope_identity', 'authority_epoch',
            'handler_reference', 'destination_binding_digest', 'guard_fate',
            'claim_guard_observed', 'native_transaction_id', 'destination_call_evidence',
            'retry_safety_evidence'}:
        raise ValueError('native evidence missing guard, topology, handler, or destination fields')
    expected = vector['expected']
    request = vector['request']
    changed = request['checkpoint_before'] != expected['checkpoint_after'] or \
              request['journal_before'] != expected['journal_after']
    fate = 'rolled_back' if vector['name'] == 'route_generation_changed' else \
           'committed' if changed else 'no_mutation'
    required = {'proof_id': native_proof_id(payload, configured['run_id']),
                'run_id': configured['run_id'],
                'report_digest': configured['report_digest'],
                'authority_report_digest': configured['authority_report_digest'],
                'topology_identifier': configured['topology_identifier'],
                'scope_identity': configured['scope_identity'],
                'authority_epoch': configured['authority_epoch'],
                'handler_reference': configured['handler_reference'],
                'destination_binding_digest': configured['destination_binding_digest'],
                'guard_fate': fate,
                'claim_guard_observed': request['operation'] in ('claim', 'dispatch', 'submit_result')}
    if any(not exact(evidence[key], value) for key, value in required.items()):
        raise ValueError('native operation proof differs from configured host or observed fate')
    transaction = evidence['native_transaction_id']
    if type(transaction) is not str or not transaction:
        raise ValueError('native transaction identity missing')
    provider_calls = observation['provider_calls']
    if provider_calls and observation['loaded_handler_source'] != {
            configured['executing_source_path']: configured['loaded_source_sha256']}:
        raise ValueError('provider call did not execute the configured installed handler variant')
    call = evidence['destination_call_evidence']
    if provider_calls:
        before = artifacts[request['journal_before']]['effect_records'][0]
        expected_call = {'idempotency_key': [configured['scope_identity'], before['effect_id']],
                         'destination_binding_digest': before['destination_binding_digest'],
                         'attempt_fence': before['attempt_fence']}
        if not exact(call, expected_call):
            raise ValueError('native destination call lacks scoped idempotency proof')
    elif call is not None:
        raise ValueError('destination call evidence without a provider call')
    verify_retry_safety_evidence(vector, evidence['retry_safety_evidence'], artifacts, configured)
    return evidence['proof_id']


def check_observation(vector, observation, artifacts):
    if type(observation) is not dict or set(observation) != {
        'response_utf8', 'checkpoint_before_utf8', 'checkpoint_after_utf8',
        'journal_before_utf8', 'journal_after_utf8', 'provider_calls', 'core_calls',
        'new_claims', 'loaded_machine_sha256', 'loaded_handler_source', 'caller_result', 'native_evidence',
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
    expected_response = expected['response']
    if expected_response is None:
        if response is not None:
            raise ValueError('operation without a public response returned caller bytes')
    else:
        if type(response) is not str:
            raise ValueError('response_utf8 must contain complete UTF-8 JSON bytes')
        parsed_response = strict_json(response.encode('utf-8'))
        if response.encode('utf-8') != canonical(parsed_response):
            raise ValueError('response is not canonical normalized JSON')
        if response.encode('utf-8') != canonical(artifacts[expected_response]):
            raise ValueError('full public response differs from oracle')
    kind = expected['caller_kind']
    after_checkpoint = artifacts[expected['checkpoint_after']]
    after_journal = artifacts[expected['journal_after']]
    caller_result = {'kind': kind, 'operation': request['operation'],
                     'checkpoint_digest': None if kind == 'no_response' else after_checkpoint['execution_checkpoint_digest'],
                     'journal_digest': None if kind == 'no_response' else after_journal['host_effect_journal_digest']}
    if not exact(observation['caller_result'], caller_result):
        raise ValueError('caller completion, abort, or no-response evidence differs')
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
    before_record = artifacts[request['journal_before']]['effect_records']
    before_record = before_record[0] if before_record else None
    if observation['provider_calls']:
        if before_record is None:
            raise ValueError('provider ran without committed effect record')
        expected_call = {key: before_record[key] for key in
                         ('effect_id', 'handler_reference', 'destination_binding_digest',
                          'route_configuration_generation', 'attempt_fence')}
        expected_call['scope_identity'] = artifacts[request['journal_before']]['scope_identity']
        expected_call['credential_generation'] = request['host_configuration']['credential_generation']
        if any(not exact(call, expected_call) for call in observation['provider_calls']):
            raise ValueError('provider call bypassed pinned route, scope, fence, or current credential')
    if observation['core_calls']:
        after = artifacts['pending-checkpoint.json'] if vector['name'] == 'route_generation_changed' else artifacts[expected['checkpoint_after']]
        receipt = after['operation_receipts'][-1]
        expected_core_call = {'event_id': receipt['event_id'],
                              'operation_kind': 'step' if receipt['operation_kind'] == 'event_terminal' else 'admit',
                              'target': after['root_record']['aggregate_state']['runtimes'][0]['target_identity']}
        if any(not exact(call, expected_core_call) for call in observation['core_calls']):
            raise ValueError('core call did not use pinned event and target')
    if observation['new_claims']:
        after_record = artifacts[expected['journal_after']]['effect_records'][0]
        expected_claim = {'effect_id': after_record['effect_id'],
                          'attempt_fence': after_record['attempt_fence'],
                          'worker_principal': request['auth_context']['principal']}
        if any(not exact(claim, expected_claim) for claim in observation['new_claims']):
            raise ValueError('claim evidence differs from committed fence')
    if expected_response is not None and parsed_response.get('status') == 'rejected' and \
            (observation['provider_calls'] or observation['core_calls']):
        raise ValueError('rejected request called provider or core')


def adapter_run(command, payload, location):
    completed = subprocess.run(command, input=canonical(payload), capture_output=True, check=False)
    if completed.returncode:
        raise ValueError(f"{location}: adapter exited {completed.returncode}: "
                         f"{completed.stderr.decode('utf-8', errors='replace').strip()}")
    return strict_json(completed.stdout)


def verify_retained_retry_evidence(proofs, destination):
    """Bind every credited decision to the independently observed destination receipts."""
    fields = ('scope_identity', 'effect_id', 'destination_binding_digest',
              'first_attempt_receipt_bytes_base64', 'repeat_attempt_receipt_bytes_base64')
    for proof in proofs:
        if type(destination) is not dict or any(not exact(proof[key], destination.get(key))
                                               for key in fields):
            raise ValueError('credited retry proof differs from observed native destination receipts')


def execute_vector(command, vector, artifacts, configured, retry_proofs=None):
    request = vector['request']
    payload = {'operation': request['operation'],
               'checkpoint_before': artifacts[request['checkpoint_before']],
               'journal_before': artifacts[request['journal_before']],
               'claim': None if request['claim'] is None else artifacts[request['claim']],
               'auth_context': request['auth_context'],
               'host_configuration': request['host_configuration'],
               'arguments': request['arguments'], 'fault': request['fault'],
               'run_id': configured['run_id'],
               'machine_source_utf8': (CASE / 'machine.yaml').read_text(encoding='utf-8'),
               'handler_source_files': {str(path.relative_to(CASE)): path.read_text(encoding='utf-8')
                                        for path in sorted((CASE / 'handler').glob('test_handler.*'))}}
    try:
        plan = request['control_plan']
        if not plan:
            observation = adapter_run(command, payload, vector['name'])
        else:
            session = str(uuid.uuid4())
            observation = None
            for index, (step, expected_event) in enumerate(zip(plan, vector['expected']['control_events'])):
                control_input = {'kind': 'control', 'session': session, 'control': step,
                                 'operation_input': payload if index == 0 else None}
                actual = adapter_run(command, control_input, f"{vector['name']} control {index}")
                if type(actual) is not dict:
                    raise ValueError('control event must be an object')
                if actual.get('session') != session:
                    raise ValueError('control event is not from the live native session')
                actual = {key: value for key, value in actual.items() if key != 'session'}
                if index == len(plan) - 1:
                    if set(actual) != set(expected_event) | {'observation', 'native_transaction_id'}:
                        raise ValueError('final native fate event lacks complete observation')
                    observation = actual['observation']
                    if type(observation) is not dict or actual['native_transaction_id'] != \
                            observation.get('native_evidence', {}).get('native_transaction_id'):
                        raise ValueError('native rollback fate is not bound to the guarded transaction')
                    actual = {key: value for key, value in actual.items()
                              if key not in ('observation', 'native_transaction_id')}
                if not exact(actual, expected_event):
                    raise ValueError(f'live control event {index} differs from barrier oracle')
            if observation is None:
                raise ValueError('route control did not produce final observation')
        check_observation(vector, observation, artifacts)
        proof_id = verify_native_evidence(vector, observation, artifacts, configured, payload)
        if retry_proofs is not None and observation['native_evidence']['retry_safety_evidence'] is not None:
            retry_proofs.append(observation['native_evidence']['retry_safety_evidence'])
        return proof_id
    except (ValueError, UnicodeDecodeError) as error:
        raise SystemExit(f"{vector['name']}: {error}") from error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--adapter', required=True, help='production effect host adapter command')
    parser.add_argument('--authority-adapter', required=True,
                        help='same configured authority installation adapter for mandatory §18 native runner')
    parser.add_argument('--parent-run-id',
                        help='bind this verified effect run to a composed parent profile run')
    parser.add_argument('--proof-summary-output', type=Path,
                        help='write the verified same-run effect and authority proof receipt')
    args = parser.parse_args()
    count = validate_profile(args.spec_root)
    manifest = strict_json((CASE / 'data/vectors.json').read_bytes())
    artifacts = {path.name: strict_json(path.read_bytes()) for path in CASE.glob('*checkpoint.json')}
    artifacts.update({'data/' + path.name: strict_json(path.read_bytes())
                      for path in (CASE / 'data').glob('*.json') if path.name != 'vectors.json'})
    command = shlex.split(args.adapter)
    if not command:
        parser.error('empty adapter command')
    authority_command = shlex.split(args.authority_adapter)
    if not authority_command:
        parser.error('empty authority adapter command')
    authority_initial = adapter_run(authority_command, {'kind': 'configured_profile'},
                                    '§18 configured authority before native probes')
    c_report = verify_authority_profile(authority_initial, args.spec_root, set(),
                                        require_native_proof=False)
    c_scenario = select_production_scenario(load_authority_profile(
        AUTHORITY_PROFILE / 'vectors.generated.json'), c_report)
    if not c_report['guarantees']['worker_fencing'] or c_scenario is None or \
            c_scenario['id'] != 'worker_sqlite':
        raise SystemExit('§19 requires the proved §18 worker SQLite authority topology')
    c_runner = Path(__file__).with_name('run_host_authority_profile.py')
    with tempfile.TemporaryDirectory(prefix='determa-effect-authority-') as temporary:
        c_summary_path = Path(temporary) / 'authority-proof.json'
        completed = subprocess.run([sys.executable, str(c_runner), '--spec-root', str(args.spec_root),
                                    '--proof-summary-output', str(c_summary_path),
                                    '--adapter', *authority_command], capture_output=True, check=False)
        c_summary = strict_json(c_summary_path.read_bytes()) if completed.returncode == 0 else None
    if completed.returncode:
        raise SystemExit('§18 native authority runner failed: ' +
                         completed.stderr.decode('utf-8', errors='replace').strip())
    authority_final = adapter_run(authority_command, {'kind': 'configured_profile'},
                                  '§18 configured authority after native probes')
    c_final = verify_authority_profile(authority_final, args.spec_root, set(),
                                      require_native_proof=False)
    if authority_final['report_bytes'] != authority_initial['report_bytes'] or c_final != c_report:
        raise SystemExit('§18 authority installation changed during native proof')
    run_id = str(uuid.uuid4())
    initial = adapter_run(command, {'kind': 'configured_profile', 'phase': 'before',
                                    'run_id': run_id}, 'configured profile before probes')
    configured = verified_profile(initial, artifacts, args.spec_root,
                                  expected_run_id=run_id, expected_proofs=set())
    bind_to_proved_authority(configured, c_report)
    proof_ids = set()
    retry_proofs = []
    for vector in manifest['vectors']:
        proof_id = execute_vector(command, vector, artifacts, configured, retry_proofs)
        if proof_id in proof_ids:
            raise SystemExit('duplicate native operation proof identity')
        proof_ids.add(proof_id)
    final = adapter_run(command, {'kind': 'configured_profile', 'phase': 'after',
                                  'run_id': run_id}, 'configured profile after probes')
    final_configured = verified_profile(final, artifacts, args.spec_root,
                                        expected_run_id=run_id, expected_proofs=proof_ids)
    bind_to_proved_authority(final_configured, c_report)
    verify_retained_retry_evidence(retry_proofs,
                                  final['installation_evidence']['destination_deduplication_proof'])
    if final_configured != configured or final['report_bytes'] != initial['report_bytes']:
        raise SystemExit('configured production profile changed during native probes')
    if args.proof_summary_output is not None:
        args.proof_summary_output.write_bytes(canonical({
            'format': 'determa.conformance.committed_native_effects.proof_summary',
            'schema_version': 1, 'parent_run_id': args.parent_run_id,
            'run_id': run_id, 'report_digest': configured['report_digest'],
            'authority_report_digest': configured['authority_report_digest'],
            'scope_identity': configured['scope_identity'],
            'topology_identifier': configured['topology_identifier'],
            'handler_reference': configured['handler_reference'],
            'destination_binding_digest': configured['destination_binding_digest'],
            'authority_summary': c_summary,
            'native_proof_ids': sorted(proof_ids),
            'adapter_command_digest': sha256_bytes(canonical(command))}))
    print(f'passed {count} committed native effect production adapter vectors under one configured host')


if __name__ == '__main__':
    main()
