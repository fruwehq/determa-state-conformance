#!/usr/bin/env python3
"""Run §21 vectors through a production adapter command, withholding all oracles."""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes
from run_committed_native_effects_profile import (
    adapter_run as effect_adapter_run, check_observation as check_effect_observation,
    verified_profile as verified_effect_profile,
    verify_native_evidence as verify_effect_native_evidence,
)

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'
TRANSPORT = ROOT / 'scripts/lossless_delivery_test_transport.py'


def strict_document(source: bytes, label: str) -> dict:
    analysis = analyze_json_artifact_source(source)
    if analysis.error or not isinstance(analysis.document, dict):
        raise ValueError(f'{label}: invalid strict UTF-8 JSON: {analysis.error}')
    return analysis.document


def strict_child_document(source: bytes, label: str) -> dict:
    document = strict_document(source, label)
    if source != canonical_json_bytes(document):
        raise ValueError(f'{label}: child response must be canonical UTF-8 JSON')
    return document


def expanded(store: dict, checkpoints: dict[str, dict]) -> dict:
    return {**store, 'checkpoint': checkpoints[store['checkpoint']]}


def digest(value: bytes) -> str:
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def configuration_digests(run_id: str) -> dict:
    closure = digest(TRANSPORT.read_bytes())
    return {
        'source_configuration_digest': digest(canonical_json_bytes([
            'determa-delivery-test-source-1', closure, 'sqlite-full-sync', run_id])),
        'destination_configuration_digest': digest(canonical_json_bytes([
            'determa-delivery-test-destination-1', closure, 'sqlite-full-sync',
            ['uncertain', 'accept', 'dead_letter'], run_id])),
        'host_storage_configuration_digest': digest(canonical_json_bytes([
            'determa-delivery-host-store-1', 'fresh-process-durable-read',
            ['checkpoint', 'binding', 'dead_letter'], run_id]))}


def adapter_call(command: list[str], payload: dict, label: str) -> dict:
    completed = subprocess.run(command, input=canonical_json_bytes(payload),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise ValueError(f'{label}: adapter exited {completed.returncode}')
    return strict_child_document(completed.stdout, label)


def transport_call(database: Path, kind: str, **fields) -> dict:
    return adapter_call([sys.executable, str(TRANSPORT)],
                        {'kind': kind, 'database_path': str(database), **fields},
                        f'test transport {kind}')


def verify_configured_delivery_profile(command: list[str], run_id: str | None = None,
                                       profile_links: dict | None = None) -> dict:
    run_id = run_id or str(uuid.uuid4())
    profile_links = profile_links or {'authority_report_digest': None,
                                      'effect_report_digest': None}
    closure = digest(TRANSPORT.read_bytes())
    configuration = configuration_digests(run_id)
    report = adapter_call(command, {'kind': 'configured_delivery_profile',
                                    'run_id': run_id,
                                    'transport_command': [sys.executable, str(TRANSPORT)],
                                    'transport_source_sha256': closure,
                                    'configuration_digests': configuration,
                                    'profile_links': profile_links},
                          'configured delivery profile')
    required = {'format': 'determa.conformance.lossless_delivery.configured_profile',
                'schema_version': 1, 'source_ordering': 'unordered',
                'transport_claims': [], 'run_id': run_id,
                'transport_source_sha256': closure,
                **configuration,
                **profile_links,
                'source_fetch': 'installed_test_transport',
                'source_acknowledgement': 'after_durable_commit',
                'ingress_dead_letter': 'durable_before_acknowledgement',
                'outbound_destination': 'installed_test_transport',
                'host_store': 'durable_fresh_process_read'}
    if report != required:
        raise ValueError('configured delivery installation or durability claim is incomplete')
    return report


def source_items(vector: dict) -> list[dict]:
    request = vector.get('request')
    if type(request) is list:
        return [entry['source'] for entry in request]
    if type(request) is dict and type(request.get('source')) is dict:
        return [request['source']]
    return []


def transport_request(vector: dict) -> tuple[object, list[dict]]:
    request = vector['request']
    if type(request) is list:
        return [{key: value for key, value in entry.items() if key != 'source'}
                for entry in request], [entry['source'] for entry in request]
    if type(request) is dict and 'source' in request:
        return {key: value for key, value in request.items() if key != 'source'}, [request['source']]
    if type(request) is dict and 'provider_result' in request:
        return {'effect_id': request['effect_id']}, []
    return request, []


def check_native_evidence(value: object, operation_id: str, run_id: str,
                          database: Path, fate: str, profile_links: dict) -> None:
    expected = {'operation_id': operation_id, 'run_id': run_id,
                'transport_source_sha256': digest(TRANSPORT.read_bytes()),
                'transport_database_path': str(database), 'commit_fate': fate,
                **configuration_digests(run_id), **profile_links}
    if type(value) is not dict or set(value) != set(expected) | {'native_transaction_id'} or \
            any(value[key] != item for key, item in expected.items()) or \
            type(value['native_transaction_id']) is not str or not value['native_transaction_id']:
        raise AssertionError('delivery native transaction evidence differs from configured operation')


def check_transport(vector: dict, database: Path, sources: list[dict], before: dict,
                    after: dict, prior_call_count: int) -> None:
    observed = transport_call(database, 'snapshot')
    source_rows = observed['sources']
    if len(source_rows) != len(sources):
        raise AssertionError(f'{vector["name"]}: source inventory differs')
    acknowledgements = {(item['source_scope'], item['source_delivery_id'])
                        for item in after['source_acknowledgements']}
    for row, source in zip(source_rows, sorted(sources, key=lambda item: (
            item['source_scope'], item['source_delivery_id']))):
        if (row['source'] != source or row['source_scope'] != source['source_scope'] or
            row['source_delivery_id'] != source['source_delivery_id'] or
            row['acknowledged'] != ((source['source_scope'], source['source_delivery_id']) in acknowledgements)):
            raise AssertionError(f'{vector["name"]}: actual source ownership differs')
    calls = observed['calls'][prior_call_count:]
    newly_acked = acknowledgements - {(item['source_scope'], item['source_delivery_id'])
                                      for item in before['source_acknowledgements']}
    actual_acks = {(call['source_scope'], call['source_delivery_id']) for call in calls
                   if call['kind'] == 'ack'}
    if actual_acks != newly_acked or len(actual_acks) != sum(call['kind'] == 'ack' for call in calls):
        raise AssertionError(f'{vector["name"]}: actual source acknowledgement differs')
    transfer = (after['bindings'][0]['admission_binding_digest'] if after['bindings'] else
                after['dead_letters'][0]['ingress_dead_letter_digest'] if after['dead_letters'] else None)
    for call in calls:
        if call['kind'] == 'ack' and (call['checkpoint_digest'] !=
                                     after['checkpoint']['execution_checkpoint_digest'] or
                                     call['transfer_digest'] != transfer):
            raise AssertionError(f'{vector["name"]}: acknowledgement lacks persisted transfer binding')
    if sources and vector['operation'] in ('ingest', 'ingest_batch', 'dead_letter') and \
            {(call['source_scope'], call['source_delivery_id']) for call in calls
             if call['kind'] == 'fetch'} != {
                 (source['source_scope'], source['source_delivery_id']) for source in sources}:
        raise AssertionError(f'{vector["name"]}: source provider was bypassed')
    deliveries = [call for call in calls if call['kind'] == 'deliver']
    if vector['operation'] == 'deliver_outbound':
        provider = vector['request']['provider_result']
        pending = next(item['intent'] for item in before['checkpoint']['pending_outbox_intents']
                       if item['intent']['effect_id'] == vector['request']['effect_id'])
        if len(deliveries) != 1 or deliveries[0]['effect_id'] != vector['request']['effect_id'] or \
                deliveries[0]['outcome'] != provider['outcome'] or \
                deliveries[0]['destination_receipt_id'] != provider['destination_receipt_id'] or \
                deliveries[0]['intent'] != pending:
            raise AssertionError(f'{vector["name"]}: actual installed destination transfer differs')
    elif deliveries:
        raise AssertionError(f'{vector["name"]}: unrequested destination transfer')


def run(command: list[str], case: Path = CASE, run_id: str | None = None,
        profile_links: dict | None = None) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    checkpoints = {path.name: strict_document(path.read_bytes(), path.name)
                   for path in case.glob('*-checkpoint-v1.json')}
    machines = {'ingress': (case / 'machine.yaml').read_text(encoding='utf-8'),
                'outbound': (case / 'outbox-machine.yaml').read_text(encoding='utf-8')}
    count = 0
    crashed: dict[str, tuple[Path, str]] = {}
    run_id = run_id or str(uuid.uuid4())
    profile_links = profile_links or {'authority_report_digest': None,
                                      'effect_report_digest': None}
    with tempfile.TemporaryDirectory(prefix='determa-delivery-') as temporary:
        for vector in manifest['vectors'] + manifest['invalid_vectors']:
            if vector.get('premise_kind') == 'hypothetical_common_rule':
                continue
            negative = 'candidate' in vector
            resume = crashed.get(vector.get('replay_of'))
            database = resume[0] if resume else Path(temporary) / f'{uuid.uuid4()}.sqlite'
            before = expanded(vector['before'], checkpoints)
            after = expanded(vector['after'], checkpoints)
            sources = source_items(vector)
            operation_id = str(uuid.uuid4())
            if not resume:
                acknowledged = {(item['source_scope'], item['source_delivery_id'])
                                for item in before['source_acknowledgements']}
                transport_call(database, 'seed', sources=[{
                    'source_scope': item['source_scope'],
                    'source_delivery_id': item['source_delivery_id'],
                    'source': item,
                    'acknowledged': (item['source_scope'], item['source_delivery_id']) in acknowledged
                } for item in sources])
            transfer_digest = (after['bindings'][0]['admission_binding_digest']
                               if after['bindings'] else
                               after['dead_letters'][0]['ingress_dead_letter_digest']
                               if after['dead_letters'] else '')
            transport_call(database, 'configure_acknowledgement_barrier',
                           observer_command=command, run_id=run_id,
                           operation_id=operation_id,
                           checkpoint_digest=after['checkpoint']['execution_checkpoint_digest'],
                           transfer_digest=transfer_digest)
            prior_call_count = len(transport_call(database, 'snapshot')['calls'])
            transport_input, references = (vector['candidate'], []) if negative else transport_request(vector)
            request = {'operation': vector['operation'], 'input': transport_input,
                       'source_references': [{'source_scope': item['source_scope'],
                                              'source_delivery_id': item['source_delivery_id']}
                                             for item in references],
                       'before': None if resume else before,
                       'resume_operation_id': resume[1] if resume else None,
                       'fault_injection': None if negative else vector['fault_injection'],
                       'machine_source': machines,
                       'run_id': run_id, 'operation_id': operation_id,
                       'transport_command': [sys.executable, str(TRANSPORT)],
                       'transport_database_path': str(database),
                       'transport_source_sha256': digest(TRANSPORT.read_bytes()),
                       'configuration_digests': configuration_digests(run_id),
                       'profile_links': profile_links}
            if not negative and vector['operation'] == 'deliver_outbound':
                route = {'ambiguous': 'uncertain', 'confirmed': 'accept',
                         'dead_lettered': 'dead_letter'}[vector['request']['provider_result']['outcome']]
                request['destination_route'] = route
            if 'authority_context' in vector:
                request['authority_context'] = vector['authority_context']
            if 'ordering_context' in vector:
                request['ordering_context'] = vector['ordering_context']
            completed = subprocess.run(command, input=canonical_json_bytes(request),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            expected_response = ({'kind': 'typed_failure',
                                  'code': vector['expected_failure'],
                                  'acknowledge_source': False}
                                 if negative else vector['expected_response'])
            crashed_now = expected_response == {'kind': 'no_response'}
            if crashed_now:
                if completed.stdout or completed.returncode == 0:
                    raise AssertionError(f'{vector["name"]}: crash cut returned a response')
                crashed[vector['name']] = (database, operation_id)
            else:
                if completed.returncode:
                    raise AssertionError(f'{vector["name"]}: adapter exited {completed.returncode}')
                observed = strict_child_document(completed.stdout, vector['name'])
                if set(observed) != {'response', 'after', 'native_evidence'}:
                    raise AssertionError(f'{vector["name"]}: adapter must return response, complete store, and native evidence')
                if canonical_json_bytes(observed['response']) != canonical_json_bytes(expected_response) or \
                        canonical_json_bytes(observed['after']) != canonical_json_bytes(after):
                    raise AssertionError(f'{vector["name"]}: response or complete store differs')
            # A separate process must read the persisted store after the operation,
            # including both crash cuts. Replays resume this exact operation's store.
            persistent = adapter_call(command, {'kind': 'observe_delivery_state',
                                                'run_id': run_id,
                                                'operation_id': operation_id,
                                                'transport_database_path': str(database)},
                                      f'{vector["name"]} fresh-process observation')
            if type(persistent) is not dict or set(persistent) != {'after', 'native_evidence'} or \
                    canonical_json_bytes(persistent['after']) != canonical_json_bytes(after):
                raise AssertionError(f'{vector["name"]}: durable post-operation store differs')
            fate = ('rolled_back' if vector.get('fault_injection') in
                    ('atomic_commit_failure', 'crash_before_commit') else
                    'committed' if before != after else 'no_mutation')
            check_native_evidence(persistent['native_evidence'], operation_id,
                                  run_id, database, fate, profile_links)
            if not crashed_now and observed['native_evidence'] != persistent['native_evidence']:
                raise AssertionError(f'{vector["name"]}: operation and persistent native proof differ')
            check_transport(vector, database, sources, before, after, prior_call_count)
            count += 1
    return count


def run_integrations(command: list[str], case: Path = CASE,
                     spec_root: Path = ROOT.parent / 'determa-state-spec') -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    effects = ROOT / 'conformance/profiles/committed-native-effects/effect-01-result'
    machine = (effects / 'machine.yaml').read_text(encoding='utf-8')
    handlers = {str(path.relative_to(effects)): path.read_text(encoding='utf-8')
                for path in sorted((effects / 'handler').glob('test_handler.*'))}
    effect_manifest = strict_document((effects / 'data/vectors.json').read_bytes(), 'effect manifest')
    effect_vectors = {item['name']: item for item in effect_manifest['vectors']}
    artifacts = {path.name: strict_document(path.read_bytes(), path.name)
                 for path in effects.glob('*checkpoint.json')}
    artifacts.update({'data/' + path.name: strict_document(path.read_bytes(), path.name)
                      for path in (effects / 'data').glob('*.json') if path.name != 'vectors.json'})
    run_id = str(uuid.uuid4())
    initial = effect_adapter_run(command, {'kind': 'configured_profile', 'phase': 'before',
                                           'run_id': run_id}, '§21 composed effect installation')
    configured = verified_effect_profile(initial, artifacts, spec_root,
                                         expected_run_id=run_id, expected_proofs=set())
    proof_ids = set()
    count = 0
    for vector in manifest['integration']['integration_vectors']:
        request = vector['request']
        effect_vector = effect_vectors[vector['effect_vector']]
        payload = {
            'operation': request['operation'],
            'checkpoint_before': vector['checkpoint_before'],
            'journal_before': vector['journal_before'],
            'claim': None if request['claim'] is None else
                strict_document((effects / request['claim']).read_bytes(), request['claim']),
            'host_configuration': request['host_configuration'],
            'auth_context': request['auth_context'],
            'arguments': request['arguments'], 'fault': request['fault'],
            'run_id': run_id,
            'machine_source_utf8': machine, 'handler_source_files': handlers,
            'delivery_observation_requested': True,
        }
        completed = subprocess.run(command, input=canonical_json_bytes(payload),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        if completed.returncode:
            raise AssertionError(f'{vector["name"]}: composed adapter failed')
        observed = strict_child_document(completed.stdout, vector['name'])
        if set(observed) != {'effect_observation', 'delivery_observation'}:
            raise AssertionError(f'{vector["name"]}: incomplete composed delivery observation')
        effect_observation = observed['effect_observation']
        check_effect_observation(effect_vector, effect_observation, artifacts)
        proof_id = verify_effect_native_evidence(effect_vector, effect_observation,
                                                 artifacts, configured, payload)
        if proof_id in proof_ids:
            raise AssertionError(f'{vector["name"]}: duplicate native effect proof')
        proof_ids.add(proof_id)
        delivery = observed['delivery_observation']
        if delivery != {'source_item': None, 'source_acknowledgements': [],
                        'result_admission_owner': 'host', 'effect_proof_id': proof_id}:
            raise AssertionError(f'{vector["name"]}: result admission acquired broker ownership')
        count += 1
    final = effect_adapter_run(command, {'kind': 'configured_profile', 'phase': 'after',
                                         'run_id': run_id}, '§21 composed effect proof closure')
    final_configured = verified_effect_profile(final, artifacts, spec_root,
                                               expected_run_id=run_id,
                                               expected_proofs=proof_ids)
    if final_configured != configured or final['report_bytes'] != initial['report_bytes']:
        raise AssertionError('composed effect installation changed during delivery proof')
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
        observed = strict_child_document(completed.stdout, vector['name'])
        expected = {'result': vector['expected_result'], 'source_acknowledgements': []}
        if canonical_json_bytes(observed) != canonical_json_bytes(expected):
            raise AssertionError(f'{vector["name"]}: core result lost a disposition or emission')
        count += 1
    return count


def configured_profile_links(command: list[str], authority_command: list[str]) -> dict:
    effect = adapter_call(command, {'kind': 'configured_profile', 'phase': 'before',
                                    'run_id': str(uuid.uuid4())},
                          '§19 configured effect installation for §21')
    authority = adapter_call(authority_command, {'kind': 'configured_profile'},
                             '§18 configured authority installation for §21')
    if set(effect) != {'report_bytes', 'installation_evidence'} or \
            set(authority) != {'report_bytes', 'installation_evidence'} or \
            type(effect['report_bytes']) is not str or \
            type(authority['report_bytes']) is not str:
        raise ValueError('configured authority/effect installation report is incomplete')
    effect_report = strict_document(effect['report_bytes'].encode('utf-8'), 'effect report')
    authority_report = strict_document(authority['report_bytes'].encode('utf-8'),
                                       'authority report')
    if effect['report_bytes'].encode('utf-8') != canonical_json_bytes(effect_report) or \
            authority['report_bytes'].encode('utf-8') != canonical_json_bytes(authority_report) or \
            effect_report.get('authority_report_bytes') != authority['report_bytes']:
        raise ValueError('configured effect and authority installations do not share one report')
    return {'authority_report_digest': digest(authority['report_bytes'].encode('utf-8')),
            'effect_report_digest': digest(effect['report_bytes'].encode('utf-8'))}


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
    if args.base_only and args.authority_adapter:
        parser.error('--base-only cannot claim an authority adapter')
    profile_links = {'authority_report_digest': None, 'effect_report_digest': None}
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
        profile_links = configured_profile_links(command, shlex.split(args.authority_adapter))
    configured_delivery = verify_configured_delivery_profile(command,
                                                             profile_links=profile_links)
    count = run(command, run_id=configured_delivery['run_id'],
                profile_links=profile_links)
    if verify_configured_delivery_profile(command, configured_delivery['run_id'],
                                          profile_links) != configured_delivery:
        raise SystemExit('configured delivery installation changed during native probes')
    core = run_core_observability(command)
    if args.base_only:
        print(f'passed {count + core} base lossless delivery vectors; no §18/§19 claim')
    else:
        integrations = run_integrations(command, spec_root=args.spec_root)
        print(f'passed {count + core + integrations} production lossless delivery vectors under one configured host')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
