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
from generate_lossless_delivery_profile import SPEC_PIN
from run_committed_native_effects_profile import (
    adapter_run as effect_adapter_run, check_observation as check_effect_observation,
    verified_profile as verified_effect_profile,
    verify_native_evidence as verify_effect_native_evidence,
)

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'
TRANSPORT = ROOT / 'scripts/lossless_delivery_test_transport.py'
STORE = ROOT / 'scripts/lossless_delivery_test_store.py'


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
            digest(STORE.read_bytes()), ['checkpoint', 'binding', 'dead_letter'], run_id]))}


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


def store_call(database: Path, kind: str, **fields) -> dict:
    return adapter_call([sys.executable, str(STORE)],
                        {'kind': kind, 'database_path': str(database), **fields},
                        f'trusted host store {kind}')


def verify_configured_delivery_profile(command: list[str], run_id: str | None = None,
                                       profile_links: dict | None = None) -> dict:
    run_id = run_id or str(uuid.uuid4())
    profile_links = profile_links or {'authority_report_digest': None,
                                      'effect_report_digest': None,
                                      'host_scope_identity': None,
                                      'host_topology_identifier': None}
    closure = digest(TRANSPORT.read_bytes())
    store_closure = digest(STORE.read_bytes())
    configuration = configuration_digests(run_id)
    report = adapter_call(command, {'kind': 'configured_delivery_profile',
                                    'run_id': run_id,
                                    'transport_command': [sys.executable, str(TRANSPORT)],
                                    'transport_source_sha256': closure,
                                    'host_store_source_sha256': store_closure,
                                    'host_store_command': [sys.executable, str(STORE)],
                                    'configuration_digests': configuration,
                                    'profile_links': profile_links},
                          'configured delivery profile')
    required = {'format': 'determa.conformance.lossless_delivery.configured_profile',
                'schema_version': 1, 'source_ordering': 'unordered',
                'transport_claims': [], 'run_id': run_id,
                'transport_source_sha256': closure,
                'host_store_source_sha256': store_closure,
                **configuration,
                **profile_links,
                'source_fetch': 'installed_test_transport',
                'source_acknowledgement': 'after_durable_commit',
                'ingress_dead_letter': 'durable_before_acknowledgement',
                'outbound_destination': 'installed_test_transport',
                'host_store': 'public_execution_store_injected_controlled_provider'}
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
                          database: Path, store_database: Path, fate: str,
                          profile_links: dict, transaction: dict | None) -> None:
    expected = {'operation_id': operation_id, 'run_id': run_id,
                'transport_source_sha256': digest(TRANSPORT.read_bytes()),
                'transport_database_path': str(database),
                'host_store_source_sha256': digest(STORE.read_bytes()),
                'host_store_database_path': str(store_database),
                'commit_fate': fate,
                'native_transaction_id': None if transaction is None else transaction['native_transaction_id'],
                'proof_id': None if transaction is None else transaction['proof_id'],
                **configuration_digests(run_id), **profile_links}
    if type(value) is not dict or value != expected:
        raise AssertionError('delivery native transaction evidence differs from configured operation')


def check_transport(vector: dict, database: Path, sources: list[dict], before: dict,
                    after: dict, prior_call_count: int,
                    prior_attempt_count: int) -> None:
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
    attempts = observed['acknowledgement_attempts'][prior_attempt_count:]
    newly_acked = acknowledgements - {(item['source_scope'], item['source_delivery_id'])
                                      for item in before['source_acknowledgements']}
    actual_acks = {(call['source_scope'], call['source_delivery_id']) for call in calls
                   if call['kind'] == 'ack'}
    if actual_acks != newly_acked or len(actual_acks) != sum(call['kind'] == 'ack' for call in calls):
        raise AssertionError(f'{vector["name"]}: actual source acknowledgement differs')
    if len(attempts) != len(newly_acked) or \
            any(item['status'] != 'accepted' or
                (item['source_scope'], item['source_delivery_id']) not in newly_acked
                for item in attempts):
        raise AssertionError(f'{vector["name"]}: premature or duplicate ack attempt')
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
        provider = vector['request'].get('provider_result')
        if provider is None:
            if deliveries:
                raise AssertionError(f'{vector["name"]}: terminal replay resent retained intent')
        else:
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
        profile_links: dict | None = None, proof_summary: list | None = None,
        timer_bridge_anchor: dict | None = None) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    checkpoints = {path.name: strict_document(path.read_bytes(), path.name)
                   for path in case.glob('*-checkpoint-v1.json')}
    machines = {'ingress': (case / 'machine.yaml').read_text(encoding='utf-8'),
                'outbound': (case / 'outbox-machine.yaml').read_text(encoding='utf-8')}
    count = 0
    sessions: dict[str, tuple[Path, Path, str, dict]] = {}
    timer_sessions: dict[str, dict] = {}
    run_id = run_id or str(uuid.uuid4())
    profile_links = profile_links or {'authority_report_digest': None,
                                      'effect_report_digest': None,
                                      'host_scope_identity': None,
                                      'host_topology_identifier': None}
    with tempfile.TemporaryDirectory(prefix='determa-delivery-') as temporary:
        for vector in manifest['vectors'] + manifest['invalid_vectors']:
            if vector.get('premise_kind') == 'hypothetical_common_rule':
                continue
            negative = 'candidate' in vector
            before = expanded(vector['before'], checkpoints)
            after = expanded(vector['after'], checkpoints)
            previous = sessions.get(vector.get('replay_of'))
            resume = (previous if previous is not None and
                      canonical_json_bytes(previous[3]) == canonical_json_bytes(before)
                      else None)
            if vector.get('replay_of') in (
                    'crash_after_atomic_commit_before_ack',
                    'outbound_confirmed_is_destination_acceptance',
                    'outbound_dead_letter_transfer') and resume is None:
                raise AssertionError(f'{vector["name"]}: retained replay lacks its original committed session')
            database = resume[0] if resume else Path(temporary) / f'{uuid.uuid4()}.sqlite'
            store_database = resume[1] if resume else Path(temporary) / f'{uuid.uuid4()}.host.sqlite'
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
                store_call(store_database, 'seed', run_id=run_id, before=before)
            trusted_before = store_call(store_database, 'snapshot', run_id=run_id)
            if canonical_json_bytes(trusted_before['after']) != canonical_json_bytes(before):
                raise AssertionError(f'{vector["name"]}: resumed host store differs from original caller state')
            prior_transactions = len(trusted_before['transactions'])
            prior_crash_cuts = len(trusted_before['crash_cuts'])
            prior_timer_invocations = store_call(
                store_database, 'timer_invocation_snapshot', run_id=run_id)['invocations'] \
                if 'timer_fire_context' in vector else []
            transfer_digest = (after['bindings'][0]['admission_binding_digest']
                               if after['bindings'] else
                               after['dead_letters'][0]['ingress_dead_letter_digest']
                               if after['dead_letters'] else '')
            transport_call(database, 'configure_acknowledgement_barrier',
                           store_command=[sys.executable, str(STORE)],
                           store_database_path=str(store_database), run_id=run_id,
                           operation_id=operation_id,
                           checkpoint_digest=after['checkpoint']['execution_checkpoint_digest'],
                           transfer_digest=transfer_digest)
            prior_transport = transport_call(database, 'snapshot')
            prior_call_count = len(prior_transport['calls'])
            prior_attempt_count = len(prior_transport['acknowledgement_attempts'])
            transport_input, references = (vector['candidate'], []) if negative else transport_request(vector)
            request = {'operation': vector['operation'], 'input': transport_input,
                       'source_references': [{'source_scope': item['source_scope'],
                                              'source_delivery_id': item['source_delivery_id']}
                                             for item in references],
                       'before': None if resume else before,
                       'resume_operation_id': resume[2] if resume else None,
                       'fault_injection': None if negative else vector['fault_injection'],
                       'machine_source': machines,
                       'run_id': run_id, 'operation_id': operation_id,
                       'transport_command': [sys.executable, str(TRANSPORT)],
                       'transport_database_path': str(database),
                       'transport_source_sha256': digest(TRANSPORT.read_bytes()),
                       'host_store_command': [sys.executable, str(STORE)],
                       'host_store_database_path': str(store_database),
                       'host_store_source_sha256': digest(STORE.read_bytes()),
                       'configuration_digests': configuration_digests(run_id),
                       'profile_links': profile_links}
            if not negative and vector['operation'] == 'deliver_outbound':
                provider = vector['request'].get('provider_result')
                if provider is not None:
                    route = {'ambiguous': 'uncertain', 'confirmed': 'accept',
                             'dead_lettered': 'dead_letter'}[provider['outcome']]
                    request['destination_route'] = route
            if 'authority_context' in vector:
                request['authority_context'] = vector['authority_context']
            if 'ordering_context' in vector:
                request['ordering_context'] = vector['ordering_context']
            if 'timer_fire_context' in vector:
                if timer_bridge_anchor is None:
                    raise AssertionError('timer ingress needs a reviewed helper bridge anchor')
                request['timer_fire_context'] = vector['timer_fire_context']
                if resume:
                    retained_timer = timer_sessions.get(vector['replay_of'])
                    if retained_timer is None or prior_timer_invocations != [retained_timer]:
                        raise AssertionError('timer replay lost the original public helper invocation')
                    request['trusted_timer_replay'] = {
                        'invocation_id': retained_timer['invocation_id'],
                        'native_transaction_id': retained_timer['native_transaction_id']}
                else:
                    invocation_id = str(uuid.uuid4())
                    request['trusted_timer_invocation'] = {
                        'command': [sys.executable, str(STORE)],
                        'database_path': str(store_database), 'run_id': run_id,
                        'invocation_id': invocation_id,
                        'factory_identity': timer_bridge_anchor['factory_identity'],
                        'bridge_identity': timer_bridge_anchor['bridge_identity'],
                        'public_request': vector['timer_fire_context'],
                        'request_digest': digest(canonical_json_bytes(vector['timer_fire_context'])),
                        'native_operation_id': operation_id,
                        'required_atomic_commit': True}
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
            else:
                if completed.returncode:
                    raise AssertionError(f'{vector["name"]}: adapter exited {completed.returncode}')
                observed = strict_child_document(completed.stdout, vector['name'])
                if set(observed) != {'response', 'after', 'native_evidence'}:
                    raise AssertionError(f'{vector["name"]}: adapter must return response, complete store, and native evidence')
                if canonical_json_bytes(observed['response']) != canonical_json_bytes(expected_response) or \
                        canonical_json_bytes(observed['after']) != canonical_json_bytes(after):
                    raise AssertionError(f'{vector["name"]}: response or complete store differs')
            # Read the driver-owned native store, outside the adapter, after both
            # crash cuts and every ordinary operation. Its commit journal is the
            # proof authority for host checkpoint/binding/dead-letter durability.
            persistent = store_call(store_database, 'snapshot', run_id=run_id)
            if canonical_json_bytes(persistent['after']) != canonical_json_bytes(after):
                raise AssertionError(f'{vector["name"]}: trusted durable host store differs')
            fate = ('rolled_back' if vector.get('fault_injection') in
                    ('atomic_commit_failure', 'crash_before_commit') else
                    'committed' if before != after else 'no_mutation')
            new_transactions = persistent['transactions'][prior_transactions:]
            new_cuts = persistent['crash_cuts'][prior_crash_cuts:]
            expected_cut = ({'operation_id': operation_id,
                             'phase': 'before_commit' if vector.get('fault_injection') == 'crash_before_commit'
                             else 'after_commit'} if crashed_now else None)
            if new_cuts != ([] if expected_cut is None else [expected_cut]):
                raise AssertionError(f'{vector["name"]}: driver-owned process crash cut missing')
            if len(new_transactions) > 1 or \
                    (new_transactions and new_transactions[0]['operation_id'] != operation_id) or \
                    (fate == 'committed' and len(new_transactions) != 1) or \
                    (fate == 'rolled_back' and new_transactions):
                raise AssertionError(f'{vector["name"]}: trusted native transaction fate differs')
            transaction = new_transactions[0] if new_transactions else None
            if transaction and (transaction['before_digest'] != digest(canonical_json_bytes(before)) or
                                transaction['after_digest'] != digest(canonical_json_bytes(after))):
                raise AssertionError(f'{vector["name"]}: trusted transaction committed different bytes')
            timer_invocation = None
            if 'timer_fire_context' in vector:
                invocations = store_call(store_database, 'timer_invocation_snapshot',
                                         run_id=run_id)['invocations']
                complete = vector['timer_fire_context']['complete_request']
                raw_result = next((item['result'] for item in after['timer_artifact']['operation_receipts']
                                   if item['operation_id'] == complete['operation_id'] and
                                   item['request_digest'] == complete['request_digest']), None)
                if raw_result is None or transaction is None or \
                        after['timer_artifact']['records'][0]['admission_receipt_digest'] != \
                        complete['arguments']['admission_receipt_digest']:
                    raise AssertionError(f'{vector["name"]}: timer helper/admission commit absent')
                if resume:
                    if invocations != prior_timer_invocations:
                        raise AssertionError(f'{vector["name"]}: replay invoked complete_fire twice')
                    timer_invocation = prior_timer_invocations[0]
                else:
                    expected_invocation = {
                        'invocation_id': invocation_id,
                        'request_digest': digest(canonical_json_bytes(vector['timer_fire_context'])),
                        'factory_identity': timer_bridge_anchor['factory_identity'],
                        'bridge_identity': timer_bridge_anchor['bridge_identity'],
                        'public_request': vector['timer_fire_context'],
                        'start_state_digest': digest(canonical_json_bytes(before)),
                        'raw_return': raw_result,
                        'return_digest': digest(canonical_json_bytes(raw_result)),
                        'return_state_digest': digest(canonical_json_bytes(after)),
                        'native_transaction_id': transaction['native_transaction_id']}
                    if invocations != [expected_invocation]:
                        raise AssertionError(f'{vector["name"]}: reviewed complete_fire return is not in the same native transaction')
                    timer_invocation = expected_invocation
            if not crashed_now:
                check_native_evidence(observed['native_evidence'], operation_id,
                                      run_id, database, store_database, fate,
                                      profile_links, transaction)
            check_transport(vector, database, sources, before, after,
                            prior_call_count, prior_attempt_count)
            if proof_summary is not None:
                transport_after = transport_call(database, 'snapshot')
                new_calls = transport_after['calls'][prior_call_count:]
                proof_summary.append({
                    'name': vector['name'], 'operation_id': operation_id,
                    'fate': fate, 'crash_cut': expected_cut,
                    'native_transaction_id': None if transaction is None else
                        transaction['native_transaction_id'],
                    'host_store_proof_id': None if transaction is None else transaction['proof_id'],
                    'after_digest': digest(canonical_json_bytes(after)),
                    'source_acknowledgements': after['source_acknowledgements'],
                    'provider_call_kinds': [item['kind'] for item in new_calls],
                    'destination_receipt_ids': [item['destination_receipt_id']
                                                for item in new_calls if item['kind'] == 'deliver']})
                if timer_invocation is not None:
                    proof_summary[-1]['timer_invocation'] = timer_invocation
            sessions[vector['name']] = (database, store_database, operation_id, after)
            if timer_invocation is not None:
                timer_sessions[vector['name']] = timer_invocation
            count += 1
    return count


def run_integrations(command: list[str], case: Path = CASE,
                     spec_root: Path = ROOT.parent / 'determa-state-spec',
                     parent_run_id: str | None = None,
                     proof_summary: list | None = None) -> int:
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
    with tempfile.TemporaryDirectory(prefix='determa-delivery-effects-') as temporary:
      for vector in manifest['integration']['integration_vectors']:
        request = vector['request']
        effect_vector = effect_vectors[vector['effect_vector']]
        store_database = Path(temporary) / f'{uuid.uuid4()}.host.sqlite'
        before_store = {'checkpoint': vector['checkpoint_before'],
                        'journal': vector['journal_before']}
        after_store = {'checkpoint': vector['checkpoint_after'],
                       'journal': vector['journal_after']}
        operation_id = str(uuid.uuid4())
        store_call(store_database, 'seed', run_id=run_id, before=before_store)
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
            'parent_run_id': parent_run_id,
            'operation_id': operation_id,
            'host_store_command': [sys.executable, str(STORE)],
            'host_store_database_path': str(store_database),
            'host_store_source_sha256': digest(STORE.read_bytes()),
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
        trusted = store_call(store_database, 'snapshot', run_id=run_id)
        if canonical_json_bytes(trusted['after']) != canonical_json_bytes(after_store) or \
                len(trusted['transactions']) != 1 or \
                trusted['transactions'][0]['operation_id'] != operation_id or \
                trusted['transactions'][0]['before_digest'] != digest(canonical_json_bytes(before_store)) or \
                trusted['transactions'][0]['after_digest'] != digest(canonical_json_bytes(after_store)):
            raise AssertionError(f'{vector["name"]}: composed effect bypassed trusted host store')
        native_transaction = trusted['transactions'][0]
        if effect_observation['native_evidence']['native_transaction_id'] != \
                native_transaction['native_transaction_id']:
            raise AssertionError(f'{vector["name"]}: effect native fate differs from trusted store')
        delivery = observed['delivery_observation']
        if delivery != {'source_item': None, 'source_acknowledgements': [],
                        'result_admission_owner': 'host', 'effect_proof_id': proof_id,
                        'host_store_proof_id': native_transaction['proof_id']}:
            raise AssertionError(f'{vector["name"]}: result admission acquired broker ownership')
        if proof_summary is not None:
            proof_summary.append({'name': vector['name'], 'effect_proof_id': proof_id,
                                  'host_store_proof_id': native_transaction['proof_id'],
                                  'native_transaction_id': native_transaction['native_transaction_id']})
        count += 1
    final = effect_adapter_run(command, {'kind': 'configured_profile', 'phase': 'after',
                                         'run_id': run_id}, '§21 composed effect proof closure')
    final_configured = verified_effect_profile(final, artifacts, spec_root,
                                               expected_run_id=run_id,
                                               expected_proofs=proof_ids)
    if final_configured != configured or final['report_bytes'] != initial['report_bytes']:
        raise AssertionError('composed effect installation changed during delivery proof')
    return count


def run_core_observability(command: list[str], case: Path = CASE,
                           proof_summary: list | None = None) -> int:
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
        if proof_summary is not None:
            proof_summary.append({'name': vector['name'],
                                  'result_digest': digest(canonical_json_bytes(observed['result']))})
        count += 1
    return count


def configured_profile_links(command: list[str], authority_command: list[str],
                             effect_summary: dict | None = None) -> dict:
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
    if effect_summary is not None:
        authority_summary = effect_summary.get('authority_summary')
        if (effect_summary.get('report_digest') != digest(effect['report_bytes'].encode('utf-8')) or
            effect_summary.get('authority_report_digest') != digest(authority['report_bytes'].encode('utf-8')) or
            effect_summary.get('scope_identity') != effect_report.get('scope_identity') or
            effect_summary.get('topology_identifier') != authority_report['topology']['identifier'] or
            type(authority_summary) is not dict or
            authority_summary.get('report_digest') != digest(authority['report_bytes'].encode('utf-8')) or
            authority_summary.get('scope_identity') != authority_report['scope_identity'] or
            authority_summary.get('topology') != authority_report['topology']):
            raise ValueError('same-run authority/effect proof receipt differs from configured installation')
    return {'authority_report_digest': digest(authority['report_bytes'].encode('utf-8')),
            'effect_report_digest': digest(effect['report_bytes'].encode('utf-8')),
            'host_scope_identity': effect_report['scope_identity'],
            'host_topology_identifier': authority_report['topology']['identifier']}


def verify_delivery_proof_summary(summary: dict, command: list[str],
                                  case: Path = CASE) -> dict:
    """Check the runner-issued, exact-installation receipt for downstream profiles."""
    expected_keys = {'format', 'schema_version', 'spec_commit', 'profile_vectors_digest',
                     'runner_source_sha256', 'parent_run_id', 'adapter_command_digest',
                     'configured_delivery_report_digest', 'configured_delivery_profile',
                     'host_store_provider_source_sha256',
                     'transport_provider_source_sha256', 'authority_effect_summary',
                     'delivery_operations', 'core_observations', 'effect_integrations',
                     'proved_claims', 'scope_limit'}
    if type(summary) is not dict or set(summary) != expected_keys or \
            summary['format'] != 'determa.conformance.lossless_delivery.proof_summary' or \
            type(summary['schema_version']) is not int or summary['schema_version'] != 1 or \
            summary['spec_commit'] != SPEC_PIN or \
            summary['profile_vectors_digest'] != digest((case / 'delivery-vectors-v1.json').read_bytes()) or \
            summary['runner_source_sha256'] != digest(Path(__file__).read_bytes()) or \
            summary['adapter_command_digest'] != digest(canonical_json_bytes(command)) or \
            summary['host_store_provider_source_sha256'] != digest(STORE.read_bytes()) or \
            summary['transport_provider_source_sha256'] != digest(TRANSPORT.read_bytes()) or \
            summary['scope_limit'] != 'exact_injected_public_test_store_and_transport':
        raise ValueError('delivery proof summary source, spec, or installation differs')
    report = summary['configured_delivery_profile']
    if type(report) is not dict or report.get('run_id') != summary['parent_run_id'] or \
            summary['configured_delivery_report_digest'] != digest(canonical_json_bytes(report)) or \
            report.get('host_store_source_sha256') != summary['host_store_provider_source_sha256'] or \
            report.get('transport_source_sha256') != summary['transport_provider_source_sha256'] or \
            any(report.get(key) != value for key, value in
                configuration_digests(summary['parent_run_id']).items()):
        raise ValueError('delivery proof summary lacks the configured native installation')
    fixture = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    checkpoints = {path.name: strict_document(path.read_bytes(), path.name)
                   for path in case.glob('*-checkpoint-v1.json')}
    vectors = [item for item in fixture['vectors'] + fixture['invalid_vectors']
               if item.get('premise_kind') != 'hypothetical_common_rule']
    operations = summary['delivery_operations']
    if type(operations) is not list or [item.get('name') for item in operations] != \
            [item['name'] for item in vectors]:
        raise ValueError('delivery proof summary omitted or reordered an operation')
    operation_ids = set()
    proof_ids = set()
    for item, vector in zip(operations, vectors):
        expected_after = expanded(vector['after'], checkpoints)
        expected_before = expanded(vector['before'], checkpoints)
        expected_fate = ('rolled_back' if vector.get('fault_injection') in
                         ('atomic_commit_failure', 'crash_before_commit') else
                         'committed' if expected_before != expected_after else 'no_mutation')
        if (type(item) is not dict or
            item.get('after_digest') != digest(canonical_json_bytes(expected_after)) or
            item.get('source_acknowledgements') != expected_after['source_acknowledgements'] or
            type(item.get('operation_id')) is not str or
            item['operation_id'] in operation_ids or
            item.get('fate') != expected_fate or
            (expected_fate == 'committed' and item.get('host_store_proof_id') is None) or
            (expected_fate == 'rolled_back' and item.get('host_store_proof_id') is not None) or
            (item.get('host_store_proof_id') is None) !=
                (item.get('native_transaction_id') is None)):
            raise ValueError('delivery operation receipt differs from pinned durable fate')
        operation_ids.add(item['operation_id'])
        if item.get('host_store_proof_id') is not None:
            if item['host_store_proof_id'] in proof_ids:
                raise ValueError('duplicate host store proof identity')
            proof_ids.add(item['host_store_proof_id'])
        expected_cut = ({'operation_id': item['operation_id'],
                         'phase': 'before_commit' if vector.get('fault_injection') == 'crash_before_commit'
                         else 'after_commit'} if vector.get('expected_response') == {'kind': 'no_response'}
                        else None)
        if item.get('crash_cut') != expected_cut:
            raise ValueError('delivery proof summary lost a provider-owned process crash cut')
        if vector['operation'] == 'deliver_outbound' and 'provider_result' not in vector['request'] and \
                ('deliver' in item.get('provider_call_kinds', []) or item.get('destination_receipt_ids')):
            raise ValueError('terminal outbound replay reported a destination resend')
    core = summary['core_observations']
    if type(core) is not list or [item.get('name') for item in core] != \
            [item['name'] for item in fixture['core_observability_vectors']] or \
            any(item['result_digest'] != digest(canonical_json_bytes(vector['expected_result']))
                for item, vector in zip(core, fixture['core_observability_vectors'])):
        raise ValueError('core observability proof inventory differs')
    full = summary['authority_effect_summary'] is not None
    integrations = summary['effect_integrations']
    if full:
        effect = summary['authority_effect_summary']
        if (effect.get('parent_run_id') != summary['parent_run_id'] or
            effect.get('report_digest') != report.get('effect_report_digest') or
            effect.get('authority_report_digest') != report.get('authority_report_digest') or
            effect.get('scope_identity') != report.get('host_scope_identity') or
            effect.get('topology_identifier') != report.get('host_topology_identifier') or
            len(effect.get('native_proof_ids', [])) != 43 or
            [item.get('name') for item in integrations] !=
                [item['name'] for item in fixture['integration']['integration_vectors']] or
            any(not item.get('host_store_proof_id') or not item.get('effect_proof_id')
                for item in integrations)):
            raise ValueError('composed authority/effect proof differs from delivery installation')
        expected_claims = ['lossless_delivery_controlled_store',
                           'host_authority_worker_sqlite_independent',
                           'five_native_effect_integrations_controlled_store']
    else:
        if integrations or any(report.get(key) is not None for key in
                               ('authority_report_digest', 'effect_report_digest',
                                'host_scope_identity', 'host_topology_identifier')):
            raise ValueError('base delivery proof invented authority/effect installation')
        expected_claims = ['lossless_delivery_controlled_store']
    if summary['proved_claims'] != expected_claims:
        raise ValueError('delivery proof summary claimed an unverified profile')
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--adapter', required=True,
                        help='command that reads one strict JSON request on stdin')
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--authority-adapter',
                        help='same configured host authority installation used by the effect adapter')
    parser.add_argument('--base-only', action='store_true',
                        help='run the weaker delivery-only claim without §18/§19 native proof')
    parser.add_argument('--proof-summary-output', type=Path,
                        help='write verified same-run delivery, authority, and effect proof summary')
    args = parser.parse_args()
    command = shlex.split(args.adapter)
    if not command:
        parser.error('empty adapter command')
    if args.base_only and args.authority_adapter:
        parser.error('--base-only cannot claim an authority adapter')
    run_id = str(uuid.uuid4())
    profile_links = {'authority_report_digest': None, 'effect_report_digest': None,
                     'host_scope_identity': None, 'host_topology_identifier': None}
    effect_summary = None
    if not args.base_only:
        if not args.authority_adapter:
            parser.error('full lossless delivery claim requires --authority-adapter')
        # The effect runner checks the installed handler/destination closure,
        # complete §19 operations, and the §18 native worker scenario against
        # this exact same production adapter command. A profile report alone
        # does not certify a broker or a durable destination.
        with tempfile.TemporaryDirectory(prefix='determa-delivery-proof-') as temporary:
            effect_summary_path = Path(temporary) / 'effect-proof.json'
            completed = subprocess.run([
                sys.executable, str(ROOT / 'scripts/run_committed_native_effects_profile.py'),
                '--spec-root', str(args.spec_root), '--adapter', args.adapter,
                '--authority-adapter', args.authority_adapter,
                '--parent-run-id', run_id,
                '--proof-summary-output', str(effect_summary_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            effect_summary = (strict_document(effect_summary_path.read_bytes(), 'effect proof summary')
                              if completed.returncode == 0 else None)
        if completed.returncode:
            raise SystemExit('§18/§19 configured native proof failed: ' +
                             completed.stderr.decode('utf-8', errors='replace').strip())
        if effect_summary['parent_run_id'] != run_id or \
                len(effect_summary['native_proof_ids']) != 43 or \
                effect_summary['adapter_command_digest'] != digest(canonical_json_bytes(command)) or \
                effect_summary['authority_summary']['adapter_command_digest'] != \
                    digest(canonical_json_bytes(shlex.split(args.authority_adapter))):
            raise SystemExit('same-run committed effect proof summary is incomplete')
        profile_links = configured_profile_links(command, shlex.split(args.authority_adapter),
                                                 effect_summary)
    configured_delivery = verify_configured_delivery_profile(command,
                                                             run_id=run_id,
                                                             profile_links=profile_links)
    delivery_proofs: list = []
    count = run(command, run_id=configured_delivery['run_id'],
                profile_links=profile_links, proof_summary=delivery_proofs)
    if verify_configured_delivery_profile(command, configured_delivery['run_id'],
                                          profile_links) != configured_delivery:
        raise SystemExit('configured delivery installation changed during native probes')
    core_proofs: list = []
    core = run_core_observability(command, proof_summary=core_proofs)
    integration_proofs: list = []
    if not args.base_only:
        integrations = run_integrations(command, spec_root=args.spec_root,
                                        parent_run_id=run_id,
                                        proof_summary=integration_proofs)
    if verify_configured_delivery_profile(command, configured_delivery['run_id'],
                                          profile_links) != configured_delivery:
        raise SystemExit('configured delivery installation changed after composed native probes')
    if args.proof_summary_output is not None:
        spec_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=args.spec_root,
                                     capture_output=True, text=True, check=True).stdout.strip()
        if spec_commit != SPEC_PIN:
            raise SystemExit(f'lossless delivery proof summary requires pinned specification {SPEC_PIN}')
        summary = {
            'format': 'determa.conformance.lossless_delivery.proof_summary',
            'schema_version': 1, 'spec_commit': spec_commit,
            'profile_vectors_digest': digest((CASE / 'delivery-vectors-v1.json').read_bytes()),
            'runner_source_sha256': digest(Path(__file__).read_bytes()),
            'parent_run_id': run_id,
            'adapter_command_digest': digest(canonical_json_bytes(command)),
            'configured_delivery_report_digest': digest(canonical_json_bytes(configured_delivery)),
            'configured_delivery_profile': configured_delivery,
            'host_store_provider_source_sha256': digest(STORE.read_bytes()),
            'transport_provider_source_sha256': digest(TRANSPORT.read_bytes()),
            'authority_effect_summary': effect_summary,
            'delivery_operations': delivery_proofs,
            'core_observations': core_proofs,
            'effect_integrations': integration_proofs,
            'proved_claims': (['lossless_delivery_controlled_store'] if args.base_only else
                              ['lossless_delivery_controlled_store',
                               'host_authority_worker_sqlite_independent',
                               'five_native_effect_integrations_controlled_store']),
            'scope_limit': 'exact_injected_public_test_store_and_transport',
        }
        verify_delivery_proof_summary(summary, command)
        args.proof_summary_output.write_bytes(canonical_json_bytes(summary))
    if args.base_only:
        print(f'passed {count + core} base lossless delivery vectors; no §18/§19 claim')
    else:
        print(f'passed {count + core + integrations} lossless delivery vectors under the controlled installed host store')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
