#!/usr/bin/env python3
"""Generate a real emitted-intent §19 fixture, separate from synthetic spec examples."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess

import rfc8785
from pathlib import Path

from generate_execution_checkpoint_profile import admit, process, terminalize, processing_request
from validate_conformance import expected_core_step_result
from generate_version1_vectors import native_v1_checkpoint, bundle_binding
from generate_version1_vectors import digest, seal_checkpoint, seal_aggregate, typed_value

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/committed-native-effects/effect-01-result'
SPEC_COMMIT = '77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0'
TOKEN = 'business-order-42'
SCOPE = 'effect-scope-1'


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def journal(checkpoint, revision, record=None, responses=None):
    value = dict(host_effect_journal_format='determa.host_effect_journal',
                 host_effect_journal_schema_version=1, scope_identity=SCOPE,
                 root_instance_id=checkpoint['root_instance_id'],
                 checkpoint_revision=checkpoint['revision'],
                 checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                 journal_revision=str(revision), effect_records=[] if record is None else [record],
                 operation_response_references=[] if responses is None else responses)
    value['host_effect_journal_digest'] = digest(['determa-host-effect-journal-digest-1', value])
    return value


def response_reference(operation_id, response):
    return {'operation_id': operation_id,
            'response_digest': digest(['determa-host-operation-response-1', response])}


def result_response(status, effect_id, fence, *, report=None, outcome=None,
                    event_id=None, receipt=None, checkpoint_revision=None,
                    journal_revision=None, error=None):
    return dict(status=status, effect_id=effect_id, attempt_fence=fence,
                attempt_report=report, outcome=outcome, result_event_id=event_id,
                admission_receipt=receipt, checkpoint_revision=checkpoint_revision,
                journal_revision=journal_revision, error_code=error)


def handler_closure():
    paths = sorted((CASE / 'handler').glob('test_handler.*'))
    preimage = bytearray(b'determa-effect-handler-closure-1\0')
    files = []
    for path in paths:
        name = str(path.relative_to(CASE))
        name_bytes = name.encode('utf-8')
        source = path.read_bytes()
        preimage.extend(len(name_bytes).to_bytes(8, 'big'))
        preimage.extend(name_bytes)
        preimage.extend(len(source).to_bytes(8, 'big'))
        preimage.extend(source)
        files.append({'path': name, 'sha256': 'sha256:' + hashlib.sha256(source).hexdigest(),
                      'byte_length': len(source)})
    return {'format': 'determa.effect_handler_closure', 'schema_version': 1,
            'files': files, 'closure_digest': 'sha256:' + hashlib.sha256(preimage).hexdigest()}


def generate(spec_root: Path):
    source_head = subprocess.check_output(
        ['git', '-C', str(spec_root), 'rev-parse', 'HEAD'], text=True).strip()
    if source_head != SPEC_COMMIT:
        raise ValueError(f'specification source changed: {source_head}')
    closure = handler_closure()
    destination_configuration = {'format': 'determa.effect_destination_binding',
                                 'schema_version': 1, 'scope_identity': SCOPE,
                                 'destination': 'conformance.fake-native-destination',
                                 'idempotency_namespace': SCOPE,
                                 'connector_version': '1'}
    destination_digest = 'sha256:' + hashlib.sha256(rfc8785.dumps(destination_configuration)).hexdigest()
    created = native_v1_checkpoint(CASE / 'machine.yaml', {
        'operation': 'create_v1', 'bundle': bundle_binding(CASE / 'machine.yaml'),
        'machine_id': 'workflow', 'machine_version': '1',
        'root_instance_id': 'effect-root-1', 'creation_id': 'effect-create-1',
        'bindings': {'input': {}, 'external': {}}})
    accepted = admit(created, 'invoke', 'invoke-1', {'operation_token': TOKEN})
    pending = process(accepted, bundle_path=CASE / 'machine.yaml')
    assert len(pending['pending_outbox_intents']) == 1
    producer_request = processing_request(accepted, 'produce-1', event_id='invoke-1')
    producer_response = {'kind': 'processing', 'body': {
        'core_result': expected_core_step_result(pending),
        'receipt': pending['operation_receipts'][-1]}}
    intent = pending['pending_outbox_intents'][0]['intent']
    assert intent['correlation_id'] == TOKEN
    effect_id = intent['effect_id']
    runtime = pending['root_record']['aggregate_state']['runtimes'][0]
    mapping = [dict(outcome_kind=kind, event=event, result_slot=slot,
                    operation_token_location={'kind': 'correlation_id'})
               for kind, event, slot in [('succeeded', 'native_succeeded', 'success'),
                                         ('cancelled', 'native_cancelled', 'cancelled')]]
    record = dict(effect_id=effect_id, operation_token=TOKEN,
                  intent_digest=digest(['determa-outbox-intent-digest-1', '1', pending['root_instance_id'], intent]),
                  handler_reference={'identifier': 'conformance.native-effect-handler', 'version': '1.0.0',
                                     'content_digest': closure['closure_digest']},
                  destination_binding_digest=destination_digest,
                  route_configuration_generation='7', result_mapping=mapping,
                  target={'root_instance_id': pending['root_instance_id'],
                          'runtime_id': runtime['runtime_id'],
                          'runtime_incarnation': runtime['identity_origin']},
                  idempotency_policy='destination_deduplicates', attempt_fence='0',
                  attempt_records=[], invocation_state='unclaimed', outcome=None,
                  result_event_id=None, admission_receipt=None, cancellation=None)
    unclaimed = journal(pending, 1, record)
    no_cancel_record = copy.deepcopy(record)
    no_cancel_record['result_mapping'] = [item for item in record['result_mapping']
                                          if item['outcome_kind'] != 'cancelled']
    no_cancel_journal = journal(pending, 1, no_cancel_record)
    confirmed_checkpoint = terminalize(pending, 0, 'confirmed')
    confirmed_journal = journal(confirmed_checkpoint, 2, record)
    leased_record = copy.deepcopy(record)
    leased_record.update(attempt_fence='1', invocation_state='leased')
    leased = journal(pending, 2, leased_record)
    claim = dict(scope_identity=SCOPE, root_instance_id=pending['root_instance_id'],
                 work_kind='effect', work_identity=effect_id, operation_token=TOKEN,
                 scope_authority_epoch='3', attempt_fence='1', worker_principal='worker-a',
                 expires_at='1893456000000000000', state='active')
    payload = typed_value({'provider_reference': 'accepted-42'})
    request = dict(effect_id=effect_id, operation_token=TOKEN, attempt_fence='1',
                   outcome_kind='succeeded', payload=payload)
    report = dict(attempt_fence='1', report_kind='succeeded',
                  report_digest=digest(['determa-effect-attempt-report-1', effect_id, TOKEN,
                                        '1', 'succeeded', payload, None]), reason=None)
    outcome = dict(kind='succeeded', payload=payload,
                   digest=digest(['determa-effect-outcome-1', effect_id, TOKEN,
                                  'succeeded', payload, '1']), attempt_fence='1')
    event_id = digest(['determa-effect-result-event-1', effect_id, 'success'])
    recorded_record = copy.deepcopy(leased_record)
    recorded_record.update(attempt_records=[report], invocation_state='outcome_recorded',
                           outcome=outcome, result_event_id=event_id)
    recorded = journal(pending, 3, recorded_record)
    admitted = admit(pending, 'native_succeeded', event_id,
                     {'provider_reference': 'accepted-42'})
    # The pinned correlation is part of the complete envelope and its digest.
    entry = admitted['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'][-1]
    entry['envelope']['correlation_id'] = TOKEN
    entry['envelope_digest'] = digest(['determa-inbox-envelope-digest-1', '1',
                                      pending['root_instance_id'], 'input', entry['envelope']])
    admitted['operation_receipts'][-1]['request_digest'] = entry['envelope_digest']
    admitted['root_record']['aggregate_state'] = seal_aggregate(admitted['root_record']['aggregate_state'])
    admitted = seal_checkpoint(admitted)
    receipt = admitted['operation_receipts'][-1]
    committed_response = result_response('committed', effect_id, '1', outcome=outcome,
                                         event_id=event_id, receipt=receipt,
                                         checkpoint_revision=admitted['revision'], journal_revision='4')
    final_record = copy.deepcopy(recorded_record)
    final_record.update(invocation_state='result_admitted', admission_receipt=receipt)
    final = journal(admitted, 4, final_record)
    rejected = {code: result_response('rejected', effect_id, '1', error=code) for code in
                ('effect_not_outstanding', 'stale_attempt_fence', 'stale_scope_authority', 'effect_result_conflict', 'unauthorized_scope', 'host_capability_mismatch')}
    rejected['stale_attempt_fence_zero'] = result_response('rejected', effect_id, '0', error='stale_attempt_fence')
    ambiguous_report = dict(attempt_fence='1', report_kind='ambiguous',
                            report_digest=digest(['determa-effect-attempt-report-1', effect_id, TOKEN,
                                                  '1', 'ambiguous', typed_value({}), 'provider_acceptance_unknown']),
                            reason='provider_acceptance_unknown')
    ambiguous_record = copy.deepcopy(leased_record)
    ambiguous_record.update(invocation_state='ambiguous', attempt_records=[ambiguous_report])
    ambiguous = journal(pending, 3, ambiguous_record)
    ambiguous_retry_record = copy.deepcopy(ambiguous_record)
    ambiguous_retry_record.update(invocation_state='leased', attempt_fence='2')
    ambiguous_retry_journal = journal(pending, 4, ambiguous_retry_record)
    ambiguous_response = result_response('report_recorded', effect_id, '1', report=ambiguous_report,
                                         checkpoint_revision=pending['revision'], journal_revision='3')
    retry_payload = typed_value({})
    retry_request = dict(effect_id=effect_id, operation_token=TOKEN, attempt_fence='1',
                         outcome_kind='retryable_failure', payload=retry_payload)
    retry_report = dict(attempt_fence='1', report_kind='retryable_failure',
                        report_digest=digest(['determa-effect-attempt-report-1', effect_id, TOKEN,
                                              '1', 'retryable_failure', retry_payload, 'destination_deduplication_proven']),
                        reason='destination_deduplication_proven')
    retry_record = copy.deepcopy(leased_record)
    retry_record.update(invocation_state='unclaimed', attempt_records=[retry_report])
    retry_journal = journal(pending, 3, retry_record)
    retry_response = result_response('report_recorded', effect_id, '1', report=retry_report,
                                     checkpoint_revision=pending['revision'], journal_revision='3')
    retry_claim_record = copy.deepcopy(retry_record)
    retry_claim_record.update(invocation_state='leased', attempt_fence='2')
    retry_claim_journal = journal(pending, 4, retry_claim_record)

    cancel_payload = typed_value({})
    cancel_request = dict(operation_id='cancel-1', effect_id=effect_id,
                          reason='operator_request', payload=cancel_payload)
    cancel_outcome = dict(kind='cancelled', payload=cancel_payload,
                          digest=digest(['determa-effect-outcome-1', effect_id, TOKEN,
                                         'cancelled', cancel_payload, '0']), attempt_fence='0')
    cancel_event = digest(['determa-effect-result-event-1', effect_id, 'cancelled'])
    cancel_record = copy.deepcopy(record)
    cancel_record.update(invocation_state='outcome_recorded', outcome=cancel_outcome,
                         result_event_id=cancel_event,
                         cancellation={'operation_id': 'cancel-1', 'reason': 'operator_request',
                                       'state': 'prevented_start'})
    cancel_rejected_response = dict(status='rejected', operation_id='cancel-1', effect_id=effect_id,
                                    cancellation=None, outcome=None, result_event_id=None,
                                    journal_revision=None, error_code='invalid_host_request')
    cancel_response = dict(status='committed', operation_id='cancel-1', effect_id=effect_id,
                           cancellation=cancel_record['cancellation'], outcome=cancel_outcome,
                           result_event_id=cancel_event, journal_revision='2', error_code=None)
    cancelled = journal(pending, 2, cancel_record,
                        [response_reference('cancel-1', cancel_response)])
    cancelled_admitted_checkpoint = admit(pending, 'native_cancelled', cancel_event, {})
    cancelled_entry = cancelled_admitted_checkpoint['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'][-1]
    cancelled_entry['envelope']['correlation_id'] = TOKEN
    cancelled_entry['envelope_digest'] = digest(['determa-inbox-envelope-digest-1', '1',
                                                 pending['root_instance_id'], 'input', cancelled_entry['envelope']])
    cancelled_admitted_checkpoint['operation_receipts'][-1]['request_digest'] = cancelled_entry['envelope_digest']
    cancelled_admitted_checkpoint['root_record']['aggregate_state'] = seal_aggregate(cancelled_admitted_checkpoint['root_record']['aggregate_state'])
    cancelled_admitted_checkpoint = seal_checkpoint(cancelled_admitted_checkpoint)
    cancelled_admitted_record = copy.deepcopy(cancel_record)
    cancelled_admitted_record.update(invocation_state='result_admitted',
                                     admission_receipt=cancelled_admitted_checkpoint['operation_receipts'][-1])
    cancelled_admitted_journal = journal(cancelled_admitted_checkpoint, 3, cancelled_admitted_record,
                                         [response_reference('cancel-1', cancel_response)])
    empty = journal(accepted, 0)
    postcall_record = copy.deepcopy(ambiguous_record)
    postcall_record['cancellation'] = {'operation_id': 'cancel-after-call',
                                       'reason': 'operator_request',
                                       'state': 'reconciliation_required'}
    postcall_response = dict(status='reconciliation_required', operation_id='cancel-after-call',
                             effect_id=effect_id, cancellation=postcall_record['cancellation'],
                             outcome=None, result_event_id=None, journal_revision='4', error_code=None)
    postcall = journal(pending, 4, postcall_record,
                       [response_reference('cancel-after-call', postcall_response)])
    # Each request is a complete driver operation. Coverage labels and expected IDs are withheld
    # from production adapters by the runner.
    def vector(name, covers, operation, cp_before, j_before, cp_after, j_after,
               *, claim_file=None, arguments=None, auth=None, fault=None,
               response_file=None, provider=0, core=0, claims=0, config=None,
               caller_kind=None, control_plan=None, control_events=None):
        return dict(name=name, covers=covers,
                    request=dict(operation=operation, checkpoint_before=cp_before,
                                 journal_before='data/' + j_before, claim=None if claim_file is None else 'data/' + claim_file,
                                 host_configuration=config or {'route_generation': '7', 'route_authorized': True,
                                                        'destination_deduplication_proven': True,
                                                        'handler_authorized': True, 'credential_available': True, 'credential_generation': '1'},
                                 auth_context=auth or {'scope_identity': SCOPE, 'principal': 'worker-a',
                                                       'scope_authority_epoch': '3', 'trusted_host_now': '1893455999999999999'},
                                 arguments={} if arguments is None else arguments, fault=fault,
                                 control_plan=[] if control_plan is None else control_plan),
                    expected=dict(response=None if response_file is None else 'data/' + response_file,
                                  caller_kind=caller_kind or ('response' if response_file else 'completed'),
                                  control_events=[] if control_events is None else control_events,
                                  checkpoint_after=cp_after, journal_after='data/' + j_after,
                                  counts={'provider_calls': provider, 'core_calls': core,
                                          'new_claims': claims}))
    proposed_journal = copy.deepcopy(unclaimed)
    proposed_journal.pop('host_effect_journal_digest')
    proposed_journal['operation_response_references'].append(
        response_reference('produce-1', producer_response))
    proposed_journal_digest = digest(['determa-host-effect-journal-digest-1', proposed_journal])
    route_control_plan = [
        {'action': 'start_call', 'barrier': None, 'route_generation': None},
        {'action': 'await_barrier', 'barrier': 'route_resolved', 'route_generation': None},
        {'action': 'release_barrier', 'barrier': 'route_resolved', 'route_generation': None},
        {'action': 'await_barrier', 'barrier': 'before_commit_guard', 'route_generation': None},
        {'action': 'set_route_generation', 'barrier': None, 'route_generation': '8'},
        {'action': 'release_barrier', 'barrier': 'before_commit_guard', 'route_generation': None},
        {'action': 'observe_native_fate', 'barrier': None, 'route_generation': None},
    ]
    route_control_events = [
        {'event': 'started'},
        {'event': 'barrier_reached', 'barrier': 'route_resolved',
         'resolved_route_generation': '7', 'handler_reference': record['handler_reference'],
         'destination_binding_digest': record['destination_binding_digest']},
        {'event': 'released', 'barrier': 'route_resolved'},
        {'event': 'barrier_reached', 'barrier': 'before_commit_guard',
         'core_event_id': 'invoke-1',
         'proposed_checkpoint_digest': pending['execution_checkpoint_digest'],
         'proposed_journal_digest': proposed_journal_digest},
        {'event': 'configuration_changed', 'route_generation': '8'},
        {'event': 'released', 'barrier': 'before_commit_guard'},
        {'event': 'native_fate', 'guard_result': 'scope_generation_conflict',
         'transaction_fate': 'rolled_back',
         'checkpoint_digest': accepted['execution_checkpoint_digest'],
         'journal_digest': empty['host_effect_journal_digest']},
    ]
    cp = 'pending-checkpoint.json'
    vectors = [
        vector('first_producing_commit', ['19.2:original_operation_evidence'], 'produce', 'accepted-checkpoint.json', 'empty-journal.json', cp, 'unclaimed-journal.json', arguments={'original_request': producer_request}, response_file='producer-response.json', core=1),
        vector('committed_selected_intent', ['19.1:committed_selected_intent'], 'claim', cp, 'unclaimed-journal.json', cp, 'leased-journal.json', arguments={'effect_id': effect_id}, claims=1),
        vector('uncommitted_intent', ['19.1:uncommitted_intent'], 'dispatch', 'accepted-checkpoint.json', 'empty-journal.json', 'accepted-checkpoint.json', 'empty-journal.json', arguments={'effect_id': effect_id}, fault='before_intent_commit', caller_kind='aborted'),
        vector('route_generation_changed', ['19.2:route_generation_changed'], 'produce', 'accepted-checkpoint.json', 'empty-journal.json', 'accepted-checkpoint.json', 'empty-journal.json', arguments={'original_request': producer_request}, config={'route_generation': '7', 'route_authorized': True, 'destination_deduplication_proven': True, 'handler_authorized': True, 'credential_available': True, 'credential_generation': '1'}, fault='route_generation_changed_at_commit_guard', core=1, caller_kind='aborted', control_plan=route_control_plan, control_events=route_control_events),
        vector('equal_request_after_route_change', ['19.2:equal_request_after_route_change'], 'produce_replay', cp, 'unclaimed-journal.json', cp, 'unclaimed-journal.json', arguments={'original_request': producer_request}, config={'route_generation': '8', 'route_authorized': True, 'destination_deduplication_proven': True, 'handler_authorized': True, 'credential_available': True, 'credential_generation': '2'}, response_file='producer-response.json'),
        vector('revoked_dispatch', ['19.2:revoked_dispatch'], 'dispatch', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={'effect_id': effect_id}, config={'route_generation': '8', 'route_authorized': False, 'destination_deduplication_proven': True, 'handler_authorized': True, 'credential_available': True, 'credential_generation': '2'}, caller_kind='aborted'),
        vector('current_credential_revoked_dispatch', ['19.2:credential_revocation'], 'dispatch', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={'effect_id': effect_id}, config={'route_generation': '8', 'route_authorized': True, 'destination_deduplication_proven': True, 'handler_authorized': True, 'credential_available': False, 'credential_generation': '2'}, caller_kind='aborted'),
        vector('changed_alias_keeps_pinned_destination', ['19.2:immutable_route_after_alias_change'], 'dispatch', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={'effect_id': effect_id}, config={'route_generation': '8', 'route_authorized': True, 'destination_deduplication_proven': True, 'handler_authorized': True, 'credential_available': True, 'credential_generation': '2'}, provider=1),
        vector('accepted_outbox_pending_business', ['19.3:accepted_outbox_pending_business'], 'terminalize_outbox', cp, 'unclaimed-journal.json', 'confirmed-checkpoint.json', 'confirmed-journal.json', arguments={'effect_id': effect_id, 'status': 'confirmed'}),
        vector('sdk_native_objects_inside_handler', ['19.3:sdk_native_objects'], 'dispatch', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={'effect_id': effect_id}, provider=1),
        vector('wrong_token', ['19.4:wrong_business_token'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={**request, 'operation_token': 'wrong-token'}, response_file='rejected-effect_not_outstanding.json'),
        vector('wrong_scope', ['19.4:wrong_scope'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', auth={'scope_identity': 'other-scope', 'principal': 'worker-a', 'scope_authority_epoch': '3', 'trusted_host_now': '1893455999999999999'}, arguments=request, response_file='rejected-unauthorized_scope.json'),
        vector('wrong_principal', ['19.4:wrong_principal'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-b', 'scope_authority_epoch': '3', 'trusted_host_now': '1893455999999999999'}, arguments=request, response_file='rejected-unauthorized_scope.json'),
        vector('stale_epoch', ['19.4:stale_epoch'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-a', 'scope_authority_epoch': '4', 'trusted_host_now': '1893455999999999999'}, arguments=request, response_file='rejected-stale_scope_authority.json'),
        vector('stale_fence', ['19.4:stale_fence'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={**request, 'attempt_fence': '0'}, response_file='rejected-stale_attempt_fence_zero.json'),
        vector('claim_expired_at_exact_boundary', ['19.4:claim_expiry_boundary'], 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-a', 'scope_authority_epoch': '3', 'trusted_host_now': '1893456000000000000'}, arguments=request, response_file='rejected-stale_attempt_fence.json'),
        vector('expired_worker_after_outcome_commit', ['19.4:expired_worker_after_outcome'], 'submit_result', cp, 'outcome-recorded-journal.json', cp, 'outcome-recorded-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-a', 'scope_authority_epoch': '3', 'trusted_host_now': '1893456000000000000'}, arguments=request, response_file='rejected-stale_attempt_fence.json'),
        vector('first_terminal_result', ['19.4:first_terminal_result'], 'submit_result', cp, 'leased-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', claim_file='active-claim.json', arguments=request, response_file='committed-response.json', core=1),
        vector('equal_result_replay', ['19.4:equal_replay'], 'submit_result', 'admitted-checkpoint.json', 'result-admitted-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', claim_file='active-claim.json', arguments=request, response_file='committed-response.json'),
        vector('old_epoch_equal_replay_after_recovery', ['19.4:old_epoch_replay_refusal'], 'submit_result', 'admitted-checkpoint.json', 'result-admitted-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-a', 'scope_authority_epoch': '2', 'trusted_host_now': '1893456000000000000'}, arguments=request, response_file='rejected-stale_scope_authority.json'),
        vector('authorized_equal_replay_after_recovery', ['19.4:authorized_replay_after_expiry'], 'submit_result', 'admitted-checkpoint.json', 'result-admitted-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', claim_file='active-claim.json', auth={'scope_identity': SCOPE, 'principal': 'worker-a', 'scope_authority_epoch': '3', 'trusted_host_now': '1893456000000000000'}, arguments=request, response_file='committed-response.json'),
        vector('unequal_result_conflict', ['19.4:unequal_conflict'], 'submit_result', 'admitted-checkpoint.json', 'result-admitted-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', claim_file='active-claim.json', arguments={**request, 'payload': typed_value({'provider_reference': 'different'})}, response_file='rejected-effect_result_conflict.json'),
        vector('intent_commit_lost_response', ['19.5:intent_commit_lost_response'], 'produce', 'accepted-checkpoint.json', 'empty-journal.json', cp, 'unclaimed-journal.json', arguments={'original_request': producer_request}, fault='after_intent_commit_before_response', core=1, caller_kind='no_response'),
        vector('provider_acceptance_lost_before_outcome', ['19.5:provider_acceptance_lost_before_outcome'], 'dispatch', cp, 'leased-journal.json', cp, 'leased-journal.json', claim_file='active-claim.json', arguments={'effect_id': effect_id}, fault='after_provider_acceptance_before_outcome', provider=1, caller_kind='no_response'),
        vector('outcome_commit_lost_before_admission', ['19.5:outcome_commit_lost_before_admission'], 'submit_result', cp, 'leased-journal.json', cp, 'outcome-recorded-journal.json', claim_file='active-claim.json', arguments=request, fault='after_outcome_before_admission', caller_kind='no_response'),
        vector('admission_commit_lost_response', ['19.5:admission_commit_lost_response'], 'recover', cp, 'outcome-recorded-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', fault='after_admission_before_response', core=1, caller_kind='no_response'),
        vector('crash_after_intent_commit', ['19.5:crash_after_intent_commit'], 'recover', cp, 'unclaimed-journal.json', cp, 'unclaimed-journal.json', fault='after_intent_commit_before_dispatch'),
        vector('crash_after_provider_acceptance', ['19.5:provider_acceptance_before_outcome'], 'recover', cp, 'leased-journal.json', cp, 'ambiguous-journal.json', claim_file='active-claim.json', fault='after_provider_acceptance_before_outcome'),
        vector('crash_after_outcome_commit', ['19.5:outcome_before_admission'], 'recover', cp, 'outcome-recorded-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', fault='after_outcome_before_admission', core=1),
        vector('crash_after_admission_commit', ['19.5:admission_before_response'], 'recover', 'admitted-checkpoint.json', 'result-admitted-journal.json', 'admitted-checkpoint.json', 'result-admitted-journal.json', fault='after_admission_before_response', response_file='committed-response.json'),
        vector('safe_retry_report', ['19.3:retryable_report'], 'submit_result', cp, 'leased-journal.json', cp, 'retryable-journal.json', claim_file='active-claim.json', arguments=retry_request, response_file='retryable-response.json'),
        *[vector('retry_safety_' + failure, ['19.3:independent_retry_safety_' + failure],
                 'submit_result', cp, 'leased-journal.json', cp, 'leased-journal.json',
                 claim_file='active-claim.json', arguments=retry_request,
                 fault='retry_safety_' + failure,
                 response_file='rejected-host_capability_mismatch.json')
          for failure in ('missing', 'boolean', 'fabricated', 'wrong_work', 'wrong_destination', 'verifier_unavailable')],
        vector('duplicate_equal_retry_report', ['19.3:equal_retry_report'], 'submit_result', cp, 'retryable-journal.json', cp, 'retryable-journal.json', claim_file='active-claim.json', arguments=retry_request, response_file='retryable-response.json'),
        vector('duplicate_unequal_retry_report', ['19.3:conflicting_retry_report'], 'submit_result', cp, 'retryable-journal.json', cp, 'retryable-journal.json', claim_file='active-claim.json', arguments={**retry_request, 'payload': typed_value({'unexpected': 'changed'})}, response_file='rejected-effect_result_conflict.json'),
        vector('safe_retry_new_fence', ['19.3:safe_retry_new_fence'], 'claim', cp, 'retryable-journal.json', cp, 'retry-claim-journal.json', arguments={'effect_id': effect_id}, claims=1),
        vector('duplicate_ambiguous_report', ['19.3:equal_ambiguous_report'], 'submit_result', cp, 'ambiguous-journal.json', cp, 'ambiguous-journal.json', claim_file='active-claim.json', arguments={**request, 'outcome_kind': 'ambiguous', 'payload': typed_value({})}, response_file='ambiguous-response.json'),
        vector('cancel_before_claim', ['19.3:cancel_before_claim'], 'cancel_effect', cp, 'unclaimed-journal.json', cp, 'preclaim-cancelled-journal.json', arguments=cancel_request, response_file='cancel-response.json'),
        vector('cancel_admission_recovery', ['19.3:cancel_admission_recovery'], 'recover', cp, 'preclaim-cancelled-journal.json', 'cancelled-admitted-checkpoint.json', 'cancelled-admitted-journal.json', fault='after_cancel_outcome_before_admission', core=1),
        vector('claim_after_preclaim_cancel_refused', ['19.3:preclaim_cancel_blocks_dispatch'], 'claim', cp, 'preclaim-cancelled-journal.json', cp, 'preclaim-cancelled-journal.json', arguments={'effect_id': effect_id}, caller_kind='aborted'),
        vector('cancel_before_claim_replay', ['19.3:cancel_equal_replay'], 'cancel_effect', cp, 'preclaim-cancelled-journal.json', cp, 'preclaim-cancelled-journal.json', arguments=cancel_request, response_file='cancel-response.json'),
        vector('cancel_after_possible_call', ['19.3:cancel_after_possible_call'], 'cancel_effect', cp, 'ambiguous-journal.json', cp, 'postcall-cancelled-journal.json', arguments={**cancel_request, 'operation_id': 'cancel-after-call'}, response_file='postcall-cancel-response.json'),
        vector('ambiguous_retry_with_proven_deduplication', ['19.3:ambiguous_retry_with_proof'], 'claim', cp, 'ambiguous-journal.json', cp, 'ambiguous-retry-claim-journal.json', arguments={'effect_id': effect_id}, claims=1),
        *[vector('ambiguous_retry_safety_' + failure, ['19.3:independent_ambiguous_retry_' + failure],
                 'claim', cp, 'ambiguous-journal.json', cp, 'ambiguous-journal.json',
                 arguments={'effect_id': effect_id}, fault='retry_safety_' + failure,
                 caller_kind='aborted')
          for failure in ('missing', 'boolean', 'fabricated', 'wrong_work', 'wrong_destination', 'verifier_unavailable')],
        vector('ambiguous_retry_requires_proof', ['19.3:ambiguous_retry_proof'], 'claim', cp, 'ambiguous-journal.json', cp, 'ambiguous-journal.json', arguments={'effect_id': effect_id}, config={'route_generation': '7', 'route_authorized': True, 'destination_deduplication_proven': False, 'handler_authorized': True, 'credential_available': True, 'credential_generation': '1'}, caller_kind='aborted'),
        vector('missing_cancel_mapping_refusal', ['19.3:missing_cancelled_mapping'], 'cancel_effect', cp, 'no-cancel-mapping-journal.json', cp, 'no-cancel-mapping-journal.json', arguments=cancel_request, response_file='cancel-rejected-response.json'),
    ]
    pins = {str(path.relative_to(spec_root)): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((spec_root / 'examples/effects').glob('*.json'))}
    case_mapping = {
        'host-native-effect-cases-v1.json': {
            'committed_selected_intent': 'committed_selected_intent',
            'uncommitted_intent': 'uncommitted_intent',
            'route_generation_changed': 'route_generation_changed',
            'equal_request_after_route_change': 'equal_request_after_route_change',
            'revoked_dispatch': 'revoked_dispatch',
            'accepted_outbox_pending_business': 'accepted_outbox_pending_business',
            'wrong_token': 'wrong_token',
            'wrong_scope_or_principal': ['wrong_scope', 'wrong_principal'],
            'old_epoch_or_fence': ['claim_expired_at_exact_boundary', 'stale_fence'],
            'equal_and_conflicting_result': ['equal_result_replay', 'unequal_result_conflict'],
            'crash_after_provider_acceptance': 'crash_after_provider_acceptance',
            'crash_after_outcome_commit': 'crash_after_outcome_commit',
            'cancellation_before_claim': ['cancel_before_claim', 'claim_after_preclaim_cancel_refused'],
            'cancellation_after_possible_call': 'cancel_after_possible_call',
        },
        'result-admission-cases-v1.json': {
            'first_terminal_result': 'first_terminal_result',
            'equal_replay': 'equal_result_replay',
            'wrong_business_token': 'wrong_token',
            'stale_attempt_fence': 'stale_fence',
            'unequal_result_after_commit': 'unequal_result_conflict',
            'wrong_worker_principal': 'wrong_principal',
            'stale_scope_epoch': 'stale_epoch',
            'wrong_scope': 'wrong_scope',
            'claim_expired_at_exact_boundary': 'claim_expired_at_exact_boundary',
            'expired_worker_after_outcome_commit': 'expired_worker_after_outcome_commit',
            'old_epoch_equal_replay_after_recovery': 'old_epoch_equal_replay_after_recovery',
            'authorized_equal_replay_after_recovery': 'authorized_equal_replay_after_recovery',
        },
        'effect-cancellation-cases-v1.json': {
            'first_preclaim_cancel': 'cancel_before_claim',
            'equal_cancel_replay': 'cancel_before_claim_replay',
            'missing_cancelled_mapping': 'missing_cancel_mapping_refusal',
            'after_possible_provider_call': 'cancel_after_possible_call',
        },
    }
    case_mapping = {file_name: {name: value if isinstance(value, list) else [value]
                                for name, value in coverage.items()}
                    for file_name, coverage in case_mapping.items()}
    handler_sources = {str(path.relative_to(CASE)): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted((CASE / 'handler').glob('test_handler.*'))}
    manifest = {'handler_sources': handler_sources, 'format': 'determa.committed_native_effects.vectors', 'schema_version': 1,
                'spec_commit': SPEC_COMMIT, 'normative_examples': pins,
                'normative_case_coverage': case_mapping, 'vectors': vectors}
    files = {
        'handler-closure.json': closure,
        'destination-configuration.json': destination_configuration,
        'no-cancel-mapping-journal.json': no_cancel_journal,
        'producer-request.json': producer_request, 'producer-response.json': producer_response,
        'ambiguous-retry-claim-journal.json': ambiguous_retry_journal,
        'retryable-journal.json': retry_journal, 'retry-claim-journal.json': retry_claim_journal,
        'retryable-response.json': retry_response, 'retry-request.json': retry_request,
        'cancel-rejected-response.json': cancel_rejected_response,
        'confirmed-checkpoint.json': confirmed_checkpoint,
        'cancelled-admitted-checkpoint.json': cancelled_admitted_checkpoint,
        'confirmed-journal.json': confirmed_journal,
        'cancelled-admitted-journal.json': cancelled_admitted_journal,
        'empty-journal.json': empty, 'postcall-cancelled-journal.json': postcall,
        'postcall-cancel-response.json': postcall_response, 'vectors.json': manifest,
        'created-checkpoint.json': created, 'accepted-checkpoint.json': accepted,
        'pending-checkpoint.json': pending, 'admitted-checkpoint.json': admitted,
        'unclaimed-journal.json': unclaimed, 'leased-journal.json': leased,
        'outcome-recorded-journal.json': recorded, 'result-admitted-journal.json': final,
        'ambiguous-journal.json': ambiguous, 'preclaim-cancelled-journal.json': cancelled,
        'active-claim.json': claim, 'result-request.json': request,
        'cancel-request.json': cancel_request, 'committed-response.json': committed_response,
        'ambiguous-response.json': ambiguous_response, 'cancel-response.json': cancel_response,
        **{f'rejected-{code}.json': response for code, response in rejected.items()},
    }
    producer_reference = response_reference('produce-1', producer_response)
    for name, value in files.items():
        if name.endswith('-journal.json') and name != 'empty-journal.json':
            body = copy.deepcopy(value)
            body.pop('host_effect_journal_digest')
            body['operation_response_references'].append(producer_reference)
            body['operation_response_references'].sort(key=lambda item: item['operation_id'].encode('utf-8'))
            body['host_effect_journal_digest'] = digest(['determa-host-effect-journal-digest-1',
                                                         {key: val for key, val in body.items() if key != 'host_effect_journal_digest'}])
            files[name] = body
    return {CASE / (name if 'checkpoint.json' in name else 'data/' + name): encode(value)
            for name, value in files.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--spec-root', type=Path, required=True)
    args = parser.parse_args()
    files = generate(args.spec_root)
    for path, expected in files.items():
        if args.check:
            if not path.exists() or path.read_bytes() != expected:
                raise SystemExit(f'outdated generated fixture: {path}')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    print(f'{"checked" if args.check else "generated"} {len(files)} committed effect artifacts')


if __name__ == '__main__':
    main()
