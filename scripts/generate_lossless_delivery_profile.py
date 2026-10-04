#!/usr/bin/env python3
"""Build §21 witnesses from the pinned specification examples and real bundle."""
from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path

from generate_version1_vectors import seal_checkpoint
from validate_conformance import hash_value, expected_core_step_result

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT.parent / 'determa-state-spec'
TARGET = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'
EXAMPLES = ('delivery-v1-cases', 'execution-checkpoint-transfer-v1',
            'queue-placement-checkpoints-v1', 'outbound-checkpoint-lifecycle-v1',
            'outbound-destination-receipts-v1')


def render(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()


def build(spec: Path) -> dict[str, bytes]:
    source = spec / 'examples/delivery'
    examples = {name: json.loads((source / f'{name}.json').read_text()) for name in EXAMPLES}
    cases = {item['name']: item for item in examples['delivery-v1-cases']['cases']}
    checkpoints = copy.deepcopy(examples['execution-checkpoint-transfer-v1'])
    admission = cases['first_committed_admission']
    first_request = admission['request']
    binding = examples['delivery-v1-cases']['admission_binding']
    empty = {'checkpoint': 'before-admission-checkpoint-v1.json', 'bindings': [],
             'dead_letters': [], 'source_acknowledgements': [], 'provider_dispatches': 0}
    committed = {'checkpoint': 'after-admission-checkpoint-v1.json', 'bindings': [binding],
                 'dead_letters': [], 'source_acknowledgements': [
                     {'source_scope': first_request['source']['source_scope'],
                      'source_delivery_id': first_request['source']['source_delivery_id']}],
                 'provider_dispatches': 0}

    def vector(name: str, operation: str, request: dict, before: dict, after: dict,
               response: dict, *, fault: str | None = None, replay_of: str | None = None) -> dict:
        return {'name': name, 'operation': operation, 'request': copy.deepcopy(request),
                'before': copy.deepcopy(before), 'after': copy.deepcopy(after),
                'fault_injection': fault, 'replay_of': replay_of,
                'expected_response': copy.deepcopy(response)}

    vectors = [
        vector('first_committed_admission', 'ingest', first_request, empty, committed,
               admission['response']),
        vector('equal_redelivery_after_lost_ack', 'ingest', first_request, committed,
               committed, admission['response'], replay_of='first_committed_admission'),
        vector('unequal_source_identity_conflict', 'ingest',
               cases['unequal_source_identity_conflict']['request'], committed, committed,
               cases['unequal_source_identity_conflict']['response']),
        vector('precommit_write_failure_keeps_source', 'ingest', first_request, empty,
               empty, cases['precommit_write_failure_keeps_source']['response'],
               fault='atomic_commit_failure'),
        vector('crash_before_atomic_commit', 'ingest', first_request, empty, empty,
               {'kind': 'no_response'}, fault='crash_before_commit'),
        vector('crash_after_atomic_commit_before_ack', 'ingest', first_request, empty,
               {**committed, 'source_acknowledgements': []}, {'kind': 'no_response'},
               fault='crash_after_commit_before_ack'),
        vector('redelivery_after_commit_crash', 'ingest', first_request,
               {**committed, 'source_acknowledgements': []}, committed,
               admission['response'], replay_of='crash_after_atomic_commit_before_ack'),
    ]
    stale = vector('stale_owner_equal_replay_refused', 'ingest', first_request,
                   {**committed, 'source_acknowledgements': []},
                   {**committed, 'source_acknowledgements': []},
                   {'kind': 'typed_failure', 'code': 'stale_scope_authority',
                    'acknowledge_source': False}, replay_of='first_committed_admission')
    stale['authority_context'] = {
        'scope_identity': 'orders/inbox', 'claimed_epoch': '1',
        'current_epoch': '2', 'guarantee': 'authoritative_scope_fencing'}
    vectors.append(stale)
    second = copy.deepcopy(first_request)
    second['source']['source_delivery_id'] = 'broker-43'
    second['source']['content']['content_value'] = 'U2Vjb25k'
    second['source']['source_content_digest'] = hash_value([
        'determa-delivery-source-content-digest-1', '1',
        second['source']['source_scope'], second['source']['source_delivery_id'],
        second['source']['content']['content_kind'], second['source']['content']['content_value']])
    second['envelope']['event_id'] = 'received-2'
    second['envelope']['cause_id'] = 'received-2'
    second['envelope']['event'] = 'unknown_event'
    first_owned = copy.deepcopy(cases['precommit_write_failure_keeps_source']['response'])
    first_owned['event_id'] = 'received-1'
    first_owned['reason'] = 'invalid_delivery'
    second_owned = copy.deepcopy(first_owned)
    second_owned.update(source_delivery_id='broker-43',
                        source_content_digest=second['source']['source_content_digest'],
                        event_id='received-2', reason='invalid_delivery')
    vectors.append(vector('batch_second_invalid_keeps_all_source_owned', 'ingest_batch',
                          [first_request, second], empty, empty,
                          [first_owned, second_owned]))
    pressure = vector('source_ordered_pressure_blocks_later_item', 'ingest',
                      second, empty, empty,
                      {**second_owned, 'reason': 'backpressure'},
                      fault='earlier_source_item_unresolved')
    pressure['ordering_context'] = {
        'mode': 'source_ordered', 'source_scope': 'orders/inbox',
        'unresolved_source_delivery_id': 'broker-42'}
    vectors.append(pressure)
    def other(name: str, operation: str, request: dict, before_checkpoint: str,
              after_checkpoint: str, response: dict, *, before: dict | None = None,
              after: dict | None = None, fault: str | None = None,
              replay_of: str | None = None) -> None:
        vectors.append({'name': name, 'operation': operation, 'request': request,
                        'before': copy.deepcopy(before or {**empty, 'checkpoint': before_checkpoint}),
                        'after': copy.deepcopy(after or {**empty, 'checkpoint': after_checkpoint}),
                        'fault_injection': fault, 'replay_of': replay_of,
                        'expected_response': response})

    other('source_owned_backpressure', 'ingest', first_request,
          'before-admission-checkpoint-v1.json', 'before-admission-checkpoint-v1.json',
          {**cases['source_owned_backpressure']['response'], 'event_id': 'received-1'},
          fault='backpressure')
    other('removed_target_keeps_source', 'ingest', first_request,
          'before-admission-checkpoint-v1.json', 'before-admission-checkpoint-v1.json',
          {**cases['removed_target_keeps_source']['response'], 'event_id': 'received-1'},
          fault='target_removed')
    other('machine_unhandled_after_admission', 'process',
          {'event_id': first_request['envelope']['event_id']},
          'after-admission-checkpoint-v1.json', 'after-unhandled-checkpoint-v1.json',
          cases['machine_unhandled_after_admission']['response'],
          before=committed, after={**committed, 'checkpoint': 'after-unhandled-checkpoint-v1.json'})
    dead_response = cases['first_durable_poison_transfer']['response']
    dead_request = {'delivery_message_kind': 'ingress_request',
                    'source': dead_response['record']['source'], 'envelope': None,
                    'delivery_mode': 'input'}
    dead_store = {**empty, 'dead_letters': [dead_response['record']],
                  'source_acknowledgements': [{
                      'source_scope': dead_request['source']['source_scope'],
                      'source_delivery_id': dead_request['source']['source_delivery_id']}]}
    other('first_durable_poison_transfer', 'dead_letter', dead_request,
          'before-admission-checkpoint-v1.json', 'before-admission-checkpoint-v1.json',
          dead_response, after=dead_store)
    other('equal_poison_redelivery', 'dead_letter', dead_request,
          'before-admission-checkpoint-v1.json', 'before-admission-checkpoint-v1.json',
          dead_response, before=dead_store, after=dead_store,
          replay_of='first_durable_poison_transfer')
    queue_names = ('after_second_admission', 'after_deferral',
                   'after_received_admission', 'after_recall')
    for label in queue_names:
        output_name = f'{label.replace("_", "-")}-checkpoint-v1.json'
        checkpoints[output_name] = examples['queue-placement-checkpoints-v1'][label]
    for name, operation, prior in (
            ('deferred_keeps_original_acceptance', 'defer', 'after-second-admission-checkpoint-v1.json'),
            ('structural_recall_reuses_acceptance', 'recall', 'after-received-admission-checkpoint-v1.json')):
        selected = cases[name]
        next_checkpoint = f'{selected["queue_checkpoint_snapshot"].replace("_", "-")}-checkpoint-v1.json'
        other(name, operation, {'event_id': selected['response']['event_id']},
              prior, next_checkpoint, selected['response'])

    # The §21 outbound prose example uses a synthetic effect id. These runnable
    # witnesses instead retain the actual emitted effect and producing receipt
    # from checkpoint-02's valid format-1 machine.
    native = ROOT / 'conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox'
    output_machine = (native / 'machine.yaml').read_bytes()
    pending = json.loads((native / 'pending-checkpoint-v1.json').read_text())
    native_confirmed = json.loads((native / 'terminal-confirmed-checkpoint-v1.json').read_text())
    effect = pending['pending_outbox_intents'][0]['intent']['effect_id']
    ambiguous = copy.deepcopy(pending)
    ambiguous['revision'] = '3'
    ambiguous['pending_outbox_intents'][0]['state_revision'] = '3'
    ambiguous['pending_outbox_intents'][0]['delivery_state'] = {
        'status': 'ambiguous', 'reason_code': 'acceptance_unknown'}
    ambiguous = seal_checkpoint(ambiguous)
    confirmed = copy.deepcopy(pending)
    confirmed['revision'] = '3'
    confirmed['pending_outbox_intents'].pop(0)
    confirmed['next_outbox_terminal_sequence'] = '1'
    terminal_record = copy.deepcopy(native_confirmed['terminal_outbox_records'][0])
    terminal_record['committed_revision'] = '3'
    confirmed['terminal_outbox_records'].append(terminal_record)
    confirmed = seal_checkpoint(confirmed)
    dead_outbound = copy.deepcopy(confirmed)
    dead_outbound['terminal_outbox_records'][0]['outcome'] = {
        'status': 'dead_lettered', 'reason_code': 'destination_policy_rejected'}
    dead_outbound = seal_checkpoint(dead_outbound)
    native_snapshots = {'native-pending-checkpoint-v1.json': pending,
                        'native-ambiguous-checkpoint-v1.json': ambiguous,
                        'native-confirmed-checkpoint-v1.json': confirmed,
                        'native-dead-lettered-checkpoint-v1.json': dead_outbound}

    def outbound_response(checkpoint: dict, outcome: str, reason: str | None,
                          destination_receipt_id: str | None) -> tuple[dict, dict | None]:
        current = next((item for item in checkpoint['pending_outbox_intents']
                        if item['intent']['effect_id'] == effect), None)
        terminal = next((item for item in checkpoint['terminal_outbox_records']
                         if item['intent']['effect_id'] == effect), None)
        location = ({'kind': 'pending', 'state_revision': current['state_revision']}
                    if current else {'kind': 'terminal',
                                    'terminal_sequence': terminal['terminal_sequence'],
                                    'committed_revision': terminal['committed_revision']})
        response = {'delivery_message_kind': 'outbound_decision', 'effect_id': effect,
                    'outcome': outcome, 'reason_code': reason,
                    'decision_authority': {'kind': 'host_profile', 'identifier': 'orders-host'},
                    'evidence': {'checkpoint': {'root_instance_id': checkpoint['root_instance_id'],
                                               'checkpoint_revision': checkpoint['revision'],
                                               'execution_checkpoint_digest': checkpoint['execution_checkpoint_digest']},
                                 'outbox_location': location},
                    'destination_receipt_id': destination_receipt_id,
                    'retention': {'profile': 'permanent', 'minimum_replay_until': None}}
        receipt = None
        if destination_receipt_id:
            receipt = {'delivery_message_kind': 'outbound_destination_receipt',
                       'root_instance_id': checkpoint['root_instance_id'],
                       'effect_id': effect, 'terminal_sequence': terminal['terminal_sequence'],
                       'outcome': outcome, 'reason_code': reason,
                       'destination_receipt_id': destination_receipt_id,
                       'destination_authority': {'kind': 'destination', 'identifier': 'test-durable-destination'},
                       'execution_checkpoint_digest': checkpoint['execution_checkpoint_digest']}
            receipt['outbound_destination_receipt_digest'] = hash_value([
                'determa-outbound-destination-receipt-digest-1', '1', receipt])
        return response, receipt

    for name, next_checkpoint, outcome, reason, destination_id in (
            ('outbound_ambiguous_remains_pending', 'native-ambiguous-checkpoint-v1.json',
             'ambiguous', 'acceptance_unknown', None),
            ('outbound_confirmed_is_destination_acceptance', 'native-confirmed-checkpoint-v1.json',
             'confirmed', None, 'destination-acceptance-actual-1'),
            ('outbound_dead_letter_transfer', 'native-dead-lettered-checkpoint-v1.json',
             'dead_lettered', 'destination_policy_rejected', 'destination-dead-letter-actual-1')):
        checkpoint = native_snapshots[next_checkpoint]
        response, receipt = outbound_response(checkpoint, outcome, reason, destination_id)
        before = {**empty, 'checkpoint': 'native-pending-checkpoint-v1.json'}
        after = {**empty, 'checkpoint': next_checkpoint,
                 'destination_receipts': [receipt] if receipt else []}
        before['destination_receipts'] = []
        other(name, 'deliver_outbound',
              {'effect_id': effect, 'provider_result': {'outcome': outcome,
               'reason_code': reason, 'destination_receipt_id': destination_id}},
              before['checkpoint'], after['checkpoint'], response, before=before, after=after)

    by_name = {item['name']: item for item in vectors}
    invalid_vectors = []
    malformed_base64 = {'nonzero_one_byte_pad_bits', 'nonzero_two_byte_pad_bits',
                        'missing_padding', 'trailing_whitespace', 'excess_padding',
                        'alternate_alphabet'}
    for invalid in examples['delivery-v1-cases']['invalid_cases']:
        invalid_vectors.append({'name': invalid['name'], 'operation': 'parse_delivery',
                                'candidate': invalid['value'], 'before': empty,
                                'after': empty,
                                'expected_failure': ('malformed_delivery' if invalid['name']
                                                     in malformed_base64 else 'invalid_delivery'),
                                'acknowledge_source': False})
    link_sources = {
        'admission_wrong_receipt_kind': ('first_committed_admission',
                                         ('evidence', 'operation_kind'), 'event_terminal'),
        'admission_dangling_receipt': ('first_committed_admission',
                                       ('evidence', 'receipt_sequence'), '9'),
        'terminal_wrong_receipt_kind': ('machine_unhandled_after_admission',
                                        ('evidence', 'operation_kind'), 'acceptance'),
        'deferred_origin_is_terminal_receipt': ('deferred_keeps_original_acceptance',
                                                ('origin', 'acceptance_receipt_sequence'), '2'),
        'recalled_wrong_queue_identity': ('structural_recall_reuses_acceptance',
                                          ('queue_sequence',), '9'),
        'outbound_dangling_terminal_sequence': ('outbound_dead_letter_transfer',
                                                 ('evidence', 'outbox_location', 'terminal_sequence'), '9'),
        'outbound_wrong_effect_identity': ('outbound_confirmed_is_destination_acceptance',
                                           ('effect_id',), 'sha256:' + 'c' * 64),
        'outbound_wrong_pending_revision': ('outbound_ambiguous_remains_pending',
                                            ('evidence', 'outbox_location', 'state_revision'), '0'),
        'outbound_dangling_destination_receipt': ('outbound_confirmed_is_destination_acceptance',
                                                  ('destination_receipt_id',), 'missing-destination-receipt'),
    }
    for name, (source_name, path, wrong) in link_sources.items():
        source_vector = by_name[source_name]
        candidate = copy.deepcopy(source_vector['expected_response'])
        member = candidate
        for key in path[:-1]:
            member = member[key]
        member[path[-1]] = wrong
        invalid_vectors.append({'name': name, 'operation': 'validate_evidence',
                                'candidate': candidate,
                                'before': source_vector['after'],
                                'after': source_vector['after'],
                                'expected_failure': 'invalid_delivery_evidence',
                                'acknowledge_source': False})
    for name, raw in (
            ('duplicate_json_key', b'{"delivery_message_kind":"ingress_request","delivery_message_kind":"ingress_request"}'),
            ('nonfinite_json', b'{"content_value":NaN}'),
            ('invalid_utf8_json', b'{"content_value":"\xff"}')):
        invalid_vectors.append({'name': name, 'operation': 'parse_delivery_bytes',
                                'candidate': base64.b64encode(raw).decode('ascii'),
                                'before': empty, 'after': empty,
                                'expected_failure': 'malformed_delivery',
                                'acknowledge_source': False})
    for name, typed in (
            ('unordered_transport_map', ['map', [['z', ['integer', '1']],
                                               ['a', ['integer', '2']]]]),
            ('nonfinite_transport_float', ['float', '7ff8000000000000']),
            ('negative_zero_transport_float', ['float', '8000000000000000']),
            ('noncanonical_transport_integer', ['integer', '01'])):
        candidate = copy.deepcopy(first_request)
        source_item = candidate['source']
        source_item['content'] = {'content_kind': 'canonical_transport_value',
                                  'content_value': typed}
        source_item['source_content_digest'] = hash_value([
            'determa-delivery-source-content-digest-1', '1',
            source_item['source_scope'], source_item['source_delivery_id'],
            source_item['content']['content_kind'], typed])
        invalid_vectors.append({'name': name, 'operation': 'parse_delivery',
                                'candidate': candidate, 'before': empty, 'after': empty,
                                'expected_failure': 'invalid_delivery',
                                'acknowledge_source': False})
    document = {'lossless_delivery_format': 'determa.conformance.lossless_delivery',
                'lossless_delivery_schema_version': 1, 'vectors': vectors,
                'invalid_vectors': invalid_vectors,
                'normative_examples': examples}
    output = {'delivery-vectors-v1.json': render(document),
              'machine.yaml': (spec / 'examples/portable-event-deferral.yaml').read_bytes(),
              'outbox-machine.yaml': output_machine,
              'native-emission-core-step-result-v1.json': render(expected_core_step_result(pending))}
    for label, checkpoint in checkpoints.items():
        if label.endswith('.json'):
            output[label] = render(checkpoint)
        elif label.startswith(('before_', 'after_')):
            output[f'{label.replace("_", "-")}-checkpoint-v1.json'] = render(checkpoint)
    for label, checkpoint in native_snapshots.items():
        output[label] = render(checkpoint)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--spec-root', type=Path, default=SPEC)
    args = parser.parse_args()
    output = build(args.spec_root)
    if args.check:
        stale = [name for name, data in output.items()
                 if not (TARGET / name).is_file() or (TARGET / name).read_bytes() != data]
        extra = set(path.name for path in TARGET.iterdir()) - set(output) - {'test.yaml'}
        if stale or extra:
            parser.error(f'stale or extra lossless delivery fixtures: {stale}, {sorted(extra)}')
    else:
        TARGET.mkdir(parents=True, exist_ok=True)
        for name, data in output.items():
            (TARGET / name).write_bytes(data)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
