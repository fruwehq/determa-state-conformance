"""Independent ownership and receipt checks for the optional §21 profile."""
from __future__ import annotations

import base64
import copy
import json
import math
import re
import struct
from pathlib import Path

from validate_conformance import (ValidationFailure, analyze_artifact, canonical_json_bytes,
                                  hash_value, validate_typed_value_canonical,
                                  analyze_json_artifact_source)

NORM = ('delivery-v1-cases', 'execution-checkpoint-transfer-v1',
        'queue-placement-checkpoints-v1', 'outbound-checkpoint-lifecycle-v1',
        'outbound-destination-receipts-v1')
VECTORS = ('first_committed_admission', 'equal_redelivery_after_lost_ack',
           'unequal_source_identity_conflict', 'precommit_write_failure_keeps_source',
           'crash_before_atomic_commit', 'crash_after_atomic_commit_before_ack',
           'redelivery_after_commit_crash')
ADDITIONAL = ('source_owned_backpressure', 'removed_target_keeps_source',
              'machine_unhandled_after_admission', 'first_durable_poison_transfer',
              'equal_poison_redelivery', 'deferred_keeps_original_acceptance',
              'structural_recall_reuses_acceptance',
              'outbound_ambiguous_remains_pending',
              'outbound_confirmed_is_destination_acceptance',
              'outbound_dead_letter_transfer')


def fail(message: str) -> None:
    raise ValidationFailure(f'lossless delivery: {message}')


def same(left: object, right: object, description: str) -> None:
    if canonical_json_bytes(left) != canonical_json_bytes(right):
        fail(description)


def valid_source(source: dict) -> None:
    content = source['content']
    value = content['content_value']
    if content['content_kind'] == 'original_bytes_base64':
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            fail(f'noncanonical Base64: {error}')
        if base64.b64encode(decoded).decode('ascii') != value:
            fail('noncanonical Base64 pad bits or spelling')
    else:
        validate_typed_value_canonical(value, 'transport content')
        def exact_typed(item: object) -> None:
            if not isinstance(item, list) or not item or not isinstance(item[0], str):
                fail('transport content lacks an exact typed projection')
            tag = item[0]
            if tag == 'null':
                if len(item) != 1:
                    fail('invalid typed null')
            elif tag == 'boolean':
                if len(item) != 2 or type(item[1]) is not bool:
                    fail('invalid typed boolean')
            elif tag == 'string':
                if len(item) != 2 or type(item[1]) is not str:
                    fail('invalid typed string')
            elif tag == 'integer':
                if (len(item) != 2 or type(item[1]) is not str or
                    not re.fullmatch(r'0|-?[1-9][0-9]*', item[1]) or
                    not -(2**63) <= int(item[1]) < 2**63):
                    fail('invalid exact typed integer')
            elif tag == 'float':
                if (len(item) != 2 or type(item[1]) is not str or
                    not re.fullmatch(r'[0-9a-f]{16}', item[1])):
                    fail('invalid typed binary64 bits')
                number = struct.unpack('>d', bytes.fromhex(item[1]))[0]
                if not math.isfinite(number) or item[1] == '8000000000000000':
                    fail('nonfinite or negative-zero typed float')
            elif tag == 'list':
                if len(item) != 2 or type(item[1]) is not list:
                    fail('invalid typed list')
                for child in item[1]:
                    exact_typed(child)
            elif tag == 'map':
                if len(item) != 2 or type(item[1]) is not list:
                    fail('invalid typed map')
                keys = []
                for pair in item[1]:
                    if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str:
                        fail('invalid typed map entry')
                    keys.append(pair[0])
                    exact_typed(pair[1])
                if keys != sorted(set(keys), key=lambda key: key.encode('utf-8')):
                    fail('unordered or duplicate typed map key')
            else:
                fail('unknown typed value tag')
        exact_typed(value)
    digest = hash_value(['determa-delivery-source-content-digest-1', '1',
                         source['source_scope'], source['source_delivery_id'],
                         content['content_kind'], value])
    if source['source_content_digest'] != digest:
        fail('source content digest differs from exact kind, scope, id, or content')


def checkpoint_evidence(checkpoint: dict) -> dict:
    return {'root_instance_id': checkpoint['root_instance_id'],
            'checkpoint_revision': checkpoint['revision'],
            'execution_checkpoint_digest': checkpoint['execution_checkpoint_digest']}


def validate_profile(case: Path, test: dict, artifacts: set[Path], spec_root: Path) -> int:
    expected_files = {'delivery-vectors-v1.json',
                      'before-admission-checkpoint-v1.json',
                      'after-admission-checkpoint-v1.json',
                      'after-unhandled-checkpoint-v1.json',
                      'after-second-admission-checkpoint-v1.json',
                      'after-deferral-checkpoint-v1.json',
                      'after-received-admission-checkpoint-v1.json',
                      'after-recall-checkpoint-v1.json',
                      'native-pending-checkpoint-v1.json',
                      'native-ambiguous-checkpoint-v1.json',
                      'native-confirmed-checkpoint-v1.json',
                      'native-dead-lettered-checkpoint-v1.json',
                      'native-emission-core-step-result-v1.json'}
    if {path.name for path in artifacts} != expected_files:
        fail('artifact manifest differs from exact profile closure')
    profile = analyze_artifact(case / 'delivery-vectors-v1.json').document
    if profile is None:
        fail('invalid profile source JSON')
    names = [v['name'] for v in profile['vectors']]
    if names != list(VECTORS + ('stale_owner_equal_replay_refused',
                               'batch_second_invalid_keeps_all_source_owned',
                               'source_ordered_pressure_blocks_later_item') + ADDITIONAL) or names != test['lossless_delivery_vectors']:
        fail('closed vector inventory differs')
    norms = profile['normative_examples']
    if set(norms) != set(NORM):
        fail('normative example inventory differs')
    for name in NORM:
        source = spec_root / 'examples/delivery' / f'{name}.json'
        same(norms[name], json.loads(source.read_text(encoding='utf-8')),
             f'{name} differs from pinned specification')
    snapshots = norms['execution-checkpoint-transfer-v1']
    for stage in ('before_admission', 'after_admission', 'after_unhandled'):
        same(analyze_artifact(case / f'{stage.replace("_", "-")}-checkpoint-v1.json').document,
             snapshots[stage], f'{stage} checkpoint differs from normative snapshot')
    if (len(norms['delivery-v1-cases']['cases']) != 14 or
        len(norms['delivery-v1-cases']['invalid_cases']) != 11 or
        len(norms['delivery-v1-cases']['invalid_link_cases']) != 9):
        fail('normative §21 case inventory incomplete')
    cases = {item['name']: item for item in norms['delivery-v1-cases']['cases']}
    first = cases['first_committed_admission']
    request = first['request']
    valid_source(request['source'])
    binding = norms['delivery-v1-cases']['admission_binding']
    unsealed = {key: value for key, value in binding.items() if key != 'admission_binding_digest'}
    if binding['admission_binding_digest'] != hash_value([
            'determa-admission-binding-digest-1', '1', unsealed]):
        fail('admission binding digest does not cover retained evidence')
    accepted = snapshots['after_admission']
    receipt = accepted['operation_receipts'][1]
    entry = accepted['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'][0]
    expected_envelope_digest = hash_value(['determa-inbox-envelope-digest-1', '1',
                                           accepted['root_instance_id'], 'input', request['envelope']])
    if (receipt['operation_kind'] != 'acceptance' or
        receipt['request_digest'] != expected_envelope_digest or
        entry['envelope_digest'] != expected_envelope_digest or
        entry['envelope'] != request['envelope'] or
        binding['envelope_digest'] != expected_envelope_digest or
        binding['evidence'] != first['response']['evidence'] or
        binding['source_content_digest'] != request['source']['source_content_digest'] or
        first['response']['evidence']['checkpoint'] != checkpoint_evidence(accepted)):
        fail('atomic admission source/binding/mailbox/receipt link differs')
    terminal = snapshots['after_unhandled']
    terminal_case = cases['machine_unhandled_after_admission']['response']
    terminal_receipt = terminal['operation_receipts'][-1]
    if (terminal_receipt['operation_kind'] != 'event_terminal' or
        terminal_case['evidence']['checkpoint'] != checkpoint_evidence(terminal) or
        terminal_case['evidence']['receipt_sequence'] != terminal_receipt['receipt_sequence'] or
        terminal_case['outcome'] != terminal_receipt['outcome'] or
        terminal['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox']):
        fail('terminal disposition lacks exact terminal receipt and empty live mailbox')
    dead = cases['first_durable_poison_transfer']['response']['record']
    if dead['ingress_dead_letter_digest'] != hash_value([
            'determa-ingress-dead-letter-digest-1', '1',
            {k: v for k, v in dead.items() if k != 'ingress_dead_letter_digest'}]):
        fail('ingress dead-letter receipt digest differs')
    valid_source(dead['source'])
    for value in norms['outbound-destination-receipts-v1']['records']:
        if value['outbound_destination_receipt_digest'] != hash_value([
                'determa-outbound-destination-receipt-digest-1', '1',
                {k: v for k, v in value.items() if k != 'outbound_destination_receipt_digest'}]):
            fail('outbound destination receipt digest differs')

    queue = norms['queue-placement-checkpoints-v1']
    for case_name in ('deferred_keeps_original_acceptance',
                      'structural_recall_reuses_acceptance'):
        normative = cases[case_name]
        value = normative['response']
        checkpoint = queue[normative['queue_checkpoint_snapshot']]
        if value['evidence'] != checkpoint_evidence(checkpoint):
            fail(f'{case_name}: wrong checkpoint evidence')
        aggregate = checkpoint['root_record']['aggregate_state']
        located = [(runtime['runtime_id'], mailbox, entry)
                   for runtime in aggregate['runtimes']
                   for mailbox in ('ready_mailbox', 'deferred_mailbox')
                   for entry in runtime[mailbox]
                   if entry['envelope']['event_id'] == value['event_id']]
        if len(located) != 1:
            fail(f'{case_name}: event has no unique live mailbox owner')
        runtime_id, mailbox, entry = located[0]
        origin = value['origin']
        matching_receipts = [receipt for receipt in checkpoint['operation_receipts']
                             if receipt['receipt_sequence'] ==
                             origin.get('acceptance_receipt_sequence')]
        if (runtime_id != value['target_runtime_id'] or
            mailbox != f'{value["placement"]}_mailbox' or
            entry['envelope_digest'] != value['envelope_digest'] or
            entry['acceptance_sequence'] != value['acceptance_sequence'] or
            entry['queue_sequence'] != value['queue_sequence'] or
            origin['origin_kind'] != 'host_acceptance' or
            len(matching_receipts) != 1 or
            matching_receipts[0]['operation_kind'] != 'acceptance' or
            matching_receipts[0]['event_id'] != value['event_id'] or
            matching_receipts[0]['acceptance_sequence'] != value['acceptance_sequence']):
            fail(f'{case_name}: placement or immutable origin differs')
    if (len(queue['after_second_admission']['operation_receipts']) !=
            len(queue['after_deferral']['operation_receipts']) or
        len(queue['after_received_admission']['operation_receipts']) + 1 !=
            len(queue['after_recall']['operation_receipts']) or
        queue['after_recall']['operation_receipts'][-1]['operation_kind'] != 'event_terminal'):
        fail('deferral or recall receipt sequence differs from the driving step')

    outbound = norms['outbound-checkpoint-lifecycle-v1']
    destination_receipts = norms['outbound-destination-receipts-v1']['records']
    for case_name in ('outbound_ambiguous_remains_pending',
                      'outbound_confirmed_is_destination_acceptance',
                      'outbound_dead_letter_transfer'):
        normative = cases[case_name]
        response = normative['response']
        checkpoint = outbound[normative['outbound_checkpoint_snapshot']]
        evidence = response['evidence']
        if evidence['checkpoint'] != checkpoint_evidence(checkpoint):
            fail(f'{case_name}: checkpoint evidence differs')
        if len(checkpoint['operation_receipts']) != len(outbound['before_delivery']['operation_receipts']):
            fail(f'{case_name}: outbox update invented an operation receipt')
        location = evidence['outbox_location']
        if location['kind'] == 'pending':
            records = checkpoint['pending_outbox_intents']
            if len(records) != 1 or (location['state_revision'] != records[0]['state_revision']
                                     or response['outcome'] != records[0]['delivery_state']['status']
                                     or response['reason_code'] != records[0]['delivery_state']['reason_code']):
                fail(f'{case_name}: pending responsibility lost or changed')
            if response['destination_receipt_id'] is not None:
                fail(f'{case_name}: pending decision claimed destination acceptance')
        else:
            records = checkpoint['terminal_outbox_records']
            if len(records) != 1 or checkpoint['pending_outbox_intents']:
                fail(f'{case_name}: terminal outbox record incomplete')
            record = records[0]
            if (location['terminal_sequence'] != record['terminal_sequence'] or
                location['committed_revision'] != record['committed_revision'] or
                response['outcome'] != record['outcome']['status'] or
                response['reason_code'] != record['outcome'].get('reason_code')):
                fail(f'{case_name}: terminal location or reason differs')
            matches = [receipt for receipt in destination_receipts
                       if receipt['destination_receipt_id'] == response['destination_receipt_id']]
            if len(matches) != 1 or any(matches[0][key] != expected for key, expected in {
                    'root_instance_id': checkpoint['root_instance_id'],
                    'effect_id': response['effect_id'],
                    'terminal_sequence': record['terminal_sequence'],
                    'outcome': response['outcome'],
                    'reason_code': response['reason_code'],
                    'execution_checkpoint_digest': checkpoint['execution_checkpoint_digest'],
            }.items()):
                fail(f'{case_name}: durable destination receipt is unbound')
        if records[0]['intent']['effect_id'] != response['effect_id']:
            fail(f'{case_name}: changed effect identity')
        if records[0]['intent'] != outbound['before_delivery']['pending_outbox_intents'][0]['intent']:
            fail(f'{case_name}: complete intent changed during delivery')

    initial = {'checkpoint': 'before-admission-checkpoint-v1.json', 'bindings': [],
               'dead_letters': [], 'source_acknowledgements': [], 'provider_dispatches': 0}
    committed = {'checkpoint': 'after-admission-checkpoint-v1.json', 'bindings': [binding],
                 'dead_letters': [], 'source_acknowledgements': [
                     {'source_scope': request['source']['source_scope'],
                      'source_delivery_id': request['source']['source_delivery_id']}],
                 'provider_dispatches': 0}
    results = [
        (request, initial, committed, first['response'], None, None),
        (request, committed, committed, first['response'], None, 'first_committed_admission'),
        (cases['unequal_source_identity_conflict']['request'], committed, committed,
         cases['unequal_source_identity_conflict']['response'], None, None),
        (request, initial, initial, cases['precommit_write_failure_keeps_source']['response'],
         'atomic_commit_failure', None),
        (request, initial, initial, {'kind': 'no_response'}, 'crash_before_commit', None),
        (request, initial, {**committed, 'source_acknowledgements': []},
         {'kind': 'no_response'}, 'crash_after_commit_before_ack', None),
        (request, {**committed, 'source_acknowledgements': []}, committed,
         first['response'], None, 'crash_after_atomic_commit_before_ack'),
    ]
    for vector, (expected_request, before, after, response, fault, replay) in zip(
            profile['vectors'][:len(VECTORS)], results):
        for key, expected in [('operation', 'ingest'), ('request', expected_request),
                              ('before', before), ('after', after),
                              ('expected_response', response), ('fault_injection', fault),
                              ('replay_of', replay)]:
            same(vector[key], expected, f'{vector["name"]}: {key} differs')
        valid_source(vector['request']['source'])
    by_name = {vector['name']: vector for vector in profile['vectors']}
    stale = by_name['stale_owner_equal_replay_refused']
    stale_store = {**committed, 'source_acknowledgements': []}
    if (stale['operation'] != 'ingest' or stale['request'] != request or
        stale['before'] != stale_store or stale['after'] != stale_store or
        stale['replay_of'] != 'first_committed_admission' or
        stale['authority_context'] != {
            'scope_identity': 'orders/inbox', 'claimed_epoch': '1',
            'current_epoch': '2', 'guarantee': 'authoritative_scope_fencing'} or
        stale['expected_response'] != {
            'kind': 'typed_failure', 'code': 'stale_scope_authority',
            'acknowledge_source': False}):
        fail('stale owner bypassed current authority guard on equal replay')
    batch = by_name['batch_second_invalid_keeps_all_source_owned']
    pressure = by_name['source_ordered_pressure_blocks_later_item']
    if (batch['operation'] != 'ingest_batch' or len(batch['request']) != 2 or
        batch['request'][0] != request or batch['before'] != initial or
        batch['after'] != initial or len(batch['expected_response']) != 2):
        fail('batch failed member partially committed or acknowledged')
    second_request = batch['request'][1]
    valid_source(second_request['source'])
    if (second_request['source']['source_scope'] != request['source']['source_scope'] or
        second_request['source']['source_delivery_id'] != 'broker-43' or
        second_request['envelope']['event_id'] != 'received-2' or
        second_request['envelope']['event'] != 'unknown_event' or
        second_request['envelope']['target'] != request['envelope']['target'] or
        batch['expected_response'][0]['source_delivery_id'] !=
            request['source']['source_delivery_id'] or
        batch['expected_response'][1]['source_delivery_id'] != 'broker-43' or
        any(item['reason'] != 'invalid_delivery' for item in batch['expected_response']) or
        any(item['acknowledge_source'] or item['delivery_message_kind'] != 'source_owned'
            for item in batch['expected_response'])):
        fail('batch source order or failure ownership differs')
    if (pressure['operation'] != 'ingest' or pressure['request'] != second_request or
        pressure['before'] != initial or pressure['after'] != initial or
        pressure['fault_injection'] != 'earlier_source_item_unresolved' or
        pressure['ordering_context'] != {
            'mode': 'source_ordered', 'source_scope': 'orders/inbox',
            'unresolved_source_delivery_id': 'broker-42'} or
        pressure['expected_response']['reason'] != 'backpressure' or
        pressure['expected_response']['acknowledge_source']):
        fail('source-ordered pressure overtook an unresolved earlier item')
    files = {path.name: analyze_artifact(path).document for path in artifacts
             if path.name.endswith('-checkpoint-v1.json')}
    emission = analyze_artifact(case / 'native-emission-core-step-result-v1.json').document
    native_producing = files['native-pending-checkpoint-v1.json']
    producing_receipt = native_producing['operation_receipts'][-1]
    if (producing_receipt['operation_kind'] != 'event_terminal' or
        emission['state'] != native_producing['root_record']['aggregate_state'] or
        emission['disposition'] != producing_receipt['outcome']['disposition'] or
        emission['fault'] != producing_receipt['outcome']['fault'] or
        emission['rejection'] != producing_receipt['outcome']['rejection'] or
        emission['lifecycle_dispositions'] != [] or
        len(emission['emissions']) != len(producing_receipt['emission_references'])):
        fail('native producer did not preserve complete core step value')
    for intent, reference in zip(emission['emissions'],
                                 producing_receipt['emission_references']):
        if (reference['kind'] != 'external_outbox' or
            intent['effect_id'] != reference['effect_id'] or
            not any(row['intent'] == intent for row in native_producing['pending_outbox_intents'])):
            fail('core emission differs from producing receipt or pending complete intent')
    for name in ADDITIONAL:
        vector = by_name[name]
        before, after = vector['before'], vector['after']
        response = vector['expected_response']
        if before['checkpoint'] not in files or after['checkpoint'] not in files:
            fail(f'{name}: missing complete checkpoint')
        for store in (before, after):
            if store['provider_dispatches'] != 0:
                fail(f'{name}: unproved provider dispatch')
        if name in ('source_owned_backpressure', 'removed_target_keeps_source'):
            same(vector['request'], request, f'{name}: changed caller input')
            same(before, initial, f'{name}: changed initial owner')
            same(after, initial, f'{name}: pre-admission source lost ownership')
            if response['delivery_message_kind'] != 'source_owned' or response['acknowledge_source']:
                fail(f'{name}: source-owned response acknowledged')
        elif name == 'machine_unhandled_after_admission':
            same(before, committed, f'{name}: wrong admitted prior')
            if (after['checkpoint'] != 'after-unhandled-checkpoint-v1.json' or
                vector['request'] != {'event_id': request['envelope']['event_id']}):
                fail(f'{name}: terminal operation lacks original event')
            same(response, terminal_case, f'{name}: terminal return differs')
        elif name in ('first_durable_poison_transfer', 'equal_poison_redelivery'):
            valid_source(vector['request']['source'])
            same(response, cases['first_durable_poison_transfer']['response'],
                 f'{name}: changed retained dead-letter receipt')
            if (after['checkpoint'] != 'before-admission-checkpoint-v1.json' or
                after['bindings'] or after['dead_letters'] != [dead] or
                len(after['source_acknowledgements']) != 1):
                fail(f'{name}: dead-letter transfer lacks durable original and source receipt')
            if name == 'equal_poison_redelivery' and before != after:
                fail('equal poison replay mutated committed terminal evidence')
        elif name in ('deferred_keeps_original_acceptance',
                      'structural_recall_reuses_acceptance'):
            same(response, cases[name]['response'], f'{name}: placement differs')
            if (vector['request'] != {'event_id': response['event_id']} or
                files[after['checkpoint']]['execution_checkpoint_digest'] !=
                    response['evidence']['execution_checkpoint_digest'] or
                before['bindings'] or after['bindings'] or
                before['source_acknowledgements'] or after['source_acknowledgements']):
                fail(f'{name}: placement changed source ownership or checkpoint')
        else:
            if vector['operation'] != 'deliver_outbound':
                fail(f'{name}: wrong outbound operation')
            prior = files[before['checkpoint']]
            current = files[after['checkpoint']]
            effect_id = vector['request']['effect_id']
            producing = [ref for receipt in prior['operation_receipts']
                         for ref in receipt.get('emission_references', [])
                         if ref.get('kind') == 'external_outbox' and ref['effect_id'] == effect_id]
            if (len(producing) != 1 or response['effect_id'] != effect_id or
                response['evidence']['checkpoint'] != checkpoint_evidence(current) or
                before['checkpoint'] != 'native-pending-checkpoint-v1.json' or
                vector['request']['provider_result']['outcome'] != response['outcome'] or
                vector['request']['provider_result']['reason_code'] != response['reason_code'] or
                vector['request']['provider_result']['destination_receipt_id'] !=
                    response['destination_receipt_id'] or
                int(current['revision']) != int(prior['revision']) + 1 or
                len(current['operation_receipts']) != len(prior['operation_receipts'])):
                fail(f'{name}: outbound decision lacks emitted intent or checkpoint')
            configured_receipts = {
                'outbound_ambiguous_remains_pending': None,
                'outbound_confirmed_is_destination_acceptance': 'destination-acceptance-actual-1',
                'outbound_dead_letter_transfer': 'destination-dead-letter-actual-1',
            }
            if response['destination_receipt_id'] != configured_receipts[name]:
                fail(f'{name}: destination receipt differs from configured test provider proof')
            pending = [row for row in current['pending_outbox_intents']
                       if row['intent']['effect_id'] == effect_id]
            terminal_rows = [row for row in current['terminal_outbox_records']
                             if row['intent']['effect_id'] == effect_id]
            if response['outcome'] == 'ambiguous':
                if (len(pending) != 1 or terminal_rows or
                    pending[0]['delivery_state']['status'] != 'ambiguous' or
                    after.get('destination_receipts')):
                    fail(f'{name}: ambiguous delivery lost pending responsibility')
            else:
                if len(terminal_rows) != 1 or pending or len(after.get('destination_receipts', [])) != 1:
                    fail(f'{name}: terminal delivery lacks durable receipt')
                record = terminal_rows[0]
                receipt = after['destination_receipts'][0]
                if any(receipt[key] != expected for key, expected in {
                        'root_instance_id': current['root_instance_id'],
                        'effect_id': effect_id,
                        'terminal_sequence': record['terminal_sequence'],
                        'outcome': record['outcome']['status'],
                        'reason_code': record['outcome'].get('reason_code'),
                        'destination_receipt_id': response['destination_receipt_id'],
                        'execution_checkpoint_digest': current['execution_checkpoint_digest'],
                }.items()):
                    fail(f'{name}: destination receipt does not bind exact terminal record')
                if receipt['outbound_destination_receipt_digest'] != hash_value([
                    'determa-outbound-destination-receipt-digest-1', '1',
                    {key: value for key, value in receipt.items()
                     if key != 'outbound_destination_receipt_digest'}]):
                    fail(f'{name}: destination receipt digest differs')
            original_intent = next(row['intent'] for row in prior['pending_outbox_intents']
                                   if row['intent']['effect_id'] == effect_id)
            if (pending or terminal_rows)[0]['intent'] != original_intent:
                fail(f'{name}: outbox delivery changed complete intent')
    negative = profile['invalid_vectors']
    invalid_inputs = norms['delivery-v1-cases']['invalid_cases']
    invalid_links = norms['delivery-v1-cases']['invalid_link_cases']
    expected_negative_names = ([item['name'] for item in invalid_inputs] +
                               [item['name'] for item in invalid_links] +
                               ['duplicate_json_key', 'nonfinite_json', 'invalid_utf8_json',
                                'unordered_transport_map', 'nonfinite_transport_float',
                                'negative_zero_transport_float',
                                'noncanonical_transport_integer'])
    if [item['name'] for item in negative] != expected_negative_names:
        fail('closed invalid source/link/parser inventory differs')
    malformed_base64 = {'nonzero_one_byte_pad_bits', 'nonzero_two_byte_pad_bits',
                        'missing_padding', 'trailing_whitespace', 'excess_padding',
                        'alternate_alphabet'}
    for index, invalid in enumerate(invalid_inputs):
        vector = negative[index]
        same(vector['candidate'], invalid['value'], f'{vector["name"]}: invalid source changed')
        if vector['operation'] != 'parse_delivery' or vector['before'] != vector['after']:
            fail(f'{vector["name"]}: invalid source mutated store')
        if invalid['name'] in malformed_base64:
            try:
                valid_source(vector['candidate']['source'])
            except ValidationFailure:
                pass
            else:
                fail(f'{vector["name"]}: malformed Base64 unexpectedly accepted')
            if vector['expected_failure'] != 'malformed_delivery':
                fail(f'{vector["name"]}: wrong malformed source result')
        elif vector['expected_failure'] != 'invalid_delivery':
            fail(f'{vector["name"]}: wrong invalid delivery result')
    link_source_names = (
        'first_committed_admission', 'first_committed_admission',
        'machine_unhandled_after_admission', 'deferred_keeps_original_acceptance',
        'structural_recall_reuses_acceptance', 'outbound_dead_letter_transfer',
        'outbound_confirmed_is_destination_acceptance',
        'outbound_ambiguous_remains_pending',
        'outbound_confirmed_is_destination_acceptance')
    for invalid, source_name, vector in zip(invalid_links, link_source_names,
                                           negative[len(invalid_inputs):]):
        source_vector = by_name[source_name]
        if (vector['operation'] != 'validate_evidence' or
            vector['expected_failure'] != 'invalid_delivery_evidence' or
            vector['before'] != source_vector['after'] or
            vector['before'] != vector['after'] or
            vector['candidate']['delivery_message_kind'] !=
                source_vector['expected_response']['delivery_message_kind'] or
            vector['candidate'] == source_vector['expected_response']):
            fail(f'{invalid["name"]}: malformed evidence probe lacks a real retained owner')
        changed = copy.deepcopy(source_vector['expected_response'])
        candidate = vector['candidate']
        # Every bad link changes exactly one leaf of a valid response; a
        # replacement of the entire response is not an evidence probe.
        def differences(left: object, right: object) -> int:
            if isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right):
                return sum(differences(left[key], right[key]) for key in left)
            return int(left != right)
        if differences(changed, candidate) != 1:
            fail(f'{invalid["name"]}: invalid link changed multiple facts')
    for vector in negative[-7:-4]:
        if vector['operation'] != 'parse_delivery_bytes' or vector['before'] != vector['after']:
            fail(f'{vector["name"]}: malformed raw input changed store')
        raw = base64.b64decode(vector['candidate'], validate=True)
        if analyze_json_artifact_source(raw).error is None:
            fail(f'{vector["name"]}: malformed JSON bytes parsed successfully')
    for vector in negative[-4:]:
        if (vector['operation'] != 'parse_delivery' or
            vector['expected_failure'] != 'invalid_delivery' or
            vector['before'] != vector['after']):
            fail(f'{vector["name"]}: invalid typed source mutated owner')
        source = vector['candidate']['source']
        if source['content']['content_kind'] != 'canonical_transport_value':
            fail(f'{vector["name"]}: wrong typed content kind')
        try:
            valid_source(source)
        except ValidationFailure:
            pass
        else:
            fail(f'{vector["name"]}: invalid typed source passed canonicality')
    if any(vector['acknowledge_source'] or vector['before'] != vector['after']
           for vector in negative):
        fail('negative delivery acknowledged or mutated authoritative store')
    return len(profile['vectors']) + len(negative)
