"""Strict source and relational gates for the optional §19 native-effect profile."""
from __future__ import annotations

import hashlib
import json
import math
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from generate_committed_native_effects_profile import CASE, SPEC_COMMIT
from generate_version1_vectors import digest, typed_value, load_yaml

SPEC_EXAMPLES = Path('examples/effects')
SCOPE_ID = 'effect-scope-1'
SCHEMAS = {
    'active-claim.json': 'host-effect-claim-v1.schema.json',
    'producer-request.json': None,
    'producer-response.json': None,
    'result-request.json': 'effect-result-request-v1.schema.json',
    'cancel-request.json': 'effect-cancellation-request-v1.schema.json',
    'committed-response.json': 'effect-result-response-v1.schema.json',
    'ambiguous-response.json': 'effect-result-response-v1.schema.json',
    'cancel-response.json': 'effect-cancellation-response-v1.schema.json',
    'cancel-rejected-response.json': 'effect-cancellation-response-v1.schema.json',
    'retry-request.json': 'effect-result-request-v1.schema.json',
    'retryable-response.json': 'effect-result-response-v1.schema.json',
    'postcall-cancel-response.json': 'effect-cancellation-response-v1.schema.json',
}


def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'duplicate JSON member: {key}')
        out[key] = value
    return out


def reject_constant(value):
    raise ValueError(f'non-finite JSON value: {value}')


def finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f'non-finite JSON number: {token}')
    return value


def reject_surrogates(value):
    if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError('invalid Unicode scalar in JSON string')
    if isinstance(value, dict):
        for key, item in value.items():
            reject_surrogates(key)
            reject_surrogates(item)
    elif isinstance(value, list):
        for item in value:
            reject_surrogates(item)
    return value


def strict_json(data):
    value = json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=unique_pairs,
                       parse_constant=reject_constant, parse_float=finite_float)
    return reject_surrogates(value)


def exact(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def schema_registry(spec_root):
    documents = {}
    for path in (spec_root / 'schema').glob('*.schema.json'):
        doc = strict_json(path.read_bytes())
        if '$id' in doc:
            documents[doc['$id']] = Resource.from_contents(doc)
    return Registry().with_resources(documents.items())


def validate_schema(value, spec_root, filename, registry):
    schema = strict_json((spec_root / 'schema' / filename).read_bytes())
    errors = list(Draft202012Validator(schema, registry=registry).iter_errors(value))
    if errors:
        raise ValueError(f'{filename}: {errors[0].message}')


def validate_profile(spec_root: Path):
    # The immutable spec pin is essential: the example prose and schemas are one contract.
    head = subprocess.check_output(['git', '-C', str(spec_root), 'rev-parse', 'HEAD'], text=True).strip()
    if head != SPEC_COMMIT:
        raise ValueError(f'specification must be checked out at {SPEC_COMMIT}; got {head}')
    data = CASE / 'data'
    manifest = strict_json((data / 'vectors.json').read_bytes())
    if set(manifest) != {'format', 'schema_version', 'spec_commit', 'normative_examples', 'normative_case_coverage', 'handler_sources', 'vectors'} or \
            manifest['format'] != 'determa.committed_native_effects.vectors' or \
            type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or \
            manifest['spec_commit'] != SPEC_COMMIT:
        raise ValueError('invalid effect vector manifest')
    examples = sorted((spec_root / SPEC_EXAMPLES).glob('*.json'))
    actual_pins = {str(path.relative_to(spec_root)): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in examples}
    if manifest['normative_examples'] != actual_pins:
        raise ValueError('normative §19 example pin changed or incomplete')
    handlers = {str(path.relative_to(CASE)): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted((CASE / 'handler').glob('test_handler.*'))}
    if manifest['handler_sources'] != handlers or len(handlers) != 2:
        raise ValueError('native handler source closure changed')
    registry = schema_registry(spec_root)
    artifacts = {}
    for path in CASE.glob('*checkpoint.json'):
        value = strict_json(path.read_bytes())
        validate_schema(value, spec_root, 'execution-checkpoint-v1.schema.json', registry)
        artifacts[path.name] = value
    for path in data.glob('*.json'):
        if path.name == 'vectors.json':
            continue
        value = strict_json(path.read_bytes())
        schema = ('host-effect-journal-v1.schema.json' if path.name.endswith('-journal.json') else
                  'effect-result-response-v1.schema.json' if path.name.startswith('rejected-') else
                  SCHEMAS.get(path.name))
        if schema:
            validate_schema(value, spec_root, schema, registry)
        artifacts['data/' + path.name] = value
    pending = artifacts['pending-checkpoint.json']
    intent = pending['pending_outbox_intents'][0]['intent']
    aggregate = pending['root_record']['aggregate_state']
    runtime = aggregate['runtimes'][0]
    if len(pending['pending_outbox_intents']) != 1 or intent['correlation_id'] != 'business-order-42':
        raise ValueError('expected one real selected committed intent with originating token')
    if aggregate['root_instance_id'] != pending['root_instance_id']:
        raise ValueError('checkpoint/root mismatch')
    bundle = load_yaml(CASE / 'machine.yaml')
    machine = bundle['machines'][0]
    events = bundle['events']
    send = machine['root']['on_events']['invoke']['action'][0]['send']
    if bundle['format'] != 1 or machine['machine_id'] != 'workflow' or \
            events['invoke']['direction'] != 'input' or \
            events['native_request']['direction'] != 'output' or \
            events['native_succeeded']['direction'] != 'input' or \
            events['native_cancelled']['direction'] != 'input' or \
            send['event'] != intent['event'] or send['to'] != {'external': True} or \
            send['correlation_id'] != 'event.payload.operation_token' or \
            intent['payload'] != typed_value({'index': int(send['payload']['index'])}) or \
            intent['sequence'] != '0':
        raise ValueError('committed intent does not follow the declared machine action')
    identity = runtime['current_definition']['machine']
    originating = artifacts['accepted-checkpoint.json']['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'][0]
    expected_effect_id = digest(['determa-effect-identity-1', '1',
                                 [identity['namespace'], identity['machine_id'], identity['machine_version']],
                                 pending['root_instance_id'], runtime['runtime_id'],
                                 originating['envelope']['cause_id'],
                                 str(int(aggregate['next_logical_step_sequence']) - 1),
                                 '/machines/0/root/on_events/invoke/action/0/send', '0'])
    if intent['effect_id'] != expected_effect_id or \
            intent['correlation_id'] != dict(originating['envelope']['payload'][1])['operation_token'][1]:
        raise ValueError('effect identity or business token differs from selected core input')

    mapping_events = {'native_succeeded', 'native_cancelled'}
    for name, value in artifacts.items():
        if name.endswith('-journal.json'):
            body = dict(value)
            got = body.pop('host_effect_journal_digest')
            if got != digest(['determa-host-effect-journal-digest-1', body]):
                raise ValueError(f'{name}: journal digest mismatch')
            checkpoint = next((cp for cp in artifacts.values() if isinstance(cp, dict) and
                               cp.get('execution_checkpoint_digest') == value['checkpoint_digest']), None)
            if checkpoint is None or checkpoint['revision'] != value['checkpoint_revision'] or \
                    checkpoint['root_instance_id'] != value['root_instance_id']:
                raise ValueError(f'{name}: torn checkpoint/journal pair')
            if name == 'data/empty-journal.json':
                if value['effect_records']:
                    raise ValueError('empty journal contains effect')
                continue
            if len(value['effect_records']) != 1:
                raise ValueError(f'{name}: effect record count')
            producer = artifacts['data/producer-response.json']
            ref = next((item for item in value['operation_response_references']
                        if item['operation_id'] == 'produce-1'), None)
            if ref is None or ref['response_digest'] != digest(['determa-host-operation-response-1', producer]):
                raise ValueError(f'{name}: original operation response not retained')
            refs = value['operation_response_references']
            if [item['operation_id'] for item in refs] != sorted(
                    [item['operation_id'] for item in refs], key=lambda text: text.encode('utf-8')) or \
                    len({item['operation_id'] for item in refs}) != len(refs):
                raise ValueError(f'{name}: operation response references are not unique and ordered')
            if name in {'data/preclaim-cancelled-journal.json',
                        'data/cancelled-admitted-journal.json'}:
                cancel_ref = next((item for item in refs if item['operation_id'] == 'cancel-1'), None)
                if cancel_ref is None or cancel_ref['response_digest'] != digest([
                        'determa-host-operation-response-1', artifacts['data/cancel-response.json']]):
                    raise ValueError(f'{name}: retained cancellation response differs')
            if name == 'data/postcall-cancelled-journal.json':
                cancel_ref = next((item for item in refs if item['operation_id'] == 'cancel-after-call'), None)
                if cancel_ref is None or cancel_ref['response_digest'] != digest([
                        'determa-host-operation-response-1', artifacts['data/postcall-cancel-response.json']]):
                    raise ValueError(f'{name}: retained reconciliation response differs')
            record = value['effect_records'][0]
            reports = record['attempt_records']
            fences = [int(item['attempt_fence']) for item in reports]
            if fences != sorted(fences) or len(fences) != len(set(fences)) or \
                    any(fence > int(record['attempt_fence']) for fence in fences):
                raise ValueError(f'{name}: attempt fence ordering invalid')
            for report in reports:
                report_payload = (record['outcome']['payload'] if record['outcome'] is not None and
                                  report['report_kind'] == record['outcome']['kind'] else typed_value({}))
                if report['report_digest'] != digest(['determa-effect-attempt-report-1',
                                                      record['effect_id'], record['operation_token'],
                                                      report['attempt_fence'], report['report_kind'],
                                                      report_payload, report['reason']]):
                    raise ValueError(f'{name}: immutable attempt report digest differs')
            state = record['invocation_state']
            has_outcome = record['outcome'] is not None
            has_result = record['result_event_id'] is not None
            has_receipt = record['admission_receipt'] is not None
            if ((state in ('unclaimed', 'leased', 'ambiguous') and (has_outcome or has_result or has_receipt)) or
                (state == 'outcome_recorded' and (not has_outcome or not has_result or has_receipt)) or
                (state in ('result_admitted', 'closed') and not (has_outcome and has_result and has_receipt))):
                raise ValueError(f'{name}: impossible invocation state/evidence combination')
            if has_outcome:
                outcome = record['outcome']
                if outcome['digest'] != digest(['determa-effect-outcome-1', record['effect_id'],
                                                record['operation_token'], outcome['kind'],
                                                outcome['payload'], outcome['attempt_fence']]):
                    raise ValueError(f'{name}: outcome digest differs')
                matching = [item for item in record['result_mapping'] if item['outcome_kind'] == outcome['kind']]
                if len(matching) != 1 or record['result_event_id'] != digest([
                        'determa-effect-result-event-1', record['effect_id'], matching[0]['result_slot']]):
                    raise ValueError(f'{name}: pinned result event identity differs')
                if outcome['attempt_fence'] == '0':
                    if reports or record['cancellation'] is None or \
                            record['cancellation']['state'] != 'prevented_start':
                        raise ValueError(f'{name}: preclaim outcome has attempt evidence')
                elif not any(item['attempt_fence'] == outcome['attempt_fence'] and
                             item['report_kind'] == outcome['kind'] for item in reports):
                    raise ValueError(f'{name}: terminal outcome lacks immutable attempt report')
            located = [item['intent'] for key in ('pending_outbox_intents', 'terminal_outbox_records')
                       for item in checkpoint[key] if item['intent']['effect_id'] == record['effect_id']]
            if len(located) != 1 or located[0] != intent:
                raise ValueError(f'{name}: journal effect is absent or differs in paired checkpoint')
            mappings = record['result_mapping']
            if len({item['result_slot'] for item in mappings}) != len(mappings) or \
                    len({item['outcome_kind'] for item in mappings}) != len(mappings) or \
                    any(events[item['event']]['direction'] != 'input' or
                        item['operation_token_location'] != {'kind': 'correlation_id'}
                        for item in mappings):
                raise ValueError(f'{name}: result mapping is not declared, unique, or token pinned')
            if record['effect_id'] != intent['effect_id'] or record['operation_token'] != intent['correlation_id'] or \
                    record['intent_digest'] != digest(['determa-outbox-intent-digest-1', '1', pending['root_instance_id'], intent]) or \
                    record['target'] != {'root_instance_id': pending['root_instance_id'],
                                         'runtime_id': runtime['runtime_id'],
                                         'runtime_incarnation': runtime['identity_origin']} or \
                    {m['event'] for m in record['result_mapping']} != (
                        {'native_succeeded'} if name == 'data/no-cancel-mapping-journal.json'
                        else mapping_events):
                raise ValueError(f'{name}: record does not bind actual intent and target')
    claim = artifacts['data/active-claim.json']
    leased_record = artifacts['data/leased-journal.json']['effect_records'][0]
    if claim['work_kind'] != 'effect' or claim['state'] != 'active' or \
            claim['scope_identity'] != SCOPE_ID or \
            claim['root_instance_id'] != pending['root_instance_id'] or \
            claim['work_identity'] != leased_record['effect_id'] or \
            claim['operation_token'] != leased_record['operation_token'] or \
            claim['attempt_fence'] != leased_record['attempt_fence']:
        raise ValueError('claim does not bind leased effect and business token')
    final = artifacts['data/result-admitted-journal.json']['effect_records'][0]
    admitted = artifacts['admitted-checkpoint.json']
    receipt = admitted['operation_receipts'][-1]
    envelope = admitted['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'][-1]['envelope']
    if final['admission_receipt'] != receipt or receipt['event_id'] != final['result_event_id'] or \
            envelope['event_id'] != final['result_event_id'] or envelope['correlation_id'] != intent['correlation_id'] or \
            envelope['target'] != runtime['target_identity']:
        raise ValueError('result event, pinned token/target, and full receipt differ')
    vectors = manifest['vectors']
    if type(vectors) is not list or len(vectors) < 20 or len({v['name'] for v in vectors}) != len(vectors):
        raise ValueError('missing effect vectors or duplicate names')
    named = {vector['name'] for vector in vectors}
    for file_name, coverage in manifest['normative_case_coverage'].items():
        source = strict_json((spec_root / SPEC_EXAMPLES / file_name).read_bytes())
        if {case['name'] for case in source['cases']} != set(coverage) or \
                any(name not in named for name in coverage.values()):
            raise ValueError(f'incomplete normative case mapping: {file_name}')
    if set(manifest['normative_case_coverage']) != {
        'host-native-effect-cases-v1.json', 'result-admission-cases-v1.json',
        'effect-cancellation-cases-v1.json'}:
        raise ValueError('normative case index incomplete')
    producing = next(vector for vector in vectors if vector['name'] == 'first_producing_commit')
    replay = next(vector for vector in vectors if vector['name'] == 'equal_request_after_route_change')
    original = artifacts['data/producer-request.json']
    if producing['request']['arguments']['original_request'] != original or \
            replay['request']['arguments']['original_request'] != original or \
            producing['expected']['response'] != 'data/producer-response.json' or \
            replay['expected']['response'] != 'data/producer-response.json' or \
            replay['request']['checkpoint_before'] != 'pending-checkpoint.json' or \
            replay['expected']['checkpoint_after'] != 'pending-checkpoint.json':
        raise ValueError('original operation or old CAS replay evidence differs')
    allowed_counts = {'provider_calls', 'core_calls', 'new_claims'}
    for vector in vectors:
        if set(vector) != {'name', 'covers', 'request', 'expected'}:
            raise ValueError('unclosed vector')
        if set(vector['request']) != {'operation', 'checkpoint_before', 'journal_before', 'claim',
                                     'host_configuration', 'auth_context', 'arguments', 'fault'}:
            raise ValueError('unclosed adapter request')
        if set(vector['expected']) != {'response', 'checkpoint_after', 'journal_after', 'counts'} or \
                set(vector['expected']['counts']) != allowed_counts:
            raise ValueError('unclosed expected observation')
        configuration = vector['request']['host_configuration']
        if type(configuration) is not dict or set(configuration) != {
                'route_generation', 'route_authorized', 'destination_deduplication_proven',
                'handler_authorized', 'credential_available', 'credential_generation'} or \
                any(type(configuration[key]) is not bool for key in (
                    'route_authorized', 'destination_deduplication_proven',
                    'handler_authorized', 'credential_available')) or \
                any(type(configuration[key]) is not str or not configuration[key].isdigit() for key in (
                    'route_generation', 'credential_generation')):
            raise ValueError('invalid current host configuration')
        auth = vector['request']['auth_context']
        if type(auth) is not dict or set(auth) != {
                'scope_identity', 'principal', 'scope_authority_epoch', 'trusted_host_now'} or \
                any(type(value) is not str or not value for value in auth.values()) or \
                not auth['scope_authority_epoch'].isdigit() or \
                not auth['trusted_host_now'].isdigit():
            raise ValueError('invalid authenticated host context')
        for member in ('checkpoint_before', 'journal_before'):
            if vector['request'][member] not in artifacts:
                raise ValueError(f'{vector["name"]}: absent before artifact')
        for member in ('checkpoint_after', 'journal_after', 'response'):
            path = vector['expected'][member]
            if path is not None and path not in artifacts:
                raise ValueError(f'{vector["name"]}: absent expected artifact')
        if vector['request']['claim'] is not None and vector['request']['claim'] not in artifacts:
            raise ValueError('absent claim')
        if any(type(n) is not int or n < 0 for n in vector['expected']['counts'].values()):
            raise ValueError('invalid count')
    return len(vectors)
