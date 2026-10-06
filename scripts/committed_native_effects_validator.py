"""Strict source and relational gates for the optional §19 native-effect profile."""
from __future__ import annotations

import hashlib
import json
import math

import rfc8785
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
    'handler-closure.json': None,
    'destination-configuration.json': None,
    'result-request.json': 'effect-result-request-v1.schema.json',
    'cancel-request.json': 'effect-cancellation-request-v1.schema.json',
    'committed-response.json': 'effect-result-response-v1.schema.json',
    'ambiguous-response.json': 'effect-result-response-v1.schema.json',
    'cancel-response.json': 'effect-cancellation-response-v1.schema.json',
    'cancel-rejected-response.json': 'effect-cancellation-response-v1.schema.json',
    'retry-request.json': 'effect-result-request-v1.schema.json',
    'retryable-response.json': 'effect-result-response-v1.schema.json',
    'postcall-cancel-response.json': 'effect-cancellation-response-v1.schema.json',
    'late-cancel-outcome_recorded-response.json': 'effect-cancellation-response-v1.schema.json',
    'late-cancel-result_admitted-response.json': 'effect-cancellation-response-v1.schema.json',
    'late-cancel-preclaim_recorded-response.json': 'effect-cancellation-response-v1.schema.json',
    'late-cancel-preclaim_admitted-response.json': 'effect-cancellation-response-v1.schema.json',
    'invalid-late-cancel-possible_call-response.json': 'effect-cancellation-response-v1.schema.json',
    'invalid-late-cancel-outcome_recorded-response.json': 'effect-cancellation-response-v1.schema.json',
    'invalid-late-cancel-result_admitted-response.json': 'effect-cancellation-response-v1.schema.json',
}



def validate_late_cancellation_vectors(manifest, artifacts):
    vectors = {vector['name']: vector for vector in manifest['vectors']}
    required_late = {'late-cancel-' + state for state in (
        'outcome_recorded', 'result_admitted', 'preclaim_recorded', 'preclaim_admitted')}
    required_invalid = {'invalid-late-cancel-' + state for state in (
        'possible_call', 'outcome_recorded', 'result_admitted')}
    if not (required_late | required_invalid).issubset(vectors):
        raise ValueError('late cancellation coverage missing')
    for name in sorted(required_late | required_invalid):
        vector = vectors[name]
        request, expected = vector['request'], vector['expected']
        before = artifacts[request['journal_before']]
        after = artifacts[expected['journal_after']]
        response = artifacts[expected['response']]
        arguments = request['arguments']
        if request['operation'] != 'cancel_effect' or response['operation_id'] != arguments['operation_id'] or \
                response['effect_id'] != arguments['effect_id'] or \
                artifacts[request['checkpoint_before']] != artifacts[expected['checkpoint_after']] or \
                expected['counts'] != {'provider_calls': 0, 'core_calls': 0, 'new_claims': 0}:
            raise ValueError(f'{name}: cancellation boundary differs')
        if name in required_invalid:
            declaration = load_yaml(CASE / 'machine.yaml')['events']['native_cancelled']
            if arguments['payload'] != typed_value({'undeclared': 'value'}) or \
                    'undeclared' in declaration.get('payload', {}):
                raise ValueError(f'{name}: payload is not the pinned undeclared field')
            if response['status'] != 'rejected' or response['error_code'] != 'invalid_host_request' or \
                    any(response[key] is not None for key in (
                        'cancellation', 'outcome', 'result_event_id', 'journal_revision')) or after != before:
                raise ValueError(f'{name}: invalid payload mutated or disclosed evidence')
        else:
            record = before['effect_records'][0]
            cancellation = {'operation_id': arguments['operation_id'], 'reason': arguments['reason'], 'state': 'too_late'}
            refs = before['operation_response_references'] + [{
                'operation_id': arguments['operation_id'],
                'response_digest': digest(['determa-host-operation-response-1', response])}]
            refs.sort(key=lambda item: item['operation_id'].encode('utf-8'))
            if response['status'] != 'committed' or response['error_code'] is not None or \
                    response['cancellation'] != cancellation or response['outcome'] != record['outcome'] or \
                    response['result_event_id'] != record['result_event_id'] or \
                    after['effect_records'] != before['effect_records'] or \
                    response['journal_revision'] != str(int(before['journal_revision']) + 1) or \
                    after['journal_revision'] != response['journal_revision'] or \
                    after['operation_response_references'] != refs:
                raise ValueError(f'{name}: winning outcome or exact cancellation evidence changed')
    return len(required_late | required_invalid)

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
    closure = strict_json((CASE / 'data/handler-closure.json').read_bytes())
    preimage = bytearray(b'determa-effect-handler-closure-1\0')
    entries = []
    for path in sorted((CASE / 'handler').glob('test_handler.*')):
        name = str(path.relative_to(CASE))
        source = path.read_bytes()
        name_bytes = name.encode('utf-8')
        preimage += len(name_bytes).to_bytes(8, 'big') + name_bytes
        preimage += len(source).to_bytes(8, 'big') + source
        entries.append({'path': name, 'sha256': 'sha256:' + hashlib.sha256(source).hexdigest(),
                        'byte_length': len(source)})
    if closure != {'format': 'determa.effect_handler_closure', 'schema_version': 1,
                   'files': entries, 'closure_digest': 'sha256:' + hashlib.sha256(preimage).hexdigest()}:
        raise ValueError('handler closure digest is not bound to exact raw source')
    destination_configuration = strict_json((CASE / 'data/destination-configuration.json').read_bytes())
    if destination_configuration != {
            'format': 'determa.effect_destination_binding', 'schema_version': 1,
            'scope_identity': SCOPE_ID, 'destination': 'conformance.fake-native-destination',
            'idempotency_namespace': SCOPE_ID, 'connector_version': '1'}:
        raise ValueError('destination configuration identity differs')
    destination_digest = 'sha256:' + hashlib.sha256(rfc8785.dumps(destination_configuration)).hexdigest()
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
            if record['destination_binding_digest'] != destination_digest:
                raise ValueError(f'{name}: pinned destination configuration differs')
            if record['handler_reference']['content_digest'] != closure['closure_digest']:
                raise ValueError(f'{name}: pinned handler reference differs from executable closure')
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
    validate_late_cancellation_vectors(manifest, artifacts)
    for file_name, coverage in manifest['normative_case_coverage'].items():
        source = strict_json((spec_root / SPEC_EXAMPLES / file_name).read_bytes())
        if {case['name'] for case in source['cases']} != set(coverage) or \
                any(type(targets) is not list or not targets or
                    any(target not in named for target in targets)
                    for targets in coverage.values()):
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
    route = next(vector for vector in vectors if vector['name'] == 'route_generation_changed')
    plan = route['request']['control_plan']
    observed = route['expected']['control_events']
    if [item['action'] for item in plan] != [
            'start_call', 'await_barrier', 'release_barrier', 'await_barrier',
            'set_route_generation', 'release_barrier', 'observe_native_fate'] or \
            [item['event'] for item in observed] != [
                'started', 'barrier_reached', 'released', 'barrier_reached',
                'configuration_changed', 'released', 'native_fate'] or \
            route['request']['host_configuration']['route_generation'] != '7' or \
            plan[4]['route_generation'] != '8' or \
            observed[1]['resolved_route_generation'] != '7' or \
            observed[3]['proposed_checkpoint_digest'] != artifacts['pending-checkpoint.json']['execution_checkpoint_digest'] or \
            observed[3]['proposed_journal_digest'] != artifacts['data/unclaimed-journal.json']['host_effect_journal_digest'] or \
            observed[6]['guard_result'] != 'scope_generation_conflict' or \
            observed[6]['transaction_fate'] != 'rolled_back' or \
            observed[6]['checkpoint_digest'] != artifacts['accepted-checkpoint.json']['execution_checkpoint_digest'] or \
            observed[6]['journal_digest'] != artifacts['data/empty-journal.json']['host_effect_journal_digest'] or \
            route['expected']['counts'] != {'provider_calls': 0, 'core_calls': 1, 'new_claims': 0} or \
            route['expected']['caller_kind'] != 'aborted':
        raise ValueError('route change lacks two-stage core proposal and native rollback proof')
    allowed_counts = {'provider_calls', 'core_calls', 'new_claims'}
    for vector in vectors:
        if set(vector) != {'name', 'covers', 'request', 'expected'}:
            raise ValueError('unclosed vector')
        if set(vector['request']) != {'operation', 'checkpoint_before', 'journal_before', 'claim',
                                     'host_configuration', 'auth_context', 'arguments', 'fault', 'control_plan'}:
            raise ValueError('unclosed adapter request')
        if set(vector['expected']) != {'response', 'caller_kind', 'control_events', 'checkpoint_after', 'journal_after', 'counts'} or \
                set(vector['expected']['counts']) != allowed_counts:
            raise ValueError('unclosed expected observation')
        caller_kind = vector['expected']['caller_kind']
        if caller_kind not in {'response', 'completed', 'aborted', 'no_response'} or \
                (caller_kind == 'response') != (vector['expected']['response'] is not None):
            raise ValueError(f'{vector["name"]}: caller response kind and oracle disagree')
        if type(vector['request']['control_plan']) is not list or \
                type(vector['expected']['control_events']) is not list or \
                (vector['request']['control_plan'] and vector['name'] != 'route_generation_changed') or \
                (vector['expected']['control_events'] and vector['name'] != 'route_generation_changed'):
            raise ValueError('invalid control plan or event scope')
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
    by_name = {item['name']: item for item in vectors}
    source_results = strict_json((spec_root / SPEC_EXAMPLES / 'result-admission-cases-v1.json').read_bytes())
    baseline_source = source_results['cases'][0]['request']
    baseline_vector = by_name['first_terminal_result']['request']['arguments']
    for case in source_results['cases']:
        target_name = manifest['normative_case_coverage']['result-admission-cases-v1.json'][case['name']][0]
        vector = by_name[target_name]
        request = vector['request']['arguments']
        response_name = vector['expected']['response']
        response = artifacts[response_name] if response_name is not None else None
        before = vector['request']
        after = vector['expected']
        changed = before['checkpoint_before'] != after['checkpoint_after'] or \
                  before['journal_before'] != after['journal_after']
        if before['operation'] != 'submit_result' or response is None or \
                response['status'] != case['expected_response']['status'] or \
                response['error_code'] != case['expected_response']['error_code'] or \
                after['counts']['core_calls'] != case['new_core_admissions'] or \
                changed != case['mutates_checkpoint_or_journal'] or \
                (request['operation_token'] == baseline_vector['operation_token']) != \
                    (case['request']['operation_token'] == baseline_source['operation_token']) or \
                request['attempt_fence'] != case['request']['attempt_fence'] or \
                request['outcome_kind'] != case['request']['outcome_kind'] or \
                (request['payload'] == baseline_vector['payload']) != \
                    (case['request']['payload'] == baseline_source['payload']):
            raise ValueError(f'{case["name"]}: normative result request/response or mutation differs')
    auth_expectations = {'wrong_worker_principal': ('principal', False),
                         'wrong_scope': ('scope_identity', False),
                         'stale_scope_epoch': ('scope_authority_epoch', False),
                         'old_epoch_equal_replay_after_recovery': ('scope_authority_epoch', False)}
    regular_auth = by_name['first_terminal_result']['request']['auth_context']
    for source_name, (field, equal_expected) in auth_expectations.items():
        target = manifest['normative_case_coverage']['result-admission-cases-v1.json'][source_name][0]
        if (by_name[target]['request']['auth_context'][field] == regular_auth[field]) != equal_expected:
            raise ValueError(f'{source_name}: normative authenticated context mismatch')
    expiration = artifacts['data/active-claim.json']['expires_at']
    for source_name in ('claim_expired_at_exact_boundary', 'expired_worker_after_outcome_commit'):
        target = manifest['normative_case_coverage']['result-admission-cases-v1.json'][source_name][0]
        if by_name[target]['request']['auth_context']['trusted_host_now'] != expiration:
            raise ValueError(f'{source_name}: exact expiry boundary missing')
    source_cancellations = strict_json((spec_root / SPEC_EXAMPLES / 'effect-cancellation-cases-v1.json').read_bytes())
    for case in source_cancellations['cases']:
        target = manifest['normative_case_coverage']['effect-cancellation-cases-v1.json'][case['name']][0]
        vector = by_name[target]
        response = artifacts[vector['expected']['response']]
        changed = vector['request']['journal_before'] != vector['expected']['journal_after']
        if vector['request']['operation'] != 'cancel_effect' or \
                response['status'] != case['expected_response']['status'] or \
                response['error_code'] != case['expected_response']['error_code'] or \
                (response['cancellation'] or {}).get('state') != \
                    (case['expected_response']['cancellation'] or {}).get('state') or \
                vector['expected']['counts']['provider_calls'] != case['provider_calls'] or \
                vector['expected']['counts']['new_claims'] != case['new_worker_claims'] or \
                changed != case['mutates_journal']:
            raise ValueError(f'{case["name"]}: normative cancellation disposition differs')
    prevented = artifacts['data/preclaim-cancelled-journal.json']['effect_records'][0]
    later_claim = by_name['claim_after_preclaim_cancel_refused']
    if prevented['cancellation']['state'] != 'prevented_start' or \
            prevented['outcome']['kind'] != 'cancelled' or \
            prevented['attempt_records'] or \
            later_claim['request']['operation'] != 'claim' or \
            later_claim['request']['journal_before'] != 'data/preclaim-cancelled-journal.json' or \
            later_claim['expected']['journal_after'] != 'data/preclaim-cancelled-journal.json' or \
            later_claim['expected']['counts'] != {'provider_calls': 0, 'core_calls': 0, 'new_claims': 0}:
        raise ValueError('preclaim cancellation did not prevent later claim and dispatch')
    # The fourteen prose examples specify operations and observable consequences.
    host_obligations = {
        'committed_selected_intent': ('claim', True, 0, 1),
        'uncommitted_intent': ('dispatch', False, 0, 0),
        'route_generation_changed': ('produce', False, 0, 0),
        'equal_request_after_route_change': ('produce_replay', False, 0, 0),
        'revoked_dispatch': ('dispatch', False, 0, 0),
        'accepted_outbox_pending_business': ('terminalize_outbox', True, 0, 0),
        'wrong_token': ('submit_result', False, 0, 0),
        'wrong_scope_or_principal': ('submit_result', False, 0, 0),
        'old_epoch_or_fence': ('submit_result', False, 0, 0),
        'equal_and_conflicting_result': ('submit_result', False, 0, 0),
        'crash_after_provider_acceptance': ('recover', True, 0, 0),
        'crash_after_outcome_commit': ('recover', True, 0, 0),
        'cancellation_before_claim': ('cancel_effect', True, 0, 0),
        'cancellation_after_possible_call': ('cancel_effect', True, 0, 0),
    }
    for source_name, (operation, mutation, provider_count, claim_count) in host_obligations.items():
        targets = manifest['normative_case_coverage']['host-native-effect-cases-v1.json'][source_name]
        primary = by_name[targets[0]]
        changed = primary['request']['checkpoint_before'] != primary['expected']['checkpoint_after'] or \
                  primary['request']['journal_before'] != primary['expected']['journal_after']
        if primary['request']['operation'] != operation or changed != mutation or \
                primary['expected']['counts']['provider_calls'] != provider_count or \
                primary['expected']['counts']['new_claims'] != claim_count:
            raise ValueError(f'{source_name}: normative host effect operation/evidence differs')
    for source_name, target_names in {
            'wrong_scope_or_principal': ['wrong_scope', 'wrong_principal'],
            'old_epoch_or_fence': ['claim_expired_at_exact_boundary', 'stale_fence'],
            'equal_and_conflicting_result': ['equal_result_replay', 'unequal_result_conflict'],
            'cancellation_before_claim': ['cancel_before_claim', 'claim_after_preclaim_cancel_refused'],
    }.items():
        if manifest['normative_case_coverage']['host-native-effect-cases-v1.json'][source_name] != target_names:
            raise ValueError(f'{source_name}: normative paired obligations incomplete')
    if any(artifacts[by_name[target]['expected']['response']]['error_code'] != 'stale_attempt_fence'
           for target in ('claim_expired_at_exact_boundary', 'stale_fence')):
        raise ValueError('old epoch/fence source example requires stale attempt refusal')
    safe = by_name['safe_retry_report']
    if artifacts[safe['expected']['response']]['attempt_report']['reason'] != 'destination_deduplication_proven':
        raise ValueError('safe retry mislabels destination deduplication as no-call proof')
    for failure in ('missing', 'boolean', 'fabricated', 'wrong_work', 'wrong_destination', 'verifier_unavailable'):
        vector = by_name.get('retry_safety_' + failure)
        if vector is None or vector['request'] != {**safe['request'], 'fault': 'retry_safety_' + failure} or \
                vector['expected'] != {**safe['expected'],
                                       'response': 'data/rejected-host_capability_mismatch.json',
                                       'journal_after': safe['request']['journal_before']}:
            raise ValueError('independent retry safety refusal boundary is incomplete or mutated')
        retry = by_name.get('ambiguous_retry_safety_' + failure)
        safe_claim = by_name['ambiguous_retry_with_proven_deduplication']
        if retry is None or retry['request'] != {**safe_claim['request'], 'fault': 'retry_safety_' + failure} or \
                retry['expected'] != {**safe_claim['expected'],
                                      'caller_kind': 'aborted', 'journal_after': safe_claim['request']['journal_before'],
                                      'counts': {'provider_calls': 0, 'core_calls': 0, 'new_claims': 0}}:
            raise ValueError('independent ambiguous retry refusal boundary is incomplete or mutated')
    return len(vectors)
