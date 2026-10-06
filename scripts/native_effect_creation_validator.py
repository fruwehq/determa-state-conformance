"""Draft initialization/journal relational checks; not a production certificate."""
from __future__ import annotations

from generate_version1_vectors import digest, typed_value


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sealed(value, member, domain):
    require(value[member] == digest([domain, {key: item for key, item in value.items()
                                           if key != member}]), member)


def validate_creation(request, checkpoint, journal, response):
    """Check observed joint facts independently of an engine's journal validator.

    These checks supplement schema validation and exact core-result goldens.
    Native authority, transactions and execution require separate runner evidence.
    """
    sealed(checkpoint, 'execution_checkpoint_digest', 'determa-execution-checkpoint-digest-1')
    sealed(journal, 'host_effect_journal_digest', 'determa-host-effect-journal-digest-1')
    aggregate = checkpoint['root_record']['aggregate_state']
    sealed(aggregate, 'aggregate_state_digest', 'determa-aggregate-state-digest-1')
    require(checkpoint['revision'] == '0', 'fresh creation revision')
    require(checkpoint['root_instance_id'] == request['root_instance_id'], 'creation root')
    receipt = checkpoint['operation_receipts'][0]
    require(receipt['operation_kind'] == 'creation' and receipt['receipt_sequence'] == '0'
            and receipt['committed_revision'] == '0', 'creation receipt')
    require(receipt['creation_id'] == request['creation_id'], 'creation identity')
    require(receipt['request_digest'] == digest([
        'determa-creation-request-digest-1', '1', request['validated_bundle_fingerprint'],
        request['namespace'], request['machine_id'], request['machine_version'],
        request['root_instance_id'], request['creation_id'], typed_value(request['bindings'])]),
        'creation request digest')
    require(receipt['resulting_aggregate_state_digest'] == aggregate['aggregate_state_digest'],
            'creation aggregate binding')
    require(journal['scope_identity'] == request['scope_identity']
            and journal['root_instance_id'] == checkpoint['root_instance_id']
            and journal['checkpoint_revision'] == checkpoint['revision']
            and journal['checkpoint_digest'] == checkpoint['execution_checkpoint_digest']
            and journal['journal_revision'] == '0', 'initial joint pair')
    intents = {item['intent']['effect_id']: item['intent']
               for item in checkpoint['pending_outbox_intents']}
    require(len(intents) == len(checkpoint['pending_outbox_intents']), 'duplicate initial intent')
    records = journal['effect_records']
    identifiers = [record['effect_id'] for record in records]
    require(identifiers == sorted(intents, key=lambda item: item.encode('utf-8')),
            'complete ordered initial effect inventory')
    for record in records:
        intent = intents[record['effect_id']]
        require(record['intent_digest'] == digest([
            'determa-outbox-intent-digest-1', '1', request['root_instance_id'], intent]),
            'initial intent digest')
        # This first fixture declares machine-visible correlation tokens.
        require(record['operation_token'] == intent['correlation_id']
                == request['bindings']['input']['operation_token'], 'declared initial token')
        for member in ('handler_reference', 'destination_binding_digest', 'result_mapping',
                       'idempotency_policy'):
            require(record[member] == request['route'][member], 'initial route ' + member)
        require(record['route_configuration_generation'] == request['route']['generation'],
                'initial route generation')
        target = record['target']
        runtime = next((item for item in aggregate['runtimes']
                        if item['runtime_id'] == target['runtime_id']), None)
        require(runtime is not None and target['root_instance_id'] == request['root_instance_id']
                and target['runtime_incarnation'] == runtime['identity_origin'], 'initial target')
        require(record['attempt_fence'] == '0' and record['attempt_records'] == []
                and record['invocation_state'] == 'unclaimed'
                and all(record[member] is None for member in (
                    'outcome', 'result_event_id', 'admission_receipt', 'cancellation')),
                'no initial invocation')
    require(journal['operation_response_references'] == [{
        'operation_id': request['creation_id'],
        'response_digest': digest(['determa-host-operation-response-1', response])}],
        'retained first response binding')
    require(response['checkpoint'] == checkpoint and response['creation_receipt'] == receipt,
            'exact creation response pair')
