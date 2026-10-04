#!/usr/bin/env python3
"""Generate the closed optional application-projection profile from pinned witnesses."""
from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

from generate_version1_vectors import (
    aggregate_shape_fingerprint_document, bundle_binding, bundle_fingerprint_document,
    commit_v1_maintenance_migration, digest, load_yaml, maintenance_request_digest,
    migrate_compatible_aggregate, native_v1_checkpoint, seal_aggregate, seal_checkpoint,
    v1_migration_audit_record,
)
from generate_execution_checkpoint_profile import admit, envelope_for, process

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'conformance/profiles/execution-checkpoint/checkpoint-07-complete-host-contract'
DEFERRAL_SOURCE = ROOT / 'conformance/core/117-version1-mailboxes'
OUTBOX_SOURCE = ROOT / 'conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox'
TARGET = ROOT / 'conformance/profiles/application-projection/projection-01-lossless-facade'
ENV_MACHINE = """format: 1
namespace: conformance.application_projection_env
machines:
  - machine_id: refresh_all
    version: 1
    root:
      variables:
        token: { type: string, external: true }
        region: { type: string, external: true }
      on_events:
        env:
          action:
            - refresh: {}
  - machine_id: refresh_only
    version: 1
    root:
      variables:
        token: { type: string, external: true }
        region: { type: string, external: true }
      on_events:
        env:
          action:
            - refresh: { only: [token] }
  - machine_id: refresh_integer
    version: 1
    root:
      variables:
        amount: { type: int, external: true }
      on_events:
        env:
          action:
            - refresh: {}
"""


def env_step(checkpoint: dict, *, faulted: bool) -> tuple[dict, dict]:
    """Normative §6/§10 oracle for the two simple refresh machines."""
    value = copy.deepcopy(checkpoint)
    aggregate = value['root_record']['aggregate_state']
    runtime = aggregate['runtimes'][0]
    entry = runtime['ready_mailbox'].pop(0)
    changed = dict(entry['envelope']['payload'][1])['changed'][1]
    changed = dict(changed)
    sequence = aggregate['next_logical_step_sequence']
    aggregate['next_logical_step_sequence'] = str(int(sequence) + 1)
    fault = None
    if faulted:
        fault = {
            'definition_fingerprint': aggregate['validated_bundle_fingerprint'],
            'runtime_id': runtime['runtime_id'], 'cause_id': entry['envelope']['cause_id'],
            'code': 'action_fault', 'step_sequence': sequence,
            'source_locator': '/machines/1/root/on_events/env/action/0/refresh/only/0',
        }
        runtime['status'] = 'faulted'
        runtime['fault'] = fault
    else:
        for variable in runtime['variables']:
            name = variable['variable_declaration_pointer'].rsplit('/', 1)[-1]
            if name in changed:
                variable['value'] = changed[name]
    aggregate = seal_aggregate(aggregate)
    value['root_record']['aggregate_state'] = aggregate
    value['revision'] = str(int(value['revision']) + 1)
    receipt_sequence = value['next_operation_receipt_sequence']
    value['next_operation_receipt_sequence'] = str(int(receipt_sequence) + 1)
    value['operation_receipts'].append({
        'operation_kind': 'event_terminal', 'receipt_sequence': receipt_sequence,
        'event_id': entry['envelope']['event_id'],
        'request_digest': entry['envelope_digest'],
        'acceptance_sequence': entry['acceptance_sequence'],
        'final_queue_sequence': entry['queue_sequence'],
        'committed_revision': value['revision'],
        'resulting_aggregate_state_digest': aggregate['aggregate_state_digest'],
        'outcome': {'disposition': 'faulted' if faulted else 'handled',
                    'status': 'faulted' if faulted else 'running',
                    'fault': fault, 'rejection': None},
        'emission_references': [],
    })
    value = seal_checkpoint(value)
    public_fault = fault
    result = {
        'core_step_result_format': 'determa.core_step_result',
        'core_step_result_schema_version': 1,
        'status': 'faulted' if faulted else 'running',
        'disposition': 'faulted' if faulted else 'handled',
        'state': aggregate, 'emissions': [], 'lifecycle_dispositions': [],
        'fault': public_fault, 'rejection': None,
    }
    return value, result



def render(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()


def build() -> dict[str, bytes]:
    checkpoints = {
        name: json.loads((SOURCE / name).read_bytes())
        for name in ('created-checkpoint-v1.json', 'accepted-checkpoint-v1.json', 'handled-checkpoint-v1.json')
    }
    checkpoints['accepted-checkpoint-v1.json'] = admit(
        checkpoints['created-checkpoint-v1.json'], 'increment', 'complete-increment', {'amount': 7}
    )
    checkpoints['handled-checkpoint-v1.json'] = process(checkpoints['accepted-checkpoint-v1.json'])
    source_responses = json.loads((SOURCE / 'responses-v1.json').read_bytes())['responses']
    source_bundle = load_yaml(SOURCE / 'machine.yaml')
    target_bundle = copy.deepcopy(source_bundle)
    target_bundle['events']['increment']['payload']['amount']['type'] = 'float'
    target_bundle['machines'][0]['root']['on_events']['increment']['action'][0]['assign']['count'] = 'count + 1'
    target_bundle_bytes = render(target_bundle)
    source_fingerprint = checkpoints['handled-checkpoint-v1.json']['root_record']['aggregate_state']['validated_bundle_fingerprint']
    target_fingerprint = bundle_fingerprint_document(target_bundle)
    shape_before = aggregate_shape_fingerprint_document(source_bundle)
    shape_after = aggregate_shape_fingerprint_document(target_bundle)
    if shape_before != shape_after:
        raise RuntimeError('replay target changed aggregate shape')
    descriptor = json.loads((ROOT / 'conformance/profiles/execution-checkpoint/checkpoint-04-version1-mailboxes/maintenance-descriptor-one.json').read_bytes())
    descriptor['source_validated_bundle_fingerprint'] = source_fingerprint
    descriptor['target_validated_bundle_fingerprint'] = target_fingerprint
    descriptor['source_aggregate_shape_fingerprint'] = shape_before
    descriptor['target_aggregate_shape_fingerprint'] = shape_after
    descriptor.pop('migration_descriptor_digest')
    descriptor['migration_descriptor_digest'] = digest(['determa-migration-descriptor-1', descriptor])
    migration_source = checkpoints['handled-checkpoint-v1.json']
    migration_source_aggregate = migration_source['root_record']['aggregate_state']
    migration_target_aggregate = migrate_compatible_aggregate(migration_source_aggregate, descriptor)
    audit = v1_migration_audit_record(migration_source_aggregate, migration_target_aggregate, descriptor)
    migration_id = 'projection-declaration-change'
    operation = {
        'operation_id': migration_id,
        'target_bundle': {'validated_bundle_fingerprint': target_fingerprint},
        'request_digest': maintenance_request_digest(
            migration_source['root_instance_id'], migration_id,
            migration_source_aggregate['aggregate_state_digest'], target_fingerprint,
            [descriptor['migration_descriptor_digest']], True,
        ),
    }
    migrated, _ = commit_v1_maintenance_migration(
        migration_source, operation, migration_target_aggregate, [audit]
    )
    checkpoints['replay-migrated-checkpoint-v1.json'] = migrated
    with tempfile.TemporaryDirectory() as temporary:
        env_bundle = Path(temporary) / 'external-machine.yaml'
        env_bundle.write_text(ENV_MACHINE)
        env_results = {}
        for slug, machine, payload, faulted in (
            ('success', 'refresh_all', {'token': 'new', 'region': 'west'}, False),
            ('fault', 'refresh_only', {'region': 'west'}, True),
            ('integer', 'refresh_integer', {'amount': 7}, False),
        ):
            env_root = f'projection-env-{slug}-root'
            creation = {
                'machine_id': machine, 'machine_version': '1',
                'root_instance_id': env_root, 'creation_id': f'projection-env-{slug}-create',
                'bindings': {'input': {}, 'external': (
                    {'amount': 0} if slug == 'integer' else {'token': 'old', 'region': 'east'}
                )},
            }
            initial = native_v1_checkpoint(env_bundle, creation)
            admitted = admit(initial, 'env', f'projection-env-{slug}-event', {'changed': payload})
            finished, core = env_step(admitted, faulted=faulted)
            names = [f'env-{slug}-{stage}-checkpoint-v1.json' for stage in ('created', 'accepted', 'processed')]
            checkpoints.update(dict(zip(names, (initial, admitted, finished))))
            envelope_value, envelope_digest = envelope_for(initial, 'env', f'projection-env-{slug}-event', {'changed': payload})
            env_results[slug] = (names, {'delivery_mode': 'input', 'envelope': envelope_value,
                                         'envelope_digest': envelope_digest}, core)
    deferral_before = json.loads((DEFERRAL_SOURCE / 'repeated-before.json').read_bytes())
    deferral_result = json.loads((DEFERRAL_SOURCE / 'repeated-deferral-result.json').read_bytes())
    deferral_candidate = deferral_result['state']
    pending_outbox = json.loads((OUTBOX_SOURCE / 'pending-checkpoint-v1.json').read_bytes())
    checkpoints['outbox-pending-checkpoint-v1.json'] = pending_outbox
    root = checkpoints['created-checkpoint-v1.json']['root_instance_id']
    envelope_value, envelope_digest = envelope_for(
        checkpoints['created-checkpoint-v1.json'], 'increment', 'complete-increment', {'amount': 7}
    )
    envelope = {'delivery_mode': 'input', 'envelope': envelope_value, 'envelope_digest': envelope_digest}
    selected = 'order-1'

    def row(checkpoint: str | None, *, owner: str = root, amount: list | None = None,
            status: str = 'pending', token: str | None = None, region: str | None = None) -> dict:
        result = {'row_id': selected, 'root_instance_id': owner, 'status': status,
                  'amount': amount or ['integer', '7']}
        if token is not None:
            result['token'] = ['string', token]
        if region is not None:
            result['region'] = ['string', region]
        return result

    def snapshot(checkpoint: str | None, **changes: object) -> dict:
        return {'selected_rows': [row(checkpoint, **changes)], 'checkpoint': checkpoint,
                'supplemental_checkpoint': checkpoint}

    def identity(checkpoint: str | None) -> dict | None:
        if checkpoint is None:
            return None
        value = checkpoints[checkpoint]
        return {'root_instance_id': value['root_instance_id'], 'revision': value['revision'],
                'digest': value['execution_checkpoint_digest']}

    def request(operation: str, before: str | None, *, boundary: str = 'declared_input',
                mapped: dict | None = None, delivery: dict | None = None,
                root_id: str = root, selected_ids: list[str] | None = None,
                shared_requested: bool = True, shared_available: bool = True,
                capacity: str = 'complete', mapping: str = 'order-amount-v1',
                target_override: str | None = None) -> dict:
        aggregate = checkpoints[before or created]['root_record']['aggregate_state']
        creation = ({'machine_id': aggregate['root_machine_id'],
                     'machine_version': aggregate['root_machine_version'],
                     'creation_id': aggregate['creation_id'],
                     'bindings': {'input': {}, 'external': {}}} if operation == 'create' else None)
        target_runtime_id = (target_override or aggregate['root_runtime_id']) if operation == 'step' else None
        return {'operation': operation, 'root_instance_id': root_id,
                'mapping': ({
                    'mapping_id': 'order-amount-v1',
                    'row_id_field': 'row_id', 'root_identity_field': 'root_instance_id',
                    'source_field': 'amount', 'input_event': 'increment',
                    'input_payload_field': 'amount', 'input_declaration': 'integer',
                    'supplemental_field': 'supplemental_checkpoint',
                    'status_field': 'status', 'status_rule': 'done_when_count_positive'
                } if mapping == 'order-amount-v1' else ({
                    'mapping_id': 'transaction-deferral-v1',
                    'row_id_field': 'row_id', 'root_identity_field': 'root_instance_id',
                    'source_field': 'transaction_id', 'input_event': 'new_request',
                    'input_payload_field': 'transaction_id', 'input_declaration': 'string',
                    'supplemental_field': 'supplemental_aggregate'
                } if mapping == 'transaction-deferral-v1' else ({
                    'mapping_id': 'external-amount-v1',
                    'row_id_field': 'row_id', 'root_identity_field': 'root_instance_id',
                    'source_fields': ['amount'], 'target': 'env.changed',
                    'declarations': ['integer'],
                    'supplemental_field': 'supplemental_checkpoint'
                } if mapping == 'external-amount-v1' else {
                    'mapping_id': 'external-token-region-v1',
                    'row_id_field': 'row_id', 'root_identity_field': 'root_instance_id',
                    'source_fields': ['region', 'token'], 'target': 'env.changed',
                    'declarations': ['string', 'string'],
                    'supplemental_field': 'supplemental_checkpoint'
                }))), 'creation': creation,
                'target_runtime_id': target_runtime_id,
                'selected_row_ids': selected_ids or [selected], 'boundary': boundary,
                'mapped_input': mapped, 'delivery': delivery,
                'expected_checkpoint': identity(before),
                'shared_transaction_requested': shared_requested,
                'shared_transaction_available': shared_available, 'supplemental_capacity': capacity}

    amount = {'field': 'amount', 'declaration': 'integer', 'value': ['integer', '7']}
    wrong = {'field': 'amount', 'declaration': 'integer', 'value': ['float', '401c000000000000']}
    undeclared = {'field': 'unknown', 'declaration': 'integer', 'value': ['integer', '7']}
    created, accepted, handled = (
        'created-checkpoint-v1.json', 'accepted-checkpoint-v1.json', 'handled-checkpoint-v1.json'
    )
    created_state = checkpoints[created]['root_record']['aggregate_state']
    accepted_state = checkpoints[accepted]['root_record']['aggregate_state']
    core_step = copy.deepcopy(source_responses['handled_delayed']['body']['core_result'])
    core_step['state'] = checkpoints[handled]['root_record']['aggregate_state']
    vectors = []

    def add(name: str, before: dict, after: dict, req: dict, kind: str, code: str | None = None,
            result: dict | None = None, calls: int = 0, committed: bool = False) -> None:
        vectors.append({'name': name, 'covers': name, 'request': req, 'before': before,
                        'after': after, 'outcome': {'kind': kind, 'code': code,
                        'result_value': result, 'core_calls': calls, 'committed': committed}})

    create_result = {'status': 'running', 'state': created_state, 'emissions': [],
                     'lifecycle_dispositions': [], 'fault': None, 'rejection': None}
    admit_result = {'status': 'running', 'accepted': True, 'state': accepted_state, 'rejection': None}
    add('create_result_shape', snapshot(None), snapshot(created),
        request('create', None, boundary='create_binding'), 'result', result=create_result, calls=1, committed=True)
    add('typed_row_input_atomic_admit', snapshot(created), snapshot(accepted),
        request('admit', created, mapped=amount, delivery=envelope), 'result', result=admit_result, calls=1, committed=True)
    add('step_preserves_complete_result', snapshot(accepted), snapshot(handled, status='done'),
        request('step', accepted), 'result', result=core_step, calls=1, committed=True)
    add('row_float_to_integer_rejected', snapshot(created, amount=wrong['value']), snapshot(created, amount=wrong['value']),
        request('admit', created, mapped=wrong), 'failure', 'invalid_projection_input')
    add('undeclared_row_field_rejected', snapshot(created), snapshot(created),
        request('admit', created, mapped=undeclared), 'failure', 'invalid_projection_input')
    original_admission = copy.deepcopy(
        next(vector['request'] for vector in vectors if vector['name'] == 'typed_row_input_atomic_admit')
    )
    add('equal_pending_delivery_replay', snapshot(accepted), snapshot(accepted),
        copy.deepcopy(original_admission), 'replay',
        result=checkpoints[accepted]['operation_receipts'][-1])
    vectors[-1]['replay_of'] = 'typed_row_input_atomic_admit'
    add('equal_delivery_replay', snapshot('replay-migrated-checkpoint-v1.json', status='done'),
        snapshot('replay-migrated-checkpoint-v1.json', status='done'),
        copy.deepcopy(original_admission), 'replay',
        result=checkpoints['handled-checkpoint-v1.json']['operation_receipts'][-1])
    vectors[-1]['replay_of'] = 'typed_row_input_atomic_admit'
    vectors[-1]['migration_source'] = 'handled-checkpoint-v1.json'
    vectors[-1]['migration_descriptor'] = 'replay-descriptor-v1.json'
    vectors[-1]['target_bundle'] = 'replay-target.yaml'
    changed_delivery = copy.deepcopy(envelope)
    changed_delivery['envelope']['payload'] = ['map', [['amount', ['float', '401c000000000000']]]]
    changed_delivery['envelope_digest'] = digest([
        'determa-inbox-envelope-digest-1', '1', root, 'input', changed_delivery['envelope']
    ])
    add('changed_identity_conflict_before_payload', snapshot(accepted), snapshot(accepted),
        request('admit', created, delivery=changed_delivery), 'failure', 'event_id_conflict')
    add('direct_state_edit_unsupported', snapshot(created), snapshot(created),
        request('step', created, boundary='direct_state_write'), 'failure', 'unsupported_projection_boundary')
    add('enum_only_prior_unrepresentable', snapshot(None), snapshot(None),
        request('step', accepted, capacity='none'), 'failure', 'projection_not_lossless')
    vectors[-1]['prior_artifact'] = accepted
    add('enum_only_pending_intents_unrepresentable',
        snapshot(None, owner=pending_outbox['root_instance_id']),
        snapshot(None, owner=pending_outbox['root_instance_id']),
        request('step', 'outbox-pending-checkpoint-v1.json',
                root_id=pending_outbox['root_instance_id'], capacity='none'),
        'failure', 'projection_not_lossless')
    vectors[-1]['prior_artifact'] = 'outbox-pending-checkpoint-v1.json'
    deferral_row = row(None, owner=deferral_before['root_instance_id'])
    deferral_row['transaction_id'] = ['string', 'transaction-r']
    deferral_snapshot = {'selected_rows': [deferral_row], 'checkpoint': None,
                         'supplemental_checkpoint': None,
                         'aggregate': 'deferral-before-aggregate-v1.json',
                         'supplemental_aggregate': 'deferral-before-aggregate-v1.json'}
    add('proposed_supplement_truncation', deferral_snapshot, copy.deepcopy(deferral_snapshot),
        request('step', None, root_id=deferral_before['root_instance_id'],
                capacity='truncate', mapping='transaction-deferral-v1',
                target_override=deferral_before['root_runtime_id']),
        'failure', 'projection_not_lossless', calls=1)
    vectors[-1]['candidate_aggregate'] = 'deferral-candidate-aggregate-v1.json'
    vectors[-1]['candidate_result'] = 'deferral-candidate-result-v1.json'
    add('wrong_root_row_selection', snapshot(created, owner='foreign-root'), snapshot(created, owner='foreign-root'),
        request('admit', created, delivery=envelope), 'failure', 'invalid_projection_selection')
    add('shared_transaction_unavailable', snapshot(created), snapshot(created),
        request('admit', created, delivery=envelope, shared_available=False),
        'failure', 'projection_transaction_unavailable')
    add('stale_revision_rolls_back_rows', snapshot(accepted), snapshot(accepted),
        request('step', created), 'failure', 'checkpoint_revision_conflict', calls=1)
    for slug in ('success', 'fault', 'integer'):
        (initial_name, admitted_name, processed_name), env_delivery, env_core = env_results[slug]
        env_root = checkpoints[initial_name]['root_instance_id']
        source_token = 'new' if slug == 'success' else 'old'
        env_rows = ({'owner': env_root} if slug == 'integer' else
                    {'owner': env_root, 'token': source_token, 'region': 'west'})
        mapped_field = 'amount' if slug == 'integer' else 'token' if slug == 'success' else 'region'
        mapped_value = ['integer', '7'] if slug == 'integer' else ['string', source_token if slug == 'success' else 'west']
        env_mapped = {'field': mapped_field, 'declaration': mapped_value[0], 'value': mapped_value}
        env_aggregate = checkpoints[admitted_name]['root_record']['aggregate_state']
        env_admit_result = {'status': 'running', 'accepted': True,
                            'state': env_aggregate, 'rejection': None}
        add(f'env_{slug}_admission', snapshot(initial_name, **env_rows),
            snapshot(admitted_name, **env_rows),
            request('admit', initial_name, boundary='external_refresh', mapped=env_mapped,
                    delivery=env_delivery, root_id=env_root, mapping='external-amount-v1' if slug == 'integer' else 'external-token-region-v1'),
            'result', result=env_admit_result, calls=1, committed=True)
        add(f'env_{slug}_step', snapshot(admitted_name, **env_rows),
            snapshot(processed_name, **env_rows),
            request('step', admitted_name, boundary='external_refresh',
                    root_id=env_root, mapping='external-amount-v1' if slug == 'integer' else 'external-token-region-v1'),
            'result', result=env_core, calls=1, committed=True)
    profile = {'application_projection_format': 'determa.conformance.application_projection',
               'application_projection_schema_version': 1, 'vectors': vectors}
    files = {'projection-v1.json': render(profile),
             'machine.yaml': (SOURCE / 'machine.yaml').read_bytes(),
             'external-machine.yaml': ENV_MACHINE.encode(),
             'deferral-machine.yaml': (DEFERRAL_SOURCE / 'machine.yaml').read_bytes(),
             'outbox-machine.yaml': (OUTBOX_SOURCE / 'machine.yaml').read_bytes(),
             'replay-target.yaml': target_bundle_bytes,
             'replay-descriptor-v1.json': render(descriptor),
             'deferral-before-aggregate-v1.json': render(deferral_before),
             'deferral-candidate-aggregate-v1.json': render(deferral_candidate),
             'deferral-candidate-result-v1.json': render(deferral_result)}
    files.update({name: render(value) for name, value in checkpoints.items()})
    test = ['title: lossless selected-row projection through embedded facade',
            'static:', '  documents:', '    - { file: machine.yaml, valid: true }',
            '    - { file: external-machine.yaml, valid: true }',
            '    - { file: deferral-machine.yaml, valid: true }',
            '    - { file: outbox-machine.yaml, valid: true }',
            '    - { file: replay-target.yaml, valid: true }',
            'artifacts:', '  documents:']
    for name in checkpoints:
        test.append(f'    - {{ file: {name}, kind: execution_checkpoint_v1, valid: true }}')
    test.extend([
        '    - { file: replay-descriptor-v1.json, kind: migration_descriptor_v1, valid: true }',
        '    - { file: deferral-before-aggregate-v1.json, kind: aggregate_state_v1, valid: true }',
        '    - { file: deferral-candidate-aggregate-v1.json, kind: aggregate_state_v1, valid: true }',
        '    - { file: deferral-candidate-result-v1.json, kind: core_step_result_v1, valid: true }',
        '    - { file: projection-v1.json, kind: application_projection_v1, valid: true }',
                 'application_projection_vectors:'])
    test.extend(f'  - {vector["name"]}' for vector in vectors)
    files['test.yaml'] = ('\n'.join(test) + '\n').encode()
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    files = build()
    if not args.check:
        TARGET.mkdir(parents=True, exist_ok=True)
    for name, expected in files.items():
        path = TARGET / name
        if args.check:
            if not path.exists() or path.read_bytes() != expected:
                raise SystemExit(f'generated projection artifact differs: {path}')
        else:
            path.write_bytes(expected)
    print(f'checked {len(files)} projection profile files' if args.check else f'generated {len(files)} projection profile files')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
