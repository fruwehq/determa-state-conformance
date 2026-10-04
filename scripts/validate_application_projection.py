"""Independent relational checks for the optional §20 projection fixtures."""
from __future__ import annotations

from pathlib import Path

from validate_conformance import (
    ValidationFailure, analyze_artifact, canonical_json_bytes, hash_value,
)

REQUIRED = frozenset({
    'create_result_shape', 'typed_row_input_atomic_admit', 'step_preserves_complete_result',
    'row_float_to_integer_rejected', 'undeclared_row_field_rejected',
    'equal_delivery_replay', 'changed_identity_conflict_before_payload',
    'direct_state_edit_unsupported', 'enum_only_prior_unrepresentable',
    'proposed_supplement_truncation', 'wrong_root_row_selection',
    'shared_transaction_unavailable', 'stale_revision_rolls_back_rows',
    'env_success_admission', 'env_success_step', 'env_fault_admission', 'env_fault_step',
})
CODES = frozenset({
    'invalid_projection_selection', 'invalid_projection_input',
    'unsupported_projection_boundary', 'projection_not_lossless',
    'projection_transaction_unavailable', 'event_id_conflict',
    'checkpoint_revision_conflict',
})


def fail(name: str, message: str) -> None:
    raise ValidationFailure(f'application projection {name}: {message}')


def validate_application_projection(case: Path, test: dict, artifact_paths: set[Path]) -> int:
    expected_files = {
        'projection-v1.json', 'created-checkpoint-v1.json',
        'accepted-checkpoint-v1.json', 'handled-checkpoint-v1.json',
        *{f'env-{mode}-{stage}-checkpoint-v1.json'
          for mode in ('success', 'fault') for stage in ('created', 'accepted', 'processed')}
    }
    if {path.name for path in artifact_paths} != expected_files:
        fail(case.name, 'closed artifact manifest differs')
    artifacts = {path.name: analyze_artifact(path).document for path in artifact_paths}
    document = artifacts['projection-v1.json']
    vectors = document['vectors']
    names = [vector['name'] for vector in vectors]
    if len(names) != len(set(names)) or set(names) != REQUIRED or names != test['application_projection_vectors']:
        fail(case.name, 'closed vector inventory or test manifest differs')
    if {vector['covers'] for vector in vectors} != REQUIRED or any(
        vector['covers'] != vector['name'] for vector in vectors
    ):
        fail(case.name, 'coverage labels differ from closed vocabulary')

    def checkpoint(filename: str | None, name: str) -> dict | None:
        if filename is None:
            return None
        if filename not in artifacts or not filename.endswith('-checkpoint-v1.json'):
            fail(name, 'unmanifested checkpoint reference')
        return artifacts[filename]

    def identity(value: dict | None) -> dict | None:
        if value is None:
            return None
        return {'root_instance_id': value['root_instance_id'], 'revision': value['revision'],
                'digest': value['execution_checkpoint_digest']}

    for vector in vectors:
        name = vector['name']
        request = vector['request']
        before = vector['before']
        after = vector['after']
        outcome = vector['outcome']
        env_mapping = request['mapping']['mapping_id'] == 'external-token-region-v1'
        if request['mapping']['mapping_id'] not in {'order-amount-v1', 'external-token-region-v1'}:
            fail(name, 'unknown mapping identity')
        if name.startswith('env_') != env_mapping:
            fail(name, 'projection mapping and selected definition differ')
        before_checkpoint = checkpoint(before['checkpoint'], name)
        after_checkpoint = checkpoint(after['checkpoint'], name)
        if len(request['selected_row_ids']) != len(set(request['selected_row_ids'])):
            fail(name, 'ambiguous selected row ids')
        if [row['row_id'] for row in before['selected_rows']] != request['selected_row_ids']:
            fail(name, 'selected row snapshot does not match request')
        if [row['row_id'] for row in after['selected_rows']] != request['selected_row_ids']:
            fail(name, 'after rows do not match selected set')
        if name != 'wrong_root_row_selection' and any(
            row['root_instance_id'] != request['root_instance_id']
            for snapshot in (before, after) for row in snapshot['selected_rows']
        ):
            fail(name, 'selected row belongs to another root')
        for snapshot in (before, after):
            if snapshot['supplemental_checkpoint'] != snapshot['checkpoint']:
                fail(name, 'supplemental storage does not reconstruct checkpoint')
        if before_checkpoint is not None and before_checkpoint['root_instance_id'] != request['root_instance_id']:
            fail(name, 'prior checkpoint is owned by another root')
        if after_checkpoint is not None and after_checkpoint['root_instance_id'] != request['root_instance_id']:
            fail(name, 'result checkpoint is owned by another root')
        if outcome['kind'] == 'failure':
            if outcome['code'] not in CODES or outcome['committed'] or outcome['result_value'] is not None:
                fail(name, 'invalid typed failure result')
            if canonical_json_bytes(before) != canonical_json_bytes(after):
                fail(name, 'failed invocation changed selected rows or checkpoint')
        else:
            if outcome['code'] is not None or outcome['result_value'] is None:
                fail(name, 'successful result lacks complete facade value')
        mapped = request['mapped_input']
        delivery = request['delivery']
        if mapped is not None:
            row_field = 'amount' if name == 'undeclared_row_field_rejected' else mapped['field']
            if row_field not in before['selected_rows'][0] or mapped['value'] != before['selected_rows'][0][row_field]:
                fail(name, 'mapped value is not the selected row value')
        if delivery is not None:
            if delivery['envelope']['target']['root']['root_instance_id'] != request['root_instance_id']:
                fail(name, 'delivery targets another root')
            expected_digest = hash_value([
                'determa-inbox-envelope-digest-1', '1', request['root_instance_id'],
                delivery['delivery_mode'], delivery['envelope']
            ])
            if delivery['envelope_digest'] != expected_digest:
                fail(name, 'delivery digest does not bind exact envelope')
        if request['operation'] == 'create':
            creation = request['creation']
            if creation is None or request['target_runtime_id'] is not None:
                fail(name, 'incomplete create caller input')
            if after_checkpoint is not None:
                created_state = after_checkpoint['root_record']['aggregate_state']
                if (creation['machine_id'], creation['machine_version'], creation['creation_id']) != (
                    created_state['root_machine_id'], created_state['root_machine_version'], created_state['creation_id']
                ):
                    fail(name, 'create identity does not match candidate state')
        elif request['creation'] is not None:
            fail(name, 'non-create request contains creation input')
        if request['operation'] == 'step':
            if before_checkpoint is not None and request['target_runtime_id'] != before_checkpoint['root_record']['aggregate_state']['root_runtime_id']:
                fail(name, 'step target is not selected root runtime')
        elif request['target_runtime_id'] is not None:
            fail(name, 'non-step request contains target runtime')
        if name == 'create_result_shape':
            if request['operation'] != 'create' or before_checkpoint is not None or request['boundary'] != 'create_binding':
                fail(name, 'create input mismatch')
        elif name == 'typed_row_input_atomic_admit':
            if request['operation'] != 'admit' or mapped is None or mapped['value'][0] != 'integer' or delivery is None:
                fail(name, 'typed admission input mismatch')
            if delivery['envelope']['payload'] != ['map', [['amount', mapped['value']]]]:
                fail(name, 'admission envelope was not built from mapped typed field')
        elif name == 'step_preserves_complete_result':
            if request['operation'] != 'step' or delivery is not None or before_checkpoint is None:
                fail(name, 'step input mismatch')
            ready = before_checkpoint['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox']
            if not ready or ready[0]['envelope']['event'] != 'increment':
                fail(name, 'step has no pending selected ready head')
        elif name in {'row_float_to_integer_rejected', 'undeclared_row_field_rejected'}:
            if mapped is None or (mapped['value'][0] == mapped['declaration'] and mapped['field'] == 'amount'):
                fail(name, 'row-derived input is actually valid')
        elif name == 'equal_delivery_replay':
            if before_checkpoint is None or delivery is None or request['expected_checkpoint'] == identity(before_checkpoint):
                fail(name, 'replay lacks historical caller identity')
            receipts = before_checkpoint['operation_receipts']
            if not any(receipt.get('event_id') == delivery['envelope']['event_id'] for receipt in receipts):
                fail(name, 'replay lacks retained event identity')
            if outcome['result_value'] != next(
                receipt for receipt in receipts if receipt.get('event_id') == delivery['envelope']['event_id']
            ):
                fail(name, 'replay return differs from exact retained receipt')
        elif name == 'changed_identity_conflict_before_payload':
            if before_checkpoint is None or delivery is None or delivery['envelope']['payload'][1][0][1][0] != 'float':
                fail(name, 'conflict payload is not type changed')
            if not any(receipt.get('event_id') == delivery['envelope']['event_id'] for receipt in before_checkpoint['operation_receipts']):
                fail(name, 'conflict lacks retained event identity')
        elif name == 'direct_state_edit_unsupported':
            if request['boundary'] != 'direct_state_write':
                fail(name, 'unsupported state edit boundary absent')
        elif name == 'enum_only_prior_unrepresentable':
            if before_checkpoint is not None or request['supplemental_capacity'] != 'none' or request['expected_checkpoint'] is None:
                fail(name, 'enum-only mapping has no prior artifact to lose')
        elif name == 'proposed_supplement_truncation':
            candidate = checkpoint(vector.get('candidate_checkpoint'), name)
            if before_checkpoint is None or request['supplemental_capacity'] != 'truncate' or candidate is None:
                fail(name, 'truncation condition absent')
            if candidate['root_instance_id'] != request['root_instance_id'] or not any(
                runtime['ready_mailbox'] or runtime['deferred_mailbox']
                for runtime in candidate['root_record']['aggregate_state']['runtimes']
            ):
                fail(name, 'proposed artifact has no queued envelope to truncate')
        elif name == 'wrong_root_row_selection':
            if all(row['root_instance_id'] == request['root_instance_id'] for row in before['selected_rows']):
                fail(name, 'selection is not mismatched')
        elif name == 'shared_transaction_unavailable':
            if not request['shared_transaction_requested'] or request['shared_transaction_available']:
                fail(name, 'missing shared transaction failure condition')
        elif name == 'stale_revision_rolls_back_rows':
            if before_checkpoint is None or request['expected_checkpoint'] == identity(before_checkpoint):
                fail(name, 'stale compare-and-swap condition absent')
        elif name.startswith('env_'):
            if request['boundary'] != 'external_refresh' or before_checkpoint is None or after_checkpoint is None:
                fail(name, 'env projection lacks a checkpoint-backed external boundary')
            if request['operation'] == 'admit':
                if delivery is None or delivery['envelope']['event'] != 'env' or mapped is None:
                    fail(name, 'env admission does not hydrate a typed source row')
                changed = dict(delivery['envelope']['payload'][1])['changed'][1]
                if dict(changed).get(mapped['field']) != mapped['value']:
                    fail(name, 'env changed value differs from selected source row')
            elif request['operation'] == 'step':
                ready = before_checkpoint['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox']
                if delivery is not None or mapped is not None or len(ready) != 1 or ready[0]['envelope']['event'] != 'env':
                    fail(name, 'env step did not consume the admitted ready head')
                previous = {v['variable_declaration_pointer'].rsplit('/',1)[-1]: v['value']
                            for v in before_checkpoint['root_record']['aggregate_state']['runtimes'][0]['variables']}
                updated = {v['variable_declaration_pointer'].rsplit('/',1)[-1]: v['value']
                           for v in after_checkpoint['root_record']['aggregate_state']['runtimes'][0]['variables']}
                if name == 'env_success_step':
                    if previous != {'token': ['string','old'], 'region': ['string','east']} or updated != {
                        'token': ['string','new'], 'region': ['string','west']
                    } or outcome['result_value']['disposition'] != 'handled':
                        fail(name, 'refresh did not apply exact changed fields')
                else:
                    fault = after_checkpoint['root_record']['aggregate_state']['runtimes'][0]['fault']
                    if previous != updated or fault is None or fault['code'] != 'action_fault' or not fault['source_locator'].endswith('/refresh/only/0'):
                        fail(name, 'missing only field did not commit rollback fault')
                    if outcome['result_value']['fault'] != fault or outcome['result_value']['disposition'] != 'faulted':
                        fail(name, 'facade fault return differs from committed fault')
                if before['selected_rows'] != after['selected_rows']:
                    fail(name, 'env step committed a source row change')
        expected_code = {
            'row_float_to_integer_rejected': 'invalid_projection_input',
            'undeclared_row_field_rejected': 'invalid_projection_input',
            'changed_identity_conflict_before_payload': 'event_id_conflict',
            'direct_state_edit_unsupported': 'unsupported_projection_boundary',
            'enum_only_prior_unrepresentable': 'projection_not_lossless',
            'proposed_supplement_truncation': 'projection_not_lossless',
            'wrong_root_row_selection': 'invalid_projection_selection',
            'shared_transaction_unavailable': 'projection_transaction_unavailable',
            'stale_revision_rolls_back_rows': 'checkpoint_revision_conflict',
        }.get(name)
        if outcome['code'] != expected_code:
            fail(name, 'failure code does not match trigger')
        if outcome['kind'] == 'result' and request['expected_checkpoint'] != identity(before_checkpoint):
            fail(name, 'committed result did not read exact prior checkpoint')
        if outcome['kind'] == 'result':
            if not outcome['committed'] or outcome['core_calls'] != 1 or after_checkpoint is None:
                fail(name, 'committed result lacks atomic evidence')
            result = outcome['result_value']
            if result['state'] != after_checkpoint['root_record']['aggregate_state']:
                fail(name, 'facade result state differs from committed checkpoint')
            if before_checkpoint is None:
                if after_checkpoint['revision'] != '0':
                    fail(name, 'creation revision is not zero')
            elif int(after_checkpoint['revision']) != int(before_checkpoint['revision']) + 1:
                fail(name, 'atomic commit has incorrect revision advance')
            if before['selected_rows'][0]['amount'] != after['selected_rows'][0]['amount']:
                fail(name, 'committed row rewrote mapped amount')
            if not env_mapping and request['operation'] == 'step' and (
                before['selected_rows'][0]['status'] != 'pending' or
                after['selected_rows'][0]['status'] != 'done'
            ):
                fail(name, 'step did not project committed domain status')
            if not env_mapping:
                count_values = [
                variable['value'] for runtime in after_checkpoint['root_record']['aggregate_state']['runtimes']
                for variable in runtime['variables']
                if variable['variable_declaration_pointer'].endswith('/count')
            ]
                if len(count_values) != 1 or (after['selected_rows'][0]['status'] == 'done') != (
                    count_values[0][0] == 'integer' and int(count_values[0][1]) > 0
                ):
                    fail(name, 'domain status differs from declared count mapping')
            if request['operation'] == 'create' and set(result) != {'status', 'state', 'emissions', 'lifecycle_dispositions', 'fault', 'rejection'}:
                fail(name, 'create result shape differs')
            if request['operation'] == 'admit' and set(result) != {'status', 'accepted', 'state', 'rejection'}:
                fail(name, 'admit result shape differs')
            if request['operation'] == 'step' and 'disposition' not in result:
                fail(name, 'step result loses disposition')
        if outcome['kind'] == 'replay' and (outcome['committed'] or outcome['core_calls'] != 0):
            fail(name, 'replay reevaluated or committed')
    return len(vectors)
