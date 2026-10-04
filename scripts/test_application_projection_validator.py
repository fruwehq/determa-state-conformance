#!/usr/bin/env python3
"""Schema-valid adversarial substitutions for §20 relational validation."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

from ruamel.yaml import YAML

from validate_application_projection import validate_application_projection
from validate_conformance import ValidationFailure, hash_value

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/application-projection/projection-01-lossless-facade'


def check_mutation(label: str, mutate) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        case = Path(temporary)
        for path in CASE.iterdir():
            if path.is_file():
                (case / path.name).write_bytes(path.read_bytes())
        profile_path = case / 'projection-v1.json'
        profile = json.loads(profile_path.read_text())
        test = YAML(typ='safe').load((case / 'test.yaml').read_text())
        mutate(profile, test)
        profile_path.write_text(json.dumps(profile, indent=2) + '\n')
        try:
            validate_application_projection(case, test, set(case.glob('*.json')))
        except ValidationFailure:
            return
        raise AssertionError(f'{label}: relational validator accepted substitution')


def vector(profile: dict, name: str) -> dict:
    return next(item for item in profile['vectors'] if item['name'] == name)


def change_replay_payload(profile: dict, _: dict) -> None:
    request = vector(profile, 'equal_delivery_replay')['request']
    delivery = request['delivery']
    delivery['envelope']['payload'] = ['map', [['amount', ['float', '401c000000000000']]]]
    delivery['envelope_digest'] = hash_value([
        'determa-inbox-envelope-digest-1', '1', request['root_instance_id'],
        delivery['delivery_mode'], delivery['envelope'],
    ])


def check_changed_declaration() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        case = Path(temporary)
        for path in CASE.iterdir():
            if path.is_file():
                (case / path.name).write_bytes(path.read_bytes())
        target_path = case / 'replay-target.yaml'
        target = json.loads(target_path.read_text())
        target['events']['increment']['payload']['amount']['type'] = 'int'
        target_path.write_text(json.dumps(target, indent=2) + '\n')
        profile = json.loads((case / 'projection-v1.json').read_text())
        test = YAML(typ='safe').load((case / 'test.yaml').read_text())
        try:
            validate_application_projection(case, test, set(case.glob('*.json')))
        except ValidationFailure:
            return
        raise AssertionError('changed declaration: validator accepted source type as target')


def main() -> int:
    probes = [
        ('row owner swap', lambda p,t: vector(p, 'create_result_shape')['before']['selected_rows'][0].update(root_instance_id='foreign')),
        ('row amount swap', lambda p,t: vector(p, 'typed_row_input_atomic_admit')['before']['selected_rows'][0].update(amount=['integer','8'])),
        ('result state swap', lambda p,t: vector(p, 'step_preserves_complete_result')['outcome']['result_value'].update(state=copy.deepcopy(vector(p, 'typed_row_input_atomic_admit')['outcome']['result_value']['state']))),
        ('failed row mutation', lambda p,t: vector(p, 'row_float_to_integer_rejected')['after']['selected_rows'][0].update(status='done')),
        ('wrong typed failure', lambda p,t: vector(p, 'wrong_root_row_selection')['outcome'].update(code='projection_not_lossless')),
        ('wrong checkpoint witness', lambda p,t: vector(p, 'step_preserves_complete_result')['after'].update(checkpoint='created-checkpoint-v1.json')),
        ('replay commits', lambda p,t: vector(p, 'equal_delivery_replay')['outcome'].update(committed=True)),
        ('resealed conflicting replay payload', change_replay_payload),
        ('wrong historical CAS', lambda p,t: vector(p, 'equal_delivery_replay')['request']['expected_checkpoint'].update(revision='77')),
        ('wrong replay origin', lambda p,t: vector(p, 'equal_delivery_replay').update(replay_of='env_success_admission')),
        ('wrong completed receipt', lambda p,t: vector(p, 'equal_delivery_replay')['outcome'].update(result_value=copy.deepcopy(vector(p, 'equal_pending_delivery_replay')['outcome']['result_value']))),
        ('env source mismatch', lambda p,t: vector(p, 'env_success_admission')['before']['selected_rows'][0].update(token=['string','stale'])),
        ('env refresh result substitution', lambda p,t: vector(p, 'env_success_step')['outcome']['result_value']['state']['runtimes'][0]['variables'][0].update(value=['string','old'])),
        ('env fault row mutation', lambda p,t: vector(p, 'env_fault_step')['after']['selected_rows'][0].update(region=['string','east'])),
        ('env fault misclassified', lambda p,t: vector(p, 'env_fault_step')['outcome']['result_value'].update(disposition='handled')),
        ('env fault locator change', lambda p,t: vector(p, 'env_fault_step')['outcome']['result_value']['fault'].update(source_locator='/machines/0/root/on_events/env/action/0/refresh/only/0')),
        ('deferred candidate substitution', lambda p,t: vector(p, 'proposed_supplement_truncation').update(candidate_aggregate='deferral-before-aggregate-v1.json')),
        ('pending intents omitted', lambda p,t: vector(p, 'enum_only_pending_intents_unrepresentable').update(prior_artifact='accepted-checkpoint-v1.json')),
        ('coverage omission', lambda p,t: t['application_projection_vectors'].pop()),
    ]
    pre_core_failures = (
        'row_float_to_integer_rejected', 'undeclared_row_field_rejected',
        'changed_identity_conflict_before_payload', 'direct_state_edit_unsupported',
        'enum_only_prior_unrepresentable', 'enum_only_pending_intents_unrepresentable',
        'wrong_root_row_selection', 'shared_transaction_unavailable',
    )
    for name in pre_core_failures:
        probes.append((f'{name} core call', lambda p,t,selected=name:
                       vector(p, selected)['outcome'].update(core_calls=1)))
    for label, mutation in probes:
        check_mutation(label, mutation)
    check_changed_declaration()
    print(f'rejected {len(probes) + 1} independent projection substitutions')
    return 0


if __name__ == '__main__':
    sys.exit(main())
