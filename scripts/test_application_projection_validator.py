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
from validate_conformance import ValidationFailure

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


def main() -> int:
    probes = [
        ('row owner swap', lambda p,t: p['vectors'][0]['before']['selected_rows'][0].update(root_instance_id='foreign')),
        ('row amount swap', lambda p,t: p['vectors'][1]['before']['selected_rows'][0].update(amount=['integer','7'])),
        ('result state swap', lambda p,t: p['vectors'][2]['outcome']['result_value'].update(state=copy.deepcopy(p['vectors'][1]['outcome']['result_value']['state']))),
        ('failed row mutation', lambda p,t: p['vectors'][3]['after']['selected_rows'][0].update(status='done')),
        ('wrong typed failure', lambda p,t: p['vectors'][10]['outcome'].update(code='projection_not_lossless')),
        ('wrong checkpoint witness', lambda p,t: p['vectors'][2]['after'].update(checkpoint='created-checkpoint-v1.json')),
        ('replay commits', lambda p,t: p['vectors'][5]['outcome'].update(committed=True)),
        ('env source mismatch', lambda p,t: p['vectors'][13]['before']['selected_rows'][0].update(token=['string','stale'])),
        ('env refresh result substitution', lambda p,t: p['vectors'][14]['outcome']['result_value']['state']['runtimes'][0]['variables'][0].update(value=['string','old'])),
        ('env fault row mutation', lambda p,t: p['vectors'][16]['after']['selected_rows'][0].update(region=['string','east'])),
        ('env fault misclassified', lambda p,t: p['vectors'][16]['outcome']['result_value'].update(disposition='handled')),
        ('env fault locator change', lambda p,t: p['vectors'][16]['outcome']['result_value']['fault'].update(source_locator='/machines/0/root/on_events/env/action/0/refresh/only/0')),
        ('coverage omission', lambda p,t: t['application_projection_vectors'].pop()),
    ]
    for label, mutation in probes:
        check_mutation(label, mutation)
    print(f'rejected {len(probes)} independent projection substitutions')
    return 0


if __name__ == '__main__':
    sys.exit(main())
