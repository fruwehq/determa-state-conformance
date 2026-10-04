#!/usr/bin/env python3
"""Adversarial inspection fixture and normative schema checks."""
from __future__ import annotations

import copy
import json
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from inspection_validator import validate_inspection_vectors
from validate_conformance import ValidationFailure, load_fixture_document, hash_value, encode_typed_value, validated_bundle_fingerprint
from generate_version1_vectors import seal_aggregate

ROOT=Path(__file__).resolve().parents[1]
CASE=ROOT/'conformance/core/125-exact-candidate-inspection'
SPEC=next(path for path in (
    Path(os.environ['DETERMA_STATE_SPEC_ROOT']) if 'DETERMA_STATE_SPEC_ROOT' in os.environ else ROOT/'.determa-state-spec',
    ROOT/'.determa-state-spec',
    ROOT.parent/'determa-state-spec',
) if (path/'schema/inspection-v1.schema.json').is_file())
PROVIDER=ROOT/'conformance/profiles/inspection-provider/provider-01-exact-closure'

def load(name: str) -> dict:
    return json.loads((CASE/name).read_text())

def validate(overrides: dict | None = None) -> None:
    test=load_fixture_document(CASE/'test.yaml')
    bundles={CASE/item['file'] for item in test['static']['documents']}
    artifacts={CASE/item['file'] for item in test['artifacts']['documents']}
    validate_inspection_vectors(CASE,test,bundles,artifacts,SPEC,overrides)

class InspectionValidatorTests(unittest.TestCase):
    def test_baseline(self) -> None:
        validate()

    def test_all_nine_normative_invalid_shapes(self) -> None:
        schemas=[json.loads((SPEC/'schema'/name).read_text()) for name in
                 ('inspection-v1.schema.json','aggregate-state-v1.schema.json')]
        registry=Registry().with_resources([(s['$id'],Resource.from_contents(s)) for s in schemas])
        cases=json.loads((SPEC/'examples/inspection/invalid-shapes-v1.json').read_text())['cases']
        self.assertEqual(len(cases),9)
        for case in cases:
            with self.subTest(case=case['name']):
                ref=schemas[0]['$id']+'#/$defs/'+case['kind']
                validator=Draft202012Validator({'$ref':ref},registry=registry)
                self.assertTrue(list(validator.iter_errors(case['value'])))

    def test_swapped_outcome(self) -> None:
        outcomes=load('outcomes.json')
        outcomes['structural_guard_defer']=copy.deepcopy(outcomes['structural_guard_default'])
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'outcomes.json':outcomes})

    def test_swapped_request(self) -> None:
        requests=load('requests.json')
        requests['structural_guard_defer']=copy.deepcopy(requests['structural_guard_default'])
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'requests.json':requests})

    def test_changed_incarnation(self) -> None:
        requests=load('requests.json')
        requests['structural_guard_defer']['runtime_incarnation']['root_instance_id']='stale'
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'requests.json':requests})

    def test_changed_fuel_budget(self) -> None:
        requests=load('requests.json')
        requests['semantic_negated_true_3']['limits']['maximum_evaluation_steps']='2'
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'requests.json':requests})

    def test_changed_binding_digest(self) -> None:
        outcomes=load('outcomes.json')
        outcomes['structural_guard_defer']['levels'][0]['handler_branches'][0]['guard_binding_digest']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'outcomes.json':outcomes})

    def test_same_locator_changed_cel_whitespace_is_rejected(self) -> None:
        outcomes=load('outcomes.json')
        slot=outcomes['structural_guard_defer']['levels'][0]['handler_branches'][0]
        fingerprint=validated_bundle_fingerprint(CASE/'machine.yaml')
        changed=hash_value(['determa-guard-binding-1',fingerprint,
            slot['guard_locator'],encode_typed_value('true ')])
        self.assertNotEqual(changed,slot['guard_binding_digest'])
        slot['guard_binding_digest']=changed
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'outcomes.json':outcomes})

    def test_resealed_aggregate_without_request_binding(self) -> None:
        before=load('aggregate-before.json')
        before['next_logical_step_sequence']='2'
        before=seal_aggregate(before)
        with self.assertRaisesRegex(ValidationFailure,'outcome differs'):
            validate({'aggregate-before.json':before,'aggregate-after.json':before})


# Optional provider checks deliberately exercise the shipped fixture code. A host
# claiming this profile must additionally run the vectors through its public loader.

class ProviderInspectionTests(unittest.TestCase):
    def test_separate_safe_entrypoint_is_bounded_and_nonmutating(self) -> None:
        path=PROVIDER/'provider/test_provider.py'
        spec=importlib.util.spec_from_file_location('inspection_test_provider',path)
        self.assertIsNotNone(spec)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        safe=module.SafeGuard()
        before=vars(safe).copy()
        self.assertEqual(safe.inspect_guard({},1,2),(True,1,2))
        self.assertEqual(vars(safe),before)
        with self.assertRaisesRegex(ValueError,'inspection_limit_exceeded'):
            safe.inspect_guard({},1,1)
        self.assertEqual(vars(safe),before)
        self.assertFalse(hasattr(module.UnsafeGuard(),'inspect_guard'))

    def test_changed_installed_source_closure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case=Path(temporary)/PROVIDER.name
            shutil.copytree(PROVIDER,case)
            source=case/'provider/test_provider.py'
            source.write_bytes(source.read_bytes()+b'\n# changed source\n')
            test=load_fixture_document(case/'test.yaml')
            bundles={case/item['file'] for item in test['static']['documents']}
            artifacts={case/item['file'] for item in test['artifacts']['documents']}
            with self.assertRaisesRegex(ValidationFailure,'provider source closure differs'):
                validate_inspection_vectors(case,test,bundles,artifacts,SPEC)

if __name__=='__main__': unittest.main()
