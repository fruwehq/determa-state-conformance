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

from inspection_validator import validate_inspection_vectors, validate_root_only_bindings, validate_snapshot_variables, snapshot_value_units, typed_value_units
from validate_conformance import ValidationFailure, load_fixture_document, hash_value, encode_typed_value, normalized_bundle_value, validated_bundle_fingerprint
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

def independent_snapshot_units(request: dict, aggregate: dict) -> int:
    """Decode payload values and count all normalized envelope and live variables."""
    def ordinary(value: object) -> int:
        if isinstance(value,dict):
            return sum(1+len(key)+ordinary(child) for key,child in value.items())
        if isinstance(value,str):return 1+len(value)
        if isinstance(value,list):return sum(1+ordinary(child) for child in value)
        return 1
    def typed(value: list) -> int:
        if value[0]=='string':return 1+len(value[1])
        if value[0]=='map':return sum(1+len(key)+typed(child) for key,child in value[1])
        if value[0]=='list':return sum(1+typed(child) for child in value[1])
        return 1
    envelope=copy.deepcopy(request['envelope'])
    payload=envelope.pop('payload')
    runtime=next(item for item in aggregate['runtimes'] if item['runtime_id']==request['runtime_id'])
    active={(item['state_definition_pointer'],item['activation_sequence'])
            for item in runtime['active_state_activations']}
    visible=sum(typed(variable['value']) for variable in runtime['variables']
        if (variable['variable_declaration_pointer'].rsplit('/variables/',1)[0],
            variable['declaring_state_activation_sequence']) in active)
    return ordinary(envelope)+1+len('payload')+typed(payload)+visible

class InspectionValidatorTests(unittest.TestCase):
    def test_baseline(self) -> None:
        validate()

    def test_input_and_external_bindings_are_machine_root_only(self) -> None:
        bundle=load_fixture_document(CASE/'machine.yaml')
        validate_root_only_bindings(bundle)
        child=bundle['machines'][0]['root']['states']['parent']['states']['child']
        for flag in ('input', 'external'):
            with self.subTest(flag=flag):
                changed=copy.deepcopy(bundle)
                nested=changed['machines'][0]['root']['states']['parent']['states']['child']
                nested['variables']['memo'][flag]=True
                with self.assertRaisesRegex(ValueError,'outside machine root'):
                    validate_root_only_bindings(changed)
        self.assertNotIn('external_memo',child['variables'])
        self.assertTrue(bundle['machines'][0]['root']['variables']['external_memo']['external'])

    def test_recursive_unicode_value_units(self) -> None:
        nested=['map',[['é',['list',[['string','😀'],['boolean',True]]]]]]
        # One map entry and one Unicode key scalar; two list slots; string
        # scalar plus emoji; Boolean scalar.
        self.assertEqual(typed_value_units(nested),7)

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

    def test_full_envelope_and_visible_variable_boundaries(self) -> None:
        requests=load('requests.json')
        base=load('aggregate-before.json')
        snapshots={
            'semantic_value_boundary':base,
            'semantic_value_preflight':base,
            'semantic_variable_boundary':load('variable-boundary-before.json'),
            'semantic_variable_preflight':load('variable-preflight-before.json'),
            'semantic_external_preflight':load('external-preflight-before.json'),
        }
        expected={'semantic_value_boundary':65536,'semantic_value_preflight':65537,
                  'semantic_variable_boundary':65536,'semantic_variable_preflight':65537,
                  'semantic_external_preflight':65537}
        for name,total in expected.items():
            with self.subTest(name=name):
                self.assertEqual(independent_snapshot_units(requests[name],snapshots[name]),total)
        self.assertEqual(len(requests['semantic_value_boundary']['envelope']['payload'][1][0][1][1]),65290)
        self.assertEqual(len(next(item['value'][1] for item in
            snapshots['semantic_variable_boundary']['runtimes'][0]['variables']
            if item['variable_declaration_pointer'].endswith('/memo'))),65300)

    def test_component_and_owned_runtime_visibility_is_local(self) -> None:
        source=ROOT/'conformance/core/117-version1-mailboxes'
        for filename in ('component-isolation-aggregate.json','spawn-isolation-aggregate.json'):
            aggregate=json.loads((source/filename).read_text())
            runtime=next(item for item in aggregate['runtimes']
                if item['identity_origin']['kind']!='root')
            envelope={'event':'probe','event_id':'probe-1','cause_id':'probe-1',
                      'source':{'host':True},'target':runtime['target_identity'],
                      'payload':['map',[]]}
            request={'runtime_id':runtime['runtime_id'],'envelope':envelope}
            with self.subTest(filename=filename):
                self.assertEqual(snapshot_value_units(envelope,runtime),
                    independent_snapshot_units(request,aggregate))
                other=next(item for item in aggregate['runtimes']
                    if item['runtime_id']!=runtime['runtime_id'])
                other['variables'].clear()
                self.assertEqual(snapshot_value_units(envelope,runtime),
                    independent_snapshot_units(request,aggregate))
                if runtime['identity_origin']['kind']=='owned_spawned_instance':
                    self.assertEqual(len(runtime['variables']),2)
                else:
                    changed=copy.deepcopy(runtime)
                    changed['variables'][0]['value']=['list',[['string','é']]]
                    self.assertEqual(snapshot_value_units(envelope,changed),
                        snapshot_value_units(envelope,runtime)+3)

    def test_envelope_overhead_changes_success_to_preflight_failure(self) -> None:
        requests=load('requests.json')
        requests['semantic_value_boundary']=copy.deepcopy(requests['semantic_value_preflight'])
        with self.assertRaisesRegex(ValidationFailure,"outcome differs.*code"):
            validate({'requests.json':requests})

    def test_resealed_visible_variable_changes_success_to_preflight_failure(self) -> None:
        requests=load('requests.json')
        requests['semantic_variable_boundary']=copy.deepcopy(requests['semantic_variable_preflight'])
        replacement=load('variable-preflight-before.json')
        outcomes=load('outcomes.json')
        outcomes['semantic_variable_boundary']['aggregate_state_digest']=replacement['aggregate_state_digest']
        with self.assertRaisesRegex(ValidationFailure,"outcome differs.*code"):
            validate({'requests.json':requests,'outcomes.json':outcomes,
                'variable-boundary-before.json':replacement,
                'variable-boundary-after.json':replacement})

    def test_resealed_external_variable_changes_success_to_preflight_failure(self) -> None:
        requests=load('requests.json')
        requests['semantic_variable_boundary']=copy.deepcopy(requests['semantic_external_preflight'])
        replacement=load('external-preflight-before.json')
        outcomes=load('outcomes.json')
        outcomes['semantic_variable_boundary']['aggregate_state_digest']=replacement['aggregate_state_digest']
        with self.assertRaisesRegex(ValidationFailure,"outcome differs.*code"):
            validate({'requests.json':requests,'outcomes.json':outcomes,
                'variable-boundary-before.json':replacement,
                'variable-boundary-after.json':replacement})

    def test_target_precedence_over_bad_envelope_is_relational(self) -> None:
        for name in ('missing_runtime_precedes_bad_envelope',
                     'stale_incarnation_precedes_bad_envelope'):
            requests=load('requests.json')
            requests[name]=copy.deepcopy(requests['wrong_direction'])
            with self.subTest(name=name), self.assertRaisesRegex(ValidationFailure,'outcome differs.*reason'):
                validate({'requests.json':requests})

    def test_request_precedence_over_target_and_envelope_is_relational(self) -> None:
        requests=load('requests.json')
        requests['stale_digest_precedes_target_and_envelope']['aggregate_state_digest']=(
            load('aggregate-before.json')['aggregate_state_digest'])
        with self.assertRaisesRegex(ValidationFailure,'outcome differs.*reason'):
            validate({'requests.json':requests})
        requests=load('requests.json')
        requests['malformed_limits_precede_target_and_envelope']['limits']=None
        with self.assertRaisesRegex(ValidationFailure,'outcome differs.*reason'):
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

    def test_completed_snapshot_cannot_retain_variables(self) -> None:
        inactive=load('inactive-before.json')
        self.assertEqual(inactive['runtimes'][0]['variables'],[])
        inactive['runtimes'][0]['variables']=copy.deepcopy(load('aggregate-before.json')['runtimes'][0]['variables'])
        inactive=seal_aggregate(inactive)
        with self.assertRaisesRegex(ValidationFailure,'completed runtime retains'):
            validate({'inactive-before.json':inactive,'inactive-after.json':inactive})

    def test_resealed_variable_activations_and_duplicates(self) -> None:
        bundle=normalized_bundle_value(CASE/'machine.yaml')
        for name in ('inactive_activation','wrong_sequence','duplicate'):
            aggregate=load('aggregate-before.json')
            runtime=aggregate['runtimes'][0]
            variable=next(item for item in runtime['variables']
                          if item['variable_declaration_pointer'].endswith('/memo'))
            if name=='inactive_activation':
                runtime['active_state_activations']=[item for item in runtime['active_state_activations']
                    if item['state_definition_pointer']!=variable['variable_declaration_pointer'].rsplit('/variables/',1)[0]]
            elif name=='wrong_sequence':
                variable['declaring_state_activation_sequence']='1'
            else:
                runtime['variables'].append(copy.deepcopy(variable))
            aggregate=seal_aggregate(aggregate)
            with self.subTest(name=name), self.assertRaises(ValidationFailure):
                validate_snapshot_variables(aggregate,bundle)
            with self.subTest(name=name+'_integrated'), self.assertRaises(ValidationFailure):
                validate({'aggregate-before.json':aggregate,'aggregate-after.json':aggregate})


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
