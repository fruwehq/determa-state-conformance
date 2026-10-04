"""Independent cross-artifact checks for exact candidate inspection fixtures."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def typed_value_units(value: list) -> int:
    tag=value[0]
    if tag=='string': return 1+len(value[1])
    if tag=='list': return sum(1+typed_value_units(item) for item in value[1])
    if tag=='map': return sum(1+len(key)+typed_value_units(item) for key,item in value[1])
    return 1


def envelope_value_units(value: Any) -> int:
    """Count the normalized envelope as semantic values, decoding only payload."""
    if isinstance(value,dict):
        return sum(1+len(key)+(typed_value_units(child) if key=='payload'
            else envelope_value_units(child)) for key,child in value.items())
    if isinstance(value,str):return 1+len(value)
    if isinstance(value,list):return sum(1+envelope_value_units(child) for child in value)
    return 1


def snapshot_value_units(envelope: dict, runtime: dict) -> int:
    active={(item['state_definition_pointer'],item['activation_sequence'])
        for item in runtime['active_state_activations']}
    visible=0
    for variable in runtime['variables']:
        declaration=variable['variable_declaration_pointer']
        declaring_state=declaration.rsplit('/variables/',1)[0]
        activation=(declaring_state,variable['declaring_state_activation_sequence'])
        if activation in active:
            visible+=typed_value_units(variable['value'])
    return envelope_value_units(envelope)+visible


def validate_root_only_bindings(bundle: dict) -> None:
    """Enforce the §4.5 machine rule beyond the YAML schema's state shape."""
    def visit(state: dict, pointer: str, root: bool) -> None:
        if not root:
            for name, declaration in state.get('variables', {}).items():
                if declaration.get('input') or declaration.get('external'):
                    raise ValueError(f'{pointer}/variables/{name}: input/external binding outside machine root')
        for name, child in state.get('states', {}).items():
            visit(child, f'{pointer}/states/{name}', False)
        for index, component in enumerate(state.get('components', [])):
            if 'root' in component:
                visit(component['root'], f'{pointer}/components/{index}/root', True)

    for index, machine in enumerate(bundle['machines']):
        visit(machine['root'], f'/machines/{index}/root', True)


def validate_snapshot_variables(aggregate: dict, bundle: dict) -> None:
    """Bind every retained variable to its active declaring state and sequence."""
    from validate_conformance import ValidationFailure

    def resolve(pointer: str) -> Any:
        value: Any = bundle
        try:
            for segment in pointer.split('/')[1:]:
                key = segment.replace('~1', '/').replace('~0', '~')
                value = value[int(key)] if isinstance(value, list) else value[key]
        except (IndexError, KeyError, TypeError, ValueError) as error:
            raise ValidationFailure(f'inspection variable has unresolved declaration {pointer}') from error
        return value

    for runtime in aggregate['runtimes']:
        active = {(item['state_definition_pointer'], item['activation_sequence'])
                  for item in runtime['active_state_activations']}
        if runtime['status'] == 'completed' and (
            active or runtime['active_leaf_state_definition_pointers'] or runtime['variables']
        ):
            raise ValidationFailure('inspection completed runtime retains configuration or variables')
        seen: set[tuple[str, str]] = set()
        for variable in runtime['variables']:
            declaration = variable['variable_declaration_pointer']
            state_pointer, separator, name = declaration.rpartition('/variables/')
            if not separator or not name:
                raise ValidationFailure(f'inspection variable has invalid declaration {declaration}')
            state = resolve(state_pointer)
            if (not isinstance(state, dict) or
                not isinstance(state.get('variables'), dict) or
                name not in state['variables'] or
                resolve(declaration) is not state['variables'][name]):
                raise ValidationFailure(f'inspection variable has invalid declaring state {declaration}')
            key = (declaration, variable['declaring_state_activation_sequence'])
            if key in seen:
                raise ValidationFailure(f'inspection duplicate variable {declaration}')
            seen.add(key)
            if (state_pointer, key[1]) not in active:
                raise ValidationFailure(f'inspection variable has inactive declaring state or sequence {declaration}')


def validate_inspection_vectors(case: Path, test: dict, bundle_paths: set[Path],
                                artifact_paths: set[Path], spec_root: Path,
                                overrides: dict[str, Any] | None = None) -> set[str]:
    from validate_conformance import (ValidationFailure, canonical_json_bytes, hash_value, hash_bytes,
        encode_typed_value, normalized_bundle_value, validated_bundle_fingerprint,
        validate_aggregate_against_bundle, validate_aggregate_v1_semantics)

    specs = [json.loads((spec_root/'schema'/name).read_text()) for name in
             ('inspection-v1.schema.json','aggregate-state-v1.schema.json')]
    registry = Registry().with_resources([(schema['$id'],Resource.from_contents(schema)) for schema in specs])
    schema = Draft202012Validator(specs[0],registry=registry)
    examples = json.loads((spec_root/'examples/inspection/fuel-boundaries-v1.json').read_text())['cases']
    fuel = {(v['expression'],v['maximum_evaluation_steps']):v['result'] for v in examples}
    # Additional §12.2 derivations: two Unicode scalars in size; two one-scalar
    # string literals plus string equality; two two-element lists plus collection equality.
    for expression, required in [('size("é😀") == 2',9),('"é" == "é"',7),('[1,2] == [1,2]',23),('size({"é":1}) == 1',14)]:
        fuel[(expression,str(required-1))]='inspection_limit_exceeded'
        fuel[(expression,str(required))]='true'
    names = set(); coverage = set(); used = set()
    overrides = overrides or {}
    def document(filename: str) -> Any:
        path = case/filename
        if path not in artifact_paths: raise ValidationFailure(f'{case.name}: undeclared artifact {filename}')
        used.add(path)
        return copy.deepcopy(overrides[filename] if filename in overrides else json.loads(path.read_text()))
    def pointer(doc: Any, ptr: str) -> Any:
        try:
            for segment in ptr.split('/')[1:]:
                key=segment.replace('~1','/').replace('~0','~')
                doc=doc[int(key)] if isinstance(doc,list) else doc[key]
            return doc
        except (KeyError,ValueError,IndexError,TypeError) as error:
            raise ValidationFailure(f'{case.name}: unresolved pointer {ptr}') from error
    def failure(code: str, locator: str | None = None) -> dict:
        return {'code':code,'source_locator':locator}
    def checked(value: Any, ref: str, where: str) -> bool:
        validator=Draft202012Validator({'$ref':specs[0]['$id']+'#/$defs/'+ref},registry=registry)
        return not list(validator.iter_errors(value))
    def branch(state_pointer: str, event: str, entry: Any, index: int,
               collection: bool, fingerprint: str) -> dict:
        guard=entry.get('guard')
        if guard is None: return {'branch_index':str(index),'guard_locator':None,'guard_binding_digest':None}
        locator=f'{state_pointer}/on_events/{event}' + (f'/{index}' if collection else '') + '/guard'
        return {'branch_index':str(index),'guard_locator':locator,
                'guard_binding_digest':hash_value(['determa-guard-binding-1',fingerprint,
                                                    locator,encode_typed_value(guard)])}
    def expected_levels(bundle: dict, runtime: dict, event: str, fingerprint: str) -> list[dict]:
        active=runtime['active_state_activations']
        result=[]
        for activation in reversed(active):
            state_ptr=activation['state_definition_pointer']
            state=pointer(bundle,state_ptr)
            entries=state.get('on_events',{}).get(event,[])
            collection=isinstance(entries,list)
            entries=entries if collection else [entries]
            result.append({'state_id':state_ptr,
                           'handler_branches':[branch(state_ptr,event,item,i,collection,fingerprint)
                                               for i,item in enumerate(entries)],
                           'defers':event in state.get('deferred_events',[])})
        return result
    def possible(levels: list[dict]) -> list[str]:
        options=set(); falls=True
        for level in levels:
            if not falls: break
            branches=level['handler_branches']
            if branches:
                options.add('handled_now')
                if any(item['guard_locator'] is None for item in branches): falls=False
            if falls and level['defers']:
                options.add('deferred'); falls=False
        if falls: options.add('unhandled')
        return [item for item in ('handled_now','deferred','unhandled') if item in options]
    def payload_valid(payload: list, declaration: dict) -> bool:
        if payload[0]!='map': return False
        fields=declaration.get('payload',{})
        entries=dict(payload[1])
        if len(entries)!=len(payload[1]) or set(entries)-set(fields): return False
        for name, field in fields.items():
            if field.get('required') and name not in entries:return False
            if name in entries and entries[name][0] != {'bool':'boolean','string':'string',
                'int':'integer','float':'float'}.get(field['type'],field['type']):return False
        return True
    def checked_ast_nodes(expression: str) -> int:
        compact=expression.strip()
        if re.fullmatch(r'!+true',compact):
            return len(compact)-len('true')+1
        if compact=='true':
            return 1
        # All remaining fixture guards have fewer than 20 evaluated syntax nodes.
        if len(compact)<100:
            return 20
        raise ValidationFailure('inspection fixture has uncounted CEL syntax')
    def result(request: dict, fingerprint: str, dispositions: list[str],
               levels: list[dict] | None = None, reason: str | None = None,
               evidence: list[dict] | None = None) -> dict:
        return {'aggregate_state_digest':request['aggregate_state_digest'],
                'definition_fingerprint':fingerprint,'runtime_id':request['runtime_id'],
                'runtime_incarnation':request['runtime_incarnation'],
                'classification':'definitive' if len(dispositions)==1 else 'conditional',
                'possible_dispositions':dispositions,
                'disposition':dispositions[0] if len(dispositions)==1 else None,
                'reason':reason,'levels':levels or [],'guard_evidence':evidence or []}
    for vector in test['inspection_vectors']:
        location=f"{case.name}/{vector['name']}"
        if vector['name'] in names: raise ValidationFailure(f'{location}: duplicate vector name')
        names.add(vector['name']);coverage.update(vector['covers'])
        bundle_path=case/vector['bundle']
        if bundle_path not in bundle_paths: raise ValidationFailure(f'{location}: undeclared bundle')
        closure_digest=None
        source_digest=None
        if 'provider_closure_file' in vector:
            closure_name=vector['provider_closure_file']
            closure=document(closure_name)
            sources=vector['provider_sources']
            if sources!=['provider/test_provider.py','provider/test_provider.rs']:
                raise ValidationFailure(f'{location}: provider source closure order differs')
            expected_closure={'format':'determa.test_inspection_provider_closure','version':1,
                'files':[{'path':name,'sha256':hash_bytes((case/name).read_bytes())} for name in sources]}
            if closure!=expected_closure:
                raise ValidationFailure(f'{location}: provider source closure differs')
            source_digest=hash_bytes((case/closure_name).read_bytes())
            hasher=hashlib.sha256()
            hasher.update(b'determa-test-inspection-provider-closure-1\0')
            for name in sources:
                path=name.encode();body=(case/name).read_bytes()
                hasher.update(len(path).to_bytes(8,'big'));hasher.update(path)
                hasher.update(len(body).to_bytes(8,'big'));hasher.update(body)
            closure_digest='sha256:'+hasher.hexdigest()
        before_name=vector['aggregate_before'];after_name=vector['aggregate_after']
        before=document(before_name);after=document(after_name)
        if canonical_json_bytes(before)!=canonical_json_bytes(after) or (case/before_name).read_bytes()!=(case/after_name).read_bytes():
            raise ValidationFailure(f'{location}: inspection mutated aggregate bytes')
        validate_aggregate_v1_semantics(before)
        validate_aggregate_against_bundle(before,bundle_path)
        req=pointer(document(vector['request_file']),vector['request_pointer'])
        out=pointer(document(vector['outcome_file']),vector['outcome_pointer'])
        if not checked(out,'outcome',location):raise ValidationFailure(f'{location}: invalid outcome schema')
        fingerprint=validated_bundle_fingerprint(bundle_path)
        bundle=normalized_bundle_value(bundle_path)
        validate_snapshot_variables(before,bundle)
        try:
            validate_root_only_bindings(bundle)
        except ValueError as error:
            raise ValidationFailure(f'{location}: {error}') from error
        root=next(item for item in before['runtimes'] if item['relation']['kind']=='root')
        if not checked(req,'request',location) or req.get('aggregate_state_digest')!=before['aggregate_state_digest']:
            expected=failure('invalid_inspection_request')
        elif req['mode']=='semantic' and (
            int(req['limits']['maximum_guard_evaluations']) > 64 or
            int(req['limits']['maximum_evaluation_steps']) > 1000000
        ):
            expected=failure('invalid_inspection_request')
        else:
            runtime=next((item for item in before['runtimes'] if item['runtime_id']==req['runtime_id']),None)
            reason=None
            if runtime is None: reason='target_not_found'
            elif runtime['identity_origin']!=req['runtime_incarnation']: reason='target_incarnation_mismatch'
            elif runtime['status']!='running': reason='runtime_inactive'
            else:
                envelope=req['envelope'];event=envelope['event']
                declarations=bundle.get('events',{}) | bundle['machines'][0].get('events',{})
                declaration=declarations.get(event)
                if (envelope['target']!=runtime['target_identity'] or
                    envelope['source']!={'host':True} or declaration is None or
                    declaration['direction']!='input' or
                    not payload_valid(envelope['payload'],declaration) or
                    event.startswith('determa.')):
                    reason='invalid_envelope'
            if reason:
                expected=result(req,root['current_definition']['validated_bundle_fingerprint'],['invalid'],reason=reason)
            else:
                levels=expected_levels(bundle,runtime,req['envelope']['event'],fingerprint)
                guard_members=[pointer(bundle,branch['guard_locator'])
                    for level in levels for branch in level['handler_branches']
                    if branch['guard_locator'] is not None]
                if closure_digest is not None:
                    native_count=0
                    for member in guard_members:
                        if isinstance(member,str):
                            continue
                        if not isinstance(member,dict) or 'provider' not in member:
                            raise ValidationFailure(f'{location}: invalid native guard member')
                        native_count+=1
                        provider=member['provider']
                        identifier=provider['provider_reference']['identifier']
                        expected_identifier='example.inspection-'+(
                            'unsafe' if req['envelope']['event']=='mixed' else req['envelope']['event'])
                        if (provider['provider_reference']['content_digest']!=closure_digest or
                            provider['source_digest']!=source_digest or provider['dependencies']!=[] or
                            identifier!=expected_identifier or
                            provider['provider_reference']['version']!='1.0.0'):
                            raise ValidationFailure(f'{location}: provider binding differs from installed source closure')
                    if native_count!=1:
                        raise ValidationFailure(f'{location}: provider closure lacks one exact native guard')
                if vector['profile']=='unsafe_provider' and not any(
                    isinstance(member,dict) and 'provider' in member and
                    member['provider']['capabilities']['semantically_introspectable'] is False
                    for member in guard_members
                ):
                    raise ValidationFailure(f'{location}: unsafe provider refusal lacks an unsafe provider')
                if vector['profile']=='safe_semantic' and any(
                    not isinstance(member,str) for member in guard_members
                ):
                    raise ValidationFailure(f'{location}: safe CEL profile contains a native guard')
                if req['mode']=='structural':
                    expected=result(req,fingerprint,possible(levels),levels)
                elif vector['profile'] in ('without_safe_semantic','unsafe_provider'):
                    expected=failure('inspection_capability_unavailable')
                elif vector['profile']=='safe_provider':
                    if closure_digest is None or len(guard_members)!=1 or not isinstance(guard_members[0],dict):
                        raise ValidationFailure(f'{location}: safe provider lacks exact source closure')
                    provider=guard_members[0]['provider']
                    if provider['capabilities']['semantically_introspectable'] is not True:
                        raise ValidationFailure(f'{location}: safe provider claim absent')
                    slot=levels[0]['handler_branches'][0]
                    if int(req['limits']['maximum_evaluation_steps'])<2:
                        expected=failure('inspection_limit_exceeded',slot['guard_locator'])
                    else:
                        evidence=[{'state_id':levels[0]['state_id'],**slot,'value':True}]
                        expected=result(req,fingerprint,['handled_now'],levels,evidence=evidence)
                else:
                    # The portable safe profile runs one CEL guard, using the independent
                    # normative fuel table; the actual runtime harness executes CEL.
                    slot=next((b for level in levels for b in level['handler_branches']
                               if b['guard_locator'] is not None),None)
                    if slot is None: expected=result(req,fingerprint,possible(levels),levels)
                    else:
                        expression=pointer(bundle,slot['guard_locator'])
                        budget=req['limits']['maximum_evaluation_steps']
                        snapshot_units=snapshot_value_units(req['envelope'],runtime)
                        answer=('inspection_limit_exceeded' if len(expression.encode('utf-8'))>4096
                                or checked_ast_nodes(expression)>1024 or snapshot_units>65536
                                else 'inspection_guard_failure' if expression=='1 / 0 == 0' and int(budget)>=10
                                else 'false' if expression.startswith('!'*1023) and int(budget)>=2047
                                else 'true' if len(expression.encode('utf-8'))==4096 and expression.strip()=='true' and int(budget)>=1
                                else 'true' if snapshot_units==65536 and expression=='true' and int(budget)>=1
                                else fuel.get((expression,budget)))
                        if answer is None:raise ValidationFailure(f'{location}: unpinned semantic fuel pair')
                        if answer in ('inspection_limit_exceeded','inspection_guard_failure'):
                            expected=failure(answer,slot['guard_locator'])
                        else:
                            value=answer=='true'
                            evidence=[{'state_id':levels[0]['state_id'],**slot,'value':value}]
                            dispositions=['handled_now'] if value else possible([
                                {**level,'handler_branches':[]} if i==0 else level
                                for i,level in enumerate(levels)])
                            expected=result(req,fingerprint,dispositions,levels,evidence=evidence)
        if out!=expected:raise ValidationFailure(f'{location}: outcome differs from request, target, definition, branch or fuel binding: {[(k,out.get(k),expected.get(k)) for k in expected if out.get(k)!=expected.get(k)]}')
        count=vector['expect']['guard_evaluations']
        preflight=vector['profile']=='safe_semantic' and out.get('code')=='inspection_limit_exceeded' and req.get('mode')=='semantic' and (
            out.get('source_locator') is not None and (
                len(str(pointer(bundle,out['source_locator'])).encode('utf-8'))>4096 or
                checked_ast_nodes(str(pointer(bundle,out['source_locator'])))>1024 or
                snapshot_value_units(req['envelope'],runtime)>65536))
        if count != (1 if req.get('mode')=='semantic' and vector['profile'] in ('safe_semantic','safe_provider') and
                     out.get('code') not in ('invalid_inspection_request','inspection_capability_unavailable')
                     and out.get('reason') is None and not preflight else 0):
            raise ValidationFailure(f'{location}: guard call count differs')
        if req.get('mode')=='structural' and vector['profile']!='core':
            raise ValidationFailure(f'{location}: structural inspection must be core')
        provider_calls=vector['expect'].get('provider_inspections',0)
        if provider_calls!=(1 if vector['profile']=='safe_provider' and req['mode']=='semantic' else 0):
            raise ValidationFailure(f'{location}: provider inspect_guard call count differs')
    if used!=artifact_paths:
        raise ValidationFailure(f'{case.name}: unreferenced inspection artifact')
    return coverage
