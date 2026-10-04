#!/usr/bin/env python3
"""Deterministic construction of sealed inspection inputs and expected outcomes.

This generator is fixture authoring only. A conformance harness must call its real
inspect_candidate API; it must not use this module to answer an inspection request.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from generate_version1_vectors import (
    bundle_fingerprint, canonical, create_v1_root, digest, normalized_bundle,
    seal_aggregate, typed_value,
)

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/core/125-exact-candidate-inspection'
MACHINE = CASE / 'machine.yaml'
STATE = '/machines/0/root/states/parent/states/child'
PARENT = '/machines/0/root/states/parent'
ROOT_STATE = '/machines/0/root'
EVENTS = ('native_guard', 'guard_defer', 'guard_default', 'ancestor', 'blocked', 'none',
          'literal_true', 'negated_true', 'both_operands', 'string_size','unicode_size','unicode_equal','list_equal','map_size')


def branch(index: int, event: str, guard: str | None = None) -> dict:
    pointer = f'{STATE}/on_events/{event}'
    if event in ('guard_default','mixed_preflight'):
        pointer += f'/{index}'
    pointer += '/guard'
    return {'branch_index': str(index), 'guard_locator': pointer if guard is not None else None,
            'guard_binding_digest': digest(['determa-guard-binding-1', bundle_fingerprint(MACHINE), pointer,
                                            typed_value(guard)]) if guard is not None else None}


def levels(event: str) -> list[dict]:
    child = []
    if event == 'guard_defer': child = [branch(0, event, 'true')]
    elif event == 'guard_default': child = [branch(0, event, 'false'), branch(1, event)]
    elif event == 'ancestor': child = [branch(0, event, 'false')]
    elif event in ('oversized_ast','exact_ast','exact_source','large_payload'):
        guard=normalized_bundle(MACHINE)['machines'][0]['root']['states']['parent']['states']['child']['on_events'][event]['guard']
        child=[branch(0,event,guard)]
    elif event == 'oversized_guard':
        guard=normalized_bundle(MACHINE)['machines'][0]['root']['states']['parent']['states']['child']['on_events'][event]['guard']
        child = [branch(0,event,guard)]
    elif event == 'guard_error': child = [branch(0,event,'1 / 0 == 0')]
    elif event in {'literal_true', 'negated_true', 'both_operands', 'string_size', 'unicode_size', 'unicode_equal', 'list_equal', 'map_size'}:
        expression = {'literal_true':'true', 'negated_true':'!true', 'both_operands':'false && true',
                      'string_size':'size("ab") == 2',
                      'unicode_size':'size("é😀") == 2', 'unicode_equal':'"é" == "é"',
                      'list_equal':'[1,2] == [1,2]', 'map_size':'size({"é":1}) == 1'}[event]
        child = [branch(0, event, expression)]
    parent = [dict(branch_index='0', guard_locator=None, guard_binding_digest=None)] if event in {'ancestor','blocked'} else []
    return [{'state_id': STATE, 'handler_branches': child, 'defers': event in {'guard_defer','blocked'}},
            {'state_id': PARENT, 'handler_branches': parent, 'defers': False},
            {'state_id': ROOT_STATE, 'handler_branches': [], 'defers': False}]


def success(request: dict, fingerprint: str, possibilities: list[str],
            event: str | None = None, reason: str | None = None,
            evidence: list[dict] | None = None) -> dict:
    return {'aggregate_state_digest': request['aggregate_state_digest'],
            'definition_fingerprint': fingerprint, 'runtime_id': request['runtime_id'],
            'runtime_incarnation': request['runtime_incarnation'],
            'classification': 'definitive' if len(possibilities) == 1 else 'conditional',
            'possible_dispositions': possibilities,
            'disposition': possibilities[0] if len(possibilities) == 1 else None,
            'reason': reason, 'levels': levels(event) if event else [],
            'guard_evidence': evidence or []}


def fixed_snapshot_units(request: dict) -> int:
    """Closed root/host envelope fixture, excluding its payload and memo value."""
    envelope=request['envelope']
    target=envelope['target']['root']
    field=lambda name: 1+len(name)
    string=lambda value: 1+len(value)
    source=field('host')+1
    target_value=(field('root')+field('root_instance_id')+string(target['root_instance_id'])
                  +field('root_runtime_id')+string(target['root_runtime_id']))
    return (field('event')+string(envelope['event'])
            +field('event_id')+string(envelope['event_id'])
            +field('cause_id')+string(envelope['cause_id'])
            +field('source')+source+field('target')+target_value
            +field('payload'))


def render() -> dict[str, bytes]:
    aggregate = create_v1_root(MACHINE, {'machine_id':'inspector','machine_version':'1',
        'root_instance_id':'inspector-1','creation_id':'create-inspector-1',
        'bindings':{'input':{},'external':{'external_memo':'e'}}})
    runtime = aggregate['runtimes'][0]
    runtime['active_state_activations'].append({'state_definition_pointer':PARENT,'activation_sequence':'0'})
    runtime['next_state_activation_sequences'].append({'definition_pointer':PARENT,'next_sequence':'1'})
    aggregate = seal_aggregate(aggregate)
    runtime = aggregate['runtimes'][0]
    fingerprint = bundle_fingerprint(MACHINE)
    def variable(runtime: dict, name: str) -> dict:
        return next(item for item in runtime['variables']
            if item['variable_declaration_pointer'].endswith('/variables/'+name))
    assert runtime['active_leaf_state_definition_pointers'] == [STATE]
    inactive=copy.deepcopy(aggregate)
    inactive['runtimes'][0]['status']='completed'
    inactive['runtimes'][0]['active_leaf_state_definition_pointers']=[]
    inactive['runtimes'][0]['active_state_activations']=[]
    inactive['runtimes'][0]['variables']=[]
    inactive=seal_aggregate(inactive)
    outputs: dict[str, bytes] = {'aggregate-before.json':canonical(aggregate),
                                 'aggregate-after.json':canonical(aggregate),
                                 'inactive-before.json':canonical(inactive),
                                 'inactive-after.json':canonical(inactive)}
    requests = {}
    outcomes = {}
    vectors = []
    def add(name: str, req: dict, out: dict, *, profile: str = 'core', calls: int = 0,
            snapshot: str = 'aggregate') -> None:
        requests[name] = req
        outcomes[name] = out
        vectors.append({'name':name,'covers':[name], 'profile':profile,
                        'bundle':'machine.yaml','aggregate_before':snapshot+'-before.json',
                        'aggregate_after':snapshot+'-after.json',
                        'request_file':'requests.json','request_pointer':'/'+name,
                        'outcome_file':'outcomes.json','outcome_pointer':'/'+name,
                        'expect':{'guard_evaluations':calls,'action_invocations':0,
                                  'external_calls':0,'emissions':0}})
    def request(event: str = 'none', mode: str = 'structural', steps: str = '9') -> dict:
        return {'mode':mode,'aggregate_state_digest':aggregate['aggregate_state_digest'],
                'runtime_id':runtime['runtime_id'],'runtime_incarnation':copy.deepcopy(runtime['identity_origin']),
                'envelope':{'event':event,'event_id':event+'-candidate','cause_id':event+'-candidate',
                            'source':{'host':True},'target':copy.deepcopy(runtime['target_identity']),
                            'payload':['map',[]]},
                'limits':None if mode=='structural' else {'maximum_guard_evaluations':'1',
                                                          'maximum_evaluation_steps':steps}}
    structural = {'guard_defer':['handled_now','deferred'], 'guard_default':['handled_now'],
                  'ancestor':['handled_now'], 'blocked':['deferred'], 'none':['unhandled'],
                  'literal_true':['handled_now','unhandled']}
    for event, possibilities in structural.items():
        req = request(event)
        add('structural_'+event, req, success(req,fingerprint,possibilities,event))
    invalids = {
        'wrong_target':('invalid_envelope',lambda r:r['envelope']['target']['root'].update(root_instance_id='other')),
        'wrong_direction':('invalid_envelope',lambda r:r['envelope'].update(event='internal_ping')),
        'wrong_payload':('invalid_envelope',lambda r:r['envelope'].update(payload=['map',[['unexpected',['string','x']]]])),
        'wrong_visibility':('invalid_envelope',lambda r:r['envelope'].update(source={'runtime':copy.deepcopy(runtime['target_identity'])})),
        'reserved_failure_event':('invalid_envelope',lambda r:r['envelope'].update(event='determa.component_failed')),
        'missing_runtime':('target_not_found',lambda r:r.update(runtime_id='sha256:'+'0'*64)),
        'stale_incarnation':('target_incarnation_mismatch',lambda r:r['runtime_incarnation'].update(root_instance_id='old')),
    }
    for name,(reason,mutate) in invalids.items():
        req=request(); mutate(req)
        add(name,req,success(req,fingerprint,['invalid'],reason=reason))
    req=request();req['aggregate_state_digest']=inactive['aggregate_state_digest']
    add('inactive_runtime',req,success(req,fingerprint,['invalid'],reason='runtime_inactive'),snapshot='inactive')
    req=request()
    req['runtime_id']='sha256:'+'0'*64
    req['envelope']['event']='internal_ping'
    add('missing_runtime_precedes_bad_envelope',req,
        success(req,fingerprint,['invalid'],reason='target_not_found'))
    req=request()
    req['runtime_incarnation']['root_instance_id']='old'
    req['envelope']['payload']=['map',[['unexpected',['string','x']]]]
    add('stale_incarnation_precedes_bad_envelope',req,
        success(req,fingerprint,['invalid'],reason='target_incarnation_mismatch'))
    req=request()
    req['aggregate_state_digest']=inactive['aggregate_state_digest']
    req['envelope']['event']='internal_ping'
    add('inactive_precedes_bad_envelope',req,
        success(req,fingerprint,['invalid'],reason='runtime_inactive'),snapshot='inactive')
    req=request();req['aggregate_state_digest']='sha256:'+'0'*64
    add('stale_digest',req,{'code':'invalid_inspection_request','source_locator':None})
    req=request();req['aggregate_state_digest']='sha256:'+'0'*64
    req['runtime_id']='sha256:'+'0'*64
    req['envelope']['event']='internal_ping'
    add('stale_digest_precedes_target_and_envelope',req,
        {'code':'invalid_inspection_request','source_locator':None})
    req=request();req['limits']={'maximum_guard_evaluations':'1','maximum_evaluation_steps':'1'}
    add('malformed_limits',req,{'code':'invalid_inspection_request','source_locator':None})
    req=request()
    req['limits']={'maximum_guard_evaluations':'1','maximum_evaluation_steps':'1'}
    req['runtime_id']='sha256:'+'0'*64
    req['envelope']['event']='internal_ping'
    add('malformed_limits_precede_target_and_envelope',req,
        {'code':'invalid_inspection_request','source_locator':None})
    for field,value in [('maximum_guard_evaluations','65'),('maximum_evaluation_steps','1000001')]:
        req=request('literal_true','semantic','9')
        req['limits'][field]=value
        add('oversized_'+field,req,{'code':'invalid_inspection_request','source_locator':None},profile='safe_semantic')
    for event,steps,value in [('literal_true','1',True),('negated_true','2',None),
                              ('negated_true','3',False),('both_operands','3',None),
                              ('both_operands','4',False),('string_size','8',None),
                              ('string_size','9',True)]:
        req=request(event,'semantic',steps)
        name='semantic_'+event+'_'+steps
        if value is None:
            out={'code':'inspection_limit_exceeded','source_locator':levels(event)[0]['handler_branches'][0]['guard_locator']}
        else:
            guard=levels(event)[0]['handler_branches'][0]
            evidence=[{'state_id':STATE,**guard,'value':value}]
            out=success(req,fingerprint,['handled_now' if value else 'unhandled'],event,evidence=evidence)
        add(name,req,out,profile='safe_semantic',calls=1)
    for event,steps,value in [('exact_ast','2047',False),('exact_source','1',True)]:
        req=request(event,'semantic',steps)
        guard=levels(event)[0]['handler_branches'][0]
        add('semantic_'+event+'_boundary',req,success(req,fingerprint,
            ['handled_now' if value else 'unhandled'],event,
            evidence=[{'state_id':STATE,**guard,'value':value}]),
            profile='safe_semantic',calls=1)
    req=request('large_payload','semantic','1')
    # §12.2 counts every envelope field and the live lexical memo value, then
    # the decoded payload map. Only the blob's Unicode scalars vary here.
    variable_units=sum(1+len(item['value'][1]) for item in runtime['variables'])
    blob_fixed=1+len('blob')+1
    boundary_length=65536-fixed_snapshot_units(req)-variable_units-blob_fixed
    req['envelope']['payload']=['map',[['blob',['string','x'*boundary_length]]]]
    guard=levels('large_payload')[0]['handler_branches'][0]
    add('semantic_value_boundary',req,success(req,fingerprint,['handled_now'],'large_payload',
        evidence=[{'state_id':STATE,**guard,'value':True}]),profile='safe_semantic',calls=1)
    req=request('oversized_ast','semantic','9')
    add('semantic_ast_preflight',req,{'code':'inspection_limit_exceeded',
        'source_locator':levels('oversized_ast')[0]['handler_branches'][0]['guard_locator']},
        profile='safe_semantic',calls=0)
    req=request('large_payload','semantic','9')
    req['envelope']['payload']=['map',[['blob',['string','x'*(boundary_length+1)]]]]
    add('semantic_value_preflight',req,{'code':'inspection_limit_exceeded',
        'source_locator':levels('large_payload')[0]['handler_branches'][0]['guard_locator']},
        profile='safe_semantic',calls=0)
    for suffix,offset in [('boundary',0),('preflight',1)]:
        req=request('literal_true','semantic','1')
        # The empty payload contributes no units; the memo string contributes
        # one scalar value plus its Unicode scalars.
        external_units=1+len(variable(runtime,'external_memo')['value'][1])
        memo_length=65536-fixed_snapshot_units(req)-external_units-1+offset
        changed=copy.deepcopy(aggregate)
        variable(changed['runtimes'][0],'memo')['value']=['string','x'*memo_length]
        changed=seal_aggregate(changed)
        snapshot='variable-'+suffix
        outputs[snapshot+'-before.json']=canonical(changed)
        outputs[snapshot+'-after.json']=canonical(changed)
        req['aggregate_state_digest']=changed['aggregate_state_digest']
        guard=levels('literal_true')[0]['handler_branches'][0]
        if offset:
            out={'code':'inspection_limit_exceeded','source_locator':guard['guard_locator']}
        else:
            out=success(req,fingerprint,['handled_now'],'literal_true',
                evidence=[{'state_id':STATE,**guard,'value':True}])
        add('semantic_variable_'+suffix,req,out,profile='safe_semantic',
            calls=0 if offset else 1,snapshot=snapshot)
    # The prior loop ended at the preflight snapshot. Start from its one-unit
    # smaller passing counterpart and increase only the live external binding.
    external_changed=copy.deepcopy(json.loads(outputs['variable-boundary-before.json']))
    variable(external_changed['runtimes'][0],'external_memo')['value']=['string','ee']
    external_changed=seal_aggregate(external_changed)
    outputs['external-preflight-before.json']=canonical(external_changed)
    outputs['external-preflight-after.json']=canonical(external_changed)
    req=request('literal_true','semantic','1')
    req['aggregate_state_digest']=external_changed['aggregate_state_digest']
    guard=levels('literal_true')[0]['handler_branches'][0]
    add('semantic_external_preflight',req,
        {'code':'inspection_limit_exceeded','source_locator':guard['guard_locator']},
        profile='safe_semantic',calls=0,snapshot='external-preflight')
    req=request('oversized_guard','semantic','9')
    add('semantic_source_preflight',req,{'code':'inspection_limit_exceeded',
        'source_locator':levels('oversized_guard')[0]['handler_branches'][0]['guard_locator']},
        profile='safe_semantic',calls=0)
    for event,required in [('unicode_size',9),('unicode_equal',7),('list_equal',23),('map_size',14)]:
        for budget in (required-1,required):
            req=request(event,'semantic',str(budget))
            slot=levels(event)[0]['handler_branches'][0]
            if budget<required: out={'code':'inspection_limit_exceeded','source_locator':slot['guard_locator']}
            else: out=success(req,fingerprint,['handled_now'],event,
                evidence=[{'state_id':STATE,**slot,'value':True}])
            add('semantic_'+event+'_'+str(budget),req,out,profile='safe_semantic',calls=1)
    req=request('guard_error','semantic','100')
    add('semantic_guard_failure',req,{'code':'inspection_guard_failure',
        'source_locator':levels('guard_error')[0]['handler_branches'][0]['guard_locator']},
        profile='safe_semantic',calls=1)
    req=request('literal_true','semantic','9')
    add('semantic_unavailable',req,{'code':'inspection_capability_unavailable','source_locator':None},
        profile='without_safe_semantic')
    outputs['requests.json']=canonical(requests)
    outputs['outcomes.json']=canonical(outcomes)
    test={'title':'Exact candidate inspection of a sealed B0 runtime',
          'static':{'documents':[{'file':'machine.yaml','valid':True}]},
          'artifacts':{'documents':[{'file':name,'kind':'aggregate_state_v1' if name.endswith(('-before.json','-after.json')) else 'json_value','valid':True}
                                    for name in outputs]},
          'inspection_vectors':vectors}
    from ruamel.yaml import YAML
    from io import StringIO
    writer=YAML()
    writer.indent(mapping=2, sequence=4, offset=2)
    stream=StringIO()
    writer.dump(test,stream)
    outputs['test.yaml']=stream.getvalue().encode()
    return outputs


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    expected=render()
    for name,data in expected.items():
        path=CASE/name
        if args.check:
            if not path.exists() or path.read_bytes()!=data:
                raise SystemExit(f'stale inspection fixture: {name}')
        else: path.write_bytes(data)
    print(f'checked {len(expected)} inspection fixture files' if args.check else f'wrote {len(expected)} inspection fixture files')

if __name__=='__main__': main()
