#!/usr/bin/env python3
"""Build the optional native inspection provider profile from exact fixture sources."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from io import StringIO

from ruamel.yaml import YAML
from generate_version1_vectors import canonical, create_v1_root, bundle_fingerprint, digest, typed_value

ROOT=Path(__file__).resolve().parents[1]
CASE=ROOT/'conformance/profiles/inspection-provider/provider-01-exact-closure'
SOURCES=('provider/test_provider.py','provider/test_provider.rs')
STATE='/machines/0/root/states/waiting'
ROOT_STATE='/machines/0/root'

def closure_digest() -> str:
    h=hashlib.sha256();h.update(b'determa-test-inspection-provider-closure-1\0')
    for name in SOURCES:
        path=name.encode();body=(CASE/name).read_bytes()
        h.update(len(path).to_bytes(8,'big'));h.update(path)
        h.update(len(body).to_bytes(8,'big'));h.update(body)
    return 'sha256:'+h.hexdigest()

def render(check: bool = False) -> dict[str,bytes]:
    contents={name:hashlib.sha256((CASE/name).read_bytes()).hexdigest() for name in SOURCES}
    closure=canonical({'format':'determa.test_inspection_provider_closure','version':1,
                       'files':[{'path':name,'sha256':'sha256:'+contents[name]} for name in SOURCES]})
    source_digest='sha256:'+hashlib.sha256(closure).hexdigest()
    content_digest=closure_digest()
    machine=(CASE/'machine.template').read_text().replace('CONTENT_DIGEST',content_digest).replace('SOURCE_DIGEST',source_digest).encode()
    if check:
        if not (CASE/'machine.yaml').exists() or (CASE/'machine.yaml').read_bytes()!=machine:
            raise SystemExit('stale provider fixture: machine.yaml')
    else:
        (CASE/'machine.yaml').write_bytes(machine)
    aggregate=create_v1_root(CASE/'machine.yaml',{'machine_id':'inspector','machine_version':'1',
        'root_instance_id':'native-inspector-1','creation_id':'create-native-inspector-1',
        'bindings':{'input':{},'external':{}}})
    runtime=aggregate['runtimes'][0]
    fingerprint=bundle_fingerprint(CASE/'machine.yaml')
    requests={};outcomes={};vectors=[]
    def levels(event):
        definition=YAML(typ='safe').load(machine.decode())['machines'][0]['root']['states']['waiting']['on_events'][event]
        entries=definition if isinstance(definition,list) else [definition]
        branches=[]
        for index,item in enumerate(entries):
            ptr=f'{STATE}/on_events/{event}' + (f'/{index}' if isinstance(definition,list) else '') + '/guard'
            branches.append({'branch_index':str(index),'guard_locator':ptr,
                'guard_binding_digest':digest(['determa-guard-binding-1',fingerprint,ptr,typed_value(item['guard'])])})
        return [{'state_id':STATE,'handler_branches':branches,'defers':False},
                {'state_id':ROOT_STATE,'handler_branches':[],'defers':False}]
    def add(name,event,mode,profile,steps,outcome,guard_calls,provider_calls):
        req={'mode':mode,'aggregate_state_digest':aggregate['aggregate_state_digest'],
             'runtime_id':runtime['runtime_id'],'runtime_incarnation':runtime['identity_origin'],
             'envelope':{'event':event,'event_id':name,'cause_id':name,'source':{'host':True},
                         'target':runtime['target_identity'],'payload':['map',[]]},
             'limits':None if mode=='structural' else {'maximum_guard_evaluations':'1',
                                                       'maximum_evaluation_steps':steps}}
        body={'aggregate_state_digest':req['aggregate_state_digest'],'definition_fingerprint':fingerprint,
              'runtime_id':req['runtime_id'],'runtime_incarnation':req['runtime_incarnation'],
              'classification':'definitive' if outcome=='handled_now' else 'conditional',
              'possible_dispositions':['handled_now'] if outcome=='handled_now' else ['handled_now','unhandled'],
              'disposition':'handled_now' if outcome=='handled_now' else None,'reason':None,
              'levels':levels(event),'guard_evidence':[{'state_id':STATE,**levels(event)[0]['handler_branches'][0],
                                                       'value':True}] if mode=='semantic' and outcome=='handled_now' else []}
        if outcome=='refused':body={'code':'inspection_capability_unavailable','source_locator':None}
        if outcome=='exhausted':body={'code':'inspection_limit_exceeded','source_locator':levels(event)[0]['handler_branches'][0]['guard_locator']}
        requests[name]=req;outcomes[name]=body
        vectors.append({'name':name,'covers':[name],'profile':profile,'bundle':'machine.yaml',
                        'aggregate_before':'aggregate-before.json','aggregate_after':'aggregate-after.json',
                        'request_file':'requests.json','request_pointer':'/'+name,
                        'outcome_file':'outcomes.json','outcome_pointer':'/'+name,
                        'provider_closure_file':'provider-closure.json','provider_sources':list(SOURCES),
                        'expect':{'guard_evaluations':guard_calls,'provider_inspections':provider_calls,
                                  'ordinary_provider_evaluations':0,'provider_state_unchanged':True,
                                  'action_invocations':0,'external_calls':0,'emissions':0}})
    add('structural_safe','safe','structural','core','0','conditional',0,0)
    add('structural_unsafe','unsafe','structural','core','0','conditional',0,0)
    add('structural_mixed','mixed','structural','core','0','conditional',0,0)
    add('semantic_safe','safe','semantic','safe_provider','2','handled_now',1,1)
    add('semantic_unsafe_refused','unsafe','semantic','unsafe_provider','1','refused',0,0)
    add('semantic_mixed_refused_before_cel','mixed','semantic','unsafe_provider','2','refused',0,0)
    add('semantic_safe_fuel_exhausted','safe','semantic','safe_provider','1','exhausted',1,1)
    outputs={'machine.yaml':machine,'provider-closure.json':closure,
             'aggregate-before.json':canonical(aggregate),'aggregate-after.json':canonical(aggregate),
             'requests.json':canonical(requests),'outcomes.json':canonical(outcomes)}
    # The exact source closure, health, configured instance, and host policy must be
    # independently established by the implementation harness before a safe claim.
    test={'title':'Optional exact native provider inspection closure',
          'static':{'documents':[{'file':'machine.yaml','valid':True}]},
          'artifacts':{'documents':[{'file':name,'kind':'aggregate_state_v1' if name.startswith('aggregate') else 'json_value','valid':True}
                                    for name in outputs if name.endswith('.json')]},
          'inspection_vectors':vectors}
    writer=YAML();writer.indent(mapping=2,sequence=4,offset=2);stream=StringIO();writer.dump(test,stream)
    outputs['test.yaml']=stream.getvalue().encode()
    return outputs

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    expected=render(args.check)
    for name,data in expected.items():
        path=CASE/name
        if args.check:
            if not path.exists() or path.read_bytes()!=data:raise SystemExit(f'stale provider fixture: {name}')
        else:path.write_bytes(data)
    print(f'checked {len(expected)} provider fixture files' if args.check else f'wrote {len(expected)} provider fixture files')

if __name__=='__main__':main()
