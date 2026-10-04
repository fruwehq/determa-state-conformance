#!/usr/bin/env python3
"""Pin the complete §24 raw examples to an explicit specification checkout."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from validate_recovery_profile import CASE
from validate_portable_archive import ROOT, canonical, digest, without
from generate_version1_vectors import native_v1_checkpoint, normalized_bundle, seal_aggregate, seal_checkpoint, typed_value
from generate_execution_checkpoint_profile import (admit, start_spawned_runtime,
    process, host_mailbox_entry, add_existing_acceptance, checkpoint_from_aggregate)


def owned_machine_source() -> bytes:
    source = (ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/owned-component-machine.yaml').read_text()
    source = source.replace('  pay:\n', '''  invoke:
    direction: input
    payload:
      operation_token: { type: string, required: true }
  native_request:
    direction: output
    payload:
      index: { type: int, required: true }
  pay:
''', 1)
    source = source.replace('    root:\n      type: composite\n      variables:', '''    root:
      type: composite
      on_events:
        invoke:
          action:
            - send:
                event: native_request
                to: { external: true }
                payload: { index: "0" }
                correlation_id: "event.payload.operation_token"
      variables:''', 1)
    return source.encode()


def build_owned_recovery() -> dict[str, bytes]:
    """Create real owned/deferred/component state and an attempted external intent."""
    machine = CASE / 'recovery-owned-machine.yaml'
    request = {'machine_id': 'order', 'machine_version': '1',
               'root_instance_id': 'recovery-owned-1', 'creation_id': 'recovery-owned-create',
               'bindings': {'input': {}, 'external': {}}}
    created = native_v1_checkpoint(machine, request)
    started = start_spawned_runtime(admit(created, 'start', 'recovery-owned-start', {}))
    invoked = process(admit(started, 'invoke', 'recovery-owned-invoke',
                            {'operation_token': 'recovery-token'}), bundle_path=machine)
    child = next(runtime for runtime in invoked['root_record']['aggregate_state']['runtimes']
                 if runtime['relation']['kind'] == 'owned_spawned_instance')
    envelope = host_mailbox_entry(invoked, target=child['target_identity'], event='hold',
                                  event_id='recovery-owned-hold', payload={})
    checkpoint = add_existing_acceptance(invoked, envelope)
    aggregate = checkpoint['root_record']['aggregate_state']
    child = next(runtime for runtime in aggregate['runtimes']
                 if runtime['relation']['kind'] == 'owned_spawned_instance')
    entry = child['ready_mailbox'].pop(0)
    entry['deferral_count'] = str(int(entry['deferral_count']) + 1)
    entry['queue_sequence'] = aggregate['next_queue_sequence']
    aggregate['next_queue_sequence'] = str(int(aggregate['next_queue_sequence']) + 1)
    aggregate['next_logical_step_sequence'] = str(int(aggregate['next_logical_step_sequence']) + 1)
    child['deferred_mailbox'].append(entry)
    checkpoint['revision'] = str(int(checkpoint['revision']) + 1)
    checkpoint['root_record']['aggregate_state'] = seal_aggregate(aggregate)
    checkpoint['pending_outbox_intents'][0]['delivery_state'] = {
        'status': 'ambiguous', 'reason_code': 'unknown_confirmation'}
    checkpoint = seal_checkpoint(checkpoint)
    base = json.loads((ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/owned-component-archive-v1.json').read_bytes())
    normative = json.loads((ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/archive-v1.json').read_bytes())
    nested = json.loads((ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-checkpoint-v1.json').read_bytes())
    nested_definition = next(item for item in base['normalized_definitions']
                             if item['validated_bundle_fingerprint'] ==
                             nested['root_record']['aggregate_state']['validated_bundle_fingerprint'])
    owned_definition = {'validated_bundle_fingerprint':
                        checkpoint['root_record']['aggregate_state']['validated_bundle_fingerprint'],
                        'normalized_bundle': typed_value(normalized_bundle(machine))}
    archive = copy.deepcopy(base)
    archive['source'] = normative['source']
    archive['participant_contract'] = normative['participant_contract']
    archive['participants'] = normative['participants']
    archive['selection']['consistency_token'] = 'recovery-owned-capture-1'
    archive['checkpoints'] = sorted([checkpoint, nested], key=lambda item: item['root_instance_id'])
    archive['selection']['root_instance_ids'] = [item['root_instance_id'] for item in archive['checkpoints']]
    archive['normalized_definitions'] = sorted([owned_definition, nested_definition],
                                               key=lambda item: item['validated_bundle_fingerprint'])
    archive['required_determa_capabilities'] = sorted(set(base['required_determa_capabilities']) |
                                                       {'archive_participant'})
    archive['members'] = sorted([
        {'identity': 'checkpoint:' + item['root_instance_id'], 'digest': digest(item),
         'byte_length': str(len(canonical(item)))} for item in archive['checkpoints']
    ] + [
        {'identity': 'definition:' + item['validated_bundle_fingerprint'], 'digest': digest(item),
         'byte_length': str(len(canonical(item)))} for item in archive['normalized_definitions']
    ] + [
        {'identity': 'participant:' + item['participant_id'], 'digest': digest(item),
         'byte_length': str(len(canonical(item)))} for item in archive['participants']
    ], key=lambda item: item['identity'])
    archive['archive_digest'] = digest(['determa-archive-digest-1', without(archive, 'archive_digest')])
    vectors = build_owned_recovery_vectors(archive, checkpoint)
    return {
        'recovery-owned-checkpoint-v1.json': (json.dumps(checkpoint, indent=2) + '\n').encode(),
        'recovery-two-root-archive-v1.json': (json.dumps(archive, indent=2) + '\n').encode(),
        'recovery-two-root-vectors-v1.json': (json.dumps(vectors, indent=2) + '\n').encode(),
    }


def build_owned_recovery_vectors(archive: dict, checkpoint: dict) -> dict:
    normative = json.loads((CASE / 'recovery-cases-v1.json').read_bytes())
    source_cases = {item['case_id']: item for item in normative['cases']}
    records = normative['records']
    stage_cases = json.loads((ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/stage-cases-v1.json').read_bytes())
    stage_base = next(item for item in stage_cases['cases']
                      if item['case_id'] == 'complete_embedded_snapshot')
    stage_request = copy.deepcopy(stage_base['input_request'])
    stage_request['archive_digest'] = archive['archive_digest']
    stage_request['staging_identity'] = 'recovery-owned-stage-1'
    stage_configuration = stage_base['configured_import']
    stage_result = copy.deepcopy(stage_base['expected_result'])
    stage_result['archive_digest'] = archive['archive_digest']
    source = {
        'logical_scope_identity': archive['source']['logical_scope_identity'],
        'ownership_binding_digest': archive['source']['ownership_binding_digest'],
        'profile_digest': archive['source']['profile_digest'],
        'participant_contract_digest': archive['participant_contract']['participant_contract_digest'],
        'archive_digest': archive['archive_digest'],
    }
    work = [{
        'work_kind': 'effect',
        'work_identity': checkpoint['pending_outbox_intents'][0]['intent']['effect_id'],
        'source_attempt': 'unknown', 'disposition': 'ambiguous',
        'evidence_digest': checkpoint['execution_checkpoint_digest'],
    }]
    checkpoint_digests = sorted(item['execution_checkpoint_digest'] for item in archive['checkpoints'])
    record_names = {'strict_quarantine': 'strict_quarantine',
                    'standalone_takeover': 'standalone_inactive',
                    'standalone_resume': 'standalone_resumed',
                    'clone_scope': 'clone_inactive'}
    generated_records = {}
    for case_name, record_name in record_names.items():
        record = copy.deepcopy(records[record_name]['record'])
        record['source'] = source
        record['work'] = work
        record['retained_checkpoint_digests'] = checkpoint_digests
        record['destination_scope_identity'] = 'recovery-owned-' + record['destination_scope_identity']
        if record['external_idempotency_namespace'] is not None:
            record['external_idempotency_namespace'] = 'recovery-owned-' + record['external_idempotency_namespace']
        if record['operation_ledger_identity'] is not None:
            record['operation_ledger_identity'] = 'recovery-owned-' + record['operation_ledger_identity']
        record['destination_binding_digest'] = digest(['determa-recovery-owned-binding-1',
                                                       record['destination_scope_identity']])
        generated_records[case_name] = record
    cases = []
    for name in ('strict_quarantine', 'standalone_takeover', 'standalone_resume',
                 'ambiguous_effect_dispatch_denied', 'old_worker_matching_effect_rejected',
                 'clone_scope'):
        base = source_cases[name]
        item = copy.deepcopy(base)
        item['case_id'] = 'owned_' + name
        item['archive_kind'] = 'owned'
        request = item['request']
        request['operation_id'] = item['case_id']
        request['destination_scope_identity'] = 'recovery-owned-' + request['destination_scope_identity']
        arguments = request['arguments']
        if 'staging_identity' in arguments:
            arguments['staging_identity'] = stage_request['staging_identity']
            arguments['archive_digest'] = archive['archive_digest']
            arguments['source'] = source
        if 'external_idempotency_namespace' in arguments:
            arguments['external_idempotency_namespace'] = 'recovery-owned-' + arguments['external_idempotency_namespace']
        if 'record_digest' in arguments:
            arguments['record_digest'] = digest(['determa-recovery-record-1',
                                                 generated_records['standalone_takeover']])
        if 'work_identity' in arguments:
            arguments['work_identity'] = work[0]['work_identity']
        request['request_digest'] = digest(['determa-recovery-request-1', without(request, 'request_digest')])
        expected = item['expected_result']
        expected['operation_id'] = request['operation_id']
        expected['request_digest'] = request['request_digest']
        expected['destination_scope_identity'] = request['destination_scope_identity']
        expected['source'] = source
        if name in generated_records:
            item['expected_record'] = generated_records[name]
            expected['record_digest'] = digest(['determa-recovery-record-1',
                                                item['expected_record']])
        else:
            item['expected_record'] = None
            expected['record_digest'] = None
        if name == 'strict_quarantine':
            item['prior_record'] = None
        elif name in ('standalone_resume', 'clone_scope'):
            item['prior_record'] = 'owned_standalone_takeover' if name == 'standalone_resume' else None
        elif name in ('ambiguous_effect_dispatch_denied', 'old_worker_matching_effect_rejected'):
            item['prior_record'] = 'owned_standalone_resume'
        else:
            item['prior_record'] = None
        cases.append(item)
    return {'fixture_format': 'determa.recovery_two_root_vectors',
            'fixture_schema_version': 1, 'source_archive_digest': archive['archive_digest'],
            'stage_request': stage_request, 'stage_configuration': stage_configuration,
            'stage_result': stage_result, 'cases': cases}


def generated(spec_root: Path) -> dict[str, bytes]:
    source = spec_root / 'examples/recovery'
    cases = (source / 'recovery-cases-v1.json').read_bytes()
    fixture = json.loads(cases)
    owned_files = build_owned_recovery()
    owned = json.loads(owned_files['recovery-two-root-vectors-v1.json'])
    manifest = {
        'title': 'strict quarantine, fresh-scope takeover, clone, and conditional local transfer',
        'recovery_vectors': {
            'early': [case['case_id'] for case in fixture['early_cases']],
            'cases': [case['case_id'] for case in fixture['cases']],
            'owned': [case['case_id'] for case in owned['cases']],
        },
    }
    result = {
        'recovery-cases-v1.json': cases,
        'archive-local-transfer-v1.json': (source / 'archive-local-transfer-v1.json').read_bytes(),
        'test.yaml': (json.dumps(manifest, indent=2) + '\n').encode(),
        'recovery-owned-machine.yaml': owned_machine_source(),
    }
    result.update(owned_files)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    CASE.mkdir(parents=True, exist_ok=True)
    for name, contents in generated(args.spec_root).items():
        target = CASE / name
        if args.check:
            if target.read_bytes() != contents:
                raise SystemExit(f'{name}: differs from pinned specification')
        else:
            target.write_bytes(contents)
    print('42 normative and 6 real two-root recovery cases checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
