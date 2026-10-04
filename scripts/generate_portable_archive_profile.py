#!/usr/bin/env python3
"""Copy the immutable §22 normative raw vectors from an explicit specification pin."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from validate_portable_archive import CASE, FILES, canonical, decode_typed, digest, without

from generate_version1_vectors import native_v1_checkpoint, normalized_bundle, seal_aggregate, seal_checkpoint, typed_value
from generate_execution_checkpoint_profile import admit, start_spawned_runtime, host_mailbox_entry, add_existing_acceptance


def build_owned_component() -> dict[str, bytes]:
    """A complete spawned child and real deferral, built through B0 lifecycle helpers."""
    machine = CASE / 'owned-component-machine.yaml'
    request = {'machine_id': 'order', 'machine_version': '1',
               'root_instance_id': 'archive-owned-1',
               'creation_id': 'archive-owned-create',
               'bindings': {'input': {}, 'external': {}}}
    created = native_v1_checkpoint(machine, request)
    started = start_spawned_runtime(admit(created, 'start', 'archive-owned-start', {}))
    child = next(runtime for runtime in started['root_record']['aggregate_state']['runtimes']
                 if runtime['relation']['kind'] == 'owned_spawned_instance')
    envelope = host_mailbox_entry(started, target=child['target_identity'], event='hold',
                                  event_id='archive-owned-hold', payload={})
    checkpoint = add_existing_acceptance(started, envelope)
    aggregate = checkpoint['root_record']['aggregate_state']
    child = next(runtime for runtime in aggregate['runtimes']
                 if runtime['relation']['kind'] == 'owned_spawned_instance')
    entry = child['ready_mailbox'].pop(0)
    # One core deferral step: retained acceptance, new queue position, no terminal receipt.
    entry['deferral_count'] = str(int(entry['deferral_count']) + 1)
    entry['queue_sequence'] = aggregate['next_queue_sequence']
    aggregate['next_queue_sequence'] = str(int(aggregate['next_queue_sequence']) + 1)
    aggregate['next_logical_step_sequence'] = str(int(aggregate['next_logical_step_sequence']) + 1)
    child['deferred_mailbox'].append(entry)
    checkpoint['revision'] = str(int(checkpoint['revision']) + 1)
    checkpoint['root_record']['aggregate_state'] = seal_aggregate(aggregate)
    checkpoint = seal_checkpoint(checkpoint)
    bundle = normalized_bundle(machine)
    definition = {'validated_bundle_fingerprint': aggregate['validated_bundle_fingerprint'],
                  'normalized_bundle': typed_value(bundle)}
    normative = json.loads((CASE / 'stage-cases-v1.json').read_bytes())
    core = next(case for case in normative['cases']
                if case['case_id'] == 'standalone_core_without_participants')
    archive = copy.deepcopy(core['input_archive'])
    archive['selection'] = {'root_instance_ids': [checkpoint['root_instance_id']],
                            'consistency_token': 'archive-owned-capture-1'}
    archive['checkpoints'] = [checkpoint]
    archive['normalized_definitions'] = [definition]
    archive['migration_descriptors'] = []
    archive['members'] = [
        {'identity': 'checkpoint:' + checkpoint['root_instance_id'],
         'digest': digest(checkpoint), 'byte_length': str(len(canonical(checkpoint)))},
        {'identity': 'definition:' + definition['validated_bundle_fingerprint'],
         'digest': digest(definition), 'byte_length': str(len(canonical(definition)))},
    ]
    archive['required_determa_capabilities'] = [
        'normalized_definition', 'portable_archive', 'portable_checkpoint']
    archive['archive_digest'] = digest(['determa-archive-digest-1',
                                        without(archive, 'archive_digest')])
    export_normative = json.loads((CASE / 'export-cases-v1.json').read_bytes())
    export_base = next(case for case in export_normative['cases']
                       if case['case_id'] == 'standalone_core_without_participants_export')
    export = copy.deepcopy(export_base)
    export['case_id'] = 'owned_component_deferred_export'
    export['input_request']['root_instance_ids'] = archive['selection']['root_instance_ids']
    export['input_request']['consistency_token'] = archive['selection']['consistency_token']
    export['source_capture']['checkpoints'] = [checkpoint]
    export['source_capture']['normalized_definitions'] = [definition]
    export['source_capture']['migration_descriptors'] = []
    evidence = export['source_capture']['inventory_evidence']
    evidence['committed_consistency_token'] = archive['selection']['consistency_token']
    evidence['selected_checkpoint_digests'] = [checkpoint['execution_checkpoint_digest']]
    export['expected_archive'] = archive
    export['expected_result']['archive_digest'] = archive['archive_digest']
    stage = copy.deepcopy(core)
    stage['case_id'] = 'owned_component_deferred_stage'
    stage['input_archive'] = archive
    stage['input_request']['archive_digest'] = archive['archive_digest']
    stage['input_request']['staging_identity'] = 'archive-owned-stage-1'
    stage['configured_import']['supported_determa_capabilities'] = archive['required_determa_capabilities']
    stage['expected_result']['archive_digest'] = archive['archive_digest']
    stage['expected_staged_archive'] = archive
    stage.pop('changed_paths_from_positive')
    value = {'fixture_format': 'determa.archive_owned_component_vectors',
             'fixture_schema_version': 1,
             'source_checkpoint': 'owned-component-checkpoint-v1.json',
             'source_machine': 'owned-component-machine.yaml',
             'export_case': export, 'stage_case': stage}
    return {
        'owned-component-checkpoint-v1.json':
            (json.dumps(checkpoint, indent=2, ensure_ascii=True) + '\n').encode(),
        'owned-component-archive-v1.json':
            (json.dumps(archive, indent=2, ensure_ascii=True) + '\n').encode(),
        'owned-component-vectors-v1.json':
            (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    source = args.spec_root / 'examples/archives'
    for name in FILES:
        expected = (source / name).read_bytes()
        target = CASE / name
        if args.check:
            if target.read_bytes() != expected:
                raise SystemExit(f'{name}: generated archive fixture differs from pinned specification')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(expected)
    archive = json.loads((source / 'archive-v1.json').read_bytes())
    for index, attachment in enumerate(archive['normalized_definitions'], 1):
        name = f'definition-{index:02d}.json'
        expected = (json.dumps(decode_typed(attachment['normalized_bundle']),
                               indent=2, ensure_ascii=True) + '\n').encode()
        target = CASE / name
        if args.check:
            if target.read_bytes() != expected:
                raise SystemExit(f'{name}: machine source differs from archive attachment')
        else:
            target.write_bytes(expected)
    for name, expected in build_owned_component().items():
        target = CASE / name
        if args.check:
            if target.read_bytes() != expected:
                raise SystemExit(f'{name}: generated owned-component archive vector differs')
        else:
            target.write_bytes(expected)
    export = json.loads((source / 'export-cases-v1.json').read_bytes())
    stage = json.loads((source / 'stage-cases-v1.json').read_bytes())
    manifest = ('title: complete portable archive export and inert staging\n'
                'archive_vectors:\n  export: ' +
                json.dumps([case['case_id'] for case in export['cases']]) +
                '\n  stage: ' +
                json.dumps([case['case_id'] for case in stage['cases']]) +
                '\n  owned_component: [owned_component_deferred_export, owned_component_deferred_stage]\n')
    if args.check:
        if (CASE / 'test.yaml').read_text(encoding='utf-8') != manifest:
            raise SystemExit('archive driver manifest differs from pinned cases')
    else:
        (CASE / 'test.yaml').write_text(manifest, encoding='utf-8')
    print(f'{len(export["cases"])+1} export and {len(stage["cases"])+1} stage vectors checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
