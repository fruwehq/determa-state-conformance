"""§24 pinned-source, closed-schema and cross-artifact validation.

These checks validate normative construction. They do not certify a recovery host.
"""
from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML

from validate_portable_archive import (ROOT, canonical, digest, read_json, require,
                                       schema_valid, validate_archive_integrity,
                                       validator_registry, without)

CASE = ROOT / 'conformance/profiles/recovery/recovery-01-scope-lifecycle'


def validate_owned_definition_closure(archive: dict, machine: Path, nested_machine: Path,
                                      spec_root: Path) -> None:
    from validate_conformance import validated_bundle_fingerprint, validate_aggregate_against_bundle
    from generate_version1_vectors import normalized_bundle, typed_value
    from jsonschema import Draft202012Validator
    sources = (nested_machine, machine)
    machine_schema = Draft202012Validator(read_json(spec_root / 'schema/machine.schema.json'))
    for path in sources:
        schema_valid(machine_schema, YAML(typ='safe').load(path.read_text()), str(path))
    expected = {validated_bundle_fingerprint(path): typed_value(normalized_bundle(path))
                for path in sources}
    attached = {item['validated_bundle_fingerprint']: item['normalized_bundle']
                for item in archive['normalized_definitions']}
    require(len(archive['normalized_definitions']) == len(expected) and attached == expected,
            'real two-root normalized definition closure')
    for checkpoint, path in zip(archive['checkpoints'], sources):
        require(checkpoint['root_record']['aggregate_state']['validated_bundle_fingerprint'] ==
                validated_bundle_fingerprint(path), 'two-root checkpoint machine fingerprint')
        validate_aggregate_against_bundle(checkpoint['root_record']['aggregate_state'], path)
    nested = archive['checkpoints'][0]['root_record']['aggregate_state']['runtimes']
    require(len(nested) == 3 and
            sum(runtime['relation']['kind'] == 'component' for runtime in nested) == 2,
            'two real nested component runtimes retained')


def validate_profile(spec_root: Path) -> int:
    spec_root = Path(spec_root)
    from generate_recovery_profile import generated
    expected_files = generated(spec_root)
    require({p.name for p in CASE.iterdir()} == set(expected_files), 'recovery file inventory')
    for name, contents in expected_files.items():
        require((CASE / name).read_bytes() == contents, name + ': normative source pin')
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    manifest = YAML(typ='safe').load((CASE / 'test.yaml').read_text())
    require(set(manifest) == {'title', 'recovery_vectors'} and
            set(manifest['recovery_vectors']) == {'early', 'cases', 'owned', 'namespace'}, 'recovery manifest shape')
    early, cases = fixture['early_cases'], fixture['cases']
    ids = [c['case_id'] for c in [*early, *cases]]
    require(len(ids) == len(set(ids)) and len(ids) == 42, 'unique complete recovery cases')
    require(manifest['recovery_vectors']['early'] == [c['case_id'] for c in early] and
            manifest['recovery_vectors']['cases'] == [c['case_id'] for c in cases],
            'recovery manifest coverage')
    validators = validator_registry(spec_root)
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    resources = []
    for path in (spec_root / 'schema').glob('*.schema.json'):
        value = read_json(path)
        resources.append((value.get('$id', path.name), Resource.from_contents(value)))
    registry = Registry().with_resources(resources)
    def validate(name: str, value, label: str) -> None:
        schema = read_json(spec_root / 'schema' / (name + '.schema.json'))
        schema_valid(Draft202012Validator(schema, registry=registry), value, label)

    archive = read_json(ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/archive-v1.json')
    local_archive = read_json(CASE / 'archive-local-transfer-v1.json')
    for item in (archive, local_archive):
        validate_archive_integrity(item, validators)
    require(all(local_archive[key] == archive[key] for key in
                ('checkpoints', 'normalized_definitions', 'migration_descriptors', 'participants')),
            'local transfer retains complete real archive contents')
    require(fixture['source_archive_path'] == '../archives/archive-v1.json' and
            fixture['local_transfer_archive_path'] == 'archive-local-transfer-v1.json',
            'source archive paths')
    stage = read_json(ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/stage-cases-v1.json')
    stage_case = next(c for c in stage['cases'] if c['case_id'] == 'complete_embedded_snapshot')
    require(fixture['stage_receipt'] == stage_case['expected_result'] and
            fixture['stage_receipt']['archive_digest'] == archive['archive_digest'],
            'trusted inert stage receipt')
    require(fixture['source_archive_digest'] == archive['archive_digest'] and
            fixture['local_transfer_archive_digest'] == local_archive['archive_digest'],
            'source archive digest binding')
    require(fixture['source_archive_participant_contract'] == archive['participant_contract'] and
            fixture['source_checkpoint_digests'] == {c['root_instance_id']: c['execution_checkpoint_digest']
                                                      for c in archive['checkpoints']},
            'complete source checkpoint and participant binding')
    require(fixture['local_transfer_stage_request']['archive_digest'] == local_archive['archive_digest'] and
            fixture['local_transfer_stage_result']['archive_digest'] == local_archive['archive_digest'],
            'local transfer stage binding')
    validate('archive-import-request-v1', fixture['local_transfer_stage_request'], 'local stage request')
    validate('archive-result-v1', fixture['local_transfer_stage_result'], 'local stage result')
    validate('recovery-batch-v1', fixture['partial_batch_result'], 'partial batch')
    for name, entry in fixture['records'].items():
        record = entry['record']
        validate('recovery-record-v1', record, name)
        require(entry['record_digest'] == digest(['determa-recovery-record-1', record]),
                name + ': record digest')
        selected = local_archive if record['source']['archive_digest'] == local_archive['archive_digest'] else archive
        require(record['source']['archive_digest'] == selected['archive_digest'] and
                record['source']['participant_contract_digest'] ==
                selected['participant_contract']['participant_contract_digest'] and
                set(record['retained_checkpoint_digests']) ==
                {c['execution_checkpoint_digest'] for c in selected['checkpoints']} and
                len(record['retained_checkpoint_digests']) == len(selected['checkpoints']),
                name + ': retained complete archive identity')
        require(record['active_claims'] == [], name + ': imported live claims')
        if record['mode'] in ('standalone', 'clone'):
            require(record['external_idempotency_namespace'] is not None and
                    record['operation_ledger_identity'] is not None and
                    record['destination_scope_identity'] != record['source']['logical_scope_identity'],
                    name + ': fresh-scope identity')
    for index, proof in enumerate(fixture['trusted_transfer_proofs']):
        validate('recovery-transfer-proof-v1', proof, f'transfer proof {index}')
        require(proof['proof_digest'] == digest(['determa-recovery-transfer-proof-1',
                                                without(proof, 'proof_digest')]),
                f'transfer proof {index}: digest')
        require(proof['archive_digest'] == local_archive['archive_digest'] and
                proof['participant_contract_digest'] ==
                local_archive['participant_contract']['participant_contract_digest'],
                f'transfer proof {index}: archive binding')
    for case in early:
        require(set(case) == {'case_id', 'input', 'expected_result'}, case['case_id'] + ': early shape')
        validate('recovery-operation-v1', case['expected_result'], case['case_id'] + ': result')
        require(case['expected_result']['status'] == 'refused', case['case_id'] + ': early refusal')
    for case in cases:
        label = case['case_id']
        require(set(case) in ({'case_id', 'prior_record', 'request', 'expected_result', 'expected_record'},
                              {'case_id', 'configured_profile', 'prior_record', 'request',
                               'expected_result', 'expected_record', 'expected_transfer_proof'}),
                label + ': closed case shape')
        request, result = case['request'], case['expected_result']
        validate('recovery-operation-v1', request, label + ': request')
        validate('recovery-operation-v1', result, label + ': result')
        require(request['request_digest'] == digest(['determa-recovery-request-1',
                                                     without(request, 'request_digest')]),
                label + ': request digest')
        for field in ('operation', 'operation_id', 'destination_scope_identity'):
            require(request[field] == result[field], label + ': request/result ' + field)
        require(request['request_digest'] == result['request_digest'], label + ': result request digest')
        if case['prior_record'] is not None:
            require(case['prior_record'] in fixture['records'] or
                    case['prior_record'] in ids, label + ': prior record')
        if case['expected_record'] is not None:
            validate('recovery-record-v1', case['expected_record'], label + ': expected record')
            require(result['record_digest'] == digest(['determa-recovery-record-1',
                                                       case['expected_record']]),
                    label + ': result record binding')
        else:
            require(result['record_digest'] is None, label + ': unexpected record')
        if case.get('expected_transfer_proof') is not None:
            validate('recovery-transfer-proof-v1', case['expected_transfer_proof'],
                     label + ': expected transfer proof')
        require(not result['safe_relocation'] or
                case.get('configured_profile') == 'proved_local_same_authority' and
                fixture['local_transfer_profile']['safe_relocation'] is True,
                label + ': unadvertised safe relocation')
    owned = read_json(CASE / 'recovery-two-root-vectors-v1.json')
    owned_archive = read_json(CASE / 'recovery-two-root-archive-v1.json')
    owned_checkpoint = read_json(CASE / 'recovery-owned-checkpoint-v1.json')
    require(manifest['recovery_vectors']['owned'] == [c['case_id'] for c in owned['cases']] and
            len(owned['cases']) == 6, 'owned recovery manifest coverage')
    validate_archive_integrity(owned_archive, validators)
    require(owned['source_archive_digest'] == owned_archive['archive_digest'] and
            owned_archive['selection']['root_instance_ids'] ==
            ['component-migration-root', 'recovery-owned-1'] and
            owned_archive['checkpoints'][1] == owned_checkpoint and
            len(owned_checkpoint['root_record']['aggregate_state']['runtimes']) == 2 and
            any(runtime['relation']['kind'] == 'owned_spawned_instance' and
                len(runtime['deferred_mailbox']) == 1
                for runtime in owned_checkpoint['root_record']['aggregate_state']['runtimes']) and
            len(owned_archive['checkpoints'][0]['root_record']['aggregate_state']['runtimes']) == 3 and
            len(owned_checkpoint['pending_outbox_intents']) == 1 and
            owned_checkpoint['pending_outbox_intents'][0]['delivery_state']['status'] == 'ambiguous',
            'real two-root owned, deferred, nested component and ambiguous effect lifecycle')
    machine = CASE / 'recovery-owned-machine.yaml'
    nested_machine = ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-machine.yaml'
    validate_owned_definition_closure(owned_archive, machine, nested_machine, spec_root)
    validate('archive-import-request-v1', owned['stage_request'], 'owned stage request')
    validate('archive-result-v1', owned['stage_result'], 'owned stage result')
    require(owned['stage_request']['archive_digest'] == owned_archive['archive_digest'] and
            owned['stage_result']['archive_digest'] == owned_archive['archive_digest'] and
            owned_archive['source'] in owned['stage_configuration']['trusted_source_profiles'] and
            owned_archive['participant_contract'] in owned['stage_configuration']['trusted_participant_contracts'],
            'owned production stage source and participant policy')
    for case in owned['cases']:
        label = case['case_id']
        validate('recovery-operation-v1', case['request'], label + ': request')
        validate('recovery-operation-v1', case['expected_result'], label + ': result')
        require(case['request']['request_digest'] == digest([
            'determa-recovery-request-1', without(case['request'], 'request_digest')]) and
            case['expected_result']['request_digest'] == case['request']['request_digest'] and
            case['expected_result']['source']['archive_digest'] == owned_archive['archive_digest'],
            label + ': request and source binding')
        if case['expected_record'] is not None:
            validate('recovery-record-v1', case['expected_record'], label + ': record')
            require(case['expected_result']['record_digest'] == digest([
                'determa-recovery-record-1', case['expected_record']]) and
                case['expected_record']['retained_checkpoint_digests'] == sorted(
                    [item['execution_checkpoint_digest'] for item in owned_archive['checkpoints']]) and
                case['expected_record']['work'][0]['work_identity'] ==
                owned_checkpoint['pending_outbox_intents'][0]['intent']['effect_id'],
                label + ': complete record and inherited ambiguous work')
    namespace = read_json(CASE / 'recovery-namespace-vectors-v1.json')
    require(set(namespace) == {'fixture_format', 'fixture_schema_version', 'cases'} and
            namespace['fixture_format'] == 'determa.recovery_namespace_reuse_vectors' and
            namespace['fixture_schema_version'] == 1 and
            len(namespace['cases']) == 4 and
            manifest['recovery_vectors']['namespace'] ==
            [item['case_id'] for item in namespace['cases']],
            'namespace reuse fixture shape and coverage')
    prior = next(item for item in cases if item['case_id'] == 'standalone_takeover')
    consumed = prior['request']['arguments']['external_idempotency_namespace']
    for item in namespace['cases']:
        label = item['case_id']
        require(set(item) == {'case_id', 'prior_record', 'terminated_setup_scope',
                              'request', 'expected_result', 'expected_record'} and
                item['prior_record'] == 'standalone_inactive' and
                type(item['terminated_setup_scope']) is bool and
                item['expected_record'] is None,
                label + ': closed independent namespace case')
        request, result = item['request'], item['expected_result']
        validate('recovery-operation-v1', request, label + ': request')
        validate('recovery-operation-v1', result, label + ': result')
        require(request['request_digest'] == digest([
                    'determa-recovery-request-1', without(request, 'request_digest')]) and
                request['request_digest'] == result['request_digest'] and
                request['arguments']['external_idempotency_namespace'] == consumed and
                request['destination_scope_identity'] != prior['request']['destination_scope_identity'] and
                result['destination_scope_identity'] == request['destination_scope_identity'] and
                result['status'] == 'refused' and result['state'] == 'unchanged' and
                result['record_digest'] is None and result['safe_relocation'] is False and
                result['code'] == ('standalone_takeover_requires_fresh_scope' if
                                   request['operation'] == 'standalone_takeover' else
                                   'scope_destination_not_empty'),
                label + ': preallocated namespace must refuse with exact closed code')
    return len(ids) + len(owned['cases']) + len(namespace['cases'])
