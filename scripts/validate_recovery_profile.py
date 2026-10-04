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
            set(manifest['recovery_vectors']) == {'early', 'cases'}, 'recovery manifest shape')
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
    return len(ids)
