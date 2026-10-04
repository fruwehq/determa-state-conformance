"""Closed §22 fixture and driver contract validation.

These are complete adapter inputs and outputs.  No case name or expected result is
supplied to an implementation under test as an execution input.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot'
FILES = ('archive-v1.json', 'export-cases-v1.json', 'stage-cases-v1.json',
         'hash-checks-v1.json', 'helper-payload-v1.schema.json',
         'host-journal-payload-v1.schema.json', 'stage-configuration-v1.schema.json')
SCHEMAS = ('archive-v1', 'archive-participant-v1', 'archive-result-v1',
           'archive-export-request-v1', 'archive-import-request-v1',
           'archive-export-source-v1', 'archive-host-journal-inventory-v1')


class ArchiveValidationError(ValueError):
    pass


def require(test: bool, message: str) -> None:
    if not test:
        raise ArchiveValidationError(message)


def parse_json_bytes(raw: bytes, label: str):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f'{label}: duplicate JSON key {key}')
            result[key] = value
        return result

    def reject_constant(value):
        raise ArchiveValidationError(f'{label}: nonfinite JSON number {value}')

    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=reject_constant)
    def strict(item):
        if isinstance(item, float):
            require(math.isfinite(item), f'{label}: nonfinite JSON number')
        elif isinstance(item, int) and not isinstance(item, bool):
            require(-(2**63) <= item <= 2**63 - 1, f'{label}: integer out of range')
        elif isinstance(item, str):
            require(not any(0xD800 <= ord(char) <= 0xDFFF for char in item),
                    f'{label}: invalid Unicode')
        elif isinstance(item, list):
            for child in item: strict(child)
        elif isinstance(item, dict):
            for key, child in item.items(): strict(key); strict(child)
    strict(value)
    return value


def read_json(path: Path):
    return parse_json_bytes(path.read_bytes(), str(path))


def canonical(value) -> bytes:
    return rfc8785.dumps(value)


def digest(value) -> str:
    from hashlib import sha256
    return 'sha256:' + sha256(canonical(value)).hexdigest()


def without(value: dict, key: str) -> dict:
    result = dict(value)
    result.pop(key)
    return result


def ordered_unique(values: list[str]) -> bool:
    return values == sorted(set(values), key=lambda item: item.encode('utf-8'))


def decode_typed(value):
    tag = value[0]
    if tag == 'map': return {key: decode_typed(item) for key, item in value[1]}
    if tag == 'list': return [decode_typed(item) for item in value[1]]
    if tag == 'null': return None
    if tag == 'integer': return int(value[1])
    if tag == 'boolean': return value[1]
    if tag == 'string': return value[1]
    if tag == 'float': return value[1]  # Exact bit pattern remains encoded.
    raise ArchiveValidationError(f'unknown typed payload tag: {tag}')


def changed_paths(left, right, prefix: str = '') -> set[str]:
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        paths = set()
        for key in left.keys() | right.keys():
            child = prefix + '/' + key.replace('~', '~0').replace('/', '~1')
            paths |= ({child} if key not in left or key not in right
                      else changed_paths(left[key], right[key], child))
        return paths
    if isinstance(left, list):
        paths = set()
        for index in range(max(len(left), len(right))):
            child = prefix + '/' + str(index)
            paths |= ({child} if index >= len(left) or index >= len(right)
                      else changed_paths(left[index], right[index], child))
        return paths
    return {prefix} if left != right else set()


def validator_registry(spec_root: Path) -> dict[str, Draft202012Validator]:
    resources = []
    for path in (spec_root / 'schema').glob('*.schema.json'):
        schema = read_json(path)
        Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        resources.append((path.name, resource))
        if '$id' in schema:
            resources.append((schema['$id'], resource))
    for name in ('host-journal-payload-v1.schema.json', 'helper-payload-v1.schema.json'):
        schema = read_json(CASE / name)
        resource = Resource.from_contents(schema)
        resources.append((name, resource))
        if '$id' in schema:
            resources.append((schema['$id'], resource))
    registry = Registry().with_resources(resources)
    result = {name: Draft202012Validator(read_json(spec_root / 'schema' / (name + '.schema.json')),
                                         registry=registry) for name in SCHEMAS}
    result['host-effect-journal-v1'] = Draft202012Validator(
        read_json(spec_root / 'schema/host-effect-journal-v1.schema.json'), registry=registry)
    for name in ('host-journal-payload-v1', 'helper-payload-v1'):
        result[name] = Draft202012Validator(read_json(CASE / (name + '.schema.json')),
                                            registry=registry)
    return result


def schema_valid(validator: Draft202012Validator, value, label: str) -> None:
    error = next(validator.iter_errors(value), None)
    require(error is None, f'{label}: {error.message if error else ""}')


def validate_archive_integrity(archive: dict, validators: dict) -> None:
    from validate_conformance import (ValidationFailure,
                                      validate_execution_checkpoint_v1_semantics)
    schema_valid(validators['archive-v1'], archive, 'archive')
    require(archive['archive_digest'] == digest(['determa-archive-digest-1',
                                                without(archive, 'archive_digest')]),
            'outer archive digest')
    source = archive['source']
    require(source['profile_digest'] == digest(['determa-archive-source-profile-1',
                                                without(source, 'profile_digest')]),
            'source profile digest')
    contract = archive['participant_contract']
    require(contract['participant_contract_digest'] == digest([
        'determa-archive-participant-contract-1', source['profile_digest'],
        contract['required_participant_ids'], contract['optional_participant_ids']]),
        'participant contract digest')
    for key in ('required_participant_ids', 'optional_participant_ids'):
        require(ordered_unique(contract[key]), key + ' order')
    require(not (set(contract['required_participant_ids']) &
                 set(contract['optional_participant_ids'])), 'participant contract overlap')
    roots = archive['selection']['root_instance_ids']
    require(bool(roots) and ordered_unique(roots), 'selected root order')
    require([item['root_instance_id'] for item in archive['checkpoints']] == roots,
            'selected checkpoint closure')
    for checkpoint in archive['checkpoints']:
        try:
            validate_execution_checkpoint_v1_semantics(checkpoint)
        except ValidationFailure as error:
            raise ArchiveValidationError(f'checkpoint semantics: {error}') from error
        require(checkpoint['execution_checkpoint_digest'] == digest([
            'determa-execution-checkpoint-digest-1',
            without(checkpoint, 'execution_checkpoint_digest')]), 'checkpoint digest')
        state = checkpoint['root_record'].get('aggregate_state')
        if state is not None:
            require(state['aggregate_state_digest'] == digest([
                'determa-aggregate-state-digest-1', without(state, 'aggregate_state_digest')]),
                'aggregate digest')
    definitions = archive['normalized_definitions']
    fingerprints = [item['validated_bundle_fingerprint'] for item in definitions]
    require(ordered_unique(fingerprints), 'definition order')
    for item in definitions:
        require(item['validated_bundle_fingerprint'] == digest([
            'determa-validated-bundle-fingerprint-1', item['normalized_bundle']]),
            'normalized definition fingerprint')
    descriptors = archive['migration_descriptors']
    descriptor_ids = [item['migration_descriptor_digest'] for item in descriptors]
    require(ordered_unique(descriptor_ids), 'descriptor order')
    for item in descriptors:
        require(item['migration_descriptor_digest'] == digest([
            'determa-migration-descriptor-1', without(item, 'migration_descriptor_digest')]),
            'migration descriptor digest')
    participants = archive['participants']
    participant_ids = [item['participant_id'] for item in participants]
    require(ordered_unique(participant_ids), 'participant order')
    require(set(contract['required_participant_ids']) <= set(participant_ids),
            'required participant missing')
    for participant in participants:
        identity = participant['participant_id']
        require(identity in contract['required_participant_ids'] + contract['optional_participant_ids'],
                'undeclared participant')
        require(participant['required'] == (identity in contract['required_participant_ids']),
                'participant requiredness')
        require(ordered_unique(participant['dependencies']), 'dependency order')
        require(set(participant['dependencies']) <= set(participant_ids), 'dependency missing')
        if participant['storage'] == 'embedded':
            require(participant['payload_digest'] == digest([
                'determa-archive-payload-1', identity,
                participant['participant_schema_digest'], participant['payload']]),
                'participant payload digest')
    member_objects = {
        **{'checkpoint:' + x['root_instance_id']: x for x in archive['checkpoints']},
        **{'definition:' + x['validated_bundle_fingerprint']: x for x in definitions},
        **{'migration_descriptor:' + x['migration_descriptor_digest']: x for x in descriptors},
        **{'participant:' + x['participant_id']: x for x in participants},
    }
    require([m['identity'] for m in archive['members']] ==
            sorted(member_objects, key=lambda key: key.encode('utf-8')), 'member identity closure')
    for member in archive['members']:
        value = member_objects[member['identity']]
        require(member['digest'] == digest(value) and
                member['byte_length'] == str(len(canonical(value))), 'member bytes')
    capability = ['portable_archive', 'portable_checkpoint']
    if definitions: capability.append('normalized_definition')
    if descriptors: capability.append('migration_descriptor')
    if participants: capability.append('archive_participant')
    if 'durable_native_results' in source['profile_claims']:
        capability.append('host_effect_journal')
    require(archive['required_determa_capabilities'] == sorted(capability),
            'required capability closure')
    require([x['participant_id'] for x in archive['optional_participant_references']] ==
            contract['optional_participant_ids'], 'optional reference closure')


def validate_journal_inventory(archive: dict, configured: dict, validators: dict) -> None:
    if 'durable_native_results' not in archive['source']['profile_claims']:
        return
    participants = [item for item in archive['participants']
                    if item['participant_id'] == 'host-effect-journal']
    require(len(participants) == 1 and participants[0]['required'],
            'durable native journal required')
    participant = participants[0]
    schema = read_json(CASE / 'host-journal-payload-v1.schema.json')
    require(participant['participant_schema_digest'] == digest(schema),
            'host journal payload schema pin')
    schema_valid(validators['host-journal-payload-v1'], participant['payload'], 'host journal payload')
    payload = decode_typed(participant['payload'])
    inventories = configured['trusted_host_journal_inventories']
    matching = [item for item in inventories
                if item['source_profile_digest'] == archive['source']['profile_digest'] and
                   item['consistency_token'] == archive['selection']['consistency_token']]
    require(len(matching) == 1, 'independent host journal inventory')
    inventory = matching[0]
    require(inventory['inventory_digest'] == digest([
        'determa-archive-host-journal-inventory-1', without(inventory, 'inventory_digest')]),
        'host journal inventory digest')
    roots = archive['selection']['root_instance_ids']
    require([item['root_instance_id'] for item in payload['journals']] == roots,
            'host journal root closure')
    require([item['root_instance_id'] for item in inventory['root_inventories']] == roots,
            'trusted host journal root closure')
    for checkpoint, journal, commitment in zip(archive['checkpoints'],
                                                payload['journals'], inventory['root_inventories']):
        schema_valid(validators['host-effect-journal-v1'], journal, 'decoded host journal')
        require(journal['host_effect_journal_digest'] == digest([
            'determa-host-effect-journal-digest-1',
            without(journal, 'host_effect_journal_digest')]), 'decoded host journal digest')
        require(journal['checkpoint_digest'] == checkpoint['execution_checkpoint_digest'] ==
                commitment['checkpoint_digest'] and
                journal['checkpoint_revision'] == checkpoint['revision'] ==
                commitment['checkpoint_revision'] and
                journal['host_effect_journal_digest'] == commitment['journal_digest'] and
                journal['journal_revision'] == commitment['journal_revision'],
                'journal/checkpoint consistent capture pair')
        records = [{
            'effect_id': record['effect_id'],
            'intent_digest': record['intent_digest'],
            'attempt_report_digests': [attempt['report_digest']
                                       for attempt in record['attempt_records']],
            'outcome_digest': record['outcome']['digest'] if record['outcome'] else None,
            'result_event_id': record['result_event_id'],
        } for record in journal['effect_records']]
        require(records == commitment['record_commitments'] and
                journal['operation_response_references'] == commitment['response_commitments'],
                'host journal inventory content commitment')
        require(journal['scope_identity'] == archive['source']['logical_scope_identity'],
                'journal source scope provenance')
        for record in journal['effect_records']:
            intent_locations = [item['intent'] for key in
                ('pending_outbox_intents', 'terminal_outbox_records')
                for item in checkpoint[key]
                if item['intent']['effect_id'] == record['effect_id']]
            tombstones = [item for item in checkpoint['outbox_effect_tombstones']
                          if item['effect_id'] == record['effect_id']]
            require(len(intent_locations) + len(tombstones) == 1,
                    'host journal effect checkpoint location')
            intent_digest = (digest(['determa-outbox-intent-digest-1', '1',
                                     checkpoint['root_instance_id'], intent_locations[0]])
                             if intent_locations else tombstones[0]['intent_digest'])
            require(record['intent_digest'] == intent_digest,
                    'host journal effect intent digest')
            reports = record['attempt_records']
            fences = [int(report['attempt_fence']) for report in reports]
            require(fences == sorted(set(fences)) and
                    all(fence <= int(record['attempt_fence']) for fence in fences),
                    'host journal attempt fence order')
            for report in reports:
                report_payload = (record['outcome']['payload']
                                  if record['outcome'] is not None and
                                  report['report_kind'] == record['outcome']['kind']
                                  else ['map', []])
                require(report['report_digest'] == digest([
                    'determa-effect-attempt-report-1', record['effect_id'],
                    record['operation_token'], report['attempt_fence'],
                    report['report_kind'], report_payload, report['reason']]),
                    'host journal attempt report digest')
            outcome = record['outcome']
            if outcome is not None:
                require(outcome['digest'] == digest([
                    'determa-effect-outcome-1', record['effect_id'],
                    record['operation_token'], outcome['kind'], outcome['payload'],
                    outcome['attempt_fence']]), 'host journal outcome digest')
                mapping = [item for item in record['result_mapping']
                           if item['outcome_kind'] == outcome['kind']]
                require(len(mapping) == 1 and record['result_event_id'] == digest([
                    'determa-effect-result-event-1', record['effect_id'],
                    mapping[0]['result_slot']]), 'host journal result event identity')
    responses = {item['operation_id']: digest([
        'determa-host-operation-response-1', item['normalized_response']])
        for item in payload['retained_operation_responses']}
    references = [item for journal in payload['journals']
                  for item in journal['operation_response_references']]
    require(len(responses) == len(payload['retained_operation_responses']) == len(references)
            and all(responses.get(item['operation_id']) == item['response_digest']
                    for item in references), 'retained public response reconstruction')


def validate_profile(spec_root: Path, *, enforce_pin: bool = True) -> int:
    spec_root = Path(spec_root)
    archive = read_json(CASE / 'archive-v1.json')
    machine_names = {f'definition-{index:02d}.json'
                     for index in range(1, len(archive['normalized_definitions']) + 1)}
    owned_names = {'owned-component-machine.yaml', 'owned-component-checkpoint-v1.json',
                   'nested-component-machine.yaml', 'nested-component-checkpoint-v1.json',
                   'owned-component-archive-v1.json', 'owned-component-vectors-v1.json'}
    require({path.name for path in CASE.iterdir()} == set(FILES) | {'test.yaml'} | machine_names | owned_names,
            'archive fixture file inventory')
    if enforce_pin:
        for name in FILES:
            require((CASE / name).read_bytes() ==
                    (spec_root / 'examples/archives' / name).read_bytes(),
                    f'{name}: differs from pinned normative example')
    validators = validator_registry(spec_root)
    stage = read_json(CASE / 'stage-cases-v1.json')
    export = read_json(CASE / 'export-cases-v1.json')
    owned = read_json(CASE / 'owned-component-vectors-v1.json')
    hashes = read_json(CASE / 'hash-checks-v1.json')
    test = YAML(typ='safe').load((CASE / 'test.yaml').read_text(encoding='utf-8'))
    require(set(test) == {'title', 'archive_vectors'}, 'archive driver manifest shape')
    require(set(test['archive_vectors']) == {'export', 'stage', 'owned_component'},
            'archive driver modes')
    require(test['archive_vectors']['export'] == [c['case_id'] for c in export['cases']],
            'export case coverage')
    require(test['archive_vectors']['stage'] == [c['case_id'] for c in stage['cases']],
            'stage case coverage')
    require(len(set(test['archive_vectors']['export'])) == len(export['cases']) and
            len(set(test['archive_vectors']['stage'])) == len(stage['cases']),
            'duplicate archive case')
    require(test['archive_vectors']['owned_component'] ==
            [owned['export_case']['case_id'], owned['stage_case']['case_id']],
            'owned component coverage')
    from generate_portable_archive_profile import build_owned_component
    for name, generated in build_owned_component().items():
        require((CASE / name).read_bytes() == generated,
                name + ': independent lifecycle derivation')
    owned_archive = read_json(CASE / 'owned-component-archive-v1.json')
    owned_checkpoint = read_json(CASE / 'owned-component-checkpoint-v1.json')
    nested_checkpoint = read_json(CASE / 'nested-component-checkpoint-v1.json')
    require(nested_checkpoint == read_json(ROOT /
        'conformance/profiles/execution-checkpoint/checkpoint-07-complete-host-contract/inactive-component-checkpoint-v1.json'),
        'nested component checkpoint provenance')
    require(owned['source_checkpoints'] == ['owned-component-checkpoint-v1.json',
                                            'nested-component-checkpoint-v1.json'] and
            owned['source_machines'] == ['owned-component-machine.yaml',
                                         'nested-component-machine.yaml'] and
            owned_archive['checkpoints'] == [owned_checkpoint, nested_checkpoint] and
            len(owned_checkpoint['root_record']['aggregate_state']['runtimes']) == 2 and
            any(runtime['relation']['kind'] == 'owned_spawned_instance' and
                len(runtime['deferred_mailbox']) == 1
                for runtime in owned_checkpoint['root_record']['aggregate_state']['runtimes']) and
            len(nested_checkpoint['root_record']['aggregate_state']['runtimes']) == 3 and
            sum(runtime['relation']['kind'] == 'component' for runtime in
                nested_checkpoint['root_record']['aggregate_state']['runtimes']) == 2,
            'owned instance, nested components, and deferred envelope witness')
    validate_archive_integrity(owned_archive, validators)
    for name in SCHEMAS:
        aliases = {'archive-v1': 'archive_schema_digest',
                   'archive-participant-v1': 'participant_schema_digest',
                   'archive-result-v1': 'result_schema_digest',
                   'archive-export-request-v1': 'export_request_schema_digest',
                   'archive-import-request-v1': 'import_request_schema_digest',
                   'archive-export-source-v1': 'export_source_schema_digest',
                   'archive-host-journal-inventory-v1': 'host_journal_inventory_schema_digest'}
        require(hashes[aliases[name]] == digest(read_json(spec_root / 'schema' / (name + '.schema.json'))),
                f'{name} schema pin')
    validate_archive_integrity(archive, validators)
    from validate_conformance import (ValidationFailure, validated_bundle_fingerprint,
                                      validate_aggregate_against_bundle)
    from generate_version1_vectors import typed_value
    attached = archive['normalized_definitions']
    machine_paths = {}
    for index, definition in enumerate(attached, 1):
        path = CASE / f'definition-{index:02d}.json'
        machine = read_json(path)
        schema = read_json(spec_root / 'schema/machine.schema.json')
        schema_valid(Draft202012Validator(schema), machine, path.name)
        require(typed_value(machine) == definition['normalized_bundle'],
                path.name + ': normalized bundle attachment')
        require(validated_bundle_fingerprint(path) == definition['validated_bundle_fingerprint'],
                path.name + ': production resolver fingerprint')
        machine_paths[definition['validated_bundle_fingerprint']] = path
    for checkpoint in archive['checkpoints']:
        aggregate = checkpoint['root_record']['aggregate_state']
        current = machine_paths[aggregate['validated_bundle_fingerprint']]
        historical = [path for fingerprint, path in machine_paths.items()
                      if fingerprint != aggregate['validated_bundle_fingerprint']]
        try:
            validate_aggregate_against_bundle(aggregate, current, *historical)
        except ValidationFailure as error:
            raise ArchiveValidationError(f'{checkpoint["root_instance_id"]}: {error}') from error
    owned_machine = CASE / 'owned-component-machine.yaml'
    require(validated_bundle_fingerprint(owned_machine) ==
            owned_archive['normalized_definitions'][0]['validated_bundle_fingerprint'],
            'owned component machine fingerprint')
    try:
        validate_aggregate_against_bundle(
            owned_checkpoint['root_record']['aggregate_state'], owned_machine)
    except ValidationFailure as error:
        raise ArchiveValidationError(f'owned component resolver: {error}') from error
    nested_machine = CASE / 'nested-component-machine.yaml'
    require(validated_bundle_fingerprint(nested_machine) ==
            nested_checkpoint['root_record']['aggregate_state']['validated_bundle_fingerprint'],
            'nested component machine fingerprint')
    try:
        validate_aggregate_against_bundle(
            nested_checkpoint['root_record']['aggregate_state'], nested_machine)
    except ValidationFailure as error:
        raise ArchiveValidationError(f'nested component resolver: {error}') from error
    require(hashes['archive_digest'] == archive['archive_digest'], 'archive golden digest')
    require(export['cases'][0]['expected_archive'] == archive and
            stage['cases'][0]['input_archive'] == archive,
            'golden archive/export/stage binding')
    for item in [*export['cases'], owned['export_case']]:
        label = item['case_id']
        schema_valid(validators['archive-export-request-v1'], item['input_request'], label + ' request')
        schema_valid(validators['archive-export-source-v1'], item['source_capture'], label + ' source')
        schema_valid(validators['archive-result-v1'], item['expected_result'], label + ' result')
        expected = item['expected_archive']
        if expected is not None:
            validate_archive_integrity(expected, validators)
            require(item['expected_result']['status'] == 'exported' and
                    item['expected_result']['archive_digest'] == expected['archive_digest'],
                    label + ': export output binding')
            require(item['input_request']['source'] == expected['source'] and
                    item['input_request']['root_instance_ids'] == expected['selection']['root_instance_ids'],
                    label + ': export source/selection binding')
            require(item['source_capture']['source'] == expected['source'],
                    label + ': captured source binding')
            for name in ('checkpoints', 'normalized_definitions', 'migration_descriptors'):
                require(item['source_capture'][name] == expected[name],
                        label + ': complete captured ' + name)
            evidence = item['source_capture']['inventory_evidence']
            require(evidence['authorized_source'] == expected['source'] and
                    evidence['committed_consistency_token'] ==
                    expected['selection']['consistency_token'] and
                    evidence['selected_checkpoint_digests'] ==
                    [checkpoint['execution_checkpoint_digest']
                     for checkpoint in expected['checkpoints']],
                    label + ': source consistency point')
        else:
            require(item['expected_result']['status'] == 'refused', label + ': refusal output')
    for item in [*stage['cases'], owned['stage_case']]:
        label = item['case_id']
        if item is not owned['stage_case']:
            require(set(item['changed_paths_from_positive']) ==
                    changed_paths(stage['cases'][0]['input_archive'], item['input_archive']),
                    label + ': exact raw provenance path map')
        schema_valid(validators['archive-import-request-v1'], item['input_request'], label + ' request')
        schema_valid(validators['archive-result-v1'], item['expected_result'], label + ' result')
        require(item['expected_host_effects'] == {
            'active_scope_created': False, 'authority_grant_created': False,
            'credentials_created': False, 'core_calls': 0, 'effect_deliveries': 0,
        }, label + ': staging must be inert')
        result = item['expected_result']
        if result['status'] == 'staged':
            validate_archive_integrity(item['input_archive'], validators)
            validate_journal_inventory(item['input_archive'], item['configured_import'], validators)
            archive_value = item['input_archive']
            configured_value = item['configured_import']
            require(archive_value['source'] in configured_value['trusted_source_profiles'] and
                    archive_value['participant_contract'] in
                    configured_value['trusted_participant_contracts'] and
                    set(archive_value['required_determa_capabilities']) <=
                    set(configured_value['supported_determa_capabilities']),
                    label + ': independent staging policy')
            for participant in archive_value['participants']:
                payload = participant['payload']
                if participant['storage'] == 'external':
                    payload = configured_value.get('resolved_external_payloads', {}).get(
                        participant['payload_digest'])
                require(payload is not None and participant['payload_digest'] == digest([
                    'determa-archive-payload-1', participant['participant_id'],
                    participant['participant_schema_digest'], payload]),
                    label + ': resolved participant bytes')
                if participant['participant_id'] == 'helper-state':
                    schema_valid(validators['helper-payload-v1'], payload,
                                 label + ': helper payload')
            require(item['expected_staged_archive'] == item['input_archive'] and
                    result['archive_digest'] == item['input_archive']['archive_digest'],
                    label + ': complete staged bytes')
        else:
            require(result['status'] == 'refused' and item['expected_staged_archive'] is None,
                    label + ': refusal must leave destination unstaged')
        # The source's declared participant set cannot set trusted requiredness.
        configured = item['configured_import']
        require(isinstance(configured['trusted_source_profiles'], list) and
                isinstance(configured['trusted_participant_contracts'], list),
                label + ': independent trusted import policy')
    return len(export['cases']) + len(stage['cases']) + 2
