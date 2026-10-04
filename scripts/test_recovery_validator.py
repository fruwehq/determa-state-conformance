#!/usr/bin/env python3
"""Adversarial static and production-response checks for §24."""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from validate_portable_archive import (ArchiveValidationError, canonical, digest, read_json,
                                       validate_archive_integrity, validator_registry, without, ROOT)
from validate_recovery_profile import CASE, validate_profile, validate_owned_definition_closure
from run_recovery_profile import (CALLS, STATE, input_for, public_source_reference,
                                  run_case, run_hosted_source, source_fault_cut,
                                  store_call, trusted_bridge,
                                  validate_source_plan, verify_local_source_step,
                                  verify_source_integrity)
from run_hosted_recovery_profile import observed_binding


def rejected(label, fn):
    try:
        fn()
    except (ArchiveValidationError, ValueError):
        return
    raise AssertionError(label + ': invalid result accepted')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    args = parser.parse_args()
    assert validate_profile(args.spec_root) == 52
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    case = next(c for c in fixture['cases'] if c['case_id'] == 'standalone_takeover')
    sent = input_for(case, fixture)
    assert not any(key.startswith('expected_') or key == 'case_id' for key in sent)
    assert sent['request'] == case['request'] and sent['setup_requests'] == []
    assert len(sent['source_archive']['checkpoints']) == 4
    assert 'stage_receipt' not in sent and 'expected_result' not in sent
    missing_helper = next(item for item in fixture['cases']
                          if item['case_id'] == 'required_helper_missing')
    missing_input = input_for(missing_helper, fixture)
    assert missing_input['stage_request']['staging_identity'] == \
        missing_helper['request']['arguments']['staging_identity']
    assert missing_input['stage_archive']['participants'] == []
    assert missing_input['source_archive']['participants'] != []
    owned = read_json(CASE / 'recovery-two-root-archive-v1.json')
    validators = validator_registry(args.spec_root)
    broken = copy.deepcopy(owned)
    broken['normalized_definitions'].pop()
    broken['members'] = [member for member in broken['members']
                         if not member['identity'].startswith('definition:') or
                         member['identity'] == 'definition:' + broken['normalized_definitions'][0]['validated_bundle_fingerprint']]
    broken['archive_digest'] = digest(['determa-archive-digest-1', without(broken, 'archive_digest')])
    validate_archive_integrity(broken, validators)
    rejected('resealed missing real definition', lambda: validate_owned_definition_closure(
        broken, CASE / 'recovery-owned-machine.yaml',
        ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-machine.yaml',
        args.spec_root))
    missing_component = copy.deepcopy(owned)
    nested = missing_component['checkpoints'][0]['root_record']['aggregate_state']
    nested['runtimes'] = [runtime for runtime in nested['runtimes']
                          if runtime['relation']['kind'] != 'component']
    rejected('removed nested component runtime', lambda: validate_owned_definition_closure(
        missing_component, CASE / 'recovery-owned-machine.yaml',
        ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/nested-component-machine.yaml',
        args.spec_root))
    original_run = subprocess.run
    captured = []
    rejected('unregistered self-reported production adapter',
             lambda: trusted_bridge(['golden-echo']))
    with patch('run_recovery_profile.trusted_bridge', return_value='changed-installation'):
        rejected('reviewed bridge drift between recovery cases',
                 lambda: run_case(['golden-echo'], case, fixture,
                                  expected_bridge_identity='original-installation'))
    with tempfile.TemporaryDirectory(prefix='determa-recovery-bridge-contract-') as temporary:
        directory = Path(temporary)
        bridge = directory / 'bridge.py'
        engine = directory / 'engine.py'
        bridge.write_text('from engine import stage, recover\n')
        engine.write_text('def stage(): pass\ndef recover(): pass\n')
        sha = lambda path: 'sha256:' + sha256(path.read_bytes()).hexdigest()
        installation = {
            'format': 'determa.conformance.recovery.installation',
            'schema_version': 1, 'language': 'python',
            'production_factory': 'engine.RecoveryHost',
            'public_stage_entrypoint': 'stage', 'public_recovery_entrypoint': 'recover',
            'public_termination_entrypoint': 'terminate',
            'native_observer_entrypoint': 'observe',
            'source_closure': [{'path': 'engine.py', 'sha256': sha(engine)}],
            'dependency_files': [], 'build_inputs': [], 'features': [],
            'toolchain': 'python-source-test', 'effective_configuration': {},
            'configured_provider_content_digest': sha(engine),
            'configured_authority_token_identity': None,
            'configured_topology_identifier': None,
            'source_lifecycle_plan_sha256': None,
        }
        installation['effective_configuration_digest'] = digest({})
        installation['dependency_inventory_digest'] = digest([])
        installation['build_anchor_digest'] = digest({
            'build_inputs': [], 'features': [], 'toolchain': 'python-source-test'})
        manifest = directory / 'installation.json'
        manifest.write_bytes(canonical(installation))
        registration = {key: installation[key] for key in (
            'language', 'production_factory', 'public_stage_entrypoint',
            'public_recovery_entrypoint', 'public_termination_entrypoint',
            'native_observer_entrypoint', 'effective_configuration_digest',
            'dependency_inventory_digest', 'build_anchor_digest',
            'configured_provider_content_digest',
            'configured_authority_token_identity',
            'configured_topology_identifier',
            'source_lifecycle_plan_sha256')}
        registration.update({
            'format': 'determa.conformance.recovery.bridge_registration',
            'schema_version': 1, 'command': [sys.executable, '-I', '-S', str(bridge)],
            'bridge_root': str(directory), 'bridge_source_path': 'bridge.py',
            'bridge_source_sha256': sha(bridge),
            'installation_root': str(directory),
            'installation_manifest_path': 'installation.json',
            'installation_manifest_sha256': sha(manifest)})
        registration_path = directory / 'registration.json'
        registration_path.write_bytes(canonical(registration))
        assert trusted_bridge(registration['command'], registration_path) == digest(registration)
        rejected('decoy command with matching installation file',
                 lambda: trusted_bridge(['golden-echo'], registration_path))
        altered = copy.deepcopy(installation)
        altered['effective_configuration'] = {'authority': 'changed'}
        manifest.write_bytes(canonical(altered))
        registration['installation_manifest_sha256'] = sha(manifest)
        registration_path.write_bytes(canonical(registration))
        rejected('changed effective configuration with resealed manifest file',
                 lambda: trusted_bridge(registration['command'], registration_path))
        altered = copy.deepcopy(installation)
        altered['features'] = ['unreviewed-feature']
        manifest.write_bytes(canonical(altered))
        registration['installation_manifest_sha256'] = sha(manifest)
        registration_path.write_bytes(canonical(registration))
        rejected('changed build feature with resealed manifest file',
                 lambda: trusted_bridge(registration['command'], registration_path))
        manifest.write_bytes(canonical(installation))
        registration['installation_manifest_sha256'] = sha(manifest)
        registration_path.write_bytes(canonical(registration))
        engine.write_text('def stage(): pass\ndef recover(): return "decoy"\n')
        rejected('changed installed engine source',
                 lambda: trusted_bridge(registration['command'], registration_path))
        bridge.write_text('print("decoy")\n')
        rejected('changed reviewed bridge source',
                 lambda: trusted_bridge(registration['command'], registration_path))
    def journal_start(sent):
        database = Path(sent['store_database_path'])
        store_call(database, sent['run_id'], 'invocation_start',
                   operation_id=sent['operation_id'], phase=sent['kind'],
                   request_digest=digest(sent['payload']),
                   bridge_identity=sent['bridge_identity'])
    def journal_return(sent, body):
        database = Path(sent['store_database_path'])
        store_call(database, sent['run_id'], 'invocation_return',
                   operation_id=sent['operation_id'], response_digest=digest(body),
                   outcome='returned')
    def journal(sent, body):
        journal_start(sent)
        journal_return(sent, body)
    def golden_echo(command, *, input, **kwargs):
        if command != ['golden-echo']:
            return original_run(command, input=input, **kwargs)
        sent = json.loads(input)
        captured.append(sent)
        if sent['kind'] == 'archive_stage':
            journal(sent, fixture['stage_receipt'])
            return SimpleNamespace(returncode=0, stderr=b'', stdout=canonical({
                'caller_response_kind': 'archive_result',
                'caller_response_body': fixture['stage_receipt'],
                'native_evidence': None}))
        return SimpleNamespace(returncode=0, stderr=b'', stdout=canonical({
            'caller_response_kind': 'recovery_result',
            'caller_response_body': case['expected_result'],
            'result': case['expected_result'], 'record': case['expected_record'],
            'transfer_proof': None, 'native_evidence': None}))
    with patch('run_recovery_profile.trusted_bridge', return_value='test-reviewed-bridge'), \
         patch('run_recovery_profile.subprocess.run', side_effect=golden_echo):
        rejected('complete golden echo without actual I1 stage',
                 lambda: run_case(['golden-echo'], case, fixture))
    assert len(captured) == 1 and captured[0]['kind'] == 'archive_stage'
    assert not any((key.startswith('expected_') and key != 'expected_before_digest') or
                   key == 'case_id' for key in captured[0])
    captured.clear()
    def staged_then_golden_echo(command, *, input, **kwargs):
        if command != ['golden-echo']:
            return original_run(command, input=input, **kwargs)
        sent = json.loads(input)
        captured.append(sent)
        if sent['kind'] == 'archive_stage':
            journal_start(sent)
            database = Path(sent['store_database_path'])
            before = store_call(database, sent['run_id'], 'snapshot')['state']
            after = copy.deepcopy(before)
            after['staged_archives'].append({
                'staging_identity': sent['payload']['stage_request']['staging_identity'],
                'archive': sent['payload']['stage_archive']})
            transaction = store_call(database, sent['run_id'], 'commit',
                operation_id=sent['operation_id'], phase='archive_stage',
                request_digest=digest(sent['payload']),
                response_digest=digest(fixture['stage_receipt']),
                expected_before_digest=sent['expected_before_digest'], after=after)
            journal_return(sent, fixture['stage_receipt'])
            return SimpleNamespace(returncode=0, stderr=b'', stdout=canonical({
                'caller_response_kind': 'archive_result',
                'caller_response_body': fixture['stage_receipt'],
                'native_evidence': {key: transaction[key] for key in
                                    ('native_transaction_id', 'proof_id')}}))
        journal(sent, case['expected_result'])
        return SimpleNamespace(returncode=0, stderr=b'', stdout=canonical({
            'caller_response_kind': 'recovery_result',
            'caller_response_body': case['expected_result'],
            'result': case['expected_result'], 'record': case['expected_record'],
            'transfer_proof': None, 'native_evidence': None}))
    with patch('run_recovery_profile.trusted_bridge', return_value='test-reviewed-bridge'), \
         patch('run_recovery_profile.subprocess.run', side_effect=staged_then_golden_echo):
        rejected('actual stage plus complete recovery golden echo without native recovery commit',
                 lambda: run_case(['golden-echo'], case, fixture))
    assert [item['kind'] for item in captured] == ['archive_stage', 'recovery']
    assert not any((key.startswith('expected_') and key != 'expected_before_digest') or
                   key == 'case_id' for key in captured[1])
    with tempfile.TemporaryDirectory(prefix='determa-recovery-reseed-') as temporary:
        database = Path(temporary) / 'single-run.sqlite'
        initial = {'staged_archives': []}
        store_call(database, 'same-run', 'init', initial=initial)
        rejected('restart attempted to reseed the same native database',
                 lambda: store_call(database, 'same-run', 'init', initial=initial))
    with tempfile.TemporaryDirectory(prefix='determa-recovery-wrong-db-') as temporary:
        other_database = Path(temporary) / 'other.sqlite'
        def wrong_database_echo(command, *, input, **kwargs):
            if command != ['golden-echo']:
                return original_run(command, input=input, **kwargs)
            sent = json.loads(input)
            actual_database = Path(sent['store_database_path'])
            initial = store_call(actual_database, sent['run_id'], 'snapshot')['state']
            store_call(other_database, sent['run_id'], 'init', initial=initial)
            sent['store_database_path'] = str(other_database)
            return staged_then_golden_echo(command, input=canonical(sent), **kwargs)
        with patch('run_recovery_profile.trusted_bridge', return_value='test-reviewed-bridge'), \
             patch('run_recovery_profile.subprocess.run', side_effect=wrong_database_echo):
            rejected('complete native stage proof from a different database',
                     lambda: run_case(['golden-echo'], case, fixture))
    namespace = read_json(CASE / 'recovery-namespace-vectors-v1.json')
    assert len(namespace['cases']) == 4
    assert all(item['request']['destination_scope_identity'] !=
               fixture['records']['standalone_inactive']['record']['destination_scope_identity']
               for item in namespace['cases'])
    assert all(item['request']['arguments']['external_idempotency_namespace'] ==
               fixture['records']['standalone_inactive']['record']['external_idempotency_namespace']
               for item in namespace['cases'])
    local_archive = read_json(CASE / 'archive-local-transfer-v1.json')
    local = next(item for item in fixture['cases'] if item['case_id'] == 'local_prepare')
    with patch('run_recovery_profile.trusted_bridge', return_value='test-reviewed-bridge'):
        rejected('local transfer without actual source lifecycle plan',
                 lambda: run_case(['golden-echo'], local, fixture,
                                  hosted_binding_digest='sha256:host',
                                  hosted_authority_token_identity='authority-token'))
    plan = {'format': 'determa.conformance.recovery.source_lifecycle',
            'schema_version': 1,
            'source_scope_identity': local_archive['source']['logical_scope_identity'],
            'root_instance_ids': local_archive['selection']['root_instance_ids'],
            'operations': ([{'operation': operation, 'root_instance_id': None,
                             'arguments': {}} for operation in
                            ('configure_scope', 'allocate_scope')] +
                           [{'operation': 'create_root', 'root_instance_id': root,
                             'arguments': {}} for root in
                            local_archive['selection']['root_instance_ids']] +
                           [{'operation': operation,
                             'root_instance_id': (local_archive['selection']['root_instance_ids'][0]
                                                  if operation in ('admit_event', 'step_root') else None),
                             'arguments': {}} for operation in
                            ('admit_event', 'step_root', 'append_host_journal', 'claim_worker')])}
    validate_source_plan(plan, local_archive)
    def fake_source(command, *, input, **kwargs):
        if command != ['golden-source']:
            return original_run(command, input=input, **kwargs)
        return SimpleNamespace(returncode=0, stderr=b'', stdout=canonical({
            'caller_response_kind': 'source_result',
            'caller_response_body': {'status': 'succeeded'},
            'native_evidence': None}))
    with patch('run_recovery_profile.trusted_bridge', return_value='test-reviewed-bridge'), \
         patch('run_recovery_profile.subprocess.run', side_effect=fake_source):
        rejected('hosted local source created only by a golden child response',
                 lambda: run_case(['golden-source'], local, fixture,
                     hosted_binding_digest='sha256:host',
                     hosted_authority_token_identity='authority-token',
                     hosted_source_plan=plan,
                     hosted_source_binding={
                         'topology_identifier': 'local',
                         'provider_content_digest': 'sha256:provider',
                         'configuration_digest': 'sha256:configuration',
                         'required_participants': []}))
    malformed = copy.deepcopy(plan)
    malformed['operations'][2]['arguments']['checkpoint'] = local_archive['checkpoints'][0]
    rejected('source lifecycle plan seeds a golden checkpoint',
             lambda: validate_source_plan(malformed, local_archive))
    source_identity = local_archive['source']['logical_scope_identity']
    source_state = {key: [] for key in STATE}
    source_state['source_scopes'] = [{
        'scope_identity': source_identity, 'storage_identity': 'native-source-db',
        'native_instance_identity': 'native-source-instance', 'state': 'frozen'}]
    source_reference = {'scope_identity': source_identity,
                        'storage_identity': 'native-source-db',
                        'native_instance_identity': 'native-source-instance',
                        'freeze_native_transaction_id': 'missing-freeze',
                        'freeze_native_proof_id': 'missing-proof',
                        'source_fault_cut': None}
    rejected('prepare uses only a transfer result with no prior native source freeze',
             lambda: verify_local_source_step(local, source_state, source_state,
                                              None, source_reference, fixture))
    proof = fixture['trusted_transfer_proofs'][0]
    frozen_scope = {
        'scope_identity': source_identity, 'storage_identity': 'native-source-db',
        'native_instance_identity': 'native-source-instance', 'state': 'frozen',
        'authority_epoch': proof['source_authority_epoch'],
        'scope_generation': proof['source_scope_generation'],
        'inventory_digest': 'sha256:frozen-inventory',
        'complete_scope_inventory': True}
    frozen_inventory = {
        'source_checkpoints': copy.deepcopy(local_archive['checkpoints']),
        'source_host_journals': [{'root_instance_id': root} for root in
                                 local_archive['selection']['root_instance_ids']],
        'source_participants': copy.deepcopy(local_archive['participants']),
        'source_worker_claims': [{'scope_identity': source_identity,
                                  'state': 'revoked'}]}
    freeze_entry = {'operation_kind': 'freeze_scope',
                    'scope_identity': source_identity,
                    'native_transaction_id': 'native-freeze',
                    'native_proof_id': 'proof-freeze',
                    'freeze_evidence_digest': proof['freeze_evidence_digest'],
                    'transaction_fate': 'known_committed'}
    frozen_state = {key: [] for key in STATE}
    frozen_state.update(copy.deepcopy(frozen_inventory))
    frozen_state['source_scopes'] = [copy.deepcopy(frozen_scope)]
    frozen_state['source_authority_ledger'] = [copy.deepcopy(freeze_entry)]
    frozen_reference = {
        'scope_identity': source_identity,
        'storage_identity': 'native-source-db',
        'native_instance_identity': 'native-source-instance',
        'frozen_source_scope': copy.deepcopy(frozen_scope),
        'frozen_inventory': copy.deepcopy(frozen_inventory),
        'source_authority_ledger': [copy.deepcopy(freeze_entry)],
        'freeze_native_transaction_id': 'native-freeze',
        'freeze_native_proof_id': 'proof-freeze',
        'source_fault_cut': None}
    assert set(public_source_reference({**frozen_reference,
            'export_observation_id': 'export-1'})) == {
        'scope_identity', 'native_instance_identity', 'storage_identity',
        'freeze_native_transaction_id', 'freeze_native_proof_id',
        'export_observation_id', 'source_fault_cut'}
    stage_case = next(item for item in fixture['cases'] if item['case_id'] == 'local_stage')
    verify_local_source_step(stage_case, frozen_state, frozen_state, None,
                             copy.deepcopy(frozen_reference), fixture)
    verify_source_integrity(frozen_state, frozen_state,
                            copy.deepcopy(frozen_reference), 'local archive stage')
    for name, mutate in [
        ('deleted checkpoint', lambda state: state['source_checkpoints'].pop()),
        ('rewritten participant', lambda state: state['source_participants'][0].update(
            participant_id='other-helper')),
        ('rewritten host journal', lambda state: state['source_host_journals'][0].update(
            root_instance_id='other-root')),
        ('rewritten source inventory', lambda state: state['source_scopes'][0].update(
            inventory_digest='sha256:other')),
    ]:
        changed = copy.deepcopy(frozen_state)
        mutate(changed)
        rejected('local stage accepted ' + name,
                 lambda state=changed: verify_local_source_step(
                     stage_case, frozen_state, state, None,
                     copy.deepcopy(frozen_reference), fixture))
        rejected('local archive stage accepted ' + name,
                 lambda state=changed: verify_source_integrity(
                     frozen_state, state, copy.deepcopy(frozen_reference),
                     'local archive stage'))
    commit_case = next(item for item in fixture['cases'] if item['case_id'] == 'local_commit')
    committed_state = copy.deepcopy(frozen_state)
    committed_state['source_scopes'][0].update(
        state='retired', authority_epoch=proof['destination_authority_epoch'],
        scope_generation=proof['destination_scope_generation'],
        old_writes_fenced=True)
    committed_state['source_authority_ledger'].append({
        'operation_kind': 'commit_transfer', 'scope_identity': source_identity,
        'native_transaction_id': 'native-retire',
        'native_proof_id': 'proof-retire',
        'freeze_native_transaction_id': 'native-freeze',
        'source_storage_identity': 'native-source-db',
        'old_writes_fenced': True, 'transaction_fate': 'known_committed'})
    retire_tx = {'native_transaction_id': 'native-retire', 'proof_id': 'proof-retire'}
    retired_reference = copy.deepcopy(frozen_reference)
    verify_local_source_step(commit_case, frozen_state, committed_state,
                             retire_tx, retired_reference, fixture)
    for name, mutate in [
        ('deleted checkpoint', lambda state: state['source_checkpoints'].pop()),
        ('rewritten host journal', lambda state: state['source_host_journals'][0].update(
            root_instance_id='other-root')),
        ('rewritten participant', lambda state: state['source_participants'][0].update(
            participant_id='other-helper')),
        ('rewritten scope inventory', lambda state: state['source_scopes'][0].update(
            inventory_digest='sha256:other')),
    ]:
        changed = copy.deepcopy(committed_state)
        mutate(changed)
        rejected('local commit accepted ' + name,
                 lambda state=changed: verify_local_source_step(
                     commit_case, frozen_state, state, retire_tx,
                     copy.deepcopy(frozen_reference), fixture))
    activate_case = next(item for item in fixture['cases'] if item['case_id'] == 'local_activate')
    verify_local_source_step(activate_case, committed_state, committed_state,
                             None, copy.deepcopy(retired_reference), fixture)
    for name, mutate in [
        ('deleted checkpoint', lambda state: state['source_checkpoints'].pop()),
        ('rewritten participant', lambda state: state['source_participants'][0].update(
            participant_id='other-helper')),
        ('rewritten journal', lambda state: state['source_host_journals'][0].update(
            root_instance_id='other-root')),
        ('rewritten scope inventory', lambda state: state['source_scopes'][0].update(
            inventory_digest='sha256:other')),
    ]:
        changed = copy.deepcopy(committed_state)
        mutate(changed)
        rejected('local activation accepted ' + name,
                 lambda state=changed: verify_local_source_step(
                     activate_case, committed_state, state, None,
                     copy.deepcopy(retired_reference), fixture))
    active_state = copy.deepcopy(frozen_state)
    active_state['source_scopes'][0].update(
        state='active', source_binding_digest=local_archive['source']['ownership_binding_digest'],
        source_profile_digest=local_archive['source']['profile_digest'],
        participant_contract_digest=local_archive['participant_contract']['participant_contract_digest'],
        root_instance_ids=local_archive['selection']['root_instance_ids'],
        authority_token_identity='host-token', topology_identifier='local',
        provider_content_digest='sha256:provider',
        configuration_digest='sha256:configuration',
        inventory_digest=digest({
            'checkpoints': frozen_inventory['source_checkpoints'],
            'host_journals': frozen_inventory['source_host_journals'],
            'participants': frozen_inventory['source_participants'],
            'worker_claims': frozen_inventory['source_worker_claims']}),
        required_participants=[])
    active_state['source_worker_claims'][0]['state'] = 'active'
    active_state['source_scopes'][0]['inventory_digest'] = digest({
        'checkpoints': active_state['source_checkpoints'],
        'host_journals': active_state['source_host_journals'],
        'participants': active_state['source_participants'],
        'worker_claims': active_state['source_worker_claims']})
    phases = []
    def fake_source_native(command, database, run_id, operation_id, phase, *args):
        phases.append(phase)
        return ({}, {}, {}, {'native_transaction_id': 'native-setup'})
    for field, stale in [('authority_epoch', '3'), ('scope_generation', '6')]:
        candidate = copy.deepcopy(active_state)
        candidate['source_scopes'][0][field] = stale
        phases.clear()
        with patch('run_recovery_profile.native_call', side_effect=fake_source_native), \
             patch('run_recovery_profile.store_call', return_value={'state': candidate}):
            rejected('freeze accepted stale actual source ' + field,
                     lambda: run_hosted_source(
                         ['bridge'], Path('/tmp/source.sqlite'), 'source-run',
                         'test-reviewed-bridge', 'sha256:host', 'host-token',
                         'local', 'sha256:provider', 'sha256:configuration', [],
                         local_archive, fixture, plan, in_doubt=False))
        assert phases == ['source_operation'] * len(plan['operations'])
    with tempfile.TemporaryDirectory(prefix='determa-recovery-source-cut-') as temporary:
        database = Path(temporary) / 'source.sqlite'
        initial = {key: [] for key in STATE}
        initial['native_calls'] = {key: 0 for key in CALLS}
        store_call(database, 'source-run', 'init', initial=initial)
        class FalseCut:
            returncode = 0
            stdout = canonical({'status': 'in_doubt'})
            stderr = b''
        with patch('run_recovery_profile.subprocess.run',
                   side_effect=lambda command, **kwargs: original_run(command, **kwargs)
                   if command != ['false-cut'] else FalseCut()):
            rejected('in-doubt source response without owned process cut',
                     lambda: source_fault_cut(['false-cut'], database, 'source-run',
                                              'test-reviewed-bridge', 'sha256:host',
                                              local_archive,
                                              fixture['trusted_transfer_proofs'][0]))
        cut_bridge = Path(temporary) / 'controlled_cut_bridge.py'
        cut_bridge.write_text('''import hashlib, json, subprocess, sys
request = json.load(sys.stdin)
def strict(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def call(kind, **fields):
    payload = {'kind': kind, 'database_path': request['store_database_path'],
               'run_id': request['run_id'], **fields}
    subprocess.run(request['store_command'], input=strict(payload), check=True,
                   stdout=subprocess.PIPE)
operation = request['operation_id']
call('invocation_start', operation_id=operation, phase='source_fault_cut',
     request_digest='sha256:' + hashlib.sha256(strict(request['payload'])).hexdigest(),
     bridge_identity=request['bridge_identity'])
call('source_process_cut', operation_id=operation,
     scope_identity=request['payload']['scope_identity'],
     source_authority_epoch=request['payload']['expected_authority_epoch'],
     source_scope_generation=request['payload']['expected_scope_generation'])
''')
        cut = source_fault_cut([sys.executable, str(cut_bridge)], database,
                                  'source-run', 'test-reviewed-bridge', 'sha256:host',
                                  local_archive, fixture['trusted_transfer_proofs'][0])
        assert store_call(database, 'source-run', 'snapshot')['source_process_cuts'][-1] == cut
        assert cut['scope_identity'] == source_identity and cut['fate'] == 'in_doubt'
    with patch('run_hosted_recovery_profile.verify_delivery_proof_summary',
               side_effect=lambda summary, command: summary):
        rejected('base-only delivery proof used for safe relocation',
                 lambda: observed_binding(['adapter'], ['authority'],
                     {'proved_claims': ['lossless_delivery_controlled_store']}, fixture))
        rejected('effect proof from a different parent run',
                 lambda: observed_binding(['adapter'], ['authority'], {
                     'proved_claims': [
                         'lossless_delivery_controlled_store',
                         'host_authority_worker_sqlite_independent',
                         'five_native_effect_integrations_controlled_store'],
                     'parent_run_id': 'delivery-run',
                     'configured_delivery_profile': {'run_id': 'delivery-run'},
                     'authority_effect_summary': {
                         'parent_run_id': 'unrelated-effect-run', 'authority_summary': {}},
                 }, fixture))
    print('42 normative, 6 real two-root and 4 namespace recovery cases; native echo adversarials passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
