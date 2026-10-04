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
from run_recovery_profile import input_for, run_case, store_call, trusted_bridge
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
            'configured_topology_identifier')}
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
