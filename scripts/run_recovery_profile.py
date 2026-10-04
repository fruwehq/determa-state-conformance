#!/usr/bin/env python3
"""Run §24 requests through a registered production recovery bridge.

Each case uses an isolated native store. The reviewed bridge invokes production
operations; the runner reads persistence outside the child and never seeds a
recovery result record or synthesizes after state.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from validate_portable_archive import ROOT, canonical, digest, parse_json_bytes, read_json
from validate_recovery_profile import CASE, validate_profile

STATE = ('recovery_records', 'scope_allocations', 'namespace_allocations',
         'operation_ledgers', 'checkpoints', 'host_journals', 'participants',
         'worker_claims', 'external_dispatches', 'ingress_acknowledgements',
         'authority_ledger', 'transfer_proofs', 'staged_archives',
         'terminated_scopes', 'source_scopes', 'source_checkpoints',
         'source_host_journals', 'source_participants', 'source_worker_claims',
         'source_authority_ledger')
CALLS = ('core_create', 'core_admit', 'core_step', 'core_migration',
         'effect_dispatch', 'helper_dispatch', 'ingress_acknowledge',
         'provider_evaluate', 'timer_fire', 'authority_commit')
STORE = ROOT / 'scripts/recovery_test_store.py'


def trusted_bridge(command: list[str], registration: Path | None = None) -> str:
    """Verify a runner-selected, reviewed native bridge and installation anchor.

    The child never selects this registration. There is no built-in production
    registration until an implementation supplies one under its trusted CI
    harness, with an independently reviewed bridge and exact installed build.
    """
    if registration is None:
        raise ValueError('production execution unverified: trusted bridge registration missing')
    entry = read_json(registration)
    keys = {'format', 'schema_version', 'command', 'language', 'bridge_root',
            'bridge_source_path', 'bridge_source_sha256', 'installation_root',
            'installation_manifest_path', 'installation_manifest_sha256',
            'production_factory', 'public_stage_entrypoint',
            'public_recovery_entrypoint', 'public_termination_entrypoint',
            'native_observer_entrypoint', 'effective_configuration_digest',
            'dependency_inventory_digest', 'build_anchor_digest',
            'configured_provider_content_digest',
            'configured_authority_token_identity',
            'configured_topology_identifier',
            'source_lifecycle_plan_sha256'}
    if type(entry) is not dict or set(entry) != keys or \
            entry['format'] != 'determa.conformance.recovery.bridge_registration' or \
            type(entry['schema_version']) is not int or entry['schema_version'] != 1 or \
            entry['language'] not in ('python', 'rust') or \
            type(entry['command']) is not list or entry['command'] != command or \
            any(type(part) is not str or not part for part in command) or \
            not all(type(entry[key]) is str and entry[key]
                    for key in keys - {'format', 'schema_version', 'command',
                                       'configured_authority_token_identity',
                                       'configured_topology_identifier',
                                       'source_lifecycle_plan_sha256'}) or \
            any(entry[key] is not None and
                (type(entry[key]) is not str or not entry[key])
                for key in ('configured_authority_token_identity',
                            'configured_topology_identifier',
                            'source_lifecycle_plan_sha256')):
        raise ValueError('production execution unverified: closed bridge registration differs')
    def anchored(root_key: str, path_key: str, hash_key: str) -> Path:
        original_root = Path(entry[root_key])
        root = original_root.resolve()
        relative = Path(entry[path_key])
        if not original_root.is_absolute() or not root.is_dir() or relative.is_absolute() or \
                '..' in relative.parts:
            raise ValueError('production execution unverified: source anchor invalid')
        source = (root / relative).resolve()
        if not source.is_relative_to(root) or not source.is_file() or \
                'sha256:' + sha256(source.read_bytes()).hexdigest() != entry[hash_key]:
            raise ValueError('production execution unverified: source or build drift')
        return source
    bridge = anchored('bridge_root', 'bridge_source_path', 'bridge_source_sha256')
    manifest = anchored('installation_root', 'installation_manifest_path',
                        'installation_manifest_sha256')
    if (entry['language'] == 'python' and
            (len(command) != 4 or command[1:3] != ['-I', '-S'] or
             Path(command[3]).resolve() != bridge or
             Path(command[0]).resolve() != Path(sys.executable).resolve())) or \
            (entry['language'] == 'rust' and
             (len(command) != 1 or Path(command[0]).resolve() != bridge)):
        raise ValueError('production execution unverified: command is not the reviewed bridge')
    installed = read_json(manifest)
    manifest_keys = {'format', 'schema_version', 'language', 'production_factory',
                     'public_stage_entrypoint', 'public_recovery_entrypoint',
                     'public_termination_entrypoint', 'native_observer_entrypoint',
                     'effective_configuration_digest', 'dependency_inventory_digest',
                     'build_anchor_digest', 'source_closure', 'dependency_files',
                     'build_inputs', 'features', 'toolchain',
                     'effective_configuration', 'configured_provider_content_digest',
                     'configured_authority_token_identity',
                     'configured_topology_identifier',
                     'source_lifecycle_plan_sha256'}
    if type(installed) is not dict or set(installed) != manifest_keys or \
            installed['format'] != 'determa.conformance.recovery.installation' or \
            type(installed['schema_version']) is not int or installed['schema_version'] != 1 or \
            any(installed[key] != entry[key] for key in manifest_keys - {
                'format', 'schema_version', 'source_closure', 'dependency_files',
                'build_inputs', 'features', 'toolchain', 'effective_configuration'}) or \
            type(installed['source_closure']) is not list or not installed['source_closure'] or \
            type(installed['dependency_files']) is not list or \
            type(installed['build_inputs']) is not list or \
            type(installed['features']) is not list or \
            any(type(feature) is not str for feature in installed['features']) or \
            installed['features'] != sorted(set(installed['features'])) or \
            type(installed['toolchain']) is not str or not installed['toolchain'] or \
            type(installed['effective_configuration']) is not dict or \
            digest(installed['effective_configuration']) != entry['effective_configuration_digest'] or \
            digest(installed['dependency_files']) != entry['dependency_inventory_digest'] or \
            digest({key: installed[key] for key in ('build_inputs', 'features', 'toolchain')}) != \
            entry['build_anchor_digest']:
        raise ValueError('production execution unverified: installation manifest differs')
    seen = set()
    for category in ('source_closure', 'dependency_files', 'build_inputs'):
        for item in installed[category]:
            if type(item) is not dict or set(item) != {'path', 'sha256'} or \
                    type(item['path']) is not str or type(item['sha256']) is not str or \
                    item['path'] in seen or Path(item['path']).is_absolute() or \
                    '..' in Path(item['path']).parts:
                raise ValueError('production execution unverified: source closure incomplete')
            seen.add(item['path'])
            source = (Path(entry['installation_root']).resolve() / item['path']).resolve()
            if not source.is_relative_to(Path(entry['installation_root']).resolve()) or \
                    not source.is_file() or \
                    'sha256:' + sha256(source.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('production execution unverified: loaded source closure drift')
    return digest(entry)

def store_call(database: Path, run_id: str, kind: str, **fields) -> dict:
    command = [sys.executable, str(STORE)]
    completed = subprocess.run(command, input=canonical({
        'kind': kind, 'database_path': str(database), 'run_id': run_id, **fields}),
        capture_output=True, check=False, timeout=120)
    if completed.returncode:
        raise ValueError('trusted recovery store: ' +
                         completed.stderr.decode('utf-8', 'replace')[:500])
    return parse_json_bytes(completed.stdout, 'trusted recovery store')


def native_call(command: list[str], database: Path, run_id: str, operation_id: str,
                phase: str, payload: dict, expected: dict | None,
                hosted_binding_digest: str | None,
                bridge_identity: str) -> tuple[dict, dict, dict, dict | None]:
    before = store_call(database, run_id, 'snapshot')
    driver_request = {
        'kind': phase, 'operation_id': operation_id, 'run_id': run_id,
        'store_command': [sys.executable, str(STORE)],
        'store_database_path': str(database),
        'store_source_sha256': 'sha256:' + sha256(STORE.read_bytes()).hexdigest(),
        'expected_before_digest': digest(before['state']),
        'payload': payload, 'configured_binding_digest': hosted_binding_digest,
        'bridge_identity': bridge_identity,
    }
    completed = subprocess.run(command, input=canonical(driver_request),
                               capture_output=True, check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{phase}: adapter exited {completed.returncode}: '
                         f'{completed.stderr.decode("utf-8", "replace")[:500]}')
    observed = parse_json_bytes(completed.stdout, phase + ': adapter response')
    fields = ({'result', 'record', 'transfer_proof', 'caller_response_kind',
               'caller_response_body', 'native_evidence'} if phase == 'recovery' else
              {'archive', 'caller_response_kind', 'caller_response_body',
               'native_evidence'} if phase == 'archive_export' else
              {'caller_response_kind', 'caller_response_body', 'native_evidence'})
    if type(observed) is not dict or set(observed) != fields:
        raise ValueError(phase + ': incomplete literal production response')
    if expected is None:
        body = observed['caller_response_body']
        if type(body) is not dict or body.get('status') not in (
                'succeeded', 'accepted', 'frozen', 'exported'):
            raise ValueError(phase + ': actual source operation did not succeed')
    else:
        equal(observed['caller_response_body'], expected, phase + ': literal caller body')
    expected_kind = ('archive_result' if phase == 'archive_stage' else
                     'scope_termination_result' if phase == 'scope_terminate' else
                     'recovery_result' if phase == 'recovery' else
                     'archive_export_result' if phase == 'archive_export' else
                     'source_result')
    if observed['caller_response_kind'] != expected_kind:
        raise ValueError(phase + ': literal caller response kind')
    after = store_call(database, run_id, 'snapshot')
    invocations = after['invocations'][len(before['invocations']):]
    if invocations != [{
            'operation_id': operation_id, 'phase': phase,
            'request_digest': digest(payload), 'bridge_identity': bridge_identity,
            'response_digest': digest(observed['caller_response_body']),
            'outcome': 'returned'}]:
        raise ValueError(phase + ': reviewed bridge did not journal actual public invocation')
    transactions = after['transactions'][len(before['transactions']):]
    changed = canonical(before['state']) != canonical(after['state'])
    if changed != (len(transactions) == 1) or len(transactions) > 1:
        raise ValueError(phase + ': native store change lacks exactly one atomic commit')
    if changed:
        transaction = transactions[0]
        if transaction['operation_id'] != operation_id or transaction['phase'] != phase or \
                transaction['request_digest'] != digest(payload) or \
                transaction['response_digest'] != digest(observed['caller_response_body']) or \
                transaction['before_digest'] != digest(before['state']) or \
                transaction['after_digest'] != digest(after['state']) or \
                observed['native_evidence'] != {
                    'native_transaction_id': transaction['native_transaction_id'],
                    'proof_id': transaction['proof_id']}:
            raise ValueError(phase + ': native transaction differs from response or exact input')
    elif observed['native_evidence'] is not None:
        raise ValueError(phase + ': response invented a native commit')
    return observed, before['state'], after['state'], transactions[0] if transactions else None


def equal(actual, expected, label: str) -> None:
    if canonical(actual) != canonical(expected):
        raise ValueError(label + ': complete canonical bytes differ')


def input_for(case: dict, fixture: dict) -> dict:
    local = case.get('configured_profile') == 'proved_local_same_authority'
    owned = case.get('archive_kind') == 'owned'
    archive = read_json(CASE / 'recovery-two-root-archive-v1.json') if owned else (
        read_json(CASE / 'archive-local-transfer-v1.json') if local else read_json(
        ROOT / 'conformance/profiles/portable-archive/archive-01-complete-snapshot/archive-v1.json')
    )
    stage_fixture = read_json(ROOT /
        'conformance/profiles/portable-archive/archive-01-complete-snapshot/stage-cases-v1.json')
    ordinary_stage = next(item for item in stage_fixture['cases']
                          if item['case_id'] == 'complete_embedded_snapshot')
    missing_helper = case['case_id'] == 'required_helper_missing'
    if missing_helper:
        negative = next(item for item in stage_fixture['cases']
                        if item['case_id'] == 'resealed_omitted_required_participant')
        stage_request = dict(negative['input_request'])
        stage_request['staging_identity'] = case['request']['arguments']['staging_identity']
        stage_archive = negative['input_archive']
        stage_configuration = negative['configured_import']
    else:
        stage_request = (fixture['owned_stage_request'] if owned else
                         fixture['local_transfer_stage_request'] if local else ordinary_stage['input_request'])
        stage_archive = archive
        stage_configuration = (fixture['owned_stage_configuration'] if owned else
                               fixture['local_transfer_stage_configuration'] if local else ordinary_stage['configured_import'])
    by_id = {item['case_id']: item for item in fixture['cases']}
    record_producers = {
        'strict_quarantine': ['strict_quarantine'],
        'standalone_inactive': ['standalone_takeover'],
        'standalone_resumed': ['standalone_takeover', 'standalone_resume'],
        'standalone_reconciled': ['standalone_takeover', 'standalone_resume',
                                  'abandon_ambiguous_with_evidence'],
        'clone_inactive': ['clone_scope'],
        'clone_resolved': ['clone_scope', 'clone_cancel_pending'],
        'clone_active': ['clone_scope', 'clone_cancel_pending', 'clone_activate'],
        'local_transfer_staged': ['local_prepare', 'local_stage'],
        'local_transfer_active': ['local_prepare', 'local_stage', 'local_commit',
                                  'local_activate'],
    }
    prior = case.get('prior_record')
    def lineage(name: str) -> list[str]:
        previous = by_id[name].get('prior_record')
        if previous in record_producers:
            return [*record_producers[previous], name]
        if previous in by_id:
            return [*lineage(previous), name]
        return [name]
    if prior in record_producers:
        setup_names = record_producers[prior]
    elif prior in by_id:
        setup_names = lineage(prior)
    elif prior is None:
        setup_names = []
    else:
        raise ValueError('unknown prior recovery lifecycle')
    # An equal replay must first execute the exact same request in this isolated host.
    if case['case_id'] == 'standalone_equal_replay':
        setup_names = ['standalone_takeover']
    result = {
        'request': case.get('request', case.get('input')),
        'source_archive': archive,
        'stage_archive': stage_archive,
        'stage_request': stage_request,
        'stage_configuration': stage_configuration,
        'setup_requests': [by_id[name]['request'] for name in setup_names],
    }
    return result


SOURCE_OPERATIONS = ('configure_scope', 'allocate_scope', 'create_root',
                     'admit_event', 'step_root', 'append_host_journal',
                     'claim_worker')


def validate_source_plan(plan: dict, archive: dict) -> None:
    if type(plan) is not dict or set(plan) != {
            'format', 'schema_version', 'source_scope_identity',
            'root_instance_ids', 'operations'} or \
            plan['format'] != 'determa.conformance.recovery.source_lifecycle' or \
            type(plan['schema_version']) is not int or plan['schema_version'] != 1 or \
            plan['source_scope_identity'] != archive['source']['logical_scope_identity'] or \
            plan['root_instance_ids'] != archive['selection']['root_instance_ids'] or \
            type(plan['operations']) is not list:
        raise ValueError('hosted source lifecycle plan is incomplete or for another scope')
    operations = plan['operations']
    names = []
    created = []
    for item in operations:
        if type(item) is not dict or set(item) != {
                'operation', 'root_instance_id', 'arguments'} or \
                item['operation'] not in SOURCE_OPERATIONS or \
                type(item['arguments']) is not dict or \
                any(key in item['arguments'] for key in (
                    'checkpoint', 'checkpoints', 'archive', 'record', 'records',
                    'source_capture', 'expected_result', 'expected_after')):
            raise ValueError('source plan must contain actual lifecycle requests, never seeded state')
        root_id = item['root_instance_id']
        if root_id is not None and root_id not in plan['root_instance_ids']:
            raise ValueError('source lifecycle step names an unselected instance')
        if item['operation'] in ('create_root', 'admit_event', 'step_root') and root_id is None:
            raise ValueError('source root operation lacks a native instance identity')
        names.append(item['operation'])
        if item['operation'] == 'create_root':
            created.append(root_id)
    if created != plan['root_instance_ids'] or \
            not {'configure_scope', 'allocate_scope', 'admit_event', 'step_root',
                 'append_host_journal', 'claim_worker'}.issubset(names):
        raise ValueError('source lifecycle lacks create/admit/step/journal/worker coverage')


def source_scope(state: dict, scope_identity: str) -> dict:
    matches = [item for item in state['source_scopes']
               if type(item) is dict and item.get('scope_identity') == scope_identity]
    if len(matches) != 1:
        raise ValueError('actual native source scope is absent or duplicated')
    return matches[0]


def source_fault_cut(command: list[str], database: Path, run_id: str,
                     bridge_identity: str, binding: str, archive: dict,
                     proof: dict) -> dict:
    before = store_call(database, run_id, 'snapshot')
    operation_id = str(uuid.uuid4())
    payload = {'scope_identity': archive['source']['logical_scope_identity'],
               'expected_authority_epoch': proof['source_authority_epoch'],
               'expected_scope_generation': proof['source_scope_generation'],
               'fault_injection': 'native_source_transaction_before_fate'}
    child = subprocess.run(command, input=canonical({
        'kind': 'source_fault_cut', 'operation_id': operation_id,
        'run_id': run_id, 'store_command': [sys.executable, str(STORE)],
        'store_database_path': str(database),
        'store_source_sha256': 'sha256:' + sha256(STORE.read_bytes()).hexdigest(),
        'expected_before_digest': digest(before['state']), 'payload': payload,
        'configured_binding_digest': binding, 'bridge_identity': bridge_identity}),
        capture_output=True, check=False, timeout=120)
    after = store_call(database, run_id, 'snapshot')
    cuts = after['source_process_cuts'][len(before['source_process_cuts']):]
    invocations = after['invocations'][len(before['invocations']):]
    if child.returncode != -signal.SIGKILL or child.stdout or \
            after['state'] != before['state'] or \
            after['transactions'] != before['transactions'] or \
            len(cuts) != 1 or \
            any(cuts[0].get(key) != value for key, value in {
                'operation_id': operation_id,
                'scope_identity': payload['scope_identity'],
                'source_authority_epoch': proof['source_authority_epoch'],
                'source_scope_generation': proof['source_scope_generation'],
                'fate': 'in_doubt'}.items()) or \
            not cuts[0].get('native_transaction_id') or \
            cuts[0].get('attempt_proof_id') != digest([
                'determa-recovery-source-cut-1', run_id, operation_id,
                cuts[0]['native_transaction_id'], payload['scope_identity'],
                proof['source_authority_epoch'], proof['source_scope_generation']]) or \
            invocations != [{'operation_id': operation_id,
                             'phase': 'source_fault_cut',
                             'request_digest': digest(payload),
                             'bridge_identity': bridge_identity,
                             'response_digest': None, 'outcome': None}]:
        raise ValueError('source in-doubt fate lacks a controlled native process cut')
    return cuts[0]


def run_hosted_source(command: list[str], database: Path, run_id: str,
                     bridge_identity: str, binding: str, token: str,
                     topology: str, provider_digest: str, config_digest: str,
                     required_participants: list[dict], archive: dict,
                     fixture: dict, plan: dict,
                      *, in_doubt: bool) -> dict:
    validate_source_plan(plan, archive)
    source_identity = archive['source']['logical_scope_identity']
    definitions = archive['normalized_definitions']
    for step in plan['operations']:
        payload = {'source_scope_identity': source_identity, 'step': step,
                   'normalized_definitions': definitions if step['operation'] == 'create_root' else None}
        _, _, _, transaction = native_call(
            command, database, run_id, str(uuid.uuid4()), 'source_operation',
            payload, None, binding, bridge_identity)
        if transaction is None:
            raise ValueError('actual production source lifecycle step did not commit')
    before_freeze = store_call(database, run_id, 'snapshot')['state']
    source = source_scope(before_freeze, source_identity)
    proof = fixture['trusted_transfer_proofs'][0]
    required = {'scope_identity': source_identity,
                'source_binding_digest': archive['source']['ownership_binding_digest'],
                'source_profile_digest': archive['source']['profile_digest'],
                'participant_contract_digest':
                archive['participant_contract']['participant_contract_digest'],
                'root_instance_ids': archive['selection']['root_instance_ids'],
                'state': 'active', 'authority_token_identity': token,
                'topology_identifier': topology,
                'provider_content_digest': provider_digest,
                'configuration_digest': config_digest,
                'required_participants': required_participants,
                'storage_identity': str(database)}
    source_inventory_digest = digest({
        'checkpoints': before_freeze['source_checkpoints'],
        'host_journals': before_freeze['source_host_journals'],
        'participants': before_freeze['source_participants'],
        'worker_claims': before_freeze['source_worker_claims']})
    if any(source.get(key) != value for key, value in required.items()) or \
            source.get('authority_epoch') != proof['source_authority_epoch'] or \
            source.get('scope_generation') != proof['source_scope_generation'] or \
            not source.get('native_instance_identity') or \
            source.get('complete_scope_inventory') is not True or \
            source.get('inventory_digest') != source_inventory_digest or \
            before_freeze['source_checkpoints'] != archive['checkpoints'] or \
            before_freeze['source_participants'] != archive['participants'] or \
            not before_freeze['source_host_journals'] or \
            any(type(item) is not dict or
                item.get('root_instance_id') not in plan['root_instance_ids']
                for item in before_freeze['source_host_journals']) or \
            {item['root_instance_id'] for item in before_freeze['source_host_journals']} != \
            set(plan['root_instance_ids']) or \
            not any(type(claim) is dict and claim.get('scope_identity') == source_identity and
                    claim.get('state') == 'active'
                    for claim in before_freeze['source_worker_claims']):
        raise ValueError('hosted local transfer lacks a live complete native source inventory')
    freeze_payload = {'scope_identity': source_identity,
                      'operation_id': archive['source_fence_reference']['operation_id'],
                      'expected_authority_epoch': proof['source_authority_epoch'],
                      'expected_scope_generation': proof['source_scope_generation'],
                      'inventory_digest': source_inventory_digest}
    freeze_response, _, frozen, freeze_tx = native_call(
        command, database, run_id, str(uuid.uuid4()), 'source_freeze',
        freeze_payload, None, binding, bridge_identity)
    frozen_scope = source_scope(frozen, source_identity)
    if freeze_tx is None or \
            digest(freeze_response['caller_response_body']) != \
            archive['source_fence_reference']['response_digest'] or \
            frozen_scope.get('state') != 'frozen' or \
            any(frozen_scope.get(key) != value for key, value in required.items()
                if key != 'state') or \
            frozen_scope.get('complete_scope_inventory') is not True or \
            frozen_scope.get('inventory_digest') != source_inventory_digest or \
            frozen_scope.get('authority_epoch') != proof['source_authority_epoch'] or \
            frozen_scope.get('scope_generation') != proof['source_scope_generation'] or \
            frozen['source_checkpoints'] != before_freeze['source_checkpoints'] or \
            frozen['source_host_journals'] != before_freeze['source_host_journals'] or \
            frozen['source_participants'] != before_freeze['source_participants'] or \
            any(type(claim) is dict and claim.get('scope_identity') == source_identity and
                claim.get('state') == 'active' for claim in frozen['source_worker_claims']):
        raise ValueError('source freeze did not atomically retain inventory and revoke writers')
    matching = [entry for entry in frozen['source_authority_ledger']
                if type(entry) is dict and all(entry.get(key) == value for key, value in {
                    'operation_kind': 'freeze_scope',
                    'operation_id': archive['source_fence_reference']['operation_id'],
                    'scope_identity': source_identity,
                    'native_transaction_id': freeze_tx['native_transaction_id'],
                    'native_proof_id': freeze_tx['proof_id'],
                    'freeze_evidence_digest': proof['freeze_evidence_digest'],
                    'authority_epoch': proof['source_authority_epoch'],
                    'scope_generation': proof['source_scope_generation'],
                    'inventory_digest': freeze_payload['inventory_digest'],
                    'transaction_fate': 'known_committed',
                    'claims_revoked': True,
                }.items())]
    if len(matching) != 1:
        raise ValueError('prepare has no preexisting retained native freeze proof')
    export_request = {
        'request_format': 'determa.archive_export_request',
        'request_schema_version': 1, 'source': archive['source'],
        'root_instance_ids': archive['selection']['root_instance_ids'],
        'required_participant_ids': archive['participant_contract']['required_participant_ids'],
        'optional_participant_ids': archive['participant_contract']['optional_participant_ids'],
        'consistency_token': archive['selection']['consistency_token']}
    before_export = store_call(database, run_id, 'snapshot')
    export_operation_id = str(uuid.uuid4())
    exported, export_before, after_export, export_tx = native_call(
        command, database, run_id, export_operation_id, 'archive_export',
        {'request': export_request, 'source_scope_identity': source_identity},
        None, binding, bridge_identity)
    after_export_observation = store_call(database, run_id, 'snapshot')
    if before_export['source_exports'] or \
            exported['archive'] != archive or export_tx is not None or \
            export_before != after_export or \
            after_export_observation['source_exports'] != [{
                'operation_id': export_operation_id,
                'archive': archive,
                'source_scope_identity': source_identity,
                'freeze_native_transaction_id': freeze_tx['native_transaction_id'],
                'inventory_digest': freeze_payload['inventory_digest'],
                'storage_identity': str(database)}]:
        raise ValueError('actual I1 export did not capture this frozen native source')
    cut_id = (source_fault_cut(command, database, run_id, bridge_identity,
                               binding, archive, proof) if in_doubt else None)
    return {'scope_identity': source_identity,
            'native_instance_identity': source['native_instance_identity'],
            'storage_identity': str(database),
            'frozen_source_scope': frozen_scope,
            'frozen_inventory': {key: frozen[key] for key in (
                'source_checkpoints', 'source_host_journals',
                'source_participants', 'source_worker_claims')},
            'source_authority_ledger': frozen['source_authority_ledger'],
            'freeze_native_transaction_id': freeze_tx['native_transaction_id'],
            'freeze_native_proof_id': freeze_tx['proof_id'],
            'export_observation_id': export_operation_id,
            'source_fault_cut': cut_id}


def verify_source_integrity(before: dict, after: dict, source_reference: dict,
                            label: str, *, retiring: bool = False,
                            expected_epoch: str | None = None,
                            expected_generation: str | None = None,
                            expected_transfer_id: str | None = None) -> None:
    """Keep the actual frozen source bytes fixed across all import phases."""
    baseline = source_reference.get('retired_source_scope',
                                    source_reference['frozen_source_scope'])
    prior_ledger = source_reference['source_authority_ledger']
    source_before = source_scope(before, source_reference['scope_identity'])
    source_after = source_scope(after, source_reference['scope_identity'])
    if source_before != baseline or \
            before['source_authority_ledger'] != prior_ledger:
        raise ValueError(label + ': source changed before the recovery operation')
    for state in (before, after):
        if any(state[key] != value for key, value in
               source_reference['frozen_inventory'].items()) or \
                any(type(claim) is dict and
                    claim.get('scope_identity') == source_reference['scope_identity'] and
                    claim.get('state') == 'active'
                    for claim in state['source_worker_claims']):
            raise ValueError(label + ': frozen source inventory or claims changed')
    if not retiring:
        if source_after != baseline or \
                after['source_authority_ledger'] != prior_ledger:
            raise ValueError(label + ': recovery mutated the frozen source')
        return
    allowed = {'state', 'authority_epoch', 'scope_generation',
               'active_transfer_id', 'old_writes_fenced'}
    if set(source_after) - set(source_before) - allowed or \
            set(source_before) - set(source_after) or \
            any(source_after.get(key) != value for key, value in source_before.items()
                if key not in allowed) or \
            source_after.get('state') != 'retired' or \
            source_after.get('authority_epoch') != expected_epoch or \
            source_after.get('scope_generation') != expected_generation or \
            source_after.get('active_transfer_id') != expected_transfer_id or \
            source_after.get('old_writes_fenced') is not True or \
            after['source_authority_ledger'][:-1] != prior_ledger or \
            len(after['source_authority_ledger']) != len(prior_ledger) + 1:
        raise ValueError(label + ': retirement changed source bytes beyond authority transition')
    source_reference['retired_source_scope'] = source_after
    source_reference['source_authority_ledger'] = after['source_authority_ledger']


def public_source_reference(source_reference: dict) -> dict:
    """Expose source proof identities, never the runner's comparison snapshots."""
    return {key: source_reference[key] for key in (
        'scope_identity', 'native_instance_identity', 'storage_identity',
        'freeze_native_transaction_id', 'freeze_native_proof_id',
        'export_observation_id', 'source_fault_cut')}


def verify_local_source_step(case: dict, before: dict, after: dict,
                             transaction: dict | None, source_reference: dict,
                             fixture: dict) -> None:
    label = case['case_id']
    operation = case['request']['operation']
    source_before = source_scope(before, source_reference['scope_identity'])
    source_after = source_scope(after, source_reference['scope_identity'])
    if source_before.get('storage_identity') != source_reference['storage_identity'] or \
            source_after.get('storage_identity') != source_reference['storage_identity'] or \
            source_before.get('native_instance_identity') != \
            source_reference['native_instance_identity'] or \
            source_after.get('native_instance_identity') != \
            source_reference['native_instance_identity']:
        raise ValueError(label + ': recovery moved to an unproved source instance or store')
    freeze = fixture['trusted_transfer_proofs'][0]
    retained = [entry for entry in before['source_authority_ledger']
                if type(entry) is dict and
                entry.get('operation_kind') == 'freeze_scope' and
                entry.get('scope_identity') == source_reference['scope_identity'] and
                entry.get('native_transaction_id') ==
                source_reference['freeze_native_transaction_id'] and
                entry.get('native_proof_id') == source_reference['freeze_native_proof_id'] and
                entry.get('freeze_evidence_digest') == freeze['freeze_evidence_digest'] and
                entry.get('transaction_fate') == 'known_committed']
    if len(retained) != 1:
        raise ValueError(label + ': source freeze was not retained before recovery operation')
    prepared_reference = source_reference.get('prepared_authority_entry')
    if prepared_reference is not None and \
            (prepared_reference not in before['authority_ledger'] or
             prepared_reference not in after['authority_ledger']):
        raise ValueError(label + ': retained destination reservation changed')
    retiring = operation == 'commit_transfer' and \
        case['expected_result']['status'] == 'succeeded'
    transfer = case.get('expected_transfer_proof') if retiring else None
    verify_source_integrity(
        before, after, source_reference, label, retiring=retiring,
        expected_epoch=transfer['destination_authority_epoch'] if transfer else None,
        expected_generation=transfer['destination_scope_generation'] if transfer else None,
        expected_transfer_id=transfer['transfer_id'] if transfer else None)
    if source_reference['source_fault_cut'] is not None:
        if label != 'local_in_doubt_source' or operation != 'prepare_transfer' or \
                case['expected_result']['code'] != 'scope_transaction_in_doubt' or \
                transaction is not None or after != before:
            raise ValueError(label + ': unknown source transaction was promoted or changed')
        return
    if operation in ('prepare_transfer', 'stage_transfer') and \
            (source_before.get('state') != 'frozen' or
             source_after.get('state') != 'frozen'):
        raise ValueError(label + ': prepare or stage lacks the actual frozen source')
    if operation == 'prepare_transfer' and case['expected_result']['status'] == 'succeeded':
        proof = case['expected_transfer_proof']
        prepared = [item for item in after['authority_ledger']
                    if type(item) is dict and
                    item not in before['authority_ledger'] and
                    all(item.get(key) == value for key, value in {
                    'operation_kind': 'prepare_transfer',
                    'scope_identity': source_reference['scope_identity'],
                    'transfer_id': proof['transfer_id'],
                    'destination_scope_identity':
                    case['request']['destination_scope_identity'],
                    'destination_binding_digest': proof['destination_binding_digest'],
                    'source_binding_digest': proof['source_binding_digest'],
                    'authority_token_identity':
                    source_reference['frozen_source_scope']['authority_token_identity'],
                    'grant_state': 'reserved',
                    'transfer_proof_digest': proof['proof_digest'],
                    'source_storage_identity': source_reference['storage_identity'],
                    'source_native_instance_identity':
                    source_reference['native_instance_identity'],
                    'freeze_native_transaction_id':
                    source_reference['freeze_native_transaction_id'],
                    'freeze_native_proof_id': source_reference['freeze_native_proof_id'],
                    'native_transaction_id': transaction['native_transaction_id'],
                    'native_proof_id': transaction['proof_id'],
                    'transaction_fate': 'known_committed',
                }.items())] if transaction is not None else []
        if len(prepared) != 1:
            raise ValueError(label + ': prepared transfer lacks native source-bound transaction')
        source_reference['prepared_authority_entry'] = prepared[0]
    if operation == 'commit_transfer' and case['expected_result']['status'] == 'succeeded':
        proof = case['expected_transfer_proof']
        request = case['request']
        destination = request['destination_scope_identity']
        binding = request['arguments']['destination_binding_digest']
        prepared = request['arguments']['prepared_proof_digest']
        staged = request['arguments']['staged_record_digest']
        source_token = source_reference['frozen_source_scope']['authority_token_identity']
        prepared_entries = [item for item in before['authority_ledger']
            if type(item) is dict and all(item.get(key) == value for key, value in {
                'operation_kind': 'prepare_transfer',
                'scope_identity': source_reference['scope_identity'],
                'transfer_id': proof['transfer_id'],
                'destination_scope_identity': destination,
                'destination_binding_digest': binding,
                'source_binding_digest': proof['source_binding_digest'],
                'authority_token_identity': source_token,
                'source_storage_identity': source_reference['storage_identity'],
                'source_native_instance_identity':
                    source_reference['native_instance_identity'],
                'transfer_proof_digest': prepared,
                'grant_state': 'reserved',
            }.items())]
        reserved_entries = [item for item in before['authority_ledger']
                            if type(item) is dict and
                            item.get('operation_kind') == 'prepare_transfer' and
                            item.get('scope_identity') == source_reference['scope_identity'] and
                            item.get('grant_state') == 'reserved']
        staged_entries = [item for item in before['recovery_records']
                          if type(item) is dict and
                          item.get('mode') == 'relocation' and
                          item.get('source', {}).get('logical_scope_identity') ==
                          source_reference['scope_identity']]
        retirement_binding = {
            'operation_kind': 'commit_transfer',
            'operation_id': request['operation_id'],
            'scope_identity': source_reference['scope_identity'],
            'source_native_instance_identity':
            source_reference['native_instance_identity'],
            'source_storage_identity': source_reference['storage_identity'],
            'authority_token_identity': source_token,
            'transfer_id': proof['transfer_id'],
            'destination_scope_identity': destination,
            'destination_binding_digest': binding,
            'source_binding_digest': proof['source_binding_digest'],
            'prepared_proof_digest': prepared,
            'staged_record_digest': staged,
            'committed_proof_digest': proof['proof_digest'],
            'archive_digest': proof['archive_digest'],
            'participant_contract_digest': proof['participant_contract_digest'],
            'grant_state': 'consumed',
            'destination_authority_epoch': proof['destination_authority_epoch'],
            'destination_scope_generation': proof['destination_scope_generation'],
            'native_transaction_id': transaction['native_transaction_id'] if transaction else None,
            'native_proof_id': transaction['proof_id'] if transaction else None,
            'freeze_native_transaction_id':
            source_reference['freeze_native_transaction_id'],
            'old_writes_fenced': True,
            'transaction_fate': 'known_committed',
        }
        source_ledger = after['source_authority_ledger']
        destination_entries = [item for item in after['authority_ledger']
                               if type(item) is dict and
                               all(item.get(key) == value for key, value in
                                   retirement_binding.items())]
        newly_consumed = [item for item in after['authority_ledger']
                          if item not in before['authority_ledger'] and
                          type(item) is dict and item.get('grant_state') == 'consumed']
        if transaction is None or source_before.get('state') != 'frozen' or \
                source_after.get('state') != 'retired' or \
                len(prepared_entries) != 1 or \
                prepared_entries[0] != prepared_reference or \
                reserved_entries != prepared_entries or \
                len(staged_entries) != 1 or \
                staged_entries[0].get('destination_scope_identity') != destination or \
                staged_entries[0].get('destination_binding_digest') != binding or \
                digest(['determa-recovery-record-1', staged_entries[0]]) != staged or \
                request['arguments']['transfer_id'] != proof['transfer_id'] or \
                binding != proof['destination_binding_digest'] or \
                source_ledger[-1] in before['source_authority_ledger'] or \
                not all(source_ledger[-1].get(key) == value for key, value in
                        retirement_binding.items()) or \
                len(destination_entries) != 1 or \
                newly_consumed != destination_entries or \
                destination_entries[0] in before['authority_ledger'] or \
                any(type(item) is dict and
                    item.get('scope_identity') == source_reference['scope_identity'] and
                    item.get('grant_state') == 'consumed'
                    for item in before['source_authority_ledger']):
            raise ValueError(label + ': old owner retirement was not native and atomic')
        if any(type(claim) is dict and claim.get('scope_identity') ==
               source_reference['scope_identity'] and claim.get('state') == 'active'
               for claim in after['source_worker_claims']):
            raise ValueError(label + ': old source writer survived retirement')
    elif operation in ('activate_import', 'guarded_action') and \
            (source_before.get('state') != 'retired' or
             source_after.get('state') != 'retired'):
        raise ValueError(label + ': destination action lacks retired source owner')
    elif case['expected_result']['status'] == 'refused' and after != before:
        raise ValueError(label + ': refused local operation changed source storage')


def run_case(command: list[str], case: dict, fixture: dict,
             *, hosted_binding_digest: str | None = None,
             hosted_authority_token_identity: str | None = None,
             bridge_registration: Path | None = None,
             expected_bridge_identity: str | None = None,
             hosted_source_plan: dict | None = None,
             hosted_source_binding: dict | None = None) -> None:
    label = case['case_id']
    bridge_identity = trusted_bridge(command, bridge_registration)
    if expected_bridge_identity is not None and bridge_identity != expected_bridge_identity:
        raise ValueError(label + ': reviewed bridge installation changed during profile')
    request = input_for(case, fixture)
    stage_fixture = read_json(ROOT /
        'conformance/profiles/portable-archive/archive-01-complete-snapshot/stage-cases-v1.json')
    if label == 'required_helper_missing':
        stage_expected = next(item['expected_result'] for item in stage_fixture['cases']
                              if item['case_id'] == 'resealed_omitted_required_participant')
    elif case.get('archive_kind') == 'owned':
        stage_expected = fixture['owned_stage_result']
    elif case.get('configured_profile') == 'proved_local_same_authority':
        stage_expected = fixture['local_transfer_stage_result']
    else:
        stage_expected = fixture['stage_receipt']
    if hosted_binding_digest is not None and not hosted_authority_token_identity:
        raise ValueError(label + ': configured native authority token identity missing')
    with tempfile.TemporaryDirectory(prefix='determa-recovery-native-') as temporary:
        database = Path(temporary) / 'recovery.sqlite'
        run_id = str(uuid.uuid4())
        initial = {key: [] for key in STATE}
        initial['native_calls'] = {key: 0 for key in CALLS}
        store_call(database, run_id, 'init', initial=initial)
        local = case.get('configured_profile') == 'proved_local_same_authority'
        if local and (hosted_source_plan is None or hosted_source_binding is None or
                      hosted_binding_digest is None):
            raise ValueError(label + ': actual hosted source lifecycle proof is required')
        source_reference = (run_hosted_source(
            command, database, run_id, bridge_identity, hosted_binding_digest,
            hosted_authority_token_identity,
            hosted_source_binding['topology_identifier'],
            hosted_source_binding['provider_content_digest'],
            hosted_source_binding['configuration_digest'],
            hosted_source_binding['required_participants'],
            request['source_archive'], fixture, hosted_source_plan,
            in_doubt=label == 'local_in_doubt_source') if local else None)
        source_request_reference = public_source_reference(source_reference) if local else None
        stage_payload = {key: request[key] for key in
                         ('source_archive', 'stage_archive', 'stage_request', 'stage_configuration')}
        if local:
            stage_payload['source_reference'] = source_request_reference
        stage_response, stage_before, stage_after, _ = native_call(
            command, database, run_id, str(uuid.uuid4()), 'archive_stage',
            stage_payload, stage_expected, hosted_binding_digest, bridge_identity)
        if local:
            verify_source_integrity(stage_before, stage_after, source_reference,
                                    label + ': archive stage')
        stage = {'staging_identity': request['stage_request']['staging_identity'],
                 'archive': request['stage_archive']}
        if stage_expected['status'] == 'staged':
            if stage_after['staged_archives'] != [stage] or \
                    stage_before['staged_archives'] != [] or \
                    {key: value for key, value in stage_after.items() if key != 'staged_archives'} != \
                    {key: value for key, value in stage_before.items() if key != 'staged_archives'}:
                raise ValueError(label + ': actual I1 stage did not persist exact archive')
        elif stage_after != stage_before:
            raise ValueError(label + ': refused I1 stage changed native storage')
        by_request = {canonical(item['request']): item for item in fixture['cases']}
        for setup_request in request['setup_requests']:
            setup_case = by_request.get(canonical(setup_request))
            if setup_case is None:
                raise ValueError(label + ': unknown setup recovery request')
            setup_payload = {'request': setup_request,
                             'source_archive': request['source_archive']}
            if local:
                setup_payload['source_reference'] = source_request_reference
            setup_observed, setup_before, setup_after, setup_tx = native_call(
                command, database, run_id, str(uuid.uuid4()), 'recovery',
                setup_payload,
                setup_case['expected_result'], hosted_binding_digest, bridge_identity)
            equal(setup_observed['result'], setup_case['expected_result'],
                  label + ': actual setup response')
            equal(setup_observed['record'], setup_case.get('expected_record'),
                  label + ': actual setup record')
            equal(setup_observed['transfer_proof'],
                  setup_case.get('expected_transfer_proof'),
                  label + ': actual setup transfer proof')
            if local:
                verify_local_source_step(setup_case, setup_before, setup_after,
                                         setup_tx, source_reference, fixture)
        if case.get('terminated_setup_scope'):
            scope = fixture['records']['standalone_inactive']['record']['destination_scope_identity']
            _, termination_before, termination_after, _ = native_call(
                command, database, run_id, str(uuid.uuid4()), 'scope_terminate',
                {'scope_identity': scope},
                {'status': 'terminated', 'scope_identity': scope},
                hosted_binding_digest, bridge_identity)
            if termination_before['namespace_allocations'] != \
                    termination_after['namespace_allocations'] or \
                    scope not in termination_after['terminated_scopes'] or \
                    scope not in termination_after['scope_allocations']:
                raise ValueError(label + ': scope termination lost permanent identity allocation')
        expected = case['expected_result']
        tested_payload = {'request': request['request'],
                          'source_archive': request['source_archive']}
        if local:
            tested_payload['source_reference'] = source_request_reference
        response, before, after, recovery_transaction = native_call(
            command, database, run_id, str(uuid.uuid4()), 'recovery',
            tested_payload,
            expected, hosted_binding_digest, bridge_identity)
        if local:
            verify_local_source_step(case, before, after, recovery_transaction,
                                     source_reference, fixture)
    equal(response['result'], expected, label + ': result')
    equal(response['record'], case.get('expected_record'), label + ': record')
    equal(response['transfer_proof'], case.get('expected_transfer_proof'),
          label + ': transfer proof')
    if not isinstance(before, dict) or not isinstance(after, dict) or \
            set(before) != set(STATE) | {'native_calls'} or \
            set(after) != set(STATE) | {'native_calls'}:
        raise ValueError(label + ': incomplete independent native host observations')
    for item in (before, after):
        if any(type(item[key]) is not list for key in STATE) or \
                type(item['native_calls']) is not dict or \
                set(item['native_calls']) != set(CALLS) or \
                any(type(count) is not int or count < 0
                    for count in item['native_calls'].values()):
            raise ValueError(label + ': invalid native store state or call journal')
    if stage_expected['status'] == 'staged' and \
            (stage not in before['staged_archives'] or
             stage not in after['staged_archives']):
        raise ValueError(label + ': staged archive vanished from native store')
    if request['setup_requests']:
        latest = by_request[canonical(request['setup_requests'][-1])]
        if latest.get('expected_record') is not None and \
                latest['expected_record'] not in before['recovery_records']:
            raise ValueError(label + ': setup lifecycle record absent from native store')
    calls = {key: after['native_calls'][key] - before['native_calls'][key]
             for key in CALLS}
    if any(value < 0 for value in calls.values()):
        raise ValueError(label + ': native call journal regressed')
    if any(calls[key] for key in ('core_create', 'core_admit', 'core_step',
                                  'core_migration', 'effect_dispatch', 'helper_dispatch',
                                  'ingress_acknowledge', 'provider_evaluate', 'timer_fire')):
        raise ValueError(label + ': recovery invoked active processing or external work')
    for key in ('external_dispatches', 'ingress_acknowledgements'):
        equal(after[key], before[key], label + ': recovery changed external work')
    from validate_portable_archive import changed_paths
    actual_paths = sorted(changed_paths(before, after))
    if expected['status'] == 'refused' or case.get('request', {}).get('operation') == 'guarded_action' or label == 'standalone_equal_replay':
        equal(after, before, label + ': read or refusal changed storage')
        if any(calls.values()):
            raise ValueError(label + ': read or refusal called a mutating operation')
    elif response['record'] is not None:
        records = after['recovery_records']
        if not isinstance(records, list) or response['record'] not in records:
            raise ValueError(label + ': complete record absent from observed durable storage')
        if not actual_paths:
            raise ValueError(label + ': successful mutation has no observed storage change')
        record = response['record']
        if (case.get('request', {}).get('operation') in ('standalone_takeover', 'clone_scope') and
                (record['destination_scope_identity'] not in after['scope_allocations'] or
                 record['destination_scope_identity'] in before['scope_allocations'] or
                 record['external_idempotency_namespace'] not in after['namespace_allocations'] or
                 record['external_idempotency_namespace'] in before['namespace_allocations'] or
                 record['operation_ledger_identity'] not in after['operation_ledgers'] or
                 record['operation_ledger_identity'] in before['operation_ledgers'])):
            raise ValueError(label + ': fresh scope, namespace or operation ledger not durably allocated')
        if record['mode'] in ('standalone', 'clone', 'strict'):
            for checkpoint in request['source_archive']['checkpoints']:
                if checkpoint not in after['checkpoints']:
                    raise ValueError(label + ': recovered scope omitted complete checkpoint bytes')
            for participant in request['source_archive']['participants']:
                if participant not in after['participants']:
                    raise ValueError(label + ': recovered scope omitted required participant bytes')
            if any(isinstance(claim, dict) and claim.get('scope_identity') ==
                   record['destination_scope_identity'] for claim in after['worker_claims']):
                raise ValueError(label + ': source worker claims were imported into destination')
    proof = case.get('expected_transfer_proof')
    if proof is not None:
        if case['request']['operation'] in ('prepare_transfer', 'commit_transfer') and \
                proof in before['transfer_proofs']:
            raise ValueError(label + ': transfer proof existed before its native commit')
        if proof not in after['transfer_proofs']:
            raise ValueError(label + ': complete local transfer proof absent from guarded ledger')
        matching = [entry for entry in after['authority_ledger']
                    if isinstance(entry, dict) and entry.get('scope_identity') == proof['scope_identity'] and
                    entry.get('authority_epoch') == proof['source_authority_epoch'] and
                    entry.get('scope_generation') == proof['source_scope_generation'] and
                    entry.get('state') == proof['source_state'] and
                    entry.get('source_binding_digest') == proof['source_binding_digest'] and
                    entry.get('authority_token_identity') == hosted_authority_token_identity and
                    entry.get('transaction_fate') == 'known_committed' and
                    entry.get('retained_checkpoint_digests') == sorted(
                        item['execution_checkpoint_digest'] for item in request['source_archive']['checkpoints']) and
                    entry.get('required_participant_ids') ==
                    request['source_archive']['participant_contract']['required_participant_ids'] and
                    (source_reference is None or
                     entry.get('source_storage_identity') == source_reference['storage_identity'] and
                     entry.get('source_native_instance_identity') ==
                     source_reference['native_instance_identity'] and
                     entry.get('freeze_native_transaction_id') ==
                     source_reference['freeze_native_transaction_id'] and
                     entry.get('freeze_native_proof_id') ==
                     source_reference['freeze_native_proof_id'])]
        if not matching or proof['transaction_fate'] != 'known_committed' or not proof['claims_revoked']:
            raise ValueError(label + ': native freeze, retirement or transaction fate unproved')
        if proof['phase'] == 'committed' and (not proof['old_writes_fenced'] or
                                            proof['grant_state'] != 'consumed'):
            raise ValueError(label + ': stale writes or transfer grant remain live')
    if expected['safe_relocation']:
        for checkpoint in request['source_archive']['checkpoints']:
            if checkpoint not in after['checkpoints']:
                raise ValueError(label + ': destination omitted a complete checkpoint')
        for participant in request['source_archive']['participants']:
            if participant not in after['participants']:
                raise ValueError(label + ': destination omitted a required participant')
    if expected['safe_relocation'] and not case.get('configured_profile') == 'proved_local_same_authority':
        raise ValueError(label + ': unproved topology claimed safe relocation')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--bridge-registration', required=True, type=Path,
                        help='trusted runner-selected native bridge and installation anchor')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('reviewed production bridge command required after --')
    validate_profile(args.spec_root)
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    owned = read_json(CASE / 'recovery-two-root-vectors-v1.json')
    namespace = read_json(CASE / 'recovery-namespace-vectors-v1.json')
    fixture['cases'] += owned['cases']
    fixture['cases'] += namespace['cases']
    fixture['owned_stage_request'] = owned['stage_request']
    fixture['owned_stage_configuration'] = owned['stage_configuration']
    fixture['owned_stage_result'] = owned['stage_result']
    installed_bridge = trusted_bridge(command, args.bridge_registration)
    standalone = [case for case in fixture['cases']
                  if case.get('configured_profile') != 'proved_local_same_authority']
    for case in [*fixture['early_cases'], *standalone]:
        run_case(command, case, fixture, bridge_registration=args.bridge_registration,
                 expected_bridge_identity=installed_bridge)
    if trusted_bridge(command, args.bridge_registration) != installed_bridge:
        raise ValueError('reviewed bridge installation changed after recovery profile')
    print(f'{len(standalone) + len(fixture["early_cases"])} standalone production recovery '
          'responses and native observations passed; 10 local transfer cases remain conditional')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'recovery profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
