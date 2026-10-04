#!/usr/bin/env python3
"""Run §24 requests through a registered production recovery bridge.

Each case uses an isolated native store. The reviewed bridge invokes production
operations; the runner reads persistence outside the child and never seeds a
recovery result record or synthesizes after state.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
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
         'terminated_scopes')
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
            'configured_topology_identifier'}
    if type(entry) is not dict or set(entry) != keys or \
            entry['format'] != 'determa.conformance.recovery.bridge_registration' or \
            type(entry['schema_version']) is not int or entry['schema_version'] != 1 or \
            entry['language'] not in ('python', 'rust') or \
            type(entry['command']) is not list or entry['command'] != command or \
            any(type(part) is not str or not part for part in command) or \
            not all(type(entry[key]) is str and entry[key]
                    for key in keys - {'format', 'schema_version', 'command',
                                       'configured_authority_token_identity',
                                       'configured_topology_identifier'}) or \
            any(entry[key] is not None and
                (type(entry[key]) is not str or not entry[key])
                for key in ('configured_authority_token_identity',
                            'configured_topology_identifier')):
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
                     'configured_topology_identifier'}
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
                phase: str, payload: dict, expected: dict,
                hosted_binding_digest: str | None,
                bridge_identity: str) -> tuple[dict, dict, dict]:
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
    fields = ({'caller_response_kind', 'caller_response_body', 'native_evidence'} if
              phase in ('archive_stage', 'scope_terminate') else
              {'result', 'record', 'transfer_proof', 'caller_response_kind',
               'caller_response_body', 'native_evidence'})
    if type(observed) is not dict or set(observed) != fields:
        raise ValueError(phase + ': incomplete literal production response')
    equal(observed['caller_response_body'], expected, phase + ': literal caller body')
    expected_kind = ('archive_result' if phase == 'archive_stage' else
                     'scope_termination_result' if phase == 'scope_terminate' else
                     'recovery_result')
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
                transaction['response_digest'] != digest(expected) or \
                transaction['before_digest'] != digest(before['state']) or \
                transaction['after_digest'] != digest(after['state']) or \
                observed['native_evidence'] != {
                    'native_transaction_id': transaction['native_transaction_id'],
                    'proof_id': transaction['proof_id']}:
            raise ValueError(phase + ': native transaction differs from response or exact input')
    elif observed['native_evidence'] is not None:
        raise ValueError(phase + ': response invented a native commit')
    return observed, before['state'], after['state']


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


def run_case(command: list[str], case: dict, fixture: dict,
             *, hosted_binding_digest: str | None = None,
             hosted_authority_token_identity: str | None = None,
             bridge_registration: Path | None = None) -> None:
    label = case['case_id']
    bridge_identity = trusted_bridge(command, bridge_registration)
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
        stage_payload = {key: request[key] for key in
                         ('source_archive', 'stage_archive', 'stage_request', 'stage_configuration')}
        stage_response, stage_before, stage_after = native_call(
            command, database, run_id, str(uuid.uuid4()), 'archive_stage',
            stage_payload, stage_expected, hosted_binding_digest, bridge_identity)
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
            setup_observed, _, _ = native_call(
                command, database, run_id, str(uuid.uuid4()), 'recovery',
                {'request': setup_request, 'source_archive': request['source_archive']},
                setup_case['expected_result'], hosted_binding_digest, bridge_identity)
            equal(setup_observed['result'], setup_case['expected_result'],
                  label + ': actual setup response')
            equal(setup_observed['record'], setup_case.get('expected_record'),
                  label + ': actual setup record')
            equal(setup_observed['transfer_proof'],
                  setup_case.get('expected_transfer_proof'),
                  label + ': actual setup transfer proof')
        if case.get('terminated_setup_scope'):
            scope = fixture['records']['standalone_inactive']['record']['destination_scope_identity']
            _, termination_before, termination_after = native_call(
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
        response, before, after = native_call(
            command, database, run_id, str(uuid.uuid4()), 'recovery',
            {'request': request['request'], 'source_archive': request['source_archive']},
            expected, hosted_binding_digest, bridge_identity)
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
                    request['source_archive']['participant_contract']['required_participant_ids']]
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
    standalone = [case for case in fixture['cases']
                  if case.get('configured_profile') != 'proved_local_same_authority']
    for case in [*fixture['early_cases'], *standalone]:
        run_case(command, case, fixture, bridge_registration=args.bridge_registration)
    print(f'{len(standalone) + len(fixture["early_cases"])} standalone production recovery '
          'responses and native observations passed; 10 local transfer cases remain conditional')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'recovery profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
