#!/usr/bin/env python3
"""Run §24 requests against a configured production recovery adapter.

Each invocation must use an isolated host fixture. The adapter executes setup
requests through production operations and reports observed storage bytes; this
runner never seeds a result record or synthesizes after state.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from validate_portable_archive import ROOT, canonical, parse_json_bytes, read_json
from validate_recovery_profile import CASE, validate_profile

STATE = ('recovery_records', 'scope_allocations', 'namespace_allocations',
         'operation_ledgers', 'checkpoints', 'host_journals', 'participants',
         'worker_claims', 'external_dispatches', 'ingress_acknowledgements',
         'authority_ledger', 'transfer_proofs', 'staged_archives')
CALLS = ('core_create', 'core_admit', 'core_step', 'core_migration',
         'effect_dispatch', 'helper_dispatch', 'ingress_acknowledge',
         'provider_evaluate', 'timer_fire', 'authority_commit')


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
             *, hosted_binding_digest: str | None = None) -> None:
    label = case['case_id']
    request = input_for(case, fixture)
    completed = subprocess.run(command, input=canonical(request), capture_output=True,
                               check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{label}: adapter exited {completed.returncode}: '
                         f'{completed.stderr.decode("utf-8", "replace")[:500]}')
    response = parse_json_bytes(completed.stdout, label + ': adapter response')
    fields = {'result', 'record', 'transfer_proof', 'before', 'after',
                         'calls', 'caller_response_kind', 'caller_response_body',
                         'mutation_paths', 'setup_responses', 'stage_setup_result'}
    if hosted_binding_digest is not None:
        fields.add('configured_binding_digest')
    if set(response) != fields:
        raise ValueError(label + ': incomplete production response')
    if hosted_binding_digest is not None and response['configured_binding_digest'] != hosted_binding_digest:
        raise ValueError(label + ': production response uses a different configured installation')
    setup = response['setup_responses']
    if not isinstance(setup, list) or len(setup) != len(request['setup_requests']):
        raise ValueError(label + ': incomplete production setup responses')
    for index, setup_request in enumerate(request['setup_requests']):
        matching = [item for item in fixture['cases']
                    if canonical(item['request']) == canonical(setup_request)]
        if len(matching) != 1:
            raise ValueError(label + ': ambiguous setup request')
        equal(setup[index], matching[0]['expected_result'], label + ': setup response')
    expected = case['expected_result']
    equal(response['result'], expected, label + ': result')
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
    equal(response['stage_setup_result'], stage_expected, label + ': actual I1 stage result')
    equal(response['record'], case.get('expected_record'), label + ': record')
    equal(response['transfer_proof'], case.get('expected_transfer_proof'),
          label + ': transfer proof')
    if response['caller_response_kind'] != 'recovery_result':
        raise ValueError(label + ': caller response kind')
    equal(response['caller_response_body'], expected, label + ': literal caller body')
    before, after = response['before'], response['after']
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(STATE) or set(after) != set(STATE):
        raise ValueError(label + ': incomplete actual host observations')
    stage = {'staging_identity': request['stage_request']['staging_identity'],
             'archive': request['stage_archive']}
    if stage_expected['status'] == 'staged':
        if stage not in before['staged_archives'] or stage not in after['staged_archives']:
            raise ValueError(label + ': production archive stage absent from observed storage')
    elif stage in before['staged_archives'] or stage in after['staged_archives']:
        raise ValueError(label + ': refused I1 stage was persisted')
    if request['setup_requests']:
        latest = next(item for item in reversed(fixture['cases'])
                      if canonical(item['request']) == canonical(request['setup_requests'][-1]))
        if latest['expected_record'] is not None and latest['expected_record'] not in before['recovery_records']:
            raise ValueError(label + ': setup lifecycle record absent from observed storage')
    calls = response['calls']
    if not isinstance(calls, dict) or set(calls) != set(CALLS) or any(
            type(count) is not int or count < 0 for count in calls.values()):
        raise ValueError(label + ': incomplete actual call counts')
    if any(calls[key] for key in ('core_create', 'core_admit', 'core_step',
                                  'core_migration', 'effect_dispatch', 'helper_dispatch',
                                  'ingress_acknowledge', 'provider_evaluate', 'timer_fire')):
        raise ValueError(label + ': recovery invoked active processing or external work')
    for key in ('external_dispatches', 'ingress_acknowledgements'):
        equal(after[key], before[key], label + ': recovery changed external work')
    from validate_portable_archive import changed_paths
    actual_paths = sorted(changed_paths(before, after))
    equal(response['mutation_paths'], actual_paths, label + ': observed mutation footprint')
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
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('production adapter command required after --')
    validate_profile(args.spec_root)
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    owned = read_json(CASE / 'recovery-two-root-vectors-v1.json')
    fixture['cases'] += owned['cases']
    fixture['owned_stage_request'] = owned['stage_request']
    fixture['owned_stage_configuration'] = owned['stage_configuration']
    fixture['owned_stage_result'] = owned['stage_result']
    standalone = [case for case in fixture['cases']
                  if case.get('configured_profile') != 'proved_local_same_authority']
    for case in [*fixture['early_cases'], *standalone]:
        run_case(command, case, fixture)
    print(f'{len(standalone) + len(fixture["early_cases"])} standalone production recovery '
          'responses and observations passed; 10 local transfer cases remain conditional')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'recovery profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
