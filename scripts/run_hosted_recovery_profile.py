#!/usr/bin/env python3
"""Conditional §24 local transfer gate for one actual configured host installation."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from pathlib import Path
import shlex
import subprocess
import sys
import uuid

from validate_portable_archive import canonical, digest, parse_json_bytes, read_json
from validate_recovery_profile import CASE, validate_profile
from run_recovery_profile import run_case

ROOT = Path(__file__).resolve().parents[1]


def call(command: list[str], value: dict, label: str) -> dict:
    completed = subprocess.run(command, input=canonical(value), capture_output=True,
                               check=False, timeout=120)
    if completed.returncode:
        raise ValueError(f'{label}: configured adapter exited {completed.returncode}: '
                         f'{completed.stderr.decode("utf-8", "replace")[:500]}')
    result = parse_json_bytes(completed.stdout, label)
    if type(result) is not dict:
        raise ValueError(label + ': complete configured object required')
    return result


def report_bytes(response: dict, label: str) -> tuple[dict, bytes]:
    if type(response.get('report_bytes')) is not str:
        raise ValueError(label + ': literal report bytes absent')
    raw = response['report_bytes'].encode('utf-8')
    report = parse_json_bytes(raw, label + ': report')
    if raw != canonical(report) or type(report) is not dict:
        raise ValueError(label + ': noncanonical configured report')
    return report, raw


def observed_binding(command: list[str], authority_command: list[str],
                     run_id: str, transport: Path, fixture: dict) -> tuple[dict, str]:
    authority_response = call(authority_command, {'kind': 'configured_profile'},
                              '§18 configured authority')
    authority, authority_raw = report_bytes(authority_response, '§18 configured authority')
    effect_response = call(command, {'kind': 'configured_profile', 'phase': 'before',
                                     'run_id': run_id}, '§19 configured effect')
    effect, effect_raw = report_bytes(effect_response, '§19 configured effect')
    transport_digest = 'sha256:' + sha256(transport.read_bytes()).hexdigest()
    delivery = call(command, {'kind': 'configured_delivery_profile', 'run_id': run_id,
                              'transport_command': [sys.executable, str(transport)],
                              'transport_source_sha256': transport_digest},
                    '§21 configured delivery')
    recovery_response = call(command, {'kind': 'configured_recovery_profile'},
                             '§24 configured recovery')
    report, raw = report_bytes(recovery_response, '§24 configured recovery')
    fields = {'format', 'schema_version', 'safe_relocation', 'topology_identifier',
              'authority_report_digest', 'effect_report_digest', 'delivery_report_digest',
              'authority_provider_reference', 'effect_handler_reference',
              'provider_reference', 'configuration_digest', 'authority_token_identity',
              'source_binding_digest', 'destination_binding_digest', 'archive_digest',
              'participant_contract_digest', 'required_participant_ids'}
    if set(report) != fields or report['format'] != 'determa.conformance.recovery.configured_profile' or \
            type(report['schema_version']) is not int or report['schema_version'] != 1 or \
            report['safe_relocation'] is not True:
        raise ValueError('§24 safe relocation is not positively configured with a closed report')
    if set(recovery_response) != {'report_bytes', 'installation_evidence'}:
        raise ValueError('§24 configured report lacks actual installation evidence')
    installation = recovery_response['installation_evidence']
    if type(installation) is not dict or set(installation) != {
            'closure_bytes_base64', 'configuration_bytes_base64', 'observed_health',
            'authority_token_identity'}:
        raise ValueError('§24 installation evidence is incomplete')
    try:
        closure = base64.b64decode(installation['closure_bytes_base64'], validate=True)
        configuration = base64.b64decode(installation['configuration_bytes_base64'], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError('§24 installed closure or configuration bytes invalid') from error
    if not closure or not configuration or installation['observed_health'] != 'healthy' or \
            installation['authority_token_identity'] != report['authority_token_identity'] or \
            not report['authority_token_identity'] or \
            'sha256:' + sha256(closure).hexdigest() != report['provider_reference']['content_digest'] or \
            'sha256:' + sha256(configuration).hexdigest() != report['configuration_digest']:
        raise ValueError('§24 claimed provider closure/configuration/token differs from installation')
    archive = read_json(CASE / 'archive-local-transfer-v1.json')
    proof = fixture['trusted_transfer_proofs'][0]
    if authority['topology']['identifier'] != report['topology_identifier'] or \
            authority['extension_report']['provider_reference'] != report['authority_provider_reference'] or \
            not authority['guarantees']['guarded_local_writes'] or \
            not authority['guarantees']['worker_fencing'] or \
            not authority['guarantees']['complete_scope_inventory'] or \
            effect['handler_reference'] != report['effect_handler_reference'] or \
            effect['authority_report_bytes'] != canonical(parse_json_bytes(
                effect['authority_report_bytes'].encode(), '§19 embedded authority')).decode() or \
            delivery['transport_source_sha256'] != transport_digest or \
            delivery['source_acknowledgement'] != 'after_durable_commit' or \
            delivery['ingress_dead_letter'] != 'durable_before_acknowledgement':
        raise ValueError('§24 host differs from the proved C/D/H installation')
    expected = {
        'authority_report_digest': 'sha256:' + sha256(authority_raw).hexdigest(),
        'effect_report_digest': 'sha256:' + sha256(effect_raw).hexdigest(),
        'delivery_report_digest': digest(delivery),
        'source_binding_digest': archive['source']['ownership_binding_digest'],
        'destination_binding_digest': proof['destination_binding_digest'],
        'archive_digest': archive['archive_digest'],
        'participant_contract_digest': archive['participant_contract']['participant_contract_digest'],
        'required_participant_ids': archive['participant_contract']['required_participant_ids'],
    }
    if any(report[key] != value for key, value in expected.items()):
        raise ValueError('§24 actual configured binding differs from local transfer source or C/D/H')
    return report, 'sha256:' + sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    parser.add_argument('--adapter', required=True)
    parser.add_argument('--authority-adapter', required=True)
    args = parser.parse_args()
    command, authority_command = shlex.split(args.adapter), shlex.split(args.authority_adapter)
    if not command or not authority_command:
        parser.error('configured host and authority adapter commands required')
    validate_profile(args.spec_root)
    hosted_runner = ROOT / 'scripts/run_lossless_delivery_profile.py'
    transport = ROOT / 'scripts/lossless_delivery_test_transport.py'
    if not hosted_runner.is_file() or not transport.is_file():
        raise ValueError('§21 hosted delivery production dependency is not merged')
    fixture = read_json(CASE / 'recovery-cases-v1.json')
    run_id = str(uuid.uuid4())
    initial, binding = observed_binding(command, authority_command, run_id, transport, fixture)
    completed = subprocess.run([sys.executable, str(hosted_runner), '--spec-root',
                                str(args.spec_root), '--adapter', args.adapter,
                                '--authority-adapter', args.authority_adapter],
                               capture_output=True, check=False, timeout=1800)
    if completed.returncode:
        raise ValueError('§18/§19/§21 configured production proof failed: ' +
                         completed.stderr.decode('utf-8', 'replace')[:1000])
    if observed_binding(command, authority_command, run_id, transport, fixture) != (initial, binding):
        raise ValueError('configured C/D/H/recovery installation changed during native proof')
    owned = read_json(CASE / 'recovery-two-root-vectors-v1.json')
    fixture['cases'] += owned['cases']
    fixture['owned_stage_request'] = owned['stage_request']
    fixture['owned_stage_configuration'] = owned['stage_configuration']
    fixture['owned_stage_result'] = owned['stage_result']
    for case in [*fixture['early_cases'], *fixture['cases']]:
        run_case(command, case, fixture, hosted_binding_digest=binding)
    if observed_binding(command, authority_command, run_id, transport, fixture) != (initial, binding):
        raise ValueError('configured C/D/H/recovery installation changed during recovery proof')
    print('48 recovery responses and observations passed under one configured local host')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'hosted recovery profile failed: {error}', file=sys.stderr)
        raise SystemExit(1)
