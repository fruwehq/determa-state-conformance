"""Adversarial §25 source, message, and actual-host runner checks."""
from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
from unittest.mock import patch

from validate_portable_archive import canonical, parse_json_bytes
from validate_public_host import (CASE, PublicHostValidationError, check_manifest,
                                  check_response, load, request_hash, validate_profile, validators)
from run_public_host_profile import run_case, run_invalid_response, verify_proof


def rejected(label, operation) -> None:
    try:
        operation()
    except (PublicHostValidationError, ValueError, KeyError):
        return
    raise AssertionError(f'{label}: invalid substitution accepted')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    spec_root = parser.parse_args().spec_root
    assert validate_profile(spec_root) == (33, 24, 15)
    good = load(CASE / 'positive-v1.json')['cases'][0]
    bad = load(CASE / 'negative-v1.json')
    vv = validators(spec_root)
    altered = copy.deepcopy(good)
    altered['request_digest'] = 'sha256:' + '0' * 64
    rejected('request digest', lambda: request_hash(altered, 'altered'))
    altered = copy.deepcopy(good)
    altered['response']['receipt']['evidence_digest'] = 'sha256:' + '0' * 64
    rejected('retained evidence', lambda: check_response(altered['request'],
             altered['request_digest'], altered['response'], 'altered'))
    altered = copy.deepcopy(good)
    altered['response']['receipt']['receipt_kind'] = 'accepted'
    rejected('committed acceptance-only receipt', lambda: check_response(altered['request'],
             altered['request_digest'], altered['response'], 'altered'))
    manifest = load(CASE / 'public-host-contract-v1.json')
    records = [load(CASE / name) for name in ('compatibility-change-v1.json',
               'source-order-compatibility-change-v1.json',
               'timer-evidence-compatibility-change-v1.json',
               'provider-correlation-compatibility-change-v1.json',
               'native-slot-identities-compatibility-change-v1.json')]
    altered_manifest = copy.deepcopy(manifest)
    altered_manifest['boundary_sources'].pop(0)
    rejected('boundary source removal', lambda: check_manifest(spec_root, altered_manifest, records, vv))
    rejected('change record omitted', lambda: check_manifest(spec_root, manifest, records[:-1], vv))
    altered_records = copy.deepcopy(records)
    altered_records[-1]['manifest_fingerprint'] = 'sha256:' + '0' * 64
    rejected('stale final change record', lambda: check_manifest(
             spec_root, manifest, altered_records, vv))
    altered_manifest = copy.deepcopy(manifest)
    altered_manifest['boundary_sources'][0]['sha256'] = 'sha256:' + '0' * 64
    rejected('boundary source drift', lambda: check_manifest(spec_root, altered_manifest, records, vv))
    assert all(list(vv['public-host-response'].iter_errors(x['response']))
               for x in bad['invalid_responses'])
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        rejected('invalid JSON source', lambda r=raw: parse_json_bytes(r, 'adversarial'))
    for value in (True, 1.0, '1'):
        altered = copy.deepcopy(good['request'])
        altered['protocol_version'] = value
        assert list(vv['public-host-request'].iter_errors(altered)), 'protocol version type accepted'
    keys = ('source_digest', 'provider_digest', 'configuration_digest', 'store_digest',
            'authority_digest', 'topology_digest')
    proof = {'run_id': 'fresh-run', 'scope_binding_identity': good['request']['scope_binding_identity'],
             'instance_identity': 'reference-host-1', **{key: 'sha256:' + '1' * 64 for key in keys}}
    proof['claim_proofs'] = {'create': {**proof, 'proof_id': 'native-create-1'}}
    rejected('stale native run', lambda: verify_proof(proof, good['request'], good['response'], 'new-run'))
    foreign = copy.deepcopy(proof)
    foreign['claim_proofs']['create']['store_digest'] = 'sha256:' + '2' * 64
    rejected('foreign native store', lambda: verify_proof(foreign, good['request'], good['response'], 'fresh-run'))
    rejected('omitted native claim', lambda: verify_proof({**proof, 'claim_proofs': {}},
             good['request'], good['response'], 'fresh-run'))
    composition = {key: value for key, value in proof.items()
                   if key not in ('run_id', 'claim_proofs')}
    state = {key: [] for key in ('active_scopes', 'authority_grants', 'credentials',
             'checkpoints', 'host_journals', 'participant_storage', 'staged_archives',
             'public_operation_receipts', 'scope_aliases', 'endpoint_authorities',
             'timer_records')}
    state['composition'] = composition
    class Result:
        returncode = 0
        stderr = b''
        stdout = canonical({'response': good['response'], 'transport_error': None,
                            'before': state, 'after': state,
                            'native_proof': proof, 'transport_attempts': [{'endpoint_authority': 'authority-local-1', 'scope_binding_identity': good['request']['scope_binding_identity'], 'operation_id': good['request']['operation_id'], 'request_digest': good['request_digest']}], 'response_bytes_base64': __import__('base64').b64encode(canonical(good['response'])).decode(), 'calls': {name: 0 for name in ('core_create', 'core_admit', 'core_step',
                            'effect_dispatch', 'timer_poll', 'authority_mutation', 'archive_stage',
                            'recovery_mutation')}})
    with patch('run_public_host_profile.subprocess.run', return_value=Result()) as call:
        rejected('forged committed unchanged host', lambda: run_case(['adapter'], good, False, 'fresh-run'))
        sent = parse_json_bytes(call.call_args.kwargs['input'], 'adapter input')
        assert set(sent) == {'run_id', 'request', 'transport_context', 'client_context'}
        assert sent['request'] == good['request'] and 'response' not in sent
    replay_output = parse_json_bytes(Result.stdout, 'replay fixture')
    replay_output['calls']['core_create'] = 1
    class ReplayWork:
        returncode = 0
        stderr = b''
        stdout = canonical(replay_output)
    with patch('run_public_host_profile.subprocess.run', return_value=ReplayWork()):
        rejected('replay ran core', lambda: run_case(['adapter'], good, False,
                 'fresh-run', replay=True))
    class Accepted:
        returncode = 0
        stdout = b'{"accepted":true,"error_code":null}'
    with patch('run_public_host_profile.subprocess.run', return_value=Accepted()):
        rejected('client accepted malformed response', lambda: run_invalid_response(
                 ['adapter'], bad['invalid_responses'][0], 'fresh-run'))
    print('public host adversarial validation passed')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
