#!/usr/bin/env python3
"""Adversarial mutations of source ownership, receipts, and raw delivery bytes."""
from __future__ import annotations

import base64
import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

from validate_conformance import ValidationFailure, hash_value, load_fixture_document
from validate_lossless_delivery import validate_profile
from run_lossless_delivery_profile import run, strict_document

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'
SPEC = ROOT.parent / 'determa-state-spec'


def vector(profile: dict, name: str) -> dict:
    return next(item for item in profile['vectors'] if item['name'] == name)


def invalid(profile: dict, name: str) -> dict:
    return next(item for item in profile['invalid_vectors'] if item['name'] == name)


def integrated(profile: dict, name: str) -> dict:
    return next(item for item in profile['integration']['integration_vectors']
                if item['name'] == name)


def check_mutation(name: str, mutate, spec_root: Path) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        case = Path(temporary)
        for path in CASE.iterdir():
            if path.is_file():
                (case / path.name).write_bytes(path.read_bytes())
        profile_path = case / 'delivery-vectors-v1.json'
        document = json.loads(profile_path.read_text())
        mutate(document)
        profile_path.write_text(json.dumps(document, indent=2) + '\n')
        try:
            validate_profile(case, load_fixture_document(case / 'test.yaml'),
                             set(case.glob('*.json')), spec_root)
        except ValidationFailure:
            return
        raise AssertionError(f'{name}: validator accepted adversarial fixture')


def reseal_destination(profile: dict) -> None:
    item = vector(profile, 'outbound_confirmed_is_destination_acceptance')
    item['expected_response']['destination_receipt_id'] = 'forged-durable-acceptance'
    item['request']['provider_result']['destination_receipt_id'] = 'forged-durable-acceptance'
    receipt = item['after']['destination_receipts'][0]
    receipt['destination_receipt_id'] = 'forged-durable-acceptance'
    receipt['outbound_destination_receipt_digest'] = hash_value([
        'determa-outbound-destination-receipt-digest-1', '1',
        {key: value for key, value in receipt.items()
         if key != 'outbound_destination_receipt_digest'}])


def reseal_source(profile: dict) -> None:
    item = vector(profile, 'equal_redelivery_after_lost_ack')
    source = item['request']['source']
    source['content']['content_value'] = 'Q2hhbmdlZA=='
    source['source_content_digest'] = hash_value([
        'determa-delivery-source-content-digest-1', '1',
        source['source_scope'], source['source_delivery_id'],
        source['content']['content_kind'], source['content']['content_value']])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', type=Path, default=SPEC)
    args = parser.parse_args()
    probes = (
        ('reseeded source content', reseal_source),
        ('replay uses current acknowledgement', lambda p: vector(
            p, 'redelivery_after_commit_crash')['before']['source_acknowledgements'].append(
                {'source_scope': 'orders/inbox', 'source_delivery_id': 'broker-42'})),
        ('precommit acknowledges', lambda p: vector(
            p, 'precommit_write_failure_keeps_source')['after']['source_acknowledgements'].append(
                {'source_scope': 'orders/inbox', 'source_delivery_id': 'broker-42'})),
        ('atomic binding missing', lambda p: vector(
            p, 'first_committed_admission')['after']['bindings'].clear()),
        ('terminal wrong checkpoint', lambda p: vector(
            p, 'machine_unhandled_after_admission')['after'].update(
                checkpoint='after-admission-checkpoint-v1.json')),
        ('wrong placement origin', lambda p: vector(
            p, 'deferred_keeps_original_acceptance')['expected_response']['origin'].update(
                acceptance_receipt_sequence='2')),
        ('pending work erased', lambda p: vector(
            p, 'outbound_ambiguous_remains_pending')['after'].update(
                checkpoint='native-confirmed-checkpoint-v1.json')),
        ('resigned destination receipt', reseal_destination),
        ('bad pad bits accepted', lambda p: invalid(
            p, 'nonzero_one_byte_pad_bits').update(expected_failure='invalid_delivery')),
        ('negative acknowledges', lambda p: invalid(
            p, 'outbound_wrong_effect_identity').update(acknowledge_source=True)),
        ('duplicate keys treated as valid', lambda p: invalid(
            p, 'duplicate_json_key').update(candidate=base64.b64encode(b'{}').decode())),
        ('confirmed invents business success', lambda p: integrated(
            p, 'confirmed_outbox_business_outstanding')['journal_after']['effect_records'][0].update(
                invocation_state='result_admitted')),
        ('host result invents broker acknowledgement', lambda p: integrated(
            p, 'host_owned_result_admission')['source_acknowledgements'].append(
                {'source_scope': 'effect-scope-1', 'source_delivery_id': 'invented'})),
        ('host result loses live mailbox', lambda p: integrated(
            p, 'host_owned_result_admission')['checkpoint_after']['root_record']['aggregate_state']['runtimes'][0]['ready_mailbox'].clear()),
        ('ambiguous retry calls provider without proof', lambda p: integrated(
            p, 'ambiguous_provider_retry_without_proof_refused')['expected']['counts'].update(
                provider_calls=1)),
        ('stale effect replay bypasses current epoch', lambda p: integrated(
            p, 'stale_result_replay_current_guard')['request']['auth_context'].update(
                scope_authority_epoch='3')),
    )
    for name, mutate in probes:
        check_mutation(name, mutate, args.spec_root)
    for label, raw in (
            ('duplicate response member', b'{"response":{},"response":{},"after":{}}'),
            ('nonfinite response', b'{"response":NaN,"after":{}}'),
            ('invalid UTF-8 response', b'{"response":"\xff","after":{}}')):
        try:
            strict_document(raw, label)
        except ValueError:
            pass
        else:
            raise AssertionError(f'{label}: response gate accepted malformed child bytes')
    with tempfile.TemporaryDirectory() as temporary:
        child = Path(temporary) / 'child.py'
        child.write_text('import sys\nsys.stdout.buffer.write(b\'{"response":{},"response":{},"after":{}}\')\n')
        try:
            run([sys.executable, str(child)])
        except ValueError:
            pass
        else:
            raise AssertionError('runner accepted malformed production child output')
        child.write_text('import sys\nsys.stdout.buffer.write(b\'{"response":{},"after":{}}\')\n')
        try:
            run([sys.executable, str(child)])
        except AssertionError:
            pass
        else:
            raise AssertionError('runner accepted valid JSON with a forged response')
        child.write_text('import sys\nsys.stdin.buffer.read()\n')
        try:
            run([sys.executable, str(child)])
        except ValueError:
            pass
        else:
            raise AssertionError('runner accepted suppressed response on a noncrash vector')
    print(f'{len(probes)} lossless delivery adversarial probes rejected')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
