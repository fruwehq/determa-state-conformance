#!/usr/bin/env python3
"""Adversarial mutations of source ownership, receipts, and raw delivery bytes."""
from __future__ import annotations

import base64
import argparse
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from validate_conformance import (ValidationFailure, canonical_json_bytes, hash_value,
                                  load_fixture_document)
from validate_lossless_delivery import validate_profile
from run_lossless_delivery_profile import (run, run_integrations,
                                           run_core_observability, strict_document,
                                           strict_child_document,
                                           transport_call, verify_configured_delivery_profile)

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


def observable(profile: dict, name: str) -> dict:
    return next(item for item in profile['core_observability_vectors']
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
        ('overflow fault lost', lambda p: observable(
            p, 'fault_is_terminal_not_source_retry')['expected_result'].update(fault=None)),
        ('lifecycle disposition lost', lambda p: observable(
            p, 'lifecycle_cancellation_is_visible')['expected_result']['lifecycle_dispositions'].clear()),
        ('migration disposal hidden', lambda p: observable(
            p, 'migration_disposal_is_explicit')['expected_result']['dispositions'].clear()),
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
    try:
        strict_child_document(b'{"response": {}, "after": {}}', 'noncanonical child')
    except ValueError:
        pass
    else:
        raise AssertionError('runner accepted noncanonical child response bytes')
    with tempfile.TemporaryDirectory() as temporary:
        child = Path(temporary) / 'child.py'
        child.write_text('import sys\nsys.stdout.buffer.write(b\'{"response":{},"response":{},"after":{}}\')\n')
        try:
            run([sys.executable, str(child)])
        except ValueError:
            pass
        else:
            raise AssertionError('runner accepted malformed production child output')
        child.write_text('import sys\nsys.stdout.buffer.write(b\'{"after":{},"native_evidence":{},"response":{}}\')\n')
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
        child.write_text('import json,sys\nsys.stdin.buffer.read()\nprint(json.dumps({"format":"determa.conformance.lossless_delivery.configured_profile","schema_version":1,"source_ordering":"source_ordered","transport_claims":["source_ordered"]}))\n')
        try:
            verify_configured_delivery_profile([sys.executable, str(child)])
        except ValueError:
            pass
        else:
            raise AssertionError('runner accepted an unproved public source_ordered report')
        child.write_text('import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b\'{"response_utf8":null,"checkpoint_after_utf8":"{}","journal_after_utf8":"{}","source_acknowledgements":[],"provider_calls":[],"core_calls":[]}\')\n')
        try:
            run_integrations([sys.executable, str(child)])
        except (AssertionError, ValueError):
            pass
        else:
            raise AssertionError('runner accepted forged composed effect evidence')
        child.write_text('import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b\'{"result":{},"source_acknowledgements":[]}\')\n')
        try:
            run_core_observability([sys.executable, str(child)])
        except AssertionError:
            pass
        else:
            raise AssertionError('runner accepted a truncated core result')
        fixture = Path(temporary) / 'fixture'
        fixture.mkdir()
        for path in CASE.iterdir():
            if path.is_file():
                (fixture / path.name).write_bytes(path.read_bytes())
        manifest_path = fixture / 'delivery-vectors-v1.json'
        manifest = json.loads(manifest_path.read_text())
        admission = vector(manifest, 'first_committed_admission')
        source = admission['request']['source']
        database = Path(temporary) / 'installed-transport.sqlite'
        transport_call(database, 'seed', sources=[{
            'source_scope': source['source_scope'],
            'source_delivery_id': source['source_delivery_id'],
            'source': source, 'acknowledged': False}])
        if transport_call(database, 'fetch', source_scope=source['source_scope'],
                          source_delivery_id=source['source_delivery_id']) != {'source': source}:
            raise AssertionError('installed source returned different original content')
        binding = admission['after']['bindings'][0]
        checkpoint = json.loads((fixture / admission['after']['checkpoint']).read_text())
        before_checkpoint = json.loads((fixture / admission['before']['checkpoint']).read_text())
        observer = Path(temporary) / 'transport-observer.py'
        transport_call(database, 'configure_acknowledgement_barrier',
                       observer_command=[sys.executable, str(observer)],
                       run_id='smoke', operation_id='admit-1',
                       checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                       transfer_digest=binding['admission_binding_digest'])
        observer.write_text('import sys\nsys.stdin.buffer.read()\n'
                            f'sys.stdout.buffer.write({canonical_json_bytes({"after": {**admission["before"], "checkpoint": before_checkpoint}})!r})\n')
        try:
            transport_call(database, 'ack', source_scope=source['source_scope'],
                           source_delivery_id=source['source_delivery_id'],
                           checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                           transfer_digest=binding['admission_binding_digest'])
        except ValueError:
            pass
        else:
            raise AssertionError('source acknowledged before durable binding was observable')
        observer.write_text('import sys\nsys.stdin.buffer.read()\n'
                            f'sys.stdout.buffer.write({canonical_json_bytes({"after": {**admission["after"], "checkpoint": checkpoint}})!r})\n')
        transport_call(database, 'ack', source_scope=source['source_scope'],
                       source_delivery_id=source['source_delivery_id'],
                       checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                       transfer_digest=binding['admission_binding_digest'])
        outbound = vector(manifest, 'outbound_confirmed_is_destination_acceptance')
        pending = json.loads((fixture / outbound['before']['checkpoint']).read_text())
        intent = next(item['intent'] for item in pending['pending_outbox_intents']
                      if item['intent']['effect_id'] == outbound['request']['effect_id'])
        provider_result = transport_call(database, 'deliver', effect_id=intent['effect_id'],
                                         intent=intent, route='accept')
        if provider_result != outbound['request']['provider_result']:
            raise AssertionError('installed destination did not return its retained acceptance')
        snapshot = transport_call(database, 'snapshot')
        if [call['kind'] for call in snapshot['calls']] != ['fetch', 'ack', 'deliver'] or \
                not snapshot['sources'][0]['acknowledged'] or \
                snapshot['calls'][-1]['intent'] != intent:
            raise AssertionError('installed transport lost durable call evidence')
        for selected in ('crash_after_atomic_commit_before_ack', 'first_committed_admission'):
            item = vector(manifest, selected)
            reduced = {**manifest, 'vectors': [item], 'invalid_vectors': []}
            manifest_path.write_text(json.dumps(reduced))
            after = {**item['after'], 'checkpoint': json.loads(
                (fixture / item['after']['checkpoint']).read_text())}
            before = {**item['before'], 'checkpoint': json.loads(
                (fixture / item['before']['checkpoint']).read_text())}
            if selected == 'crash_after_atomic_commit_before_ack':
                child.write_text('import json,sys\n'
                                 f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                                 'from validate_conformance import canonical_json_bytes\n'
                                 'r=json.load(sys.stdin)\n'
                                 'if r.get("kind")=="observe_delivery_state":\n'
                                 f' sys.stdout.buffer.write(canonical_json_bytes({{"after":{before!r},"native_evidence":{{}}}}))\n'
                                 'else: sys.exit(9)\n')
            else:
                child.write_text('import json,sys\n'
                                 f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                                 'from run_lossless_delivery_profile import configuration_digests\n'
                                 'from validate_conformance import canonical_json_bytes\n'
                                 'r=json.load(sys.stdin)\n'
                                 'e={"operation_id":r["operation_id"],"run_id":r["run_id"],'
                                 '"transport_source_sha256":' + repr(
                                     'sha256:' + hashlib.sha256(
                                         (ROOT / 'scripts/lossless_delivery_test_transport.py').read_bytes()).hexdigest()) + ','
                                 '"transport_database_path":r["transport_database_path"],'
                                 '"commit_fate":"committed","native_transaction_id":"forged"}\n'
                                 'e.update(configuration_digests(r["run_id"]))\n'
                                 'e.update(r.get("profile_links", {"authority_report_digest":None,"effect_report_digest":None}))\n'
                                 'if r.get("kind")=="observe_delivery_state":\n'
                                 f' sys.stdout.buffer.write(canonical_json_bytes({{"after":{after!r},"native_evidence":e}}))\n'
                                 'else:\n'
                                 f' sys.stdout.buffer.write(canonical_json_bytes({{"response":{item["expected_response"]!r},'
                                 f'"after":{after!r},"native_evidence":e}}))\n')
            try:
                run([sys.executable, str(child)], fixture)
            except AssertionError as error:
                expected_error = ('durable post-operation store differs' if selected.startswith('crash')
                                  else 'actual source ownership differs')
                if expected_error not in str(error):
                    raise AssertionError(f'{selected}: wrong rejection: {error}') from error
            else:
                raise AssertionError(f'runner accepted forged {selected} without durable transport proof')
    print(f'{len(probes) + 3} lossless delivery adversarial probes rejected')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
