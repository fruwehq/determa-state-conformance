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
                                           check_transport,
                                           store_call, transport_call,
                                           verify_configured_delivery_profile, STORE)

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
        ('confirmed terminal replay resends', lambda p: vector(
            p, 'confirmed_terminal_replay_no_resend')['request'].update(
                provider_result={'outcome': 'confirmed', 'reason_code': None,
                                 'destination_receipt_id': 'destination-acceptance-actual-1'})),
        ('dead-letter terminal replay loses receipt', lambda p: vector(
            p, 'dead_letter_terminal_replay_no_resend')['after']['destination_receipts'].clear()),
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
        host_store = Path(temporary) / 'installed-host-store.sqlite'
        before_store = {**admission['before'], 'checkpoint': before_checkpoint}
        after_store = {**admission['after'], 'checkpoint': checkpoint}
        seeded = store_call(host_store, 'seed', run_id='smoke', before=before_store)
        transport_call(database, 'configure_acknowledgement_barrier',
                       store_command=[sys.executable, str(STORE)],
                       store_database_path=str(host_store),
                       run_id='smoke', operation_id='admit-1',
                       checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                       transfer_digest=binding['admission_binding_digest'])
        try:
            transport_call(database, 'ack', source_scope=source['source_scope'],
                           source_delivery_id=source['source_delivery_id'],
                           checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                           transfer_digest=binding['admission_binding_digest'])
        except ValueError:
            pass
        else:
            raise AssertionError('source acknowledged before durable binding was observable')
        if transport_call(database, 'snapshot')['acknowledgement_attempts'][0]['status'] != 'rejected':
            raise AssertionError('early acknowledgement attempt was hidden')
        store_call(host_store, 'commit', run_id='smoke', operation_id='admit-1',
                   expected_before_digest=seeded['seed_digest'], after=after_store)
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
                [item['status'] for item in snapshot['acknowledgement_attempts']] != ['rejected', 'accepted'] or \
                snapshot['calls'][-1]['intent'] != intent:
            raise AssertionError('installed transport lost durable call evidence')
        for label, committed_state, decoy in (
                ('checkpoint_without_binding', {**before_store, 'checkpoint': checkpoint}, False),
                ('binding_without_checkpoint', {**before_store, 'bindings': [binding]}, False),
                ('wrong_source_binding', {**after_store, 'bindings': [
                    {**binding, 'source_delivery_id': 'other-item'}]}, False),
                ('decoy_host_database', after_store, True)):
            probe_transport = Path(temporary) / f'{label}.transport.sqlite'
            probe_store = Path(temporary) / f'{label}.host.sqlite'
            probe_run = f'probe-{label}'
            transport_call(probe_transport, 'seed', sources=[{
                'source_scope': source['source_scope'],
                'source_delivery_id': source['source_delivery_id'],
                'source': source, 'acknowledged': False}])
            transport_call(probe_transport, 'fetch', source_scope=source['source_scope'],
                           source_delivery_id=source['source_delivery_id'])
            seeded_probe = store_call(probe_store, 'seed', run_id=probe_run, before=before_store)
            transport_call(probe_transport, 'configure_acknowledgement_barrier',
                           store_command=[sys.executable, str(STORE)],
                           store_database_path=str(probe_store), run_id=probe_run,
                           operation_id='op',
                           checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                           transfer_digest=binding['admission_binding_digest'])
            write_store = Path(temporary) / f'{label}.decoy.sqlite' if decoy else probe_store
            if decoy:
                store_call(write_store, 'seed', run_id=probe_run, before=before_store)
            store_call(write_store, 'commit', run_id=probe_run, operation_id='op',
                       expected_before_digest=seeded_probe['seed_digest'],
                       after=committed_state)
            try:
                transport_call(probe_transport, 'ack', source_scope=source['source_scope'],
                               source_delivery_id=source['source_delivery_id'],
                               checkpoint_digest=checkpoint['execution_checkpoint_digest'],
                               transfer_digest=binding['admission_binding_digest'])
            except ValueError:
                pass
            else:
                raise AssertionError(f'{label}: partial or decoy host store authorized ack')
            probe_snapshot = transport_call(probe_transport, 'snapshot')
            if probe_snapshot['sources'][0]['acknowledged'] or \
                    [item['status'] for item in probe_snapshot['acknowledgement_attempts']] != ['rejected']:
                raise AssertionError(f'{label}: rejected ack was not durably visible')
        for selected in ('crash_after_atomic_commit_before_ack',
                         'crash_committed_without_store_cut',
                         'first_committed_admission'):
            item = vector(manifest, 'crash_after_atomic_commit_before_ack'
                          if selected == 'crash_committed_without_store_cut' else selected)
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
            elif selected == 'crash_committed_without_store_cut':
                child.write_text('import json,sys\nfrom pathlib import Path\n'
                                 f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                                 'from run_lossless_delivery_profile import store_call,digest\n'
                                 'from validate_conformance import canonical_json_bytes\n'
                                 'r=json.load(sys.stdin)\n'
                                 f'store_call(Path(r["host_store_database_path"]),"commit",run_id=r["run_id"],operation_id=r["operation_id"],expected_before_digest=digest(canonical_json_bytes(r["before"])),after={after!r})\n'
                                 'sys.exit(9)\n')
            else:
                attempted = Path(temporary) / 'forged-ack-attempt.txt'
                child.write_text('import json,sys\n'
                                 'from pathlib import Path\n'
                                 f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                                 'from run_lossless_delivery_profile import configuration_digests,transport_call\n'
                                 'from validate_conformance import canonical_json_bytes\n'
                                 'r=json.load(sys.stdin)\n'
                                 'ref=r["source_references"][0]\n'
                                 'db=Path(r["transport_database_path"])\n'
                                 'transport_call(db,"fetch",**ref)\n'
                                 'try:\n'
                                 f' transport_call(db,"ack",**ref,checkpoint_digest={checkpoint["execution_checkpoint_digest"]!r},transfer_digest={binding["admission_binding_digest"]!r})\n'
                                 'except ValueError:\n'
                                 f' Path({str(attempted)!r}).write_text("fetch;ack-rejected")\n'
                                 'e={"operation_id":r["operation_id"],"run_id":r["run_id"],'
                                 '"transport_source_sha256":' + repr(
                                     'sha256:' + hashlib.sha256(
                                         (ROOT / 'scripts/lossless_delivery_test_transport.py').read_bytes()).hexdigest()) + ','
                                 '"transport_database_path":r["transport_database_path"],'
                                 '"commit_fate":"committed","native_transaction_id":"forged"}\n'
                                 'e.update(configuration_digests(r["run_id"]))\n'
                                 'e.update(r.get("profile_links", {"authority_report_digest":None,"effect_report_digest":None,"host_scope_identity":None,"host_topology_identifier":None}))\n'
                                 'if r.get("kind")=="observe_delivery_state":\n'
                                 f' sys.stdout.buffer.write(canonical_json_bytes({{"after":{after!r},"native_evidence":e}}))\n'
                                 'else:\n'
                                 f' sys.stdout.buffer.write(canonical_json_bytes({{"response":{item["expected_response"]!r},'
                                 f'"after":{after!r},"native_evidence":e}}))\n')
            try:
                run([sys.executable, str(child)], fixture)
            except AssertionError as error:
                expected_error = ('driver-owned process crash cut missing'
                                  if selected == 'crash_committed_without_store_cut' else
                                  'trusted durable host store differs')
                if expected_error not in str(error):
                    raise AssertionError(f'{selected}: wrong rejection: {error}') from error
                if selected == 'first_committed_admission' and (
                        not attempted.is_file() or attempted.read_text() != 'fetch;ack-rejected'):
                    raise AssertionError('forged adapter did not reach real provider fetch and ack barrier')
            else:
                raise AssertionError(f'runner accepted forged {selected} without durable transport proof')
        crash_before = vector(manifest, 'crash_before_atomic_commit')
        crash_after = vector(manifest, 'crash_after_atomic_commit_before_ack')
        replay = vector(manifest, 'redelivery_after_commit_crash')
        manifest_path.write_text(json.dumps({**manifest,
            'vectors': [crash_before, crash_after, replay], 'invalid_vectors': []}))
        crashed_store = {**crash_after['after'], 'checkpoint': json.loads(
            (fixture / crash_after['after']['checkpoint']).read_text())}
        replayed_store = {**replay['after'], 'checkpoint': json.loads(
            (fixture / replay['after']['checkpoint']).read_text())}
        child.write_text('import json,sys\nfrom pathlib import Path\n'
                         f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                         'from run_lossless_delivery_profile import transport_call,store_call,configuration_digests,digest,TRANSPORT,STORE\n'
                         'from validate_conformance import canonical_json_bytes\n'
                         'r=json.load(sys.stdin)\n'
                         'db=Path(r["transport_database_path"])\n'
                         'host=Path(r["host_store_database_path"])\n'
                         'ref=r["source_references"][0]\n'
                         'transport_call(db,"fetch",**ref)\n'
                         'if r["fault_injection"]=="crash_before_commit":\n'
                         ' store_call(host,"crash_before_commit",run_id=r["run_id"],operation_id=r["operation_id"])\n'
                         ' sys.exit(99)\n'
                         'if r["fault_injection"]=="crash_after_commit_before_ack":\n'
                         f' store_call(host,"commit",run_id=r["run_id"],operation_id=r["operation_id"],expected_before_digest=digest(canonical_json_bytes(r["before"])),after={crashed_store!r},crash_after_commit=True)\n'
                         ' sys.exit(99)\n'
                         'assert r["before"] is None and r["resume_operation_id"]\n'
                         'prior=store_call(host,"snapshot",run_id=r["run_id"])\n'
                         f'assert prior["after"]=={crashed_store!r}\n'
                         f'tx=store_call(host,"commit",run_id=r["run_id"],operation_id=r["operation_id"],expected_before_digest=digest(canonical_json_bytes(prior["after"])),after={replayed_store!r})\n'
                         f'transport_call(db,"ack",**ref,checkpoint_digest={replayed_store["checkpoint"]["execution_checkpoint_digest"]!r},transfer_digest={binding["admission_binding_digest"]!r})\n'
                         'e={"operation_id":r["operation_id"],"run_id":r["run_id"],'
                         '"transport_source_sha256":digest(TRANSPORT.read_bytes()),'
                         '"transport_database_path":r["transport_database_path"],'
                         '"host_store_source_sha256":digest(STORE.read_bytes()),'
                         '"host_store_database_path":r["host_store_database_path"],'
                         '"commit_fate":"committed","native_transaction_id":tx["native_transaction_id"],'
                         '"proof_id":tx["proof_id"]}\n'
                         'e.update(configuration_digests(r["run_id"]))\n'
                         'e.update(r["profile_links"])\n'
                         f'sys.stdout.buffer.write(canonical_json_bytes({{"response":{replay["expected_response"]!r},"after":{replayed_store!r},"native_evidence":e}}))\n')
        crash_proofs = []
        if run([sys.executable, str(child)], fixture,
               proof_summary=crash_proofs) != 3:
            raise AssertionError('controlled crash and retained replay smoke did not execute')
        if ([item['name'] for item in crash_proofs] != [
                'crash_before_atomic_commit', 'crash_after_atomic_commit_before_ack',
                'redelivery_after_commit_crash'] or
            crash_proofs[0]['host_store_proof_id'] is not None or
            crash_proofs[0]['crash_cut']['phase'] != 'before_commit' or
            not crash_proofs[1]['host_store_proof_id'] or
            crash_proofs[1]['crash_cut']['phase'] != 'after_commit' or
            not crash_proofs[2]['host_store_proof_id'] or
            crash_proofs[2]['source_acknowledgements'] != replayed_store['source_acknowledgements']):
            raise AssertionError('controlled crash proof summary lost native commit or source ownership')
        first_terminal = vector(manifest, 'outbound_confirmed_is_destination_acceptance')
        terminal = vector(manifest, 'confirmed_terminal_replay_no_resend')
        manifest_path.write_text(json.dumps({**manifest,
            'vectors': [first_terminal, terminal], 'invalid_vectors': []}))
        terminal_after = {**terminal['after'], 'checkpoint': json.loads(
            (fixture / terminal['after']['checkpoint']).read_text())}
        child.write_text('import json,sys\nfrom pathlib import Path\n'
                         f'sys.path.insert(0,{str(ROOT / "scripts")!r})\n'
                         'from run_lossless_delivery_profile import transport_call,store_call,configuration_digests,digest,TRANSPORT,STORE\n'
                         'from validate_conformance import canonical_json_bytes\n'
                         'r=json.load(sys.stdin)\n'
                         'db=Path(r["transport_database_path"])\n'
                         'host=Path(r["host_store_database_path"])\n'
                         'if "destination_route" in r:\n'
                         ' intent=next(item["intent"] for item in r["before"]["checkpoint"]["pending_outbox_intents"] if item["intent"]["effect_id"]==r["input"]["effect_id"])\n'
                         ' provider=transport_call(db,"deliver",effect_id=intent["effect_id"],intent=intent,route=r["destination_route"])\n'
                         f' assert provider=={first_terminal["request"]["provider_result"]!r}\n'
                         f' after={terminal_after!r}\n'
                         ' tx=store_call(host,"commit",run_id=r["run_id"],operation_id=r["operation_id"],expected_before_digest=digest(canonical_json_bytes(r["before"])),after=after)\n'
                         ' fate="committed"\n'
                         'else:\n'
                         ' assert r["before"] is None and r["resume_operation_id"]\n'
                         ' after=store_call(host,"snapshot",run_id=r["run_id"])["after"]\n'
                         f' assert after=={terminal_after!r}\n'
                         ' tx=None\n'
                         ' fate="no_mutation"\n'
                         'e={"operation_id":r["operation_id"],"run_id":r["run_id"],'
                         '"transport_source_sha256":digest(TRANSPORT.read_bytes()),'
                         '"transport_database_path":r["transport_database_path"],'
                         '"host_store_source_sha256":digest(STORE.read_bytes()),'
                         '"host_store_database_path":r["host_store_database_path"],'
                         '"commit_fate":fate,"native_transaction_id":None if tx is None else tx["native_transaction_id"],'
                         '"proof_id":None if tx is None else tx["proof_id"]}\n'
                         'e.update(configuration_digests(r["run_id"]))\n'
                         'e.update(r["profile_links"])\n'
                         f'sys.stdout.buffer.write(canonical_json_bytes({{"response":{terminal["expected_response"]!r},"after":after,"native_evidence":e}}))\n')
        terminal_proofs = []
        if run([sys.executable, str(child)], fixture,
               proof_summary=terminal_proofs) != 2:
            raise AssertionError('controlled terminal replay smoke did not execute')
        if ([item['provider_call_kinds'] for item in terminal_proofs] != [['deliver'], []] or
            terminal_proofs[0]['host_store_proof_id'] is None or
            terminal_proofs[1]['host_store_proof_id'] is not None or
            terminal_proofs[1]['destination_receipt_ids']):
            raise AssertionError('terminal replay proof summary hid a destination resend')
        terminal_transport = Path(temporary) / 'terminal-replay.transport.sqlite'
        intent = next(item['intent'] for item in
                      terminal_after['checkpoint']['terminal_outbox_records']
                      if item['intent']['effect_id'] == terminal['request']['effect_id'])
        transport_call(terminal_transport, 'deliver', effect_id=intent['effect_id'],
                       intent=intent, route='accept')
        try:
            check_transport(terminal, terminal_transport, [], terminal_after,
                            terminal_after, 0, 0)
        except AssertionError as error:
            if 'terminal replay resent retained intent' not in str(error):
                raise AssertionError(f'wrong terminal replay rejection: {error}') from error
        else:
            raise AssertionError('runner accepted terminal retry that resent effect')
    print(f'{len(probes) + 9} lossless delivery adversarial probes rejected; 5 controlled crash/terminal replay operations passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
