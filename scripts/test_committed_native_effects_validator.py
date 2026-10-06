#!/usr/bin/env python3
"""Adversarial §19 fixture and adapter boundary tests."""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import copy
import json
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

import rfc8785

import committed_native_effects_validator as effect_validator
from committed_native_effects_validator import CASE, strict_json, validate_profile
from generate_version1_vectors import digest
from run_committed_native_effects_profile import (bind_to_proved_authority, check_observation, closure_bytes, execute_vector,
                                                   native_proof_id, verify_native_evidence,
                                                   verify_retained_retry_evidence,
                                                   verified_profile)

SPEC = Path(__file__).resolve().parents[2] / 'determa-state-spec'


class CommittedEffectsValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = strict_json((CASE / 'data/vectors.json').read_bytes())
        cls.artifacts = {path.name: strict_json(path.read_bytes()) for path in CASE.glob('*checkpoint.json')}
        cls.artifacts.update({'data/' + path.name: strict_json(path.read_bytes())
                              for path in (CASE / 'data').glob('*.json') if path.name != 'vectors.json'})

    @classmethod
    def configured(cls):
        record = cls.artifacts['data/unclaimed-journal.json']['effect_records'][0]
        return {'report_digest': 'sha256:' + '1' * 64,
                'authority_report_digest': 'sha256:' + '2' * 64,
                'topology_identifier': 'single-sqlite-database',
                'scope_identity': 'effect-scope-1', 'authority_epoch': '3',
                'handler_reference': record['handler_reference'],
                'destination_binding_digest': record['destination_binding_digest'],
                'executing_source_path': 'handler/test_handler.py',
                'loaded_source_sha256': 'sha256:' + hashlib.sha256(
                    (CASE / 'handler/test_handler.py').read_bytes()).hexdigest(),
                'run_id': 'test-native-run'}

    def operation_payload(self, vector):
        request = vector['request']
        return {'operation': request['operation'],
                'checkpoint_before': self.artifacts[request['checkpoint_before']],
                'journal_before': self.artifacts[request['journal_before']],
                'claim': None if request['claim'] is None else self.artifacts[request['claim']],
                'auth_context': request['auth_context'],
                'host_configuration': request['host_configuration'],
                'arguments': request['arguments'], 'fault': request['fault'],
                'run_id': self.configured()['run_id'],
                'machine_source_utf8': (CASE / 'machine.yaml').read_text(),
                'handler_source_files': {str(path.relative_to(CASE)): path.read_text()
                                         for path in (CASE / 'handler').glob('test_handler.*')}}

    def observation(self, vector):
        request, expected = vector['request'], vector['expected']
        serial = lambda name: rfc8785.dumps(self.artifacts[name]).decode('utf-8')
        response = expected['response']
        before_records = self.artifacts[request['journal_before']]['effect_records']
        before_record = before_records[0] if before_records else None
        provider_call = ({key: before_record[key] for key in
                          ('effect_id', 'handler_reference', 'destination_binding_digest',
                           'route_configuration_generation', 'attempt_fence')}
                         if before_record else {})
        if provider_call:
            provider_call.update(scope_identity=self.artifacts[request['journal_before']]['scope_identity'],
                                 credential_generation=request['host_configuration']['credential_generation'])
        after = self.artifacts['pending-checkpoint.json'] if vector['name'] == 'route_generation_changed' else self.artifacts[expected['checkpoint_after']]
        receipt = after['operation_receipts'][-1]
        core_call = {'event_id': receipt['event_id'],
                     'operation_kind': 'step' if receipt['operation_kind'] == 'event_terminal' else 'admit',
                     'target': after['root_record']['aggregate_state']['runtimes'][0]['target_identity']}
        after_record = self.artifacts[expected['journal_after']]['effect_records']
        claim = {'effect_id': after_record[0]['effect_id'],
                 'attempt_fence': after_record[0]['attempt_fence'],
                 'worker_principal': request['auth_context']['principal']} if after_record else {}
        kind = expected['caller_kind']
        caller_result = {'kind': kind, 'operation': request['operation'],
                         'checkpoint_digest': None if kind == 'no_response' else self.artifacts[expected['checkpoint_after']]['execution_checkpoint_digest'],
                         'journal_digest': None if kind == 'no_response' else self.artifacts[expected['journal_after']]['host_effect_journal_digest']}
        configured = self.configured()
        changed = request['checkpoint_before'] != expected['checkpoint_after'] or \
                  request['journal_before'] != expected['journal_after']
        fate = 'rolled_back' if vector['name'] == 'route_generation_changed' else \
               'committed' if changed else 'no_mutation'
        retry_evidence = None
        if vector['name'] in ('safe_retry_report', 'duplicate_equal_retry_report', 'safe_retry_new_fence',
                              'ambiguous_retry_with_proven_deduplication'):
            retry_evidence = {key: before_record[key] for key in ('effect_id', 'operation_token',
                              'attempt_fence', 'handler_reference', 'destination_binding_digest')}
            receipt = base64.b64encode(b'actual scoped native destination receipt').decode()
            retry_evidence.update(kind='destination_deduplication', scope_identity=configured['scope_identity'],
                                  root_instance_id=self.artifacts[request['checkpoint_before']]['root_instance_id'],
                                  first_attempt_receipt_bytes_base64=receipt, repeat_attempt_receipt_bytes_base64=receipt)
        evidence = {'proof_id': native_proof_id(self.operation_payload(vector), configured['run_id']),
                    'run_id': configured['run_id'],
                    'report_digest': configured['report_digest'],
                    'authority_report_digest': configured['authority_report_digest'],
                    'topology_identifier': configured['topology_identifier'],
                    'scope_identity': configured['scope_identity'],
                    'authority_epoch': configured['authority_epoch'],
                    'handler_reference': configured['handler_reference'],
                    'destination_binding_digest': configured['destination_binding_digest'],
                    'guard_fate': fate,
                    'claim_guard_observed': request['operation'] in ('claim', 'dispatch', 'submit_result'),
                    'retry_safety_evidence': retry_evidence,
                    'native_transaction_id': 'native-txn-test',
                    'destination_call_evidence': ({'idempotency_key': [configured['scope_identity'], before_record['effect_id']],
                                                   'destination_binding_digest': before_record['destination_binding_digest'],
                                                   'attempt_fence': before_record['attempt_fence']}
                                                  if expected['counts']['provider_calls'] else None)}
        return {'response_utf8': serial(response) if response else None,
                'caller_result': caller_result,
                'native_evidence': evidence,
                'checkpoint_before_utf8': serial(request['checkpoint_before']),
                'checkpoint_after_utf8': serial(expected['checkpoint_after']),
                'journal_before_utf8': serial(request['journal_before']),
                'journal_after_utf8': serial(expected['journal_after']),
                'provider_calls': [provider_call] * expected['counts']['provider_calls'],
                'core_calls': [core_call] * expected['counts']['core_calls'],
                'new_claims': [claim] * expected['counts']['new_claims'],
                'loaded_machine_sha256': 'sha256:' + __import__('hashlib').sha256((CASE / 'machine.yaml').read_bytes()).hexdigest(),
                'loaded_handler_source': ({'handler/test_handler.py': 'sha256:' + __import__('hashlib').sha256((CASE / 'handler/test_handler.py').read_bytes()).hexdigest()}
                                          if expected['counts']['provider_calls'] else {})}

    def vector(self, name):
        return next(vector for vector in self.manifest['vectors'] if vector['name'] == name)

    def test_python_native_object_stays_inside_handler(self):
        handler = runpy.run_path(str(CASE / 'handler/test_handler.py'))['invoke']
        class Destination:
            def __init__(self):
                self.calls = []
            def call(self, scope, effect, payload):
                self.calls.append((scope, effect, payload))
                return ('receipt-1', True)
        destination = Destination()
        result = handler(['map', []], {'scope_identity': 'scope', 'effect_id': 'effect'},
                         {'attempt_fence': '1'}, destination)
        self.assertEqual(destination.calls, [('scope', 'effect', ['map', []])])
        self.assertEqual(result, {'report_kind': 'succeeded',
                                  'payload': ['map', [['provider_reference', ['string', 'receipt-1']]]],
                                  'reason': None})
        self.assertEqual(rfc8785.dumps(result), rfc8785.dumps(strict_json(rfc8785.dumps(result))))

    def configured_report_observation(self, *, proofs):
        authority = copy.deepcopy(strict_json((CASE.parent.parent / 'host-authority/vectors.generated.json').read_bytes())['profiles'][2]['expected_report'])
        authority['scope_identity'] = 'effect-scope-1'
        authority['authority_epoch'] = '3'
        authority_closure = b'actual-authority-provider-source'
        authority_configuration = b'actual-authority-native-configuration'
        authority['extension_report']['provider_reference']['content_digest'] = 'sha256:' + hashlib.sha256(authority_closure).hexdigest()
        authority['topology']['configuration_digest'] = 'sha256:' + hashlib.sha256(authority_configuration).hexdigest()
        participants = []
        for index, participant in enumerate(authority['required_participants']):
            source = ('actual-' + participant['role'] + '-participant-source').encode()
            participant['provider_reference']['content_digest'] = 'sha256:' + hashlib.sha256(source).hexdigest()
            participants.append({'participant': participant, 'closure_bytes_base64': base64.b64encode(source).decode(),
                                 'observed_health': 'healthy'})
        record = self.artifacts['data/unclaimed-journal.json']['effect_records'][0]
        report = {'format': 'determa.committed_native_effects.configured_profile',
                  'schema_version': 1, 'scope_identity': 'effect-scope-1',
                  'handler_reference': record['handler_reference'],
                  'destination_binding_digest': record['destination_binding_digest'],
                  'idempotency_policy': 'destination_deduplicates',
                  'authority_report_bytes': rfc8785.dumps(authority).decode()}
        receipt = base64.b64encode(b'one-retained-destination-receipt').decode()
        proof = None if not proofs else {'scope_identity': 'effect-scope-1',
                                          'effect_id': record['effect_id'],
                                          'destination_binding_digest': record['destination_binding_digest'],
                                          'first_attempt_receipt_bytes_base64': receipt,
                                          'repeat_attempt_receipt_bytes_base64': receipt}
        installation = {'run_id': self.configured()['run_id'],
                        'handler_closure_bytes_base64': base64.b64encode(closure_bytes()).decode(),
                        'destination_configuration_bytes_base64': base64.b64encode(rfc8785.dumps(
                            self.artifacts['data/destination-configuration.json'])).decode(),
                        'executing_source_path': 'handler/test_handler.py',
                        'loaded_source_sha256': self.configured()['loaded_source_sha256'],
                        'observed_health': 'healthy',
                        'authority_closure_bytes_base64': base64.b64encode(authority_closure).decode(),
                        'authority_configuration_bytes_base64': base64.b64encode(authority_configuration).decode(),
                        'participant_installations': participants,
                        'native_proof_ids': sorted(proofs),
                        'destination_deduplication_proof': proof}
        return {'report_bytes': rfc8785.dumps(report).decode(), 'installation_evidence': installation}

    def test_configured_profile_binds_actual_closure_and_authority(self):
        before = self.configured_report_observation(proofs=set())
        configured = verified_profile(before, self.artifacts, SPEC,
                                      expected_run_id=self.configured()['run_id'], expected_proofs=set())
        self.assertEqual(configured['scope_identity'], 'effect-scope-1')
        proved = copy.deepcopy(configured['authority_report'])
        proved['scope_identity'] = 'scope-42'
        proved['authority_epoch'] = '2'
        bind_to_proved_authority(configured, proved)
        other_installation = copy.deepcopy(proved)
        other_installation['topology']['configuration_digest'] = 'sha256:' + '0' * 64
        with self.assertRaises(ValueError):
            bind_to_proved_authority(configured, other_installation)
        after = self.configured_report_observation(proofs={'native-proof-1'})
        verified_profile(after, self.artifacts, SPEC,
                         expected_run_id=self.configured()['run_id'], expected_proofs={'native-proof-1'})
        broken = copy.deepcopy(after)
        broken['installation_evidence']['handler_closure_bytes_base64'] = base64.b64encode(b'copied-hash').decode()
        with self.assertRaises(ValueError):
            verified_profile(broken, self.artifacts, SPEC,
                             expected_run_id=self.configured()['run_id'], expected_proofs={'native-proof-1'})
        broken = copy.deepcopy(after)
        broken['installation_evidence']['destination_deduplication_proof']['repeat_attempt_receipt_bytes_base64'] = base64.b64encode(b'different').decode()
        with self.assertRaises(ValueError):
            verified_profile(broken, self.artifacts, SPEC,
                             expected_run_id=self.configured()['run_id'], expected_proofs={'native-proof-1'})

    def test_late_cancellation_coverage_cannot_be_dropped(self):
        self.assertEqual(effect_validator.validate_late_cancellation_vectors(self.manifest, self.artifacts), 7)
        manifest = copy.deepcopy(self.manifest)
        manifest['vectors'] = [item for item in manifest['vectors'] if item['name'] != 'late-cancel-outcome_recorded']
        with self.assertRaises(ValueError):
            effect_validator.validate_late_cancellation_vectors(manifest, self.artifacts)

    def test_late_cancellation_cannot_replace_the_winning_record(self):
        for field, replacement in [('cancellation', {'state': 'reconciliation_required'}),
                                   ('outcome', None), ('invocation_state', 'ambiguous')]:
            with self.subTest(field=field):
                artifacts = copy.deepcopy(self.artifacts)
                artifacts['data/late-cancel-outcome_recorded-journal.json']['effect_records'][0][field] = replacement
                with self.assertRaises(ValueError):
                    effect_validator.validate_late_cancellation_vectors(self.manifest, artifacts)

    def test_invalid_late_payload_cannot_disclose_revision_or_outcome(self):
        for field in ['journal_revision', 'outcome']:
            with self.subTest(field=field):
                artifacts = copy.deepcopy(self.artifacts)
                artifacts['data/invalid-late-cancel-outcome_recorded-response.json'][field] = (
                    '4' if field == 'journal_revision' else artifacts['data/outcome-recorded-journal.json']['effect_records'][0]['outcome'])
                with self.assertRaises(ValueError):
                    effect_validator.validate_late_cancellation_vectors(self.manifest, artifacts)

    def test_invalid_late_vector_cannot_reject_a_valid_payload(self):
        manifest = copy.deepcopy(self.manifest)
        vector = next(item for item in manifest['vectors'] if item['name'] == 'invalid-late-cancel-outcome_recorded')
        vector['request']['arguments']['payload'] = ['map', []]
        with self.assertRaises(ValueError):
            effect_validator.validate_late_cancellation_vectors(manifest, self.artifacts)

    def test_source_and_artifact_gate(self):
        self.assertEqual(validate_profile(SPEC), 62)

    def test_all_complete_oracles_accept_matching_observations(self):
        for vector in self.manifest['vectors']:
            with self.subTest(vector=vector['name']):
                observation = self.observation(vector)
                check_observation(vector, observation, self.artifacts)
                self.assertEqual(verify_native_evidence(vector, observation, self.artifacts,
                                                        self.configured(), self.operation_payload(vector)),
                                 observation['native_evidence']['proof_id'])

    def test_retry_credit_refuses_assertions_wrong_bindings_and_unequal_receipts(self):
        vector = self.vector('safe_retry_report')
        for damage in ('missing', 'boolean', 'wrong_work', 'wrong_root', 'wrong_token',
                       'wrong_fence', 'wrong_handler', 'wrong_destination', 'empty', 'unequal'):
            with self.subTest(damage=damage):
                observation = self.observation(vector)
                proof = observation['native_evidence']['retry_safety_evidence']
                if damage == 'missing':
                    observation['native_evidence']['retry_safety_evidence'] = None
                elif damage == 'boolean':
                    observation['native_evidence']['retry_safety_evidence'] = True
                elif damage in ('empty', 'unequal'):
                    proof['repeat_attempt_receipt_bytes_base64'] = '' if damage == 'empty' else base64.b64encode(b'different').decode()
                else:
                    field = {'wrong_work': 'effect_id', 'wrong_root': 'root_instance_id',
                             'wrong_token': 'operation_token', 'wrong_fence': 'attempt_fence',
                             'wrong_handler': 'handler_reference', 'wrong_destination': 'destination_binding_digest'}[damage]
                    proof[field] = 'different'
                with self.assertRaises(ValueError):
                    verify_native_evidence(vector, observation, self.artifacts,
                                           self.configured(), self.operation_payload(vector))

    def test_equal_fabricated_retry_receipts_do_not_match_the_observed_destination(self):
        vector = self.vector('safe_retry_report')
        observed = self.observation(vector)
        proof = observed['native_evidence']['retry_safety_evidence']
        destination = {key: proof[key] for key in ('scope_identity', 'effect_id', 'destination_binding_digest',
                                                  'first_attempt_receipt_bytes_base64', 'repeat_attempt_receipt_bytes_base64')}
        verify_retained_retry_evidence([proof], destination)
        fabricated = copy.deepcopy(proof)
        fabricated['first_attempt_receipt_bytes_base64'] = fabricated['repeat_attempt_receipt_bytes_base64'] = base64.b64encode(b'equal fabricated bytes').decode()
        with self.assertRaises(ValueError):
            verify_retained_retry_evidence([fabricated], destination)
        with self.assertRaises(ValueError):
            verify_retained_retry_evidence([proof], None)

    def test_ambiguous_next_fence_requires_native_evidence(self):
        vector = self.vector('ambiguous_retry_with_proven_deduplication')
        for missing in (None, True, {}):
            observation = self.observation(vector)
            observation['native_evidence']['retry_safety_evidence'] = missing
            with self.assertRaises(ValueError):
                verify_native_evidence(vector, observation, self.artifacts,
                                       self.configured(), self.operation_payload(vector))

    def test_rejected_retry_cannot_credit_evidence(self):
        vector = self.vector('retry_safety_missing')
        observation = self.observation(vector)
        observation['native_evidence']['retry_safety_evidence'] = self.observation(
            self.vector('safe_retry_report'))['native_evidence']['retry_safety_evidence']
        with self.assertRaises(ValueError):
            verify_native_evidence(vector, observation, self.artifacts,
                                   self.configured(), self.operation_payload(vector))

    def test_strict_json_decoder(self):
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'{"a":"\\ud800"}', b'\xff'):
            with self.assertRaises((ValueError, UnicodeDecodeError)):
                strict_json(body)

    def test_independent_semantic_substitutions(self):
        def tamper(relative, mutation):
            with tempfile.TemporaryDirectory() as temporary:
                case = Path(temporary) / 'case'
                shutil.copytree(CASE, case)
                path = case / relative
                value = strict_json(path.read_bytes())
                mutation(value)
                path.write_text(json.dumps(value), encoding='utf-8')
                original = effect_validator.CASE
                effect_validator.CASE = case
                try:
                    with self.assertRaises(ValueError):
                        validate_profile(SPEC)
                finally:
                    effect_validator.CASE = original
        def wrong_intent(value):
            value['effect_records'][0]['intent_digest'] = 'sha256:' + '0' * 64
            value.pop('host_effect_journal_digest')
            value['host_effect_journal_digest'] = digest(['determa-host-effect-journal-digest-1', value])
        def wrong_target(value):
            value['effect_records'][0]['target']['runtime_id'] = 'sha256:' + '0' * 64
            value.pop('host_effect_journal_digest')
            value['host_effect_journal_digest'] = digest(['determa-host-effect-journal-digest-1', value])
        def wrong_source_pin(value):
            key = next(iter(value['normative_examples']))
            value['normative_examples'][key] = 'sha256:' + '0' * 64
        tamper('data/unclaimed-journal.json', wrong_intent)
        tamper('data/leased-journal.json', wrong_target)
        tamper('data/vectors.json', wrong_source_pin)
        def skip_core_proposal(value):
            vector = next(item for item in value['vectors'] if item['name'] == 'route_generation_changed')
            vector['request']['control_plan'] = []
        def misbind_expired_claim(value):
            value['normative_case_coverage']['host-native-effect-cases-v1.json']['old_epoch_or_fence'] = ['stale_epoch']
        def omit_preclaim_dispatch_refusal(value):
            value['normative_case_coverage']['host-native-effect-cases-v1.json']['cancellation_before_claim'] = ['cancel_before_claim']
        def invented_handler_digest(value):
            value['effect_records'][0]['handler_reference']['content_digest'] = 'sha256:' + 'b' * 64
            value.pop('host_effect_journal_digest')
            value['host_effect_journal_digest'] = digest(['determa-host-effect-journal-digest-1', value])
        tamper('data/vectors.json', skip_core_proposal)
        tamper('data/vectors.json', misbind_expired_claim)
        tamper('data/vectors.json', omit_preclaim_dispatch_refusal)
        tamper('data/unclaimed-journal.json', invented_handler_digest)

    def test_full_response_and_bytes(self):
        vector = self.vector('first_terminal_result')
        observation = self.observation(vector)
        check_observation(vector, observation, self.artifacts)
        broken = copy.deepcopy(observation)
        broken['response_utf8'] = broken['response_utf8'].replace('"committed"', '"rejected"', 1)
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)
        broken = copy.deepcopy(observation)
        broken['journal_after_utf8'] = broken['journal_before_utf8']
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)

    def test_rejection_cannot_call_or_mutate(self):
        vector = self.vector('wrong_token')
        observation = self.observation(vector)
        check_observation(vector, observation, self.artifacts)
        broken = copy.deepcopy(observation)
        broken['provider_calls'] = [{'effect_id': 'unauthorized'}]
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)
        broken = copy.deepcopy(observation)
        broken['checkpoint_after_utf8'] = rfc8785.dumps(self.artifacts['admitted-checkpoint.json']).decode('utf-8')
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)

    def test_child_adapter_cannot_fake_crash_reply_or_skip_live_barriers(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / 'adapter.py'
            response_file = Path(temporary) / 'observed.json'
            script.write_text('import pathlib,sys\nsys.stdout.write(pathlib.Path(sys.argv[1]).read_text())\n')
            command = [sys.executable, str(script), str(response_file)]
            crashed = self.vector('outcome_commit_lost_before_admission')
            false_success = self.observation(crashed)
            false_success['caller_result']['kind'] = 'completed'
            false_success['response_utf8'] = '{}'
            response_file.write_text(json.dumps(false_success))
            with self.assertRaises(SystemExit):
                execute_vector(command, crashed, self.artifacts, self.configured())
            route = self.vector('route_generation_changed')
            response_file.write_text(json.dumps(self.observation(route)))
            with self.assertRaises(SystemExit):
                execute_vector(command, route, self.artifacts, self.configured())
            dispatch = self.vector('sdk_native_objects_inside_handler')
            copied_hash = self.observation(dispatch)
            copied_hash['loaded_handler_source'] = {'handler/test_handler.py': 'sha256:' + '0' * 64}
            response_file.write_text(json.dumps(copied_hash))
            with self.assertRaises(SystemExit):
                execute_vector(command, dispatch, self.artifacts, self.configured())

    def test_exact_types_and_duplicate_response_member(self):
        vector = self.vector('wrong_token')
        observation = self.observation(vector)
        broken = copy.deepcopy(observation)
        broken['new_claims'] = False
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)
        broken = copy.deepcopy(observation)
        broken['response_utf8'] = '{"status":"rejected","status":"rejected"}'
        with self.assertRaises(ValueError):
            check_observation(vector, broken, self.artifacts)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', type=Path, required=True)
    args = parser.parse_args()
    SPEC = args.spec_root
    unittest.main(argv=[__file__])
