"""Adversarial checks for the unfinished shared native creation case."""
import argparse
import copy
import json
import sys
import unittest
from pathlib import Path

from committed_native_effects_validator import schema_registry, validate_schema
from generate_version1_vectors import digest
from native_effect_creation_validator import validate_creation

FIXTURE = Path(__file__).parent / 'fixtures/native-effect-creation/initial-two-effects.json'


class NativeCreationValidatorTests(unittest.TestCase):
    def setUp(self):
        self.case = json.loads(FIXTURE.read_text())

    def check(self):
        validate_creation(*(self.case[key] for key in ('request', 'checkpoint', 'journal', 'response')))

    def reseal_journal(self):
        journal = self.case['journal']
        journal['host_effect_journal_digest'] = digest([
            'determa-host-effect-journal-digest-1',
            {key: value for key, value in journal.items() if key != 'host_effect_journal_digest'}])

    def test_actual_initial_two_effects(self):
        self.check()
        self.assertEqual(len(self.case['checkpoint']['pending_outbox_intents']), 2)

    def test_checkpoint_and_journal_schemas(self):
        registry = schema_registry(SPEC)
        for key, schema in (
            ('checkpoint', 'execution-checkpoint-v1.schema.json'),
            ('journal', 'host-effect-journal-v1.schema.json')):
            validate_schema(self.case[key], SPEC, schema, registry)

    def test_rehashed_missing_initial_record_refuses(self):
        self.case['journal']['effect_records'].pop()
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'initial effect inventory'):
            self.check()

    def test_rehashed_duplicate_initial_record_refuses(self):
        self.case['journal']['effect_records'].append(
            copy.deepcopy(self.case['journal']['effect_records'][0]))
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'initial effect inventory'):
            self.check()

    def test_rehashed_changed_declared_token_refuses(self):
        self.case['journal']['effect_records'][0]['operation_token'] = 'invented-token'
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'declared initial token'):
            self.check()

    def test_rehashed_changed_target_incarnation_refuses(self):
        self.case['journal']['effect_records'][0]['target']['runtime_incarnation'] = {'kind': 'root'}
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'initial target'):
            self.check()

    def test_rehashed_changed_route_generation_refuses(self):
        self.case['journal']['effect_records'][0]['route_configuration_generation'] = '99'
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'initial route generation'):
            self.check()

    def test_rehashed_started_invocation_refuses(self):
        self.case['journal']['effect_records'][0]['invocation_state'] = 'leased'
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'no initial invocation'):
            self.check()

    def test_rehashed_unequal_first_response_refuses(self):
        self.case['response']['creation_receipt']['creation_id'] = 'different-creation'
        self.case['journal']['operation_response_references'][0]['response_digest'] = digest([
            'determa-host-operation-response-1', self.case['response']])
        self.reseal_journal()
        with self.assertRaisesRegex(ValueError, 'exact creation response pair'):
            self.check()

    def test_changed_typed_binding_refuses(self):
        self.case['request']['bindings']['input']['operation_token'] = 'different-business-token'
        with self.assertRaisesRegex(ValueError, 'creation request digest'):
            self.check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', type=Path, required=True)
    arguments, remaining = parser.parse_known_args()
    SPEC = arguments.spec_root
    unittest.main(argv=[sys.argv[0], *remaining])
