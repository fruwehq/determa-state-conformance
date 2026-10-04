#!/usr/bin/env python3
"""Adversarial §19 fixture and adapter boundary tests."""
from __future__ import annotations

import argparse
import copy
import json
import runpy
import unittest
from pathlib import Path

import rfc8785

from committed_native_effects_validator import CASE, strict_json, validate_profile
from run_committed_native_effects_profile import check_observation

SPEC = Path(__file__).resolve().parents[2] / 'determa-state-spec'


class CommittedEffectsValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = strict_json((CASE / 'data/vectors.json').read_bytes())
        cls.artifacts = {path.name: strict_json(path.read_bytes()) for path in CASE.glob('*checkpoint.json')}
        cls.artifacts.update({'data/' + path.name: strict_json(path.read_bytes())
                              for path in (CASE / 'data').glob('*.json') if path.name != 'vectors.json'})

    def observation(self, vector):
        request, expected = vector['request'], vector['expected']
        serial = lambda name: rfc8785.dumps(self.artifacts[name]).decode('utf-8')
        response = expected['response']
        return {'response_utf8': serial(response) if response else '{}',
                'checkpoint_before_utf8': serial(request['checkpoint_before']),
                'checkpoint_after_utf8': serial(expected['checkpoint_after']),
                'journal_before_utf8': serial(request['journal_before']),
                'journal_after_utf8': serial(expected['journal_after']),
                'provider_calls': [{'reference': 'fixture-call'}] * expected['counts']['provider_calls'],
                'core_calls': [{'operation': 'fixture-call'}] * expected['counts']['core_calls'],
                'new_claims': [{'fence': '1'}] * expected['counts']['new_claims'],
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

    def test_source_and_artifact_gate(self):
        self.assertEqual(validate_profile(SPEC), 36)

    def test_all_complete_oracles_accept_matching_observations(self):
        for vector in self.manifest['vectors']:
            with self.subTest(vector=vector['name']):
                check_observation(vector, self.observation(vector), self.artifacts)

    def test_strict_json_decoder(self):
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff'):
            with self.assertRaises((ValueError, UnicodeDecodeError)):
                strict_json(body)

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
