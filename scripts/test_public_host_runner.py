"""Adversarial checks of public-host protocol observations; no native certification."""
from __future__ import annotations

import base64
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from run_public_host_profile import CALLS, STATE_LISTS, run_case
from validate_portable_archive import canonical
from validate_public_host import CASE, load


class PublicHostRunnerTests(unittest.TestCase):
    def observation(self, name, negative=False):
        cases = load(CASE / ('negative-v1.json' if negative else 'positive-v1.json'))['cases']
        case = next(item for item in cases if item['name'] == name)
        request = case['request']
        response = case['expected_response'] if negative else case['response']
        binding = request['scope_binding_identity']
        composition = {'scope_binding_identity': binding, 'instance_identity': 'host-1'}
        composition.update({key: 'sha256:' + '1' * 64 for key in (
            'source_digest', 'provider_digest', 'configuration_digest',
            'store_digest', 'authority_digest', 'topology_digest')})
        proof = {'run_id': 'test-run', **composition}
        claims = {request['operation']}
        if request['operation'] == 'scope_operation':
            claims.add(request['arguments']['action'])
        if request['operation'] == 'timer_command':
            claims.add(request['arguments']['timer_request']['operation'])
        proof['claim_proofs'] = {claim: {**proof, 'proof_id': claim} for claim in claims}
        state = {key: [] for key in STATE_LISTS}
        state['composition'] = composition
        observation = {
            'response': response,
            'response_bytes_base64': None if response is None else base64.b64encode(canonical(response)).decode(),
            'transport_error': case['expected_error'] if negative and response is None else None,
            'before': copy.deepcopy(state), 'after': copy.deepcopy(state),
            'calls': dict.fromkeys(CALLS, 0), 'native_proof': proof,
            'transport_attempts': [{'endpoint_authority': 'local',
                'scope_binding_identity': binding, 'operation_id': request['operation_id'],
                'request_digest': case['request_digest']}],
        }
        return case, observation

    def execute(self, case, observation, negative=False, **kwargs):
        result = SimpleNamespace(returncode=0, stderr=b'', stdout=canonical(observation))
        with patch('run_public_host_profile.subprocess.run', return_value=result):
            return run_case(['adapter'], case, negative, 'test-run', **kwargs)

    def test_nested_reads_reject_state_changes_and_all_active_calls(self):
        for name in ('timer_read_timer', 'authority_scope_read'):
            case, original = self.observation(name)
            self.execute(case, original)
            altered = copy.deepcopy(original)
            altered['after']['credentials'].append({'unexpected': True})
            with self.assertRaisesRegex(ValueError, 'changed host state'):
                self.execute(case, altered)
            for counter in CALLS:
                altered = copy.deepcopy(original)
                altered['calls'][counter] = 1
                with self.assertRaisesRegex(ValueError, 'active work'):
                    self.execute(case, altered)

    def test_refusals_reject_timer_and_authority_work(self):
        for name in ('authority_stale_epoch_nested_refusal', 'timer_clock_unavailable'):
            case, original = self.observation(name, True)
            self.execute(case, original, True)
            for counter in CALLS:
                altered = copy.deepcopy(original)
                altered['calls'][counter] = 1
                with self.assertRaisesRegex(ValueError, 'active work'):
                    self.execute(case, altered, True)

    def committed_create(self):
        case, observed = self.observation('create_committed')
        observed['calls']['core_create'] = 1
        observed['after']['checkpoints'] = [case['response']['value']['result']['checkpoint']]
        observed['after']['public_operation_receipts'] = [{
            'scope_binding_identity': case['response']['receipt']['scope_binding_identity'],
            'operation_id': case['request']['operation_id'],
            'request_digest': case['request_digest'],
            'response_bytes_base64': observed['response_bytes_base64'],
        }]
        return case, observed

    def test_commit_requires_linked_receipt_checkpoint_and_core_call(self):
        case, observed = self.committed_create()
        self.execute(case, observed)
        for key in ('checkpoints', 'public_operation_receipts'):
            altered = copy.deepcopy(observed)
            altered['after'][key] = []
            altered['after']['credentials'].append({'unrelated': True})
            with self.assertRaises(ValueError):
                self.execute(case, altered)
        altered = copy.deepcopy(observed)
        altered['calls']['core_create'] = 0
        with self.assertRaisesRegex(ValueError, 'actual core call'):
            self.execute(case, altered)

    def test_replay_requires_continuous_state_and_instance(self):
        case, first = self.committed_create()
        first_bytes, first_after = self.execute(case, first)
        replay = copy.deepcopy(first)
        replay['before'] = copy.deepcopy(first_after)
        replay['calls'] = dict.fromkeys(CALLS, 0)
        replay_bytes, _ = self.execute(case, replay, replay=True, previous_after=first_after)
        self.assertEqual(first_bytes, replay_bytes)
        altered = copy.deepcopy(replay)
        altered['before']['credentials'].append({'foreign': True})
        altered['after'] = copy.deepcopy(altered['before'])
        with self.assertRaisesRegex(ValueError, 'not continuous'):
            self.execute(case, altered, replay=True, previous_after=first_after)
        with self.assertRaisesRegex(ValueError, 'not continuous'):
            self.execute(case, replay, replay=True)


if __name__ == '__main__':
    unittest.main()
