#!/usr/bin/env python3
"""Run §21 vectors through a production adapter command, withholding all oracles."""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path

from validate_conformance import analyze_json_artifact_source, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/lossless-delivery/delivery-01-source-transfer'


def strict_document(source: bytes, label: str) -> dict:
    analysis = analyze_json_artifact_source(source)
    if analysis.error or not isinstance(analysis.document, dict):
        raise ValueError(f'{label}: invalid strict UTF-8 JSON: {analysis.error}')
    return analysis.document


def expanded(store: dict, checkpoints: dict[str, dict]) -> dict:
    return {**store, 'checkpoint': checkpoints[store['checkpoint']]}


def run(command: list[str], case: Path = CASE) -> int:
    manifest = strict_document((case / 'delivery-vectors-v1.json').read_bytes(), 'manifest')
    checkpoints = {path.name: strict_document(path.read_bytes(), path.name)
                   for path in case.glob('*-checkpoint-v1.json')}
    machines = {'ingress': (case / 'machine.yaml').read_text(encoding='utf-8'),
                'outbound': (case / 'outbox-machine.yaml').read_text(encoding='utf-8')}
    count = 0
    for vector in manifest['vectors'] + manifest['invalid_vectors']:
        negative = 'candidate' in vector
        request = {'operation': vector['operation'],
                   'input': vector['candidate'] if negative else vector['request'],
                   'before': expanded(vector['before'], checkpoints),
                   'fault_injection': None if negative else vector['fault_injection'],
                   'machine_source': machines}
        if 'authority_context' in vector:
            request['authority_context'] = vector['authority_context']
        if 'ordering_context' in vector:
            request['ordering_context'] = vector['ordering_context']
        completed = subprocess.run(command, input=canonical_json_bytes(request),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)
        expected_response = ({'kind': 'typed_failure',
                              'code': vector['expected_failure'],
                              'acknowledge_source': False}
                             if negative else vector['expected_response'])
        if expected_response == {'kind': 'no_response'}:
            if completed.stdout or completed.returncode == 0:
                raise AssertionError(f'{vector["name"]}: crash cut returned a response')
            count += 1
            continue
        if completed.returncode:
            raise AssertionError(f'{vector["name"]}: adapter exited {completed.returncode}')
        observed = strict_document(completed.stdout, vector['name'])
        if set(observed) != {'response', 'after'}:
            raise AssertionError(f'{vector["name"]}: adapter must return response and complete after store')
        expected = {'response': expected_response,
                    'after': expanded(vector['after'], checkpoints)}
        if canonical_json_bytes(observed) != canonical_json_bytes(expected):
            raise AssertionError(f'{vector["name"]}: response or complete store differs')
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--adapter', required=True,
                        help='command that reads one strict JSON request on stdin')
    args = parser.parse_args()
    count = run(shlex.split(args.adapter))
    print(f'passed {count} production lossless delivery vectors')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
