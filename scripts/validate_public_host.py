"""Validate the pinned §25 public message and compatibility boundary fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator, validators as jsonschema_validators
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from validate_portable_archive import canonical, digest, parse_json_bytes

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / 'conformance/profiles/public-host/host-01-protocol'
SOURCES = {
    'positive-v1.json': 'examples/public-host/positive-v1.json',
    'negative-v1.json': 'examples/public-host/negative-v1.json',
    'public-host-contract-v1.json': 'schema/public-host-contract-v1.json',
    'compatibility-change-v1.json': 'examples/public-host/compatibility-change-v1.json',
    'source-order-compatibility-change-v1.json': 'examples/public-host/source-order-compatibility-change-v1.json',
    'timer-evidence-compatibility-change-v1.json': 'examples/public-host/timer-evidence-compatibility-change-v1.json',
    'provider-correlation-compatibility-change-v1.json': 'examples/public-host/provider-correlation-compatibility-change-v1.json',
    'native-slot-identities-compatibility-change-v1.json': 'examples/public-host/native-slot-identities-compatibility-change-v1.json',
}
SPEC_PIN = '77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0'


def strict_const(validator, expected, instance, schema):
    if type(expected) is not type(instance) or expected != instance:
        yield ValidationError(f'expected exact constant {expected!r}')


StrictValidator = jsonschema_validators.extend(Draft202012Validator, {'const': strict_const})

class PublicHostValidationError(ValueError):
    pass


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise PublicHostValidationError(detail)


def load(path: Path):
    return parse_json_bytes(path.read_bytes(), str(path))


def validators(spec_root: Path):
    resources = []
    for path in (spec_root / 'schema').glob('*.schema.json'):
        schema = load(path)
        Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        resources.append((path.name, resource))
        if '$id' in schema:
            resources.append((schema['$id'], resource))
    registry = Registry().with_resources(resources)
    return {name: StrictValidator(load(spec_root / 'schema' / f'{name}-v1.schema.json'), registry=registry)
            for name in ('public-host-request', 'public-host-response', 'public-host-contract', 'public-host-change-record')}


def schema_ok(validator, value, label: str) -> None:
    errors = list(validator.iter_errors(value))
    require(not errors, f'{label}: {errors[0].message if errors else "schema failure"}')


def request_hash(case: dict, label: str) -> None:
    operand = canonical(['determa-public-host-request-digest-1', '1', case['request']])
    require(case['request_hash_operand_jcs'].encode() == operand, f'{label}: request operand')
    require(case['request_digest'] == 'sha256:' + hashlib.sha256(operand).hexdigest(), f'{label}: request digest')


def check_response(request: dict, request_digest: str, response: dict, label: str) -> None:
    require(response['operation_id'] == request['operation_id'], f'{label}: response operation ID')
    status = response['status']
    receipt = response['receipt']
    if status == 'committed':
        require(response['value']['operation'] == request['operation'], f'{label}: value operation')
    if status == 'rejected':
        require(response['error']['operation'] == request['operation'], f'{label}: error operation')
        for nested, code_field in (('authority_result', 'error_code'), ('effect_result', 'error_code'),
                                   ('cancellation_result', 'error_code'), ('timer_result', 'error_code'),
                                   ('archive_result', 'code'), ('recovery_result', 'code')):
            value = response['error'].get(nested)
            if value is not None:
                require(value[code_field] == response['error']['code'], f'{label}: nested refusal code')
    if receipt is not None:
        require(status in ('committed', 'pending'), f'{label}: receipt status')
        require(receipt['scope_binding_identity'] == request['scope_binding_identity'], f'{label}: receipt binding')
        require(receipt['operation_id'] == request['operation_id'], f'{label}: receipt identity')
        require(receipt['request_digest'] == request_digest, f'{label}: receipt request digest')
        if status == 'committed':
            require(receipt['receipt_kind'] == 'committed', f'{label}: committed receipt kind')
            require(receipt['evidence_digest'] == digest(['determa-public-host-evidence-1', '1', response['value']]),
                    f'{label}: evidence digest')
        else:
            require(receipt['receipt_kind'] == 'accepted', f'{label}: pending receipt kind')
            require(receipt['evidence_digest'] == digest(['determa-public-host-acceptance-evidence-1', '1',
                    receipt['scope_binding_identity'], receipt['operation_id'], request_digest,
                    receipt['acceptance_receipt']]), f'{label}: acceptance evidence digest')
    if status == 'committed' and request['operation'] == 'capabilities':
        report = response['value']['result']
        unsigned = dict(report)
        unsigned.pop('profile_digest')
        require(report['profile_digest'] == digest(['determa-public-host-profile-1', '1',
                report['scope_binding_identity'], unsigned]), f'{label}: capability profile digest')
        if request['scope_binding_identity'] is not None:
            require(report['scope_binding_identity'] == request['scope_binding_identity'],
                    f'{label}: capability scope remapped')
    if status == 'committed' and request['operation'] == 'process':
        disposition = response['value']['result']['core_result']['disposition']
        if disposition in ('handled', 'deferred', 'unhandled', 'faulted'):
            require(receipt is not None, f'{label}: processed event has no public receipt')
    if request['operation'] in ('read', 'inspect'):
        require(status != 'committed' or receipt is None, f'{label}: read mutated')
    if status == 'committed' and request['operation'] in ('create', 'admit', 'effect_result', 'cancel_effect'):
        require(receipt is not None, f'{label}: mutation receipt missing')


def check_manifest(spec_root: Path, manifest: dict, records: list[dict], vv: dict) -> None:
    schema_ok(vv['public-host-contract'], manifest, 'boundary manifest')
    require({record['issue'] for record in records} == {'96', '104', '106', '108', '110'},
            'required public compatibility change records absent')
    for record in records:
        schema_ok(vv['public-host-change-record'], record, 'change record')
    sources = manifest['boundary_sources']
    paths = [item['path'] for item in sources]
    require(len(paths) == len(set(paths)), 'duplicate boundary source')
    required = {'SPEC.md', 'VERSION', *(str(p.relative_to(spec_root)) for p in (spec_root / 'schema').glob('*.schema.json'))}
    require(required <= set(paths), 'boundary manifest omits a schema or primary source')
    for item in sources:
        path = spec_root / item['path']
        require(path.is_file(), f'missing boundary source {path}')
        actual = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
        require(actual == item['sha256'], f'boundary source drift: {item["path"]}')
    for field in ('hash_domains', 'capability_meanings', 'helper_participant_rules'):
        names = [entry.get('name', entry.get('kind')) for entry in manifest[field]]
        require(len(names) == len(set(names)), f'duplicate {field}')
    require({'determa-public-host-request-digest-1', 'determa-public-host-evidence-1',
             'determa-public-host-acceptance-evidence-1', 'determa-public-host-profile-1'} <=
            {entry['name'] for entry in manifest['hash_domains']}, 'public hash domains absent')
    protocol_fingerprint = 'sha256:' + hashlib.sha256(
        (spec_root / 'schema/public-host-request-v1.schema.json').read_bytes() +
        (spec_root / 'schema/public-host-response-v1.schema.json').read_bytes()).hexdigest()
    manifest_fingerprint = 'sha256:' + hashlib.sha256(
        (spec_root / 'schema/public-host-contract-v1.json').read_bytes()).hexdigest()
    for record in records:
        require(record['proposed_protocol_fingerprint'] == protocol_fingerprint,
                f'issue {record["issue"]}: protocol fingerprint drift')
        require(record['manifest_fingerprint'] == manifest_fingerprint,
                f'issue {record["issue"]}: manifest fingerprint drift')
        require({row['consumer'] for row in record['cross_language_fixture_matrix']} ==
                {'Python embedded client', 'Rust embedded client', 'local reference host', 'future hosted service'},
                f'issue {record["issue"]}: cross-language review matrix incomplete')


def validate_profile(spec_root: Path, *, enforce_source: bool = True) -> tuple[int, int, int]:
    if enforce_source and (spec_root / '.git').exists():
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=spec_root,
                                  capture_output=True, text=True, check=True).stdout.strip()
        require(revision == SPEC_PIN, f'public specification revision {revision} differs from {SPEC_PIN}')
    if enforce_source:
        for local, source in SOURCES.items():
            require((CASE / local).read_bytes() == (spec_root / source).read_bytes(), f'{local}: spec pin drift')
    vv = validators(spec_root)
    positive, negative = load(CASE / 'positive-v1.json'), load(CASE / 'negative-v1.json')
    manifest = load(CASE / 'public-host-contract-v1.json')
    records = [load(CASE / name) for name in SOURCES if 'compatibility-change' in name]
    check_manifest(spec_root, manifest, records, vv)
    require(positive['schema_version'] == negative['schema_version'] == 1, 'fixture version')
    for label, cases in (('positive', positive['cases']), ('negative', negative['cases'])):
        names = [case['name'] for case in cases]
        require(len(names) == len(set(names)), f'duplicate {label} case')
        for case in cases:
            name = f'{label}/{case["name"]}'
            request_hash(case, name)
            error = list(vv['public-host-request'].iter_errors(case['request']))
            if label == 'positive':
                require(not error, f'{name}: invalid request {error[0].message if error else ""}')
                schema_ok(vv['public-host-response'], case['response'], name)
                check_response(case['request'], case['request_digest'], case['response'], name)
            else:
                expected = case['expected_response']
                if expected is not None:
                    require(not error, f'{name}: expected semantic refusal has malformed request')
                    schema_ok(vv['public-host-response'], expected, name)
                    check_response(case['request'], case['request_digest'], expected, name)
                    require(expected['error']['code'] == case['expected_error'] if expected['status'] == 'rejected'
                            else case['expected_error'] == 'replay_evidence_expired', f'{name}: refusal code')
                else:
                    require(case['expected_error'] in ('invalid_request', 'transport_access_denied',
                        'client_binding_mismatch', 'transport_outcome_unknown'), f'{name}: no-response reason')
    operations = {case['request']['operation'] for case in positive['cases']}
    actions = {case['request']['arguments']['action'] for case in positive['cases']
               if case['request']['operation'] == 'scope_operation'}
    timer_commands = {case['request']['arguments']['timer_request']['operation']
                      for case in positive['cases'] if case['request']['operation'] == 'timer_command'}
    for case in positive['cases']:
        if case['request']['operation'] != 'capabilities':
            continue
        report = case['response']['value']['result']
        require(set(report['supported_operations']) <= operations,
                f'{case["name"]}: advertised operation lacks positive matrix call')
        require(set(report['supported_scope_actions']) <= actions,
                f'{case["name"]}: advertised scope action lacks positive matrix call')
        require(set(report['supported_timer_commands']) <= timer_commands,
                f'{case["name"]}: advertised timer command lacks positive matrix call')
    for case in negative['invalid_responses']:
        require(list(vv['public-host-response'].iter_errors(case['response'])),
                f'{case["name"]}: invalid response accepted')
    return len(positive['cases']), len(negative['cases']), len(negative['invalid_responses'])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec-root', required=True, type=Path)
    args = parser.parse_args()
    print('%s positive, %s negative, %s malformed responses' % validate_profile(args.spec_root))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
