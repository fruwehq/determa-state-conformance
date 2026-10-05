# Public client and execution-host protocol (§25)

`host-01-protocol` contains the exact approved specification bytes from commit
`86bb88dd21cb1f799eefe5020b6e49dabf6e7225`: 33 positive messages, 24
negative messages, 15 invalid responses, the public-host-contract manifest and
all four current compatibility change records. The validator checks every canonical request
hash operand, digest, schema, response receipt and nested refusal, and all 101
specification boundary-source SHA-256 fingerprints. The manifest includes all
current schema sources, version-1 hash domains, capability meanings, and helper
participant rules. This validates normative fixtures; it does not certify a
configured reference host or future service.

`run_public_host_profile.py` invokes an adapter that must use the actual public
client and execution host. The adapter reads one canonical JSON object from stdin
with `run_id`, `request`, `transport_context`, and `client_context`. The
runner chooses a fresh `run_id` and requires each native proof to bind it. The latter two are null
unless present in the normative fixture. Its one JSON output has exactly
`response`, `response_bytes_base64`, `transport_error`, `before`, `after`,
`calls`, `transport_attempts`, and `native_proof`. `response_bytes_base64` is the exact wire response
bytes, or null when no protocol response exists. `response` is the
actual protocol response or null. `transport_error` is null when a protocol
response exists, otherwise the precise client/transport outcome. `before` and
`after` are independent complete host observations. Each has lists for
`active_scopes`, `authority_grants`, `credentials`, `checkpoints`,
`host_journals`, `participant_storage`, `staged_archives`,
`public_operation_receipts`, `scope_aliases`, `endpoint_authorities`, and
`timer_records`, plus `composition` bound to the native proof. The two
unauthorized root cases require independent checkpoints proving one named root
exists and the other is absent while their transport denial stays identical.
`calls` counts actual `core_create`, `core_admit`, `core_step`, `effect_dispatch`,
`timer_poll`, `authority_mutation`, `archive_stage`, and `recovery_mutation`
calls. `native_proof` contains the exact generated `run_id`, resolved
`scope_binding_identity`, source/provider/configuration/store/authority/topology
SHA-256 digests, instance identity, and a `claim_proofs` map. Each advertised
operation, action, helper command, Determa capability, enabled guarantee, and
extension claim must have a native proof ID tied to those same fields. Missing,
stale-run, foreign-scope, foreign-store, or omitted-claim evidence fails the run.
`transport_attempts` records the actual endpoint authority, scope binding,
operation ID, and request digest used for each attempt. Lost-response tests
reject alias retargeting and require retry/query to remain on the saved endpoint.
The adapter receives no case ID or expected output. For each of the 15 malformed
responses the runner sends `run_id` and `candidate_response` to the production
client decoder; the adapter returns exactly `accepted: false` and
`error_code: schema_validation`. Its deployment must
prepare the scoped roots, capabilities, binding aliases, endpoint principal,
participants, and saved lost-response operations described by the spec fixtures.
It must use a single configured host instance across each relevant scenario.

The runner compares complete canonical response values, replays every committed
mutation using the identical request and binding, and requires the exact first
wire response bytes on replay. It checks read/refusal nonmutation, prevents replay
from triggering work, and requires observed state change for first commits. A successful run certifies only the actual
injected client/host/storage/provider/configuration combination. A capability
report alone is not evidence of the backing provider, native authority, archive
participants, or topology. Production release claims require independent native
proof for those dependencies, tied to the same configured instance and run.
Portable deterministic closures may compare exact repeat execution; weak or
nondeterministic providers are checked for artifact bytes, retained evidence,
identities, capability reports, and refusals only. No SaaS infrastructure is
required by this profile; a future hosted implementation runs this same suite
for every capability it advertises.

```sh
python scripts/generate_public_host_profile.py --spec-root SPEC --check
python scripts/validate_public_host.py --spec-root SPEC
python scripts/test_public_host_validator.py --spec-root SPEC
python scripts/run_public_host_profile.py --spec-root SPEC -- ADAPTER
```

The first three commands require the exact approved specification checkout from the current repository spec pin. The last
command requires a production adapter and provisioned host. There is no fixture
response adapter in this repository.
