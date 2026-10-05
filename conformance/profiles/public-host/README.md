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
from triggering work, and requires observed state change for first commits.
Committed responses must match exactly one independently observed retained
`public_operation_receipts` record with `scope_binding_identity`, `operation_id`,
`request_digest`, and `response_bytes_base64`. Returned checkpoints must match
the complete checkpoint in the observer's `checkpoints` list. First core
create/admit/process commits require one corresponding actual core call.
Replay must begin at the first call's complete after-state, including composition.
Read-only authority and timer commands, refusals, and replays permit none of the
eight active-work counters to advance.

A successful run establishes protocol observations only. The adapter's
`native_proof` fields are correlation metadata: checking internally consistent
digests and proof IDs does not independently execute or certify a capability.
Configured native capability certification remains unmet until separate reviewed
operational gates execute against the same configured implementation and
topology. This includes the execution-store native gate mapping described in
the [checkpoint profile](../execution-checkpoint/README.md), plus the native
authority, helper, archive and recovery gates for every advertised operation.
The native tests and independent observer implementation require source review;
an adapter-generated expected response or proof ID is never a substitute.
Portable deterministic closures may compare exact repeat execution; weak or
nondeterministic providers are checked for artifact bytes, retained evidence,
identities, capability reports, and refusals only. No SaaS infrastructure is
required by this profile; a future hosted implementation runs this same suite
for every capability it advertises.

```sh
python scripts/generate_public_host_profile.py --spec-root SPEC --check
python scripts/validate_public_host.py --spec-root SPEC
python scripts/test_public_host_validator.py --spec-root SPEC
python scripts/test_public_host_runner.py
python scripts/run_public_host_profile.py --spec-root SPEC -- ADAPTER
```

The first three commands require the exact approved specification checkout from the current repository spec pin. The last
command requires a production adapter and provisioned host. There is no fixture
response adapter in this repository.
