# Execution-checkpoint durable host profile

This optional profile binds hosts that implement the portable schema-version-1
execution checkpoint from SPEC section 17. It fixes durable transaction outcomes and
before/after bytes without standardizing a language API, database schema, worker,
daemon, socket, broker, or command-line surface.

The profile covers:

- checkpoint creation, input admission, processing, durable receipts, exact replay,
  conflict ordering, stale writers, and crashes on both sides of commit;
- every pending and terminal outbox state, equal-state replay, effect tombstones,
  conflict handling, and dependency-safe deletion refusal;
- bounded pruning, irreversible retention history, root tombstones, root no-reuse,
  adapter registration, composed capabilities, and logical store isolation;
- native admission, processing, replay, pruning, and tombstoning with schema-version-1
  mailbox and receipt identities;
- owned spawned-runtime and terminal spawned-runtime host traces; and
- keyed maintenance migration, including empty, one-hop, two-hop, sequential,
  replay, conflict, stale-writer, retention, and tombstoned-root cases.

Every maintenance receipt retains `target_validated_bundle_fingerprint`. Maintenance
requests retain a non-empty operation identity and the exact ordered descriptor digest
route. Replay and operation-identity conflict are resolved before the writer revision
and checkpoint-digest comparison.

Every durable vector also names one required `raw_response` artifact. Production
operation vectors invoke the complete request on the production host and record the complete
operation-local return or directly caught typed error in the closed
`durable-host-responses-v1` driver serialization. It must capture the return from that
call: it may not inspect persisted after-state, read a golden file, or switch on vector
name to fabricate a response. The after checkpoint or store snapshot, outcome,
mutation, core-call count, and broker acknowledgement are separate observations.
Fixture generation derives expected response values from independent retained golden
evidence; repository validation cross-binds the response to request identity and that
evidence. This serialization is a test-driver contract, not a required language API.

The 26 registration, resolution and composed-profile probes classified below instead
exercise shared production **decision functions under hypothetical premises**. Their
raw returns remain exact and required, but are not configured-instance evidence.

The response union retains every normative returned field used by these operations:

| Operation | Complete normalized response value |
|---|---|
| creation, pending outbox update, terminal outbox transition, root tombstone | Exact SPEC §17 literal receipt, record, terminal record, or tombstone body; first and equal replay use the same body. |
| admission | Ordered acceptance receipts or retained event-identity tombstone evidence for every requested member. |
| processing | Full §16 core step result, including state, disposition, emissions, lifecycle dispositions, fault, and rejection, plus the committed terminal receipt. An equal terminal step retry returns only its retained terminal receipt, without calling core. First-commit persistence processing also retains migration audit records; its equal retry returns the retained terminal receipt without a core call. |
| conditional adapter registration/resolution and capability policy | The exact registration, selected registration/configuration, or composed-policy decision returned by the shared production decision function under the stipulated premises. No configured store or operational guarantee follows. |
| store injection, scope operation | The exact injected adapter reference or authorized scope record returned by the operation. The injection acknowledgment alone proves no configured capability. |
| pruning, compaction, backup/restore, quarantine release | The operation's direct committed, replayed, validated, or released acknowledgement; persisted bytes are checked separately. |
| rejection, quarantine, crash | Direct typed code, typed code plus quarantine record, or explicit no response. |

For host calls without a literal SPEC return object, the table defines the local
wrapper's complete normalized value for these probes. It does not require a production
API to return full checkpoints or store snapshots. A wrapper may serialize its own
production call's return value and typed error fields; it must not reconstruct one
from the post-commit store. Missing or extra body fields and a schema-valid response
from a different request fail validation.

Profile requests, results, store snapshots, and call logs use dedicated closed schemas
under `scripts/schemas/`. Checkpoint and aggregate members use only the specification's
schema-version-1 formats. Machine documents continue to use integer `format: 1` because
machine grammar and portable artifact schema versions are separate domains.

`durable-host-inputs-v1.schema.json` is a closed operation-tagged union. Each request
contains the complete driver input for its operation: selected and authorized scope;
bundle, machine, bindings, and creation identities; a canonical ordered admission
`envelopes` batch with each exact source, target, mode, payload, correlation, and
digest; selected pending input; one outbox effect and disposition; pruning cutoff,
mode, and dependencies; adapter registration or configuration; composed capabilities;
or the complete persistence transaction input. There is no generic parameter map and
replay repeats the original operation request.

Each replay vector names an earlier atomic first operation with the closed
`replay_of` relation. The caller request is byte-identical after normalization, including scope, operation
identity, digest, transaction inputs, and the original checkpoint revision/digest.
A retry does not acquire a fresh caller precondition. The host reads the current
checkpoint or store independently; the vector names it as `checkpoint_before` or
`store_before`. A stale-writer vector additionally names the committed store artifact
as `stored_checkpoint_before`, distinct from the presented `checkpoint_before`.
These are driver observations, never extra caller request fields. The validator checks
the first atomic commit, retained identity evidence, unchanged replay state, and
replay before stale compare-and-swap failure. It rejects a changed caller request,
a missing first commit, or missing current receipt/idempotency evidence.

The vector's `failure_boundary` is a one-attempt host fault injection. In particular,
a post-commit lost response does not alter `transaction_inputs.failure_policy`;
redelivery repeats that exact caller transaction input after the one-shot fault clears.

The repository validator derives operation-specific invariants from those requests. It
requires each first writer's request checkpoint identity to equal its
`checkpoint_before` and each replay's identity to equal the first writer's original
checkpoint and binds canonical envelope digests, ordered allocation, targets,
receipts, effects, the creation receipt digest computed from the literal request,
disposition, retention transition, store inbox, and application writes to the named
before/after artifacts. Creation commits revision `0`; each admission, processing,
outbox, pruning, or tombstone mutation advances exactly one revision; the combined
persistence migration, admission, processing, inbox, outbox, audit, and application
write transaction advances exactly one revision. A golden from
another request is therefore not interchangeable even when it is schema-valid.
Deletion-refusal vectors use an explicit retained-record deletion operation with a
stable operation identity and a typed target. The validator derives refusal from the
targeted retained root identity or referenced effect tombstone, rather than from test
names, coverage labels, or expected result codes.

The complete host-contract case additionally covers creation rejection, pending and
terminal replay precedence, handled/unhandled/rejected/faulted delivery, foreground
and delayed equivalence, concurrent writer exclusion, dependency variants, both
retention modes, complete backup/restore, direct store injection, public adapter
registration and resolution, backend capability boundaries, positive and negative
composed profiles derived from the exact `host_profile`, exact adapter identifier and
URI-scheme grammar, and relational logical-scope isolation for equal portable
identities/effects with separate store records.

## Conditional adapter decisions and native evidence

Exactly 26 vectors carry `evidence_layer: conditional_adapter_policy`: the public
registry and capability-composition probes in checkpoint-03, and all four
registration, eight resolution and twelve composed-profile probes in checkpoint-07.
The closed vector schema requires this marker for exactly
`checkpoint_register_adapter_v1`, `checkpoint_resolve_adapter_v1`, and
`checkpoint_validate_capabilities_v1`. An independent case/name inventory rejects
deleted, substituted or duplicated probes even if their coverage labels survive.
No production processing operation may acquire this marker.

These probes supply stipulated descriptors, configuration and capability/feature
premises. In particular, `postgresql://db/state` is hypothetical configuration,
not a live service. The implementation harness must call the same production
registration, URI-selection, configuration and requirement decision functions used
by its public registry, through an internal seam that returns only policy decisions.
It must capture each function's actual complete return or typed error. A test-only
interpreter, reconstructed golden response, or operational store/verified handle
created from these premises fails the contract. Policy decisions never grant
capabilities and cannot be accepted as public verification input.

Run the isolated comparison gate with:

```sh
python scripts/run_adapter_policy_profile.py --adapter <implementation-policy-harness>
```

The adapter receives only `evidence_layer` and the complete request. It receives no
case name, coverage label, fixture path, expected response or after-state. It returns
exactly `raw_response`, `root_accesses`, and `operational_handles_created`. The latter
two are integer zero, measured by the reviewed harness at actual root-access and
handle-construction boundaries, not inferred from expected outcomes. Corrupting a
production decision function's return must fail this gate. Existing engine harnesses
must continue to compare production durable first/replay returns and persisted bytes
exactly; policy classification is not a waiver for any of those operations.

Configured claims require separate public and native evidence. The public registry
must verify the executing provider closure, effective configuration, exact native
instance and current health before root access. Bundled and third-party providers
use the same public path; URI schemes remain lookup hints distinct from provider
identity. Direct injection needs the same verification. The checkpoint-07
`direct_store_injection` acknowledgment, with its stipulated capability list, cannot
discharge any native gate.

`scripts/adapter_evidence.py` defines the closed operational assertion inventory.
It can be read as JSON with:

```sh
python scripts/run_execution_store_gates.py --inventory
```

The foundation gates cover public registration/selection (including `vendor+https`,
duplicate/unknown registrations and direct injection), executing-source identity,
actual configured-instance binding, current health and forged-evidence rejection
before any root load/create/process. Every positive native claim depends on these
foundation checks. Memory/file behavior, actual SQLite transactions/configuration,
and live PostgreSQL transactions/concurrency/configuration have separate gates.
Composed claims additionally require the actual durable-processing, retention,
broker, strict/compact-outbox or shared-transaction behavior named by their gate;
a store alone never supplies an ingress, worker or application participant.

Each engine checks in a reviewed mapping from **every** gate ID to actual native test
entry points. To complete this full adapter-integration audit, run:

```sh
python scripts/run_execution_store_gates.py \
  --implementation-root <engine-checkout> --mapping <engine-gate-map.json>
```

The closed map has `gates` (gate ID to nonempty list of exact JUnit
`classname::name` selectors) and `runs` (nonempty list of objects with `command`,
`report`, `required_environment`). Commands are argument arrays executed without a
shell in the engine checkout. Each command includes a literal `{report}` placeholder,
replaced by a fresh private output path. `report` is a relative name, such as
`postgresql.xml`; `required_environment` lists service configuration variable names,
never secret values. A Rust test wrapper may normalize actual cargo test execution to
JUnit, but must preserve each real test identity and all ignored/failed outcomes.
No expected-output simulator or arbitrary `passed: true` document is evidence.

Mappings and test bodies are reviewed source code. Multiple gates may share a test
only when it independently asserts every mapped obligation; listing an unrelated
passing test is not conforming. Test commands must actually execute the mapped native
tests, not manufacture reports. The runner requires fresh command execution, successful
exit, every mapped test, and no failures, skips, disabled tests or duplicate identities.
Missing/unknown/duplicate mappings, absent services, omitted reports, and unexecuted
tests leave the audit unmet. PostgreSQL tests must fail when the service is absent;
they cannot convert service absence to a skip or hypothetical success. Native test
assertions must observe real SQLite/PostgreSQL rows and transaction outcomes.

The full audit requires all listed gates. Implementations declaring a smaller optional
surface may separately prove only that surface, but cannot report this full audit as
complete. CI test success does not create production verification flags: production
code still checks each actual configured instance, health and topology at use. Final
release evidence records reviewed mapping/test sources, exact implementation and
conformance commits, service/configuration identity and native run logs. Until the
Python and Rust mappings and native runs pass, verified adapter integration remains
incomplete even when all 26 conditional probes pass.

Generate and verify deterministic artifacts with:

```sh
python scripts/generate_execution_checkpoint_profile.py
python scripts/generate_execution_checkpoint_profile.py --check
python scripts/generate_version1_vectors.py --check
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```
