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

Every durable vector also names one required `raw_response` artifact. The runner
invokes the complete request on the production host and records the complete
operation-local return or directly caught typed error in the closed
`durable-host-responses-v1` driver serialization. It must capture the return from that
call: it may not inspect persisted after-state, read a golden file, or switch on vector
name to fabricate a response. The after checkpoint or store snapshot, outcome,
mutation, core-call count, and broker acknowledgement are separate observations.
Fixture generation derives expected response values from independent retained golden
evidence; repository validation cross-binds the response to request identity and that
evidence. This serialization is a test-driver contract, not a required language API.

The response union retains every normative returned field used by these operations:

| Operation | Complete normalized response value |
|---|---|
| creation, pending outbox update, terminal outbox transition, root tombstone | Exact SPEC §17 literal receipt, record, terminal record, or tombstone body; first and equal replay use the same body. |
| admission | Ordered acceptance receipts or retained event-identity tombstone evidence for every requested member. |
| processing | Full §16 core step result, including state, disposition, emissions, lifecycle dispositions, fault, and rejection, plus the committed terminal receipt. An equal terminal step retry returns only its retained terminal receipt, without calling core. First-commit persistence processing also retains migration audit records; its equal retry returns the retained terminal receipt without a core call. |
| adapter registration/resolution, capability validation, store injection, scope operation | The exact registration, resolved registration and configuration, configured capability report, injected adapter reference, or authorized scope record returned by the adapter. |
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

Generate and verify deterministic artifacts with:

```sh
python scripts/generate_execution_checkpoint_profile.py
python scripts/generate_execution_checkpoint_profile.py --check
python scripts/generate_version1_vectors.py --check
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```
