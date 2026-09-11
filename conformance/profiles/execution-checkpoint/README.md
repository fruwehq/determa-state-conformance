# Execution-checkpoint durable host profile

This optional profile binds hosts that implement the portable schema-version-2
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
- native admission, processing, replay, pruning, and tombstoning with schema-version-2
  mailbox and receipt identities;
- owned spawned-runtime and terminal spawned-runtime host traces; and
- keyed maintenance migration, including empty, one-hop, two-hop, sequential,
  replay, conflict, stale-writer, retention, and tombstoned-root cases.

Every maintenance receipt retains `target_validated_bundle_fingerprint`. Maintenance
requests retain a non-empty operation identity and the exact ordered descriptor digest
route. Replay and operation-identity conflict are resolved before the writer revision
and checkpoint-digest comparison.

Profile requests, results, store snapshots, and call logs use dedicated closed schemas
under `scripts/schemas/`. Checkpoint and aggregate members use only the specification's
schema-version-2 formats. Machine documents continue to use integer `format: 1` because
machine grammar and portable artifact schema versions are separate domains.

`durable-host-inputs-v2.schema.json` is a closed operation-tagged union. Each request
contains the complete driver input for its operation: selected and authorized scope;
bundle, machine, bindings, and creation identities; canonical admission envelope and
target; selected pending input; one outbox effect and disposition; pruning cutoff,
mode, and dependencies; adapter registration or configuration; composed capabilities;
or the complete persistence transaction input. There is no generic parameter map and
replay repeats the original operation request.

The repository validator derives operation-specific invariants from those requests. It
binds checkpoint identity, canonical envelope digest, target, receipt, effect,
disposition, retention transition, store inbox, and application writes to the named
before/after artifacts. Creation commits revision `0`; each admission, processing,
outbox, pruning, or tombstone mutation advances exactly one revision; the combined
persistence admission-and-processing transaction advances exactly two. A golden from
another request is therefore not interchangeable even when it is schema-valid.

The complete host-contract case additionally covers creation rejection, pending and
terminal replay precedence, handled/unhandled/rejected/faulted delivery, foreground
and delayed equivalence, concurrent writer exclusion, dependency variants, both
retention modes, complete backup/restore, direct store injection, public adapter
registration and resolution, backend capability boundaries, positive and negative
composed profiles, and logical-scope isolation for equal portable identities/effects.

Generate and verify deterministic artifacts with:

```sh
python scripts/generate_execution_checkpoint_profile.py
python scripts/generate_execution_checkpoint_profile.py --check
python scripts/generate_version2_vectors.py --check
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```
