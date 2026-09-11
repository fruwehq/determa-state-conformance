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

Generate and verify deterministic artifacts with:

```sh
python scripts/generate_execution_checkpoint_profile.py
python scripts/generate_execution_checkpoint_profile.py --check
python scripts/generate_version2_vectors.py --check
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```
