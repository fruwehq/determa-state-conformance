# Execution-checkpoint maintenance profile

This optional profile binds hosts that support the portable schema-version-2
execution checkpoint and its maintenance migration operation from SPEC section 17. It
does not standardize a language API, database schema, worker, daemon, socket, broker,
or command-line surface.

The profile contains only `checkpoint_migrate_v2` vectors. Every vector names the
exact checkpoint before the operation, the closed operation input, the expected result,
and the checkpoint after a successful mutation. Existing-checkpoint writers provide
the exact revision and checkpoint digest they read. Exact replay and operation identity
conflict are resolved before the stale-writer comparison.

The fixtures cover:

- empty, one-hop, and two-hop maintenance migration;
- an empty migration receipt followed by an applied migration;
- exact replay after response loss;
- operation identity conflict and a distinct stale writer;
- retained receipt sequence continuity and bounded-retention cutoffs; and
- an empty migration receipt that remains canonically verifiable after the aggregate
  has been replaced by a root tombstone.

Every maintenance receipt includes `target_validated_bundle_fingerprint`. The durable
validator recomputes the request digest from the retained source aggregate digest, the
target definition fingerprint, the descriptor route, and maintenance mode. This check
also applies after tombstoning, when no aggregate definition remains. Resealed negative
fixtures prove that a missing or altered target fingerprint, altered historical request
digest, receipt allocation gap, audit reordering, and invalid retention cutoff are
rejected for their semantic defect rather than an outer digest mismatch.

All JSON artifacts are canonical RFC 8785 bytes and are validated against the exact
schema-version-2 schemas in the pinned specification checkout. Generate or verify the
fixtures with:

```sh
python scripts/generate_version2_vectors.py
python scripts/generate_version2_vectors.py --check
```

Machine documents continue to use integer `format: 1`; machine grammar and portable
artifact schema versions are separate version domains.
