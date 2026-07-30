# Execution-checkpoint host profile

This optional profile binds hosts that declare support for the portable SPEC §17
execution-checkpoint contract. It does not bind a core-only engine and does not
standardize a language API, SQL schema, object-relational mapper, URI, daemon, socket,
broker protocol, outbox worker, or command-line surface.

Each case contains a compact table of closed `execution_checkpoint_profile.vectors`.
A vector names:

- one real SPEC §17 host operation; replay repeats that operation and exact input;
- the exact checkpoint before and after the operation;
- one JSON Pointer to a closed operation input in `inputs.json`;
- one JSON Pointer to the projected pure-core result when a core call occurs;
- the exact closed result or failure code;
- whether checkpoint bytes are absent, created, changed once, or unchanged; and
- whether the host calls `create`, `dispatch`, `migrate`, or no core operation.

Every writer against an existing checkpoint supplies the exact `expected_revision`
and `expected_checkpoint_digest` it read. Equal pending/committed identity and equal
outbox/tombstone retries are checked before this stale-writer guard as required by
SPEC §17; a genuinely new mutation with stale values returns
`checkpoint_revision_conflict` before a core call. There is no synthetic `replay` or
standalone compare-and-swap operation.

`inputs.json` has the closed
`determa.execution_checkpoint_profile.inputs` format. Every cited bundle includes its
exact source-byte SHA-256 and validated bundle fingerprint. Create inputs additionally
fix namespace and machine version; dispatch inputs are relationally equal to the
presented mode, event, identity, target, and decoded typed payload; migration inputs
bind the target bundle, descriptor files/digest route, source aggregate, and request
digest.

`core-results.json` has the closed
`determa.execution_checkpoint_profile.core_evidence` format. It rejects extra
language-specific fields, pins the exact SPEC, Python, Python version, and Rust
verification revisions, and binds every projected call to its complete input using:

```text
sha256(JCS(["determa-conformance-execution-checkpoint-operation-input-1", input]))
```

All named checkpoints are strict JSON artifacts validated against the exact
`execution-checkpoint.schema.json` pin. The durable validator independently verifies
RFC 8785 checkpoint and embedded aggregate digests, envelope digests, mathematical
sequence order, counters, receipt/revision relations, permanent and bounded retention,
root membership, gap-free permanent delivery allocation, internal-delivery origin
links, producer-linked outbox state revisions, outbox effect links, root-tombstone
final-state evidence, and migration-audit links. Compact intent digests are checked
relationally against the exact full pre-compaction intent and operation input.
Canonical companions are exact bytes with no trailing newline.

Operation/result/failure-code/core-call combinations are closed. Coverage labels are
independently checked by a total declarative table plus relational predicates over the
input, before/after checkpoint, receipt, outbox/retention transition, adapter
capabilities, and composed host features. Validator self-mutations prove that swapped
creation coverage, wrong code/pin/input digest, rebound dispatch drift, extra evidence
members, and capability-first invalid-configuration handling are rejected.

Coverage is intentionally grouped into three scenario directories:

- `checkpoint-01-delivery-lifecycle` covers creation commit/replay/conflict and
  rejection without reservation, durable pending acceptance/replay, injected
  pre-commit rollback, delayed and foreground processing, handled, internal-send,
  internal-consume, unhandled, rejected, and deliberately faulted receipts, revision
  progression, committed response replay, stale processing, and every closed
  pre-acceptance failure except the tombstoned-root branch.
- `checkpoint-02-outbox-lifecycle` covers initial, retryable, ambiguous, and all five
  terminal states; idempotent pending and terminal updates; unequal-effect conflict;
  stale writer rejection; compact effect tombstones; receipt linkage; canonical
  ordering; and forbidden deletion while a retained receipt references the effect.
- `checkpoint-03-retention-and-root-lifecycle` covers a non-empty keyed maintenance
  migration/audit, post-commit response loss and replay, operation conflict, permanent
  retention, irreversible bounded retention in both directions, dependency-safe
  pruning, stale pruning/tombstoning, completed-root tombstoning/replay, root identity
  non-reuse, tombstoned pre-acceptance, and unsupported physical deletion. It also
  covers direct injection, bundled and third-party public registration, all four
  standard adapter capability boundaries, and complete positive/negative composed
  host-profile requirements.

The invalid artifacts separately prove format/version classification, structural
closure, digest mismatch, foreign-root delivery targets, permanent delivery-allocation
gaps, noncanonical outbox order, dangling effect linkage, wrong compact intent digest,
wrong initial outbox state revision, a bounded cutoff that crosses a retained internal
origin, and an unrelated root-tombstone final digest. Every semantic probe recomputes
the outer checkpoint digest.

## Generation and independent core verification

`scripts/generate_execution_checkpoint_profile.py` is the reproducible fixture
generator. It imports the Python core, invokes only public pure `load_bundle`,
`create`, `dispatch`, aggregate encoding, and migration operations, projects native
payloads into SPEC §16.2 typed values, and then applies the SPEC §17 host transaction
rules. Run it from this repository with the Python implementation environment:

```sh
/path/to/determa-state-python/.venv/bin/python \
  scripts/generate_execution_checkpoint_profile.py --check
```

`--check` resolves the imported `determa.state` module to its Git checkout and fails
unless `HEAD` is exactly the pinned Python commit and tracked files are clean. The
recorded commit therefore cannot be produced by importing a different or modified
checkout.

The checked generation used:

- specification `318ef1f16ae024770090bd338c8b70056df2855b`;
- Python core `7b17d788b48049648e7e463aa3d35ba13dc1aa6e`; and
- Rust core `d17480c8b281dcd17953f59afcf6b5d23ff44efd`.

Each `core-results.json` records schema-enforced constant pins. The Rust cross-check loaded the same
machines and exact inputs, then compared every encoded aggregate, status, disposition,
rejection, fault, internal event identity, external effect identity, payload, logical
and output counter, variable value, migration result, and audit record to the generated
artifacts. It covered the complete six-dispatch delivery chain, all eight output
emissions, and the non-empty migration. This verification does not add an engine,
adapter, host API, SQL schema, worker, daemon, socket protocol, CLI, or release.
