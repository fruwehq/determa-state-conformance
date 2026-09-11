# Persistence durable host profile

This profile fixes the transaction trace required by SPEC sections 16.12 and 17.9.
Each case names exact schema-version-2 store snapshots, operation inputs, outcomes, and
ordered host calls. Store metadata remains outside portable checkpoint bytes.

The six required cases are:

- `persistence-01-inbox-idempotency`: the first commit records the inbox identity and
  equal redelivery returns the committed result without another core call;
- `persistence-02-atomic-aggregate-inbox-outbox-audit`: checkpoint aggregate, inbox,
  outbox, migration audit, revision, and participating application rows commit or roll
  back as one unit;
- `persistence-03-crash-boundaries`: a pre-commit crash preserves the initial store,
  while a post-commit pre-acknowledgement crash preserves the full commit for replay;
- `persistence-04-transient-retry`: transient failure rolls back and requires a later
  attempt from committed durable state;
- `persistence-05-permanent-quarantine-release`: permanent failure records quarantine
  without a core call, explicit release changes only quarantine state, and processing
  resumes only after release; and
- `persistence-06-resolve-before-transaction-cache-boundary`: scope selection,
  artifact resolution, local caching, and capability validation finish before the
  transaction begins.

Every processing request retains `target_validated_bundle_fingerprint` and the exact
ordered migration descriptor digest route. Machine documents remain `format: 1`.

The request also carries the exact presented envelope and digest, selected logical
scope, expected checkpoint identity, application writes, configured store
capabilities, composed host profile, and failure policy. Validation binds those fields
to the before/after store snapshots and requires inbox identity, checkpoint revisions,
outbox and audit state, and application rows to commit as one request-derived result.
Quarantine release requests name the retained event, digest, reason, scope, and release
authorization.
