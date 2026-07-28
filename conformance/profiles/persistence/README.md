# Persistence host profile

This optional profile binds hosts that declare support for the SPEC §16 lazy
transactional persistence contract. It does not bind a core-only engine and does not
standardize SQL, a database schema, an object-relational mapper, a broker, or an
acknowledgement API.

Every case starts from `initial-store.json`. A profile adapter executes the ordered
`persistence_profile.steps` and compares the complete named `expect_store` and
`expect_call_log` JSON values after each step.

The store snapshot is assertion notation for:

- the exact canonical aggregate value;
- committed or blocked inbox records;
- ordered outbox intents;
- deterministic migration audit records;
- host quarantine metadata; and
- acknowledged input identities.

The call log makes the transaction boundary observable. All definition, descriptor,
route, trust, and resource resolution occurs before `begin_transaction`. Staged writes
become visible only at `commit`; rollback preserves the prior snapshot exactly.
Acknowledgement occurs only after commit.

Coverage:

- `persistence-01-inbox-idempotency` — duplicate replay returns the committed outcome
  without another migration, dispatch, outbox write, or audit record.
- `persistence-02-atomic-aggregate-inbox-outbox-audit` — all logical writes commit or
  roll back together, including one deterministic emitted output intent in the outbox.
- `persistence-03-crash-before-and-after-commit` — pre-commit crashes leave no writes;
  post-commit/pre-acknowledgement crashes retain an unacknowledged committed inbox
  outcome, and its replay performs the first acknowledgement without redispatch.
- `persistence-04-transient-retry` — transaction conflict or temporary storage failure
  does not quarantine and retries from newly read state.
- `persistence-05-permanent-quarantine-and-release` — permanent deterministic failure
  preserves aggregate bytes, blocks the inbox item, and records quarantine/audit before
  a corrected route is released.
- `persistence-06-local-cache-transaction-boundary` — no remote resolution or trust
  service call occurs inside the transaction.
