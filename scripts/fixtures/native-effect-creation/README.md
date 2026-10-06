# Native effect creation — unfinished shared-test checkpoint

The first fixture captures actual portable initialization from the reviewed
Python checkpoint implementation at `39def1ac8268de55237f90e5cb8d7110fe27fc78`:
one declared business-token binding produces two distinct initial external intents.
The proposed journal is derived from those intents using approved §19 fields.
The creation response follows the existing Rust owner-local creation return.
This is a development fixture, not a new public transport or certified provider.

`test_native_effect_creation_validator.py` checks specification schemas and
independent joint relations, including valid-hash tampering. These checks cannot
prove the core result, native transactions, authority authorization or SDK call
counts. No adapter runner currently executes this fixture. It is deliberately
outside the normative profile manifest until all prerequisite reviews pass.

Before Python implementation, complete and independently review:

- Deterministic source/golden derivation and registration in the shared profile.
- Input-only configured-adapter runner, exact observed first response and retained
  replay/conflict cases; no expected result or case-name execution inputs.
- Committed faulted initialization versus rejected creation and successful retry.
- Empty outbox, lifecycle receipts/internal mailbox emissions, typed numeric
  bindings/defaults, machine-visible and host-only token provenance.
- Tombstone replay/conflict and current native authority/ownership prerequisites.

Actual SQLite staging/commit races, post-staging source loss and SIGKILL remain
separate required native implementation evidence. Existing 62-vector effects
success does not certify initialization. Admission, transport and examples are
outside this slice. Version 0.3.0 remains unreleased with version-1 contracts and
numeric machine `format: 1`.
