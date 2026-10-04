# Lossless application projection profile

This optional profile exercises SPEC §20 through an application-owned embedded facade. A runner supplies each `request` as the exact driver input to its production facade, selects only the named application rows, and observes the facade's direct return and the selected rows and checkpoint after the invocation. The `name`, `covers`, `outcome`, and `after` fields are assertions, never execution inputs. A runner must not synthesize the return from the golden or run a separate expected-state simulator.

The row's `amount`, `token`, and `region` are typed §16.2 source fields. Snapshot-level `supplemental_checkpoint` is configured related storage for the complete portable checkpoint; it participates in the same selected transaction. The row status is a domain projection and cannot replace aggregate configuration, variables, history, mailboxes, receipts, effect intents, tombstones, or outbox order. The generator copies pinned, schema-valid checkpoints from the execution-checkpoint profile and binds all results to exact reconstructed state. A runner should implement `create`, `admit`, and `step` through its public facade, including replay and revision-guard paths, then capture its direct operation-specific §8 result or typed error. It must inspect the full checkpoint and selected row snapshot after the invocation.

`shared_transaction_requested` claims one native application/checkpoint transaction only when `shared_transaction_available` is true in the configured test composition. A failed invocation preserves both row and checkpoint evidence. The profile does not claim that lossless projection alone grants durability, CAS, transport acknowledgement, or scope authority. `supplemental_capacity` models complete, absent, and deliberately truncating storage. The test driver never commits the truncating proposed candidate.

The external-refresh witnesses use a separate three-machine bundle. The string and integer success handlers copy the admitted `changed` fields; the fault handler requests an absent `refresh.only` field, commits the exact `action_fault` and checkpoint receipt, and leaves the selected application row unchanged. The prior snapshot remains caller-owned.

The JSON profile and `test.yaml` use closed schema-version-1 driver formats. Machine source still uses `format: 1`; the conformance and specification repositories remain SemVer `0.3.0`. Rebuild only this profile with `python scripts/generate_application_projection_profile.py`, and check it with `--check`. The repository validator and `scripts/test_application_projection_validator.py` independently reject schema-valid row, result, checkpoint, code, and coverage substitutions.

The thirteen normative examples in SPEC §20.3 map to these exact witnesses:

| SPEC §20.3 example | Projection vector witness |
|---|---|
| `status = pending`, complete prior, typed integer `7`, atomic result | `typed_row_input_atomic_admit` |
| Exact create/admit result fields, without invented fields | `create_result_shape`, `typed_row_input_atomic_admit` |
| Row float presented to integer declaration | `row_float_to_integer_rejected` |
| Equal retained delivery replay after an integer-to-float declaration change | `equal_pending_delivery_replay`, `equal_delivery_replay` |
| Changed retained event identity conflicts before payload validation | `changed_identity_conflict_before_payload` |
| Admitted `env.changed.amount = ["integer","7"]` with `refresh: {}` | `env_integer_admission`, `env_integer_step`; string field variant: `env_success_admission`, `env_success_step` |
| Admitted `env` missing `refresh.only` field commits `action_fault` | `env_fault_admission`, `env_fault_step` |
| Direct active-state write without declared boundary | `direct_state_edit_unsupported` |
| Enum-only row loses retained mailbox, receipt, or pending intent | `enum_only_prior_unrepresentable`, `enum_only_pending_intents_unrepresentable` |
| Proposed deferred payload exceeds supplemental capacity | `proposed_supplement_truncation` |
| Selected row belongs to another root | `wrong_root_row_selection` |
| Native shared transaction cannot be proved | `shared_transaction_unavailable` |
| Concurrent revision change rolls back selected rows | `stale_revision_rolls_back_rows` |

The completed replay witness derives a compatible maintenance migration from the handled checkpoint. `replay-target.yaml` changes the `increment.amount` declaration from integer to float while retaining the old terminal receipt; the validator binds the target fingerprint, descriptor, audit, receipt, and original caller request bytes. A separate pending replay returns the acceptance receipt. Both preserve the historical checkpoint CAS from the first admission.

The deferred-capacity witness uses the exact portable `repeated-before` aggregate and its deferred step result from core case 117. The pending-intent witness uses a checkpoint with five outstanding effects from the execution-checkpoint profile. Both are generator-pinned source artifacts; their complete before and candidate values are checked relationally. `outcome` remains only an assertion. A runtime harness must invoke the production projection facade from `request`, `before`, and its configured mapping, then compare the returned value and observed storage to the golden.
