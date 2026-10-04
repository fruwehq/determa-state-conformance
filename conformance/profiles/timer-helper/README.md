# Optional external timer helper profile

This profile exercises SPEC §23 through an installed helper. The base `create`, `admit`, and `step` APIs have no clock, timer record, heartbeat, mandatory scheduler or background poll. `timer-01-external-helper/machine.yaml` and its scenario demonstrate actual declared scheduling intent and ordinary declared event return; the helper request is separate host work.

`vectors.generated.json` binds the 24 pinned normative helper examples to complete helper artifacts before and after invocation. Each row gives a literal helper request, trusted-clock fixture, independently observed checkpoint, exact result, full artifact and call counts. A production adapter receives only the machine, setup scenario, before state, request and clock/transaction controls; it must invoke its real installed helper and return its direct result plus observed state and call counts. It must not reconstruct results from the fixture or use case identifiers as inputs. Run it with `python scripts/run_timer_helper_profile.py --spec-root ../determa-state-spec --adapter <child command...>`.

The 21 ordinary cases cover schedule/replay/collision, cancel/claim ordering, due boundary, coordinated commit, stale fencing, proved-uncommitted retry, ambiguous fate, read, invalid times, overflow, unavailable clock and rejected admission. Three early errors cover unsupported interface, unsupported version and invalid request shape. Another 25 executable clock vectors cover every listed signed-64 absolute, nonnegative duration, malformed time and arithmetic boundary. Three claim vectors check expiry equality, principal mismatch and altered fire event identity with unchanged helper and checkpoint state. A separate lifecycle vector starts from a real format-1 target definition, creates its checkpoint, schedules and claims the helper record, commits the ordinary `received` admission, and steps that event to its terminal unhandled receipt. Rebuild with `python scripts/generate_timer_helper_profile.py --spec-root ../determa-state-spec`; use `--check` in CI.

Every source `name` below maps to the identical `cases[].id` in `vectors.generated.json`; the runner submits the row's literal `request` without the ID.

| SPEC §23 source case | Executable observation |
|---|---|
| `schedule_first` | Fresh durable record and retained first result |
| `schedule_equal_replay` | Exact first result despite later record state |
| `operation_id_collision` | Changed request digest conflicts |
| `timer_id_collision` | Different schedule cannot reuse retained timer ID |
| `cancel_pending` | Preclaim cancellation, no fire attempt |
| `cancel_loses_to_claim` | Claimed fire prevents cancellation success |
| `claim_at_deadline` | Due equality allocates a fenced claim |
| `claim_before_deadline` | Premature claim changes nothing |
| `coordinated_fire_commits` | Fire, helper receipt and ordinary admission commit |
| `complete_equal_replay` | Exact retained completion, no second admission |
| `stale_fence` | Old claim cannot complete a newer attempt |
| `uncommitted_fire_recovery` | Proven uncommitted attempt gets new fence |
| `ambiguous_fire_fate` | Unknown fate blocks retry |
| `read_timer` | Complete read without mutation |
| `negative_zero`, `fraction`, `above_max`, `json_number` | Invalid time representations fail before mutation |
| `duration_overflow` | Checked signed-64 addition refuses overflow |
| `clock_unavailable` | Clock failure prevents acceptance |
| `admission_rejected_before_commit` | Neither helper nor checkpoint commits |
| `unsupported_interface` | Early protocol refusal |
| `unsupported_version` | Early version refusal |
| `invalid_request_shape` | Early malformed request refusal |

`clock_vectors[]` maps the three valid absolute, two valid duration, eight invalid absolute, seven invalid duration and five arithmetic/availability entries from `timer-clock-cases-v1.json` in source order. `fence_vectors[]` adds the three explicit claim checks named above. `lifecycle.generated.json` binds the complete create, intent, schedule, cancel, claim, admission and step trajectory. The two archive source files map to one export and two stage/refusal child calls. This is 24 normative helper cases, 25 clock boundaries, three extra fence cases, one lifecycle and three archive cases.

`source-ownership.generated.json` binds the same fire envelope to §21's stable timer source ID, full typed transport content, source digest, exact checkpoint acceptance receipt and admission binding. Source acknowledgement follows the checkpoint and binding commit. The delivery profile's native transport/recovery runner provides the operational crash and replay proof for a helper that advertises an independent source route; this local artifact does not confer that claim by itself.

The normative samples specify abbreviated prior premises. This profile supplies full helper record fixtures and checkpoint observations for those premises. Passing fixture validation proves source consistency and relational assertions; a configured production helper must pass the child runner to claim the corresponding operation behavior. The runner also checks a configured public timer report, hashes the loaded closure and configuration bytes, and binds its operational proof to the tested helper, scope and topology. Coordinated admission additionally requires authority, delivery and effect evidence from the same installed topology. The three timer-specific archive cases verify required participant export, inert import, and refusal when an apparently resealed archive omits the required helper.

For each `timer_operation` call the child receives the exact request, full `before` helper artifact and checkpoint, trusted clock observation and explicit admission/fate controls. It returns exactly `result`, `after` and `calls`. The `timer_lifecycle` call receives the two format-1 machines, create and timer command requests, foreground intent inputs and trusted clock sequence. It must drive create/admit/step on both declared intent branches and the target, then return every intermediate helper artifact and target checkpoint, exact fired envelope and call counts. Its input contains no expected checkpoint, result, envelope, case ID or coverage label. Archive export/stage calls use the I1 profile's child protocol and full active-state observations. This full runner exercises the durable coordinated helper claim; an independent or ephemeral helper needs only its applicable cases and cannot gain the coordinated claim from this runner.

After those calls, the child answers `{"kind":"configured_timer_helper"}` with exactly `report`, `installation` and `operational_proof`. `report` is the public configured extension capability report. `installation` supplies an ordered complete list of loaded source/dependency files, exact Base64 bytes, live module paths, configuration Base64 and digest, scope identity, topology identity and storage binding. The runner reads each installed file and hashes the full closure as `hash(["determa-test-timer-provider-closure-1", [[logical_path, sha256(bytes)], ...]])`, comparing it to the report reference. It checks report health and the exact one-of durability/delivery claim pairs. `operational_proof` repeats the provider, configuration, scope, topology, storage binding, claims and observed request digests, without receiving or returning case names. Coordinated claims also carry receipt digests for authority, delivery and effect evidence bound to that same storage. Those receipts must come from the actual configured runners; self-description alone does not establish a hosted guarantee.
