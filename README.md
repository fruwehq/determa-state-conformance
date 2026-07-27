# Determa State — conformance suite

The language-agnostic executable correctness target for
[Determa State](https://github.com/fruwehq/determa-state-spec).

This suite targets the pre-release integer `format: 1` grammar. The prose, JSON Schema,
and examples live in `determa-state-spec`; this repository pins portable behavior that
every implementation must reproduce. Where normative prose and a core behavior case
disagree, the case wins and the specification must be corrected.

Host and plugin behavior deliberately excluded by format 1 is not made normative merely
by this repository. Queue delivery policy, timers, dead letters, stores, CLI shapes, and
other host surfaces remain outside core conformance.

Migration note: repository revisions before issue #21 used the pre-format-1 grammar and
are not authoritative for format 1. The authority statement above applies to the
migrated suite.

## Layout

- `conformance/<number>-<name>/machine.yaml` — the primary format-1 bundle.
- `conformance/<number>-<name>/test.yaml` — a scenario or static-validation assertion.
- Additional bundle files in a case are named explicitly by its `test.yaml`.
- `VERSION` — the synchronized specification version, currently `0.0.6`.

There is no repository CI or standalone runner. Each implementation's harness must load
and execute every retained case; implementation work follows this suite in a separate
pull request.

## Harness trace

Unless a case says otherwise, the harness creates the first machine in `machine.yaml`.
Optional `create.bindings` supplies the exact `input` and `external` maps.

Each `send` is one host call to the root or to `bound_instance`. The harness supplies a
stable unique `event_id` when the fixture omits it. A send invokes exactly one core
`dispatch`; it does not recursively deliver returned emissions.

`retain_emissions_as` names the ordered emissions returned by that call. A later
`deliver: { retained, index }` presents that exact immutable internal envelope to its
already-resolved target. This records a fixed delivery trace without imposing a queue
plugin's ordering, retry, acknowledgement, or retention policy.

An `expect` map compares only the fields it names. Common fields are `status`,
`disposition`, `config`, `variables`, `history`, `emissions`, `components`,
`owned_instances`, and `fault`. `caller_still_owns_input` verifies that a faulting
envelope remains caller-owned rather than becoming engine queue or dead-letter state.

Static cases use either:

```yaml
static: { valid: false, error: destroyed_variable_write }
```

or a `static.documents` list naming multiple files. `error` is the exact load-time code;
`structural_validation` means rejection by the JSON Schema before semantic validation.

## Coverage

| case | portable behavior |
|---|---|
| 01 | guarded leaf dispatch and unhandled disposition (§6) |
| 02 | ancestor handling and composite self-reset (§6) |
| 03 | initial-transition actions (§4, §6) |
| 04 | intentionally absent: deferral is queue-plugin policy (§11) |
| 05 | scoped variables, shadowing, destruction, and reinitialization (§4) |
| 06 | input payload validation (§4, §6) |
| 07 | internal reaction versus transition exit/entry (§6) |
| 08 | local preservation versus unmarked descendant reset (§6) |
| 09 | isolated parallel components and explicit routing (§7) |
| 10 | deep-history restoration versus plain restart (§6) |
| 11 | shallow-history restoration versus plain restart (§6) |
| 12 | ordered guarded transitions (§6) |
| 13 | owned spawn, natural completion, and reserved `done` (§7) |
| 14 | explicit multi-target send and owner reply (§4, §7) |
| 15 | external creation binding plus reserved `env`/`refresh` (§4, §6) |
| 16 | external scheduling request and correlated elapsed input (§11) |
| 17 | atomic action-fault rollback and caller-owned input (§10) |
| 18 | declared domain failure as ordinary input (§10) |
| 19 | valid public output/correlated-input contract (§4) |
| 20 | unresolved public correlation rejection (§5) |
| 21 | intentionally absent: no portable snapshot wire format |
| 22 | intentionally absent: definition migration is unsupported |
| 23–25 | dynamic/chained choices and missing-default rejection (§5, §6) |
| 26–28 | unreachable state, dead branch, and reachable positive validation (§5) |
| 29 | owned spawn with typed input binding and completion (§7) |
| 30 | synchronous owned-instance cancellation (§7) |
| 31 | intentionally absent: no standardized enabled-event inspection shape |
| 32 | explicit history resume versus plain restart (§6) |
| 33 | history capture only when the composite exits (§6) |
| 34 | first-entry history fallback (§6) |
| 35 | shallow versus deep restoration from equivalent configurations (§6) |
| 36 | history restores configuration, not destroyed variable values (§6) |
| 37 | destroyed variable write rejection and surviving-scope positive (§5) |
| 38 | destroyed reference binding rejection (§5) |
| 39 | ancestor-selected internal transition with no exit/entry (§6) |
| 40 | structural rejection of removed/noncanonical transition shapes (§4) |
| 41 | local and unmarked descendant lifecycle traces (§6) |
| 42 | initial-transition history-target rejection (§4) |
| 43 | self-history lifecycle replay (§6) |
| 44 | local history targeting (§6) |
| 45 | proper-ancestor target bounds (§6) |

## Deliberate format-1 boundaries

- Parallel behavior uses isolated components; regions and implicit broadcast do not
  exist.
- Deferral, discard, retry, acknowledgement, and dead-letter policy belong to a queue
  plugin. The core stores no unhandled or faulting envelope.
- Time behavior uses declared external requests and later correlated inputs. The core has
  no clock or timer.
- Separate named contracts are replaced by bundle public event declarations.
- Submachines are replaced by explicit lifecycle-bound components or owned spawning.
- Portable snapshots, definition migration, package imports, and version resolution are
  unsupported.
- Store protocols, CLI JSON, queue inspection, enabled-event lists, and visualization
  output are implementation/host surfaces rather than portable executable behavior.

## License

MIT — see [LICENSE](LICENSE).
