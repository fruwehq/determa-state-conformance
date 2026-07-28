# Determa State — conformance suite

The language-agnostic executable correctness target for
[Determa State](https://github.com/fruwehq/determa-state-spec).

This suite targets the pre-release integer `format: 1` grammar. The prose, JSON Schema,
and examples live in `determa-state-spec`; the cases under `conformance/core/` pin
portable behavior that every implementation must reproduce. Where normative prose and
a core case disagree, the core case wins and the specification must be corrected.

Host and plugin behavior deliberately excluded by format 1 is not made normative merely
by this repository. Cases under `conformance/profiles/<profile>/` bind only
implementations that declare support for that profile, and never override core prose.
Queue delivery policy, timers, dead letters, stores, CLI shapes, and other host surfaces
remain outside core conformance.

Migration note: repository revisions before issue #21 used the pre-format-1 grammar and
are not authoritative for format 1. The authority statement above applies to the
migrated suite.

## Layout

- `conformance/core/<number>-<name>/machine.yaml` — the primary bundle for a
  normative core case.
- `conformance/core/<number>-<name>/test.yaml` — its scenario or static-validation
  assertion.
- `conformance/profiles/<profile>/` — optional, explicitly non-core compatibility
  surfaces.
- Additional bundle files in a core case are named explicitly by its `test.yaml`.
- `VERSION` — the synchronized specification version, currently `0.0.6`.

There is no repository CI or standalone runtime runner. Repository validation can parse
and schema-check fixtures and verify their internal references, but it does not prove the
scenario traces. Each implementation's harness must later load and execute every core
case; implementation work follows this suite in a separate pull request.

## Driver mechanics (non-normative)

Let `case_name` be the case directory basename, including its numeric prefix. Unless a
case says otherwise, the harness creates the first machine in `machine.yaml` with:

- `root_instance_id = "conformance:" + case_name + ":root"`; and
- `creation_id = "conformance:" + case_name + ":create"`.

`create.root_instance_id` and `create.creation_id` may override those values with
non-empty strings. Optional `create.bindings` supplies the exact `input` and `external`
maps. A fixture may also carry `create.expect`; it applies to the exact creation result
before the first listed step, including a rejected result that created no state.

The driver-only value `{ invalid_unicode_scalar: "D800" }` constructs a runtime string
containing the lone UTF-16 surrogate code unit U+D800 without putting that invalid
string in the YAML fixture source. It is accepted only in a case explicitly testing a
programmatic create/dispatch rejection and is replaced before the core call; it is
never passed as a map value.

`load: { valid: true }` is an explicit semantic-load assertion made before creation.
Scenario bundles are always required to load successfully; the marker calls out cases
where load validity itself is a regression boundary in addition to the runtime trace.

Each `send` at zero-based step index `step_index` is one host call to the root or to
`bound_instance`. Its omitted event id is exactly
`"conformance:" + case_name + ":step:" + canonical_decimal(step_index) + ":input"`.
`send.event_id` may override it with a non-empty string. Root, creation, and input-event
identities MUST be unique across the suite; the consistency validator rejects duplicate
explicit/default values. A send invokes exactly one core `dispatch` with
`{ input: envelope }`; it does not recursively deliver returned emissions.

`send.bundle: relative-file.yaml` supplies that named validated bundle only to that
dispatch call. The aggregate prior state is still the exact state created and advanced
with the original bundle; the harness neither recreates nor transforms it. This driver
operation exists to test the specification's prior-state/bundle compatibility check.

`capture_emissions_as` names the ordered emissions returned by that call. A later
`deliver: { captured, index }` presents that exact immutable internal envelope,
including its complete tagged target and `event_id`, through
`{ internal: envelope }`. It never resolves an author target shorthand again. This
records a fixed delivery trace without imposing a queue plugin's ordering, retry,
acknowledgement, or retention policy.

These keys describe the test driver only. Implementations are not required to expose
capture or delivery as public APIs. Explicit delivery is intentional: automatically
draining returned emissions would silently standardize FIFO or run-to-quiescence
behavior that format 1 assigns to queue plugins.

## Assertion vocabulary (normative)

An `expect` map compares only the fields it names. Common fields are `status`,
`disposition`, `config`, `variables`, `history`, `emissions`, `components`,
`owned_instances`, and `fault`. `caller_still_owns_input` verifies that a faulting
envelope remains caller-owned rather than becoming engine queue or dead-letter state,
as required by specification §10.1. When named, `components` and `owned_instances`
compare collection membership exactly, including an asserted empty collection; fields
inside each listed member may still be partial.

`variables` is a recursively partial assertion. At each asserted runtime, each named
variable resolves to the nearest active lexical declaration after normal shadowing and
its value is compared recursively using the named list/map members in the fixture.
Unlisted visible variables do not affect the assertion. Nested component and owned
runtime `variables` use that runtime's own lexical scopes. A fixture cannot address a
shadowed outer declaration through the flat `variables` map; when that distinction is
material, it MUST first transition to a configuration where the outer declaration is
visible or assert behavior that exposes it, as case 05 does. No declaration-path
assertion notation is defined.

`config` is an exact list of active leaf-state paths for the asserted runtime. Each path
is a dot-separated, root-relative path through nested `states`; the machine root itself
is omitted. A top-level leaf is therefore `ready`, while a leaf nested under `work` and
`outer` is `work.outer.ready`. The list contains no composite ancestors as separate
members. For multiple active leaves it is ordered by ascending UTF-8 bytes of the full
path. An empty list is required for a completed/faulted diagnostic runtime with no
active configuration. Component and owned-runtime `config` assertions use the same
rule relative to that runtime's root. A final state is a completion trigger and never
appears as a stable committed `config` member.

When named, `history` compares the complete history-slot map for that runtime. A slot
key is the dot-separated root-relative path of the composite declaration; the machine
root, if it declares history, uses the assertion-only key `$root`. A slot value is
`null` until no committed exit has populated it. A populated shallow slot is the exact
ordered list containing its recorded direct-child path; a populated deep slot is the
exact ordered list of recorded active leaf paths. Every recorded path is root-relative
and uses the same ordering and spelling as `config`. Omitting a declared slot from an
asserted `history` map fails exact membership; omitting `history` from `expect` makes no
history assertion.

Expected emission targets use assertion notation, not an alternative wire format:

- `root` expands to the aggregate's complete root target member;
- `owner` expands from the emitting runtime to its complete immediate-owner target;
- `{component: component_id}` expands to the complete allocated component target,
  including owner runtime, component runtime, and activation sequence, that existed
  when the emission was created; and
- `{bound_instance: variable_name}` expands to the complete nominal
  `spawned_instance` target stored in that variable at emission time.
- `external` identifies an external output intent returned by the core. It is assertion
  notation, not another input-envelope target-union member. The harness compares the
  intent's named `event`, `payload`, `correlation_id`, `effect_id`, and `sequence`
  fields when present in the expected map; omitted fields remain partial assertions.

The harness MUST compare the fully expanded target for exact equality. Matching only a
component identifier, machine identifier, or current placement is insufficient: a
wrong or stale activation/runtime identity fails the assertion. Captured envelopes
retain their original expansion even if the named component is later disposed and
re-created or the reference variable later changes.

Whenever `emissions` is asserted, the expected list has exact length and order. Each
listed emission map remains a partial named-field assertion, but an extra, missing, or
reordered actual emission fails the case.

`owned_instances` is an exact list of the non-disposed spawned runtimes still present
in aggregate logical state: running, retained-faulted, or root-frozen diagnostic
descendants. Its canonical identity key is the pair
`(owner_runtime_id, spawn_sequence)`. Each expected member therefore contains:

```yaml
- key: { owner: root, spawn_sequence: 0 }
  machine_id: worker
  status: running
```

The `owner` value uses the exact target-expansion notation above and resolves to the
owning runtime identity; `spawn_sequence` is the non-negative mathematical integer
allocated by that owner. Members are ordered by owner runtime-id UTF-8 bytes, then
ascending spawn sequence. As a convenience, `key: { bound_instance: variable_name }`
may replace the canonical pair only when that currently visible reference resolves
uniquely to exactly one retained member; ambiguity or a null/disposed reference fails
the assertion. Unbound children and multiple children formerly associated with the
same holder remain representable through the canonical pair.

Disposed subtrees are removed and never appear as tombstones. A disposed nominal
reference may remain serializable in `variables`; tests assert that surviving value
separately with `targetable: false`. `owned_instances: []` asserts exact emptiness.

Scalar assertions are type-sensitive. In particular, YAML `1` asserts a CEL `int` and
YAML `1.0` asserts a normalized CEL `double`; numerical equality alone is insufficient.
`rejection.code` names the exact pre-step rejection code and is distinct from the
aggregate's retained `fault` record.

Static cases use either:

```yaml
static: { valid: false, error: destroyed_variable_write }
```

or a `static.documents` list naming multiple files. `error` is the exact load-time code;
`structural_validation` means rejection by the JSON Schema before semantic validation.
A `static.documents` list may coexist with scenario `steps`; in that form the named
documents are load-time checks and the case's primary `machine.yaml` is still created
and driven by the scenario.

## Optional CLI profile

The black-box runner is preserved at `conformance/profiles/cli/run_cli.py` as
non-normative profile infrastructure. No CLI profile cases currently ship. The previous
fixtures asserted legacy public fields and a core-owned FIFO queue with manual stepping,
which contradict format 1's plugin boundary.

A later, separate issue may define commands, exit codes, and JSON shapes for
implementations that declare a CLI profile, without queue introspection. Until then,
the absence of CLI cases is intentional and no CLI surface is portable conformance.

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
| 09 | isolated parallel components, explicit routing, and terminal owner cleanup (§7) |
| 10 | deep-history restoration versus plain restart (§6) |
| 11 | shallow-history restoration versus plain restart (§6) |
| 12 | ordered guarded transitions (§6) |
| 13 | owned spawn completion ordering across exit output and reserved `done` (§7) |
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
| 41 | intentionally absent: duplicate of case 08 |
| 42 | initial-transition history-target rejection (§4) |
| 43 | self-history lifecycle replay (§6) |
| 44 | local history targeting (§6) |
| 45 | proper-ancestor target bounds (§6) |
| 46 | root boundary plus destroyed refresh validation (§5, §6) |
| 47 | state-scoped reference cleanup with populated and null paths (§7) |
| 48 | null instance cancellation is a successful no-op (§7) |
| 49 | exit-action cancellation after automatic child cleanup (§6, §7) |
| 50 | root-fault terminality freezes and protects a live child (§6, §10) |
| 51 | isolated component initialization fault and pending target identity (§7, §10) |
| 52 | isolated spawned initialization fault and enclosing-owner rollback (§7, §10) |
| 53 | compound choice actions resolve before one lifecycle transition (§6) |
| 54 | stale component target identity is never re-resolved (§6, §7) |
| 55 | root execution of an owner-targeted send faults deterministically (§4, §10) |
| 56 | variable declaration initialization requirements (§4) |
| 57 | creation bindings override or fall back to typed initial values (§4, §8) |
| 58 | missing required creation binding rejection (§4, §8) |
| 59 | payload defaults materialize while optional fields remain absent (§4, §6) |
| 60 | payload/default numeric source-type, range, and structural validation (§2, §4, §5) |
| 61 | expression-map snapshot and deterministic fault precedence (§4, §10) |
| 62 | runnable YAML 1.2 Boolean-like string identity plus unsafe parsed-value rejection (§2, §4, §6) |
| 63 | entry-time stop interrupts pending component initialization (§6, §7) |
| 64 | correlation expression precedence over a failing dynamic target (§4, §10) |
| 65 | portable CEL arithmetic, error absorption, conversion, and Unicode semantics (§5) |
| 66 | CEL profile, activation-field, and CEL-visible-name rejections (§4, §5) |
| 67 | prior state is bound to the exact validated bundle, including `meta` (§8) |
| 68–69 | non-absorbed CEL `&&`/`||` runtime errors (§5) |
| 70 | dynamic target-list expression fault precedence (§4, §10) |
| 71–72 | reversed non-absorbed CEL `&&`/`||` runtime errors (§5) |
| 73 | complete synchronous-initialization dependency-cycle rejection (§5) |
| 74 | canonical sibling owned-child cascade and emission order (§7) |
| 75 | terminal diagnostic aggregate after a root initialization fault (§8, §10) |
| 76–77 | invalid runtime Unicode rejection at create and dispatch boundaries (§2, §8) |
| 78 | explicit owner-to-component environment forwarding and refresh (§4, §6, §7) |
| 79 | missing selected external refresh field faults and rolls back atomically (§6, §10) |
| 80 | unbound owned child survives state exit and joins aggregate cleanup (§7) |

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
