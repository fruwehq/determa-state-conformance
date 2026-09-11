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
External broker delivery policy, timers, production stores, CLI shapes, and other host
surfaces remain outside core conformance. Runtime-local ready/deferred mailboxes in
aggregate-state schema version 2 are core state and do not define a broker or worker.
SPEC §16 defines the sole portable aggregate wire and pure migration operations; cases
117–118 cover that boundary. Machine document `format: 1` remains unchanged and is
independent of portable artifact schema versioning.

Migration note: repository revisions before issue #21 used the pre-format-1 grammar and
are not authoritative for format 1. The authority statement above applies to the
migrated suite.

## Layout

- `conformance/core/<number>-<name>/machine.yaml` — the primary bundle for a
  normative core case.
- `conformance/core/<number>-<name>/test.yaml` — its scenario or static-validation
  assertion.
- `conformance/core/117-*` onward may use `version2_vectors` plus a strict
  `artifacts.documents` manifest for portable JSON operations.
- `conformance/profiles/<profile>/` — optional, explicitly non-core host surfaces.
- `conformance/profiles/execution-checkpoint/` — the optional SPEC §17 durable-host
  checkpoint profile.
- `conformance/closed-code-registry/registry.json` — the single machine-readable
  authority for closed portable failure, rejection, fault, and disposition sets.
- `conformance/closed-code-registry/vectors.generated.json` — the generated
  category/code projection consumed by implementation harnesses.
- Additional bundle files in a core case are named explicitly by its `test.yaml`.
- `VERSION` — the synchronized specification version, currently `0.2.0`.

The v2-only artifact cleanup retains `VERSION` 0.2.0 while review is in progress.
Current fixture totals are reported by the repository validator rather than maintained
as release promises in prose.

Repository CI parses every fixture with YAML 1.2 or strict JSON, classifies deliberate
pre-schema rejections, checks declared structural results against an immutable
specification commit, verifies artifact digests, and compares canonical JSON files as
exact bytes. CI does not
execute scenario traces, and there is no standalone runtime runner.
Each implementation's harness must later load and execute every core case;
implementation work follows this suite in a separate pull request.

Run the same durable validation locally:

```sh
python -m pip install --requirement scripts/validation-requirements.txt
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```

The supplied specification checkout must be the dependency revision under review; the
workflow pins that revision by commit rather than following a mutable branch.

Durable-host profile changes must also pass the deterministic profile generator:

```sh
python scripts/generate_execution_checkpoint_profile.py --check
```

The durable-host request schema is a closed operation-tagged union. The validator
cross-binds request semantics to exact result and after-state artifacts, enforces exact
revision equations, and rejects schema-valid goldens belonging to another request.
Malformed batch members are represented by exact driver-owned UTF-8 JSON sources or
JSON values; the harness applies the repository's strict JSON source checks and the
durable-host input schema to each ordered member before admission.
Scoped operations receive exactly the selected authorized record, or no records when
scope authorization fails; equality across scopes is checked relationally between
separate vectors.
Stale admission replay vectors name the exact historical checkpoint read by the
original admission. The validator binds that root, revision, and digest to the retained
acceptance receipt before replay or same-identity conflict can precede CAS.

### Closed-code registry

The registry assigns each closed set a stable category and records every exact portable
string with its trigger and normative source. The same portable string may occur in
more than one category when the specification deliberately permits it on distinct
surfaces; duplicate category/code pairs are invalid.

`scripts/validate_conformance.py` validates the registry schema, the independent
closed category vocabulary, complete category coverage, ordering, duplicates, and
generated vector bytes. Update the generated projection only from the registry:

```sh
python scripts/closed_code_registry.py
python scripts/closed_code_registry.py --check
python scripts/test_closed_code_registry.py
python scripts/test_version2_validator.py
```

The registry is conformance-first. Current Python and Rust releases do not yet expose
enumerable complete code sets, so this repository does not claim to compare their
production exports. Separate implementation changes must add discoverable exports and
exact registry-set gates without requiring language-specific enum or type names to
match.

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

The driver-only values `{ non_finite_double: nan }`,
`{ non_finite_double: positive_infinity }`, and
`{ non_finite_double: negative_infinity }` construct the corresponding host binary64
value without placing non-JSON YAML numeric syntax in a fixture. The driver recursively
materializes them only in creation bindings, input payloads, envelope replacements, and
the prior-state corruption probe below. An exact one-member map with this key is always
a marker in those locations, not an ordinary host map.

`load: { valid: true }` is an explicit semantic-load assertion made before creation.
Scenario bundles are always required to load successfully; the marker calls out cases
where load validity itself is a regression boundary in addition to the runtime trace.

Each `send` at zero-based step index `step_index` is one host input call. Its target is
the root by default. `bound_instance: variable_name` resolves the complete nominal
spawned-instance target in the root runtime's currently visible variable.
`component: component_id` resolves the complete currently retained component target and
exists only to exercise the host-ingress rejection boundary; it does not make direct
component ingress valid. The two target selectors are mutually exclusive. The omitted
event id is exactly
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
`deliver: { captured, index }` clones and presents that exact immutable internal
envelope, including its complete tagged target and `event_id`, through
`{ internal: envelope }`. It never resolves an author target shorthand again. This
records a fixed delivery trace without imposing a queue plugin's ordering, retry,
acknowledgement, or retention policy.

Boundary cases may add one non-empty `deliver.replace` map to the cloned envelope. The
stored capture remains unchanged. Its closed fields are:

- `payload` — replace the complete payload with the supplied map;
- `target` — replace the complete target with `root`,
  `{bound_instance: variable_name}`, or `{component: component_id}`, resolved from the
  current aggregate; or
- `spawned_instance_reference` — replace the named non-empty subset of
  `root_instance_id`, `instance_id`, `machine_id`, and `machine_version` in an existing
  `spawned_instance` target.

This mutation notation is only a driver mechanism for malformed-envelope and target
eligibility assertions. It does not define a public API or permit a captured emission
to change.

An `inspect.corrupt_prior_state` step deep-copies the current abstract state, replaces
one nested value inside a visible root variable, and performs a null-delivery dispatch
with that malformed prior state:

```yaml
inspect:
  corrupt_prior_state:
    runtime: root
    variable: stored_map
    path: [nested, 0]
    value: { non_finite_double: nan }
```

`path` is a non-empty list of string map keys and non-negative list indexes. This is a
driver-only prior-state validation probe, not a snapshot format. The dispatch result
becomes the scenario's current result like any other step.

These keys describe the test driver only. Implementations are not required to expose
capture or delivery as public APIs. Explicit delivery is intentional: automatically
draining returned emissions would silently standardize FIFO or run-to-quiescence
behavior that format 1 assigns to queue plugins.

### Portable version-2 vector mechanics

Cases with `version2_vectors` exercise the pure, language-neutral operations from SPEC
§§8, 16, and 17. Their operation names are driver adapters, not required public API
names. A vector supplies the exact aggregate or checkpoint before value where required,
an exact target or request artifact, and either canonical RFC 8785 result bytes or one
closed failure code with the byte-identical unchanged input artifact.

One `step_v2` names one runtime and processes at most its ready head. No version-2
operation chooses another runtime or drains an aggregate. Repository validation checks
result artifacts against the pinned schema-version-2 schemas, recomputes aggregate,
checkpoint, envelope, descriptor, and maintenance request digests, validates single
mailbox ownership and retained receipt relations, rejects repeated coverage claims, and
requires the closed coverage set. The checkpoint profile is intentionally limited to
maintenance migration.

The required native core coverage is grouped as follows:

| Case | Required coverage labels |
|---|---|
| `119-native-v2-aggregate-integrity` | aggregate round trips; typed values; exact root, component, and spawned targets; relation and discriminator rejection |
| `120-native-v2-definition-package` | definition resolution; package attachment digest, uniqueness, resolver seeding, trust, and put-if-absent behavior |
| `121-native-v2-migration-totality` | active and historical state, variables, components, owned runtimes, counters, identities, and total mapping rejection |
| `122-native-v2-migration-execution` | unchanged-definition resume; route adjacency, order, cycle, and absence; retry; all migration-then-processing outcomes; terminal migration |
| `123-native-v2-migration-guards` | trust, resource and security limits, request validation, transform faults, and failure/discriminator precedence |
| `124-native-v2-occurrence-identity` | occurrence-local bindings plus exact decimal target identity boundaries for spawn and component activation sequences |

Generate or independently verify the canonical fixtures with:

```sh
python scripts/generate_version2_vectors.py
python scripts/generate_version2_vectors.py --check
```

## Assertion vocabulary (normative)

An `expect` map compares only the fields it names. Common fields are `status`,
`disposition`, `config`, `variables`, `history`, `emissions`, `components`,
`owned_instances`, and `fault`. `caller_still_owns_input` verifies that a faulting
envelope remains caller-owned rather than becoming engine queue or dead-letter state,
as required by specification §10.1. When named, `components` and `owned_instances`
compare collection membership exactly, including an asserted empty collection; fields
inside each listed member may still be partial.

`state_bytes_unchanged: true` strengthens a version-1 caller-owned `deferred` result:
the implementation must compare the complete serialized state before and after dispatch
and require byte-identical state, not only the partial fields named by the fixture.

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
The assertion-only value `{ normalized_double: positive_zero }` requires an actual
binary64 zero with its sign bit clear. It may appear recursively anywhere a scalar
value is asserted and is never a literal expected map. `caller_still_owns_state`
verifies that an invalid-prior-state dispatch did not mutate the malformed state value
supplied by the driver. It is the state-only counterpart of
`caller_still_owns_input`.
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

## Optional profiles

The black-box runner is preserved at `conformance/profiles/cli/run_cli.py` as
non-normative profile infrastructure. No CLI profile cases currently ship. The previous
fixtures asserted legacy public fields and a core-owned FIFO queue with manual stepping,
which contradict format 1's plugin boundary.

A later, separate issue may define commands, exit codes, and JSON shapes for
implementations that declare a CLI profile, without queue introspection. Until then,
the absence of CLI cases is intentional and no CLI surface is portable conformance.

The `execution-checkpoint` profile fixes the portable SPEC §17 durable-host lifecycle
over the schema-version-2 checkpoint artifact. It covers native creation, ordered-batch
admission and its exact failure precedence, processing, replay, outbox transitions,
pruning, root identity, spawned-runtime traces, exact adapter scheme grammar,
profile-derived capabilities, relational store-scope isolation, and keyed maintenance migration. The persistence
profile adds the six required host transaction traces. Both bind only hosts that
declare them and do not standardize storage or a public API. See the profile READMEs.

## Coverage

| case | portable behavior |
|---|---|
| 01 | guarded leaf dispatch and unhandled disposition (§6) |
| 02 | ancestor handling and composite self-reset (§6) |
| 03 | initial-transition actions (§4, §6) |
| 04 | UML level-by-level event deferral, direct version-1 caller ownership, grammar, capacity, and guard precedence (§4, §6, §8) |
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
| 21 | historically absent; portable aggregate encoding now begins at case 94 |
| 22 | historically absent; definition migration now begins at case 99 |
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
| 62 | runnable YAML 1.2 `no`/`off`/`yes`/`on` string identity plus exhaustive noncanonical Boolean/null and numeric scalar rejection (§2, §4, §6) |
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
| 81 | bound-child lifetime survives holder clearing/reuse and retains canonical cleanup order (§7) |
| 82 | spawned targets match every nominal `instance_reference` field (§4, §6) |
| 83 | a contained runtime dynamically targets its eligible owned instance using the nominal reference (§4, §7) |
| 84 | choice-action `stop` abandons the selected target and remaining choice chain (§6) |
| 85 | component/spawn initialization faults roll back author intents and output allocations (§9, §10) |
| 86 | last-component initialization orders `component_completed` immediately before parallel `done` (§7, §9) |
| 87 | internal `env` delivery is accepted only for a component target (§6) |
| 88 | malformed fixed lifecycle payloads reject before handler selection (§4, §6) |
| 89 | recursive non-finite host-value rejection during creation (§5, §8) |
| 90 | recursive host numeric validation, negative-zero normalization, and prior-state rejection (§5, §8) |
| 91 | ordinary host input to a live component rejects with `invalid_instance_target` (§6, §8) |
| 92 | aggregate-root fault terminality overrides retained component target status (§6, §8) |
| 93 | non-correlating input and internal envelopes may carry optional correlation ids (§6) |
| 116 | legacy definition discriminator policy: 0.0.1–0.0.6 rejection, explicit-format structural rejection, and 0.0.7/current format-1 acceptance (§2) |
| 117 | runtime-local ready/deferred mailboxes, explicit one-step processing, recall, capacity, isolation, and lifecycle outcomes (§6–§10, §16.15) |
| 118 | schema-version-2 aggregate creation, admission, stepping, migration, canonical bytes, and migration totality (§16) |

## Deliberate format-1 boundaries

- Parallel behavior uses isolated components; regions and implicit broadcast do not
  exist.
- Portable aggregate-state schema version 2 owns accepted ready and deferred envelopes;
  external broker retry and acknowledgement remain host policy.
- Time behavior uses declared external requests and later correlated inputs. The core has
  no clock or timer.
- Separate named contracts are replaced by bundle public event declarations.
- Submachines are replaced by explicit lifecycle-bound components or owned spawning.
- Portable aggregate encoding and declarative definition migration use the sole
  schema-version-2 JSON artifacts in SPEC §16; they do not change machine `format: 1`.
- Package imports and dependency/version resolution remain unsupported.
- Production store protocols, CLI JSON, queue inspection, enabled-event lists, and
  visualization output are implementation/host surfaces rather than portable core
  behavior. The optional execution-checkpoint and persistence durable-host profiles
  bind only hosts that declare them.

## License

MIT — see [LICENSE](LICENSE).
