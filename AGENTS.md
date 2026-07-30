# AGENTS.md — determa-state-conformance

Guidance for AI/coding agents working in this repository. (Tool-agnostic; not specific to any one assistant.)

## What this repo is
The **language-agnostic conformance suite** — the executable definition of *correct*
Determa State behavior. The core tier in this repo, not any single implementation, is
the arbiter (SPEC §2).
Layout:
- `conformance/core/01`–`NN` — **core engine** cases: each `<case>/` has
  `machine.yaml` (the format-1 bundle) and `test.yaml` (a scenario or static
  validation assertion).
- Core persistence cases use a closed `persistence_vectors` driver mode plus strict
  JSON artifact manifests. Exact returned-byte expectations are compared byte-for-byte;
  successful non-no-op operations normally return canonical JSON, while an empty-route
  migration no-op preserves the supplied aggregate envelope bytes exactly.
- `conformance/profiles/<profile>/` — optional non-core compatibility surfaces. They
  bind only implementations that declare the profile and never override core prose.
- The execution-checkpoint profile uses a closed `execution_checkpoint_profile`
  vector driver plus strict checkpoint artifacts. It fixes portable host transaction
  results and before/after bytes without defining a language API, store schema, worker,
  daemon, or socket protocol.
- Additional bundle files are allowed only when `test.yaml` names them explicitly.
- `VERSION` — the synchronized spec version this suite targets.

Repository CI parses every fixture with YAML 1.2 or strict JSON, checks its declared
structural result against immutable specification-schema pins, verifies portable
artifact digests, and compares canonical-byte goldens. Runtime behavior is still
exercised by each implementation's harness, which fetches this suite at the release
tag matching its version.

## Determa in one paragraph
**Determa** is a family of tools for defining/running well-specified, verifiable behavior.
Its first product, **Determa State**, is a language-agnostic **statechart engine**
(Harel/UML lineage, PSiCC RTC semantics): one YAML/JSON machine runs identically under any
implementation because all are validated against *this* suite. Guards/action values are
**CEL**. An umbrella `determa` launcher dispatches `determa <product> …` → `determa-<product>`.

## Repositories (org `fruwehq`, local folders under `~/src/personal/`)
| Repo | Role |
|---|---|
| determa-state-spec | normative prose spec + schema. No CI. |
| **determa-state-conformance** (this) | conformance suite + source/schema consistency CI. |
| determa-state-python | Python impl (dist `determa-state`, import `determa.state`). |
| determa-state-rust | Rust impl (crate `determa-state`). |
| determa | umbrella launcher (`python/`, `rust/`, `node/`). |

## Working rules (every Determa repo)
- **One issue → one PR**, branch → PR → **squash-merge**, linear history, resolve threads; `main` protected.
- **No AI/assistant attribution** anywhere (commits, PRs, comments, docs).
- **Conformance-first:** spec text → the case here → implementations. This repo is where a new behavior is pinned executably.
- **Synchronized SemVer** with spec + impls (currently **0.1.0**).
- **No new abbreviations** in public JSON/identifiers. Format 1 uses `variables`,
  `machine_id`, `component_id`, and explicit `spawn.machine_id`; established keywords
  such as `config`, `lang`, `meta`, and `on_events` remain intentional.

## Running the suite locally

Core cases are driven by each implementation's own harness. A `send` performs one core
dispatch. Driver-only `capture_emissions_as` and `deliver` steps fix the input trace
without standardizing a queue plugin or requiring equivalent public engine APIs.
Assertions in `expect`, including `caller_still_owns_input`, are normative. There is no
standalone core runtime runner in this repository.

Persistence vectors exercise the pure aggregate encode, decode, package, migration,
and migrate-then-dispatch boundaries from SPEC §16. Their operation names are
driver-only adapters; named result files, exact returned bytes, audit records,
emissions, resolver results, dispositions, and failure codes are normative. The
optional persistence profile fixes host transaction traces without standardizing a
database schema or production store API.

Execution-checkpoint vectors exercise SPEC §17 creation, acceptance, processing,
receipt replay, writer compare-and-swap guards, retention, root lifecycle, and durable outbox
transitions, plus only the portable adapter-registry and composed-capability results.
Replay repeats the original operation with its exact input; never add a synthetic
replay or compare-and-swap operation. Existing-checkpoint writers must name their exact
expected revision and digest. Named before/after checkpoint artifacts, operation-input
and core-result references, exact response fields, mutation classification, core-call
classification, canonical bytes, digests, and failure codes are normative.
Operation inputs and core evidence use their dedicated closed schemas; do not regress
them to generic `json_value` artifacts. Bind bundle bytes/fingerprints and every core
projection to the exact cited input. Coverage names are validated behavior claims, not
free-form annotations. Configuration validation must precede adapter capability
evaluation.

The durable source/schema validator uses YAML 1.2 and the specification's Draft
2020-12 schema:

```sh
python -m pip install --requirement scripts/validation-requirements.txt
python scripts/validate_conformance.py --spec-root ../determa-state-spec
```

The workflow uses the same command against an explicitly pinned specification commit.
The execution-checkpoint generator and independent Python/Rust verification method are
documented in its profile README. Durable validation proves fixture construction,
schema dispositions, cross-artifact semantics, and generated core-result linkage; it
does not replace each implementation's runtime harness.

The non-normative CLI profile runner is retained at
`conformance/profiles/cli/run_cli.py`, but no CLI profile cases are currently defined.

## Releasing
Bump `VERSION`, tag `vX.Y.Z` after merge. Implementations pin the suite at that tag
(python fetches it into `.cache/`; rust as a git submodule that CI force-pins to the tag).

## Pointers
- Coverage table + case index: `README.md`.
- Persistence host profile: `conformance/profiles/persistence/README.md`.
- Execution-checkpoint profile:
  `conformance/profiles/execution-checkpoint/README.md`.
- Fixture conventions: `README.md`. The spec it targets: `determa-state-spec/SPEC.md`.
