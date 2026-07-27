# AGENTS.md — determa-state-conformance

Guidance for AI/coding agents working in this repository. (Tool-agnostic; not specific to any one assistant.)

## What this repo is
The **language-agnostic conformance suite** — the executable definition of *correct*
Determa State behavior. This repo, not any single implementation, is the arbiter (SPEC §2).
Layout:
- `conformance/01`–`NN` — **engine** cases: each `<case>/` has `machine.yaml` (the
  format-1 bundle) and `test.yaml` (a scenario or static validation assertion).
- Additional bundle files are allowed only when `test.yaml` names them explicitly.
- `VERSION` — the synchronized spec version this suite targets.

**No CI here.** Correctness is exercised by each implementation's harness, which fetches
this suite at the release tag matching its version.

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
| **determa-state-conformance** (this) | the conformance suite. No CI. |
| determa-state-python | Python impl (dist `determa-state`, import `determa.state`). |
| determa-state-rust | Rust impl (crate `determa-state`). |
| determa | umbrella launcher (`python/`, `rust/`, `node/`). |

## Working rules (every Determa repo)
- **One issue → one PR**, branch → PR → **squash-merge**, linear history, resolve threads; `main` protected.
- **No AI/assistant attribution** anywhere (commits, PRs, comments, docs).
- **Conformance-first:** spec text → the case here → implementations. This repo is where a new behavior is pinned executably.
- **Synchronized SemVer** with spec + impls (currently **0.0.6**).
- **No new abbreviations** in public JSON/identifiers. Format 1 uses `variables`,
  `machine_id`, `component_id`, and explicit `spawn.machine_id`; established keywords
  such as `config`, `lang`, `meta`, and `on_events` remain intentional.

## Running the suite locally

Engine cases are driven by each implementation's own harness. A `send` performs one
core dispatch. Returned emissions are delivered only through an explicit later
`deliver` step, so the suite fixes an input trace without standardizing a queue plugin.
There is no standalone runner or CI in this repository.

## Releasing
Bump `VERSION`, tag `vX.Y.Z` after merge. Implementations pin the suite at that tag
(python fetches it into `.cache/`; rust as a git submodule that CI force-pins to the tag).

## Pointers
- Coverage table + case index: `README.md`.
- Fixture conventions: `README.md`. The spec it targets: `determa-state-spec/SPEC.md`.
