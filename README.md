# Determa State — conformance suite

The **language-agnostic conformance suite** for the
[**Determa State**](https://github.com/fruwehq/determa-state-spec) statechart engine.

This repository — not any single implementation — is the normative definition of
**correct behavior**. The prose specification lives in
[`fruwehq/determa-state-spec`](https://github.com/fruwehq/determa-state-spec) (`SPEC.md`, the JSON Schema, and
examples); this repository holds the **executable correctness target** that every
implementation (e.g. [`fruwehq/determa-state-python`](https://github.com/fruwehq/determa-state-python))
must pass. Where prose and the suite disagree, **the suite wins** (SPEC §2) and a bug is
filed against the spec.

> **Format 1 migration status:** the current fixture corpus targets the pre-format-1
> grammar and is not authoritative for format 1 until the migration tracked by issue
> #21 lands. During that interval, format-1 prose/schema conflicts must be resolved
> against the specification rather than these legacy fixtures.

Implementations consume this repo as a **pinned git submodule** (single source of truth,
no copy-paste drift).

## Layout
- `conformance/01`–`30` — **engine** cases (SPEC §9). Each `<case>/` has:
  - `machine.yaml` (or versioned `v*.yaml` for migration) — the definition(s),
  - `test.yaml` — the scenario (`steps:` of `send`/`advance`/`upgrade` + `expect`),
  - `contracts/*.yaml` — optional, for contract cases.
- `conformance/cli/<case>` — **CLI** cases (SPEC §13.6): a `cli.yaml` of steps plus the
  referenced `machine.yaml`, covering the standard CLI surface and batch/streaming mode.
- `conformance/run_cli.py` — the **black-box CLI runner**: it shells out to any
  implementation's `determa-state` binary as a subprocess (so it is language-agnostic).

## Running

**Engine cases** are driven through each implementation's own harness (it loads the
definitions, creates the root, runs each `test.yaml` step to quiescence, then checks
`expect`). See SPEC §9 for the format.

**CLI cases** run black-box against the built/installed binary:
```sh
python conformance/run_cli.py --cmd "determa-state"            # or "python -m determa.state", "node …"
python conformance/run_cli.py --cmd "determa-state" 01-turnstile   # one case
```
`--cmd` is the command that invokes the implementation's CLI (shell-quoted); optional
positional case names restrict the run. Exit code is non-zero on any failure.

## Coverage
| cases | covers |
|---|---|
| 01–04 | guards, ancestor handling, initial-transition actions, deferred-set |
| 05–08 | esvs scope/shadow/re-init, typed payloads, transition kinds + ordering |
| 09–12 | orthogonal regions + `done`, shallow/deep history, first-match-wins |
| 13–15 | spawn + directed/subscribed publish + scope, `external`/`env`/`refresh` |
| 16–20 | timers, faults + dead-letter, static contracts (pass/fail) |
| 21–22 | snapshot round-trip, safe-point migration |
| 23–25 | choice pseudostates — dynamic branch, chained choices, no-`else` rejected (§5.5.1) |
| 26–28 | static validation — unreachable state, dead branch, reachable-ok (§2) |
| 29–30 | submachine states — synchronous reuse + completion, parent interrupt (§5.6.1) |
| 31 | enabled-events introspection from active configuration (§14) |
| cli/01–03 | CLI surface + JSON shapes, batch/streaming mode, and manual stepping/inspection (§13.6/§13.7/§14) |

## License
MIT — see [LICENSE](LICENSE).
