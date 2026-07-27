# Contributing to Determa State conformance

This repository is the language-agnostic executable correctness target for the
format-1 Determa State specification.

## Adding or changing a case

Add one narrowly focused directory under `conformance/`:

- `machine.yaml` contains the primary format-1 bundle;
- `test.yaml` contains the execution trace or static-validation assertion; and
- additional bundle documents are allowed only when `test.yaml` names them explicitly.

Every host-facing event belongs in bundle `events` with `direction: input` or
`direction: output`. Machine-local events are private and `internal`. Internal delivery
must be explicit: retain a returned emission and deliver that exact envelope in a later
step rather than assuming broadcast or recursive queue processing.

Use the exact error code for static semantic rejection. A structural rejection uses
`structural_validation`. Ordering-sensitive behavior should make entry, exit, and
transition actions observable through a trace variable.

## Validation

Before opening a pull request:

1. parse every YAML file as YAML 1.2;
2. validate every positive bundle against the current specification schema;
3. confirm structural-negative documents fail that schema;
4. check semantic-negative fixtures name the exact expected error;
5. check all retained public vocabulary is format 1;
6. keep `VERSION` synchronized and unchanged unless a release is explicitly authorized;
   and
7. run `git diff --check`.

There is no CI or standalone runner here. Engine cases are executed by each
implementation's harness after the specification and conformance changes land.

## Workflow

1. Create one issue and one branch for one pull request.
2. Branch from `main`; never push directly to protected `main`.
3. Land specification text first, conformance second, and implementations last.
4. Squash-merge only after every review thread is resolved.
5. Do not include assistant attribution in commits, pull requests, comments, or docs.

## License

Contributions are made under the project's [MIT license](LICENSE).
