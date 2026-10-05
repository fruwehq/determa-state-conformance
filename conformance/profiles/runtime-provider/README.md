# Exact runtime provider and source compilation profile (unreleased 0.3)

This optional profile targets SPEC §5.4 and the common §11.5 registration boundary at immutable specification commit `77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0`. Its 44 vectors exercise exact installed identity, transitive source closure, weak native execution, action output validation, safe inspection, source compilation, and restoration. CEL guards and structured actions remain mandatory core behavior. Hosts advertise this profile only after running the vectors through their production provider registration, resolver, loader, evaluator, compiler and host commit paths. Source/schema validation alone is not operational certification.

`provider/test_provider.py` and `provider/test_provider.rs` are executable equivalents. `provider-closure.json` records the exact raw source byte hashes. A provider `content_digest` is SHA-256 over `determa-test-runtime-provider-closure-1\0` followed, in Python then Rust order, by each eight-byte big-endian path length, UTF-8 path bytes, eight-byte big-endian source length, and raw source bytes. `source_digest` hashes the canonical closure JSON bytes. The `example.native-common` reference is a required transitive dependency, even though the test source has no third-party package dependency. A production adapter must independently verify that the actually loaded or compiled code and its complete dependency closure match these bytes, that the exact descriptor is installed, trusted and healthy, and that the configured host policy proves each positive capability. A path or digest copied from the request is not proof. Changed, missing and untrusted closures fail before creation, evaluation, migration target activation or restoration, with no alias substitution or automatic recompilation.

The files named `norm-*` preserve all fourteen specification provider examples byte for byte, including the original YAML source. That YAML's unquoted `1.0.0` does not satisfy this suite's strict YAML 1.2 lexical rule; the exact original is kept as `.source`. `machine.yaml` and `machine-safe.yaml` are strict format-1 test bundles with exact fixture closure bindings. `source-package.json` and `source-manifest.json` adapt the original language source and manifest examples to the executing compiler reference, recompute their typed artifact digests, include the exact compiler dependency closure, and bind the generated strict bundle fingerprint. Direct runtime slots need no compiler. The generated CEL definition restores from its exact validated fingerprint and supplied source/manifest provenance with an empty installed provider registry; no compiler is invoked. Direct native restoration requires runtime references and their transitive dependency, while an installed compiler cannot replace a missing runtime provider. Fresh compilation requires the exact compiler closure. Installed references are the sole installed-presence input; no separate Boolean switch can contradict the registry. The original examples remain separate provenance artifacts.

The weak profile deliberately allows a native provider to perform external I/O before a Determa commit. It discloses false deterministic, pure, portable, semantic inspection and process containment guarantees, and true external I/O possibility. A strong host profile refuses that configuration. A failed action or compare-and-swap attempt leaves the native irreversible effect recorded while Determa state remains uncommitted. The compare-and-swap vector permits exactly one attempt and no automatic reevaluation or retry. Provider input is an immutable snapshot of portable typed values. The Python `ExternalReply` and Rust `ExternalReply` stand in for SDK or protobuf objects that stay inside the provider; only Boolean guard results and structured typed action proposals cross the boundary. Both the machine's external send and the provider's external send proposal carry the stable nonempty `provider-correlation` token required by SPEC §5.3. The base machine remains in its reachable pending state. Separate bundles compare native and ordinary root assignments before final completion, reject writes to destroyed local scopes on event, choice and initialization paths, and capture complete guard/action snapshots. Initialization has no prior aggregate: a rejected creation returns a fault diagnostic without committing state or proposals. The invalid output vector keeps the ordinary `action_fault` core fault and records `runtime_provider_output_invalid` as a boundary diagnostic. Action proposals cannot inject lifecycle operations.

Semantic inspection calls only a separately verified bounded `inspect_guard` entrypoint. `machine-safe.yaml` reaches that guard directly, so one guard evaluation and two steps cover the native call itself. The provider inspection entry does not mutate any of its fields; the host traces invocation and fuel outside provider state. The source tests compare the entire provider state before and after successful and exhausted inspections. An unsafe guard fails during preflight, including when a CEL branch precedes it; zero ordinary provider evaluations occur. Structural inspection only reports the binding. Effective guarantees are the AND of every participating CEL/compiler/runtime provider and host policy, except external I/O possibility, which is OR with unknown treated as possible.

Run the structural and relational gates with:

```sh
python scripts/validate_conformance.py --spec-root <pinned-spec>
python scripts/test_runtime_provider_validator.py --spec-root <pinned-spec>
python scripts/generate_runtime_provider_profile.py --spec-root <pinned-spec> --check
```

For operational certification, run:

```sh
python scripts/run_runtime_provider_profile.py --spec-root <pinned-spec> --adapter '<production-adapter-command>'
```

The runner sends each adapter invocation a fresh JSON object containing only `request`, `profile_root`, `source_files` and `source_closure_file`. The temporary `profile_root` contains only that operation's input files. It never sends a vector name, expected observation, oracle file, or case ID. The adapter must execute the complete `request` through production surfaces and return exactly `observation`, `loaded_source`, and `loaded_closure_digest`. `observation` records every stage, result, code, output value, provider call count, external call count, irreversible side effect record, Determa commit status, complete declared state projection before and after the call, and effective capability report. `loaded_source` maps each actually loaded or compiled language source to its SHA-256; the adapter verifies the complete declared two-file closure independently. It is empty for generated CEL restoration, which executes no provider. These are driver observations, not public wire fields. The runner rejects duplicate JSON members, non-finite values, wrong field types, and any recursively unequal observation. The adapter may project language-specific API shapes into these fields but cannot reconstruct an observation from `expected`, vector identity, or source hash alone. Each vector starts with a fresh provider instance and state. A positive profile claim requires the adapter run and independent configured-instance capability proof; this repository does not contain a production adapter.

Repeated sends from one native slot use the containing action-element pointer and
continuing local ordinals; the operational vector checks exact IDs, sequences and
receipt indexes alongside the resulting state. A separate durable vector commits all three intents, checks the terminal receipt references and pending outbox, then replays the original request with its original checkpoint identity. Replay must return the same terminal receipt without changing checkpoint bytes or reentering either provider. Positive and duplicate-ID negative
normative examples have independently recomputed hashes. The inert metadata/map
value vector proves that provider-like keys outside executable grammar slots do not
require code installation. Both fixture languages produce the actual repeated-send
result from their source closure.

The mixed-send vector interleaves two external and two internal proposals before an ordinary external send. It checks independently derived effect and event IDs, separate local ordinals, retained internal mailbox references, and the unchanged ordinal reset of the following ordinary slot. Durable replay compares the complete retained effect references and pending outbox entries, including IDs, local indexes, sequences, payload, correlation, revision and delivery state.

Compiler preflight accepts only executable grammar slots. For `invalid_slot:
metadata_guard`, the adapter copies the source template, inserts `meta.guard:
"true"`, and changes the sole region locator to `/meta/guard`. For
`invalid_slot: variable_action`, it inserts the root variable declaration
`data: {type: map, init: {action: []}}`, changes the region kind to `actions`,
and uses `/machines/0/root/variables/data/init/action`. In each case it reseals
the modified source artifact and supplies no compilation manifest. Both are
rejected during source preflight, before resolution or any compiler invocation;
matching the last pointer token is insufficient. The `compile_region` call count
is measured at the actual entrypoint, including failed invocations.

The `weak_compiler` input withholds positive compiler capability proofs while
retaining the exact trusted source closure. The fixture still compiles the same
CEL guard. With `without_manifest: true`, successful compilation must retain the
source digest, compiler dependency references, generated fingerprint, and weaker
effective source capability report in its returned compilation evidence. The
adapter reports that evidence from the production return, then independently
loads and restores the generated CEL definition with no installed compiler.
Its runtime capability reports remain strong, and restoration invokes no compiler.
Historical compilation guarantees do not become generated-core requirements.
