# Committed native effects and authenticated results (unreleased 0.3)

This optional profile targets SPEC §19 at immutable specification commit `6bd25e3fcdf068af861aa289903a8489bd8f0139`. Its 39 driver vectors use a real format-1 workflow. The generated checkpoint contains a selected and committed external intent; its effect ID, typed payload, correlation token, exact target incarnation, and complete intent digest are derived from the same core emission. `native_succeeded` and `native_cancelled` are declared input events in that definition. Result admission adds the complete pinned envelope and acceptance receipt to a new checkpoint. The journal remains a separate host-owned artifact whose checkpoint reference, revision and digest are checked together. Confirmed outbox acceptance leaves the business invocation outstanding.

The `data/vectors.json` manifest pins every source JSON example under the specification's `examples/effects/` directory by raw SHA-256 and maps every named case in the three normative case lists to a driver vector. Those examples remain source provenance: the specification's committed-effect checkpoint is explicitly synthetic and is never given to a production adapter as a restored machine state. The profile's generated checkpoint and journal are its executable fixture. The validator enforces strict JSON decoding, Draft 2020-12 schemas, journal digests, intent and target binding, source closure, complete receipt/envelope linkage, and closed vector input and observation fields. The generator refuses a changed output under `--check`.

The handler files provide Python and Rust equivalents for a native destination call. Each constructs an internal SDK-style response object and emits only portable report fields. Their raw source hashes are pinned. Production adapters must load and independently verify the implementation they actually execute. The driver passes the source files as inputs; they do not authorize a host handler by themselves. Scope, worker principal, current authority epoch, live claim, route authorization, trusted time, and handler allowlisting must come from the configured production host. The driver fault fields are one-attempt crash injection points, not machine events or public host wire fields.

Run the source, fixture, and adversarial gates with:

```sh
python scripts/validate_conformance.py --spec-root <pinned-spec>
python scripts/test_committed_native_effects_validator.py --spec-root <pinned-spec>
python scripts/generate_committed_native_effects_profile.py --spec-root <pinned-spec> --check
```

For an operational claim, run each implementation's production host adapter:

```sh
python scripts/run_committed_native_effects_profile.py --spec-root <pinned-spec> --adapter '<production-adapter-command>'
```

The runner starts a fresh adapter process for each vector and sends only the complete prior checkpoint, journal, current claim, auth context, operation arguments, fault boundary, and source files. It withholds vector names, source coverage labels, expected effect IDs, output states, response bodies, and oracle files. The adapter returns a full canonical UTF-8 JSON response, complete canonical checkpoint and journal bytes before and after, concrete provider/core/claim call evidence, and the loaded machine and handler source hashes. The runner compares all available exact artifact and response oracles; rejected operations must retain identical before/after bytes and have no provider or core calls. A null response oracle marks a host driver action whose public response is not fixed by this fixture; state and call evidence remain exact. The adapter must invoke production claim, dispatch, result, cancellation, recovery and journal paths; projecting an answer from the fixture request is not a conformance run.

The common source/schema gate does not certify an actual host or either language engine. Runtime certification requires independent configured-instance authority, handler trust and destination deduplication proof, followed by real adapter runs for both Python and Rust. No adapter or such capability certificate is bundled here.
