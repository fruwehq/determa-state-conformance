# Committed native effects and authenticated results (unreleased 0.3)

This optional profile targets SPEC §19 at immutable specification commit `77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0`. Its 43 driver vectors use a real format-1 workflow. The generated checkpoint contains a selected and committed external intent; its effect ID, typed payload, correlation token, exact target incarnation, and complete intent digest are derived from the same core emission. `native_succeeded` and `native_cancelled` are declared input events. Result admission adds the complete pinned envelope and receipt to a new checkpoint. The separate host journal binds that checkpoint by revision and digest. Confirmed outbox acceptance leaves the business invocation outstanding.

`data/vectors.json` pins every JSON source example under the specification's `examples/effects/` directory by raw SHA-256. It maps all 30 named cases in the three normative case lists to executable vectors. The validator checks their request differences, response status and error code, admission, claim, provider and mutation counts, expiry and auth premises, and linked follow-up obligations. The specification's example committed-effect checkpoint is explicitly synthetic; the production runner receives only this profile's valid generated machine and checkpoint.

`data/handler-closure.json` hashes both handler source files with a domain-separated length-prefixed raw-byte algorithm. The pinned journal provider reference uses that closure digest. `data/destination-configuration.json` supplies exact connector configuration bytes, whose digest pins the immutable destination without containing credentials. Python and Rust handler variants each construct an internal SDK-style response object and emit portable report fields. An adapter must verify the installed closure, select and report the variant it actually executes, and supply current authorized credentials independently of these inputs.

The route-generation vector uses a live seven-action control sequence: start a producing operation at generation 7, observe route resolution, let the core evaluate and propose checkpoint/journal bytes, block before the native commit guard, change the configured generation to 8, then release and observe rollback. The runner makes separate adapter calls at each barrier and checks the same live session, resolved route, complete proposed digests, guard refusal and native transaction identity. The old operation replay supplies its original request and checkpoint precondition and requires the exact retained full response after the alias changes. Separate crash attempts require `no_response`; subsequent recovery runs use retained outcome evidence and need no old worker lease. Internal operations with no fixed public response require closed `completed` or `aborted` caller evidence and a null response byte field. All specified public result and cancellation responses are compared in full.

The runner first reads the **actual configured** effect and §18 authority reports, their raw installed handler, destination, authority and participant closure/configuration bytes, and observed health. It binds every native operation proof to that report, the authority epoch, topology, guarded transaction fate, selected source variant, pinned route, and scoped destination idempotency key. After the probes it requires the unchanged report, all newly observed proof IDs, and equal nonempty receipt bytes from a repeated call to the scoped fake destination. Host-configured test controls and hypothetical source examples never count as this operational proof. The D runner first executes the §18 production runner for the same installed authority provider and requires its worker SQLite topology. It checks unchanged C report bytes and binds D's authority extension, topology configuration, storage boundary, participants and guarantee claims to that proved installation. The effect adapter then supplies its own actual configured report and D native operation proofs. The trusted harness must observe its real database, worker claims and fake destination; copied claims or test-control booleans never constitute proof.

Run the source, fixture, and adversarial gates with:

```sh
python scripts/validate_conformance.py --spec-root <pinned-spec>
python scripts/test_committed_native_effects_validator.py --spec-root <pinned-spec>
python scripts/generate_committed_native_effects_profile.py --spec-root <pinned-spec> --check
```

Run a configured production adapter with:

```sh
python scripts/run_committed_native_effects_profile.py --spec-root <pinned-spec> --adapter '<effect-adapter-command>' --authority-adapter '<authority-adapter-command>'
```

The adapter receives prior checkpoint, journal, current claim, trusted harness controls and source files. It never receives a vector name, expected response or state, source coverage label, or oracle file. It returns canonical full checkpoint and journal bytes before and after, caller completion/abort/no-response evidence, applicable full public response bytes, concrete provider/core/claim calls, installed source identity, and native guard and destination proof. A passing source/schema gate does not certify a production host. No production adapter or runtime certificate is bundled here; Python and Rust must each pass their real configured instance before either claims this profile.
