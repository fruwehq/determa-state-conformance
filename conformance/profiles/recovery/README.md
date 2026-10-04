# Recovery profile (§24)

`recovery-01-scope-lifecycle` pins all 39 ordinary and 3 early normative
recovery cases from the merged specification. The source validator checks both
complete archives, closed version-1 schemas, all request and record digests,
checkpoint and participant continuity, the trusted stage receipt, transfer
proofs, and exact case inventory. The local transfer archive retains the same
real definitions, migrated checkpoint, queues, deferred events, counters,
receipts, effects, intents, outbox, and helper participant as the merged §22
archive. The base core needs no authority coordinator or background service.

Six additional cases use a generated two-root archive from the merged §17 and
§22 lifecycle helpers. One root owns a spawned child with a deferred event and
an attempted ambiguous effect; the other has two nested component runtimes.
The resolver checks both complete machine definitions and checkpoint bytes.
Four more cases use a newly allocated destination with a previously consumed
external namespace, both while the first scope is allocated and after its
production termination. They cover standalone takeover and clone separately.

An implementation claims this optional profile only after running
`scripts/run_recovery_profile.py --spec-root SPEC --bridge-registration REGISTRATION
-- BRIDGE` against its real
configured host. The runner creates a fresh driver-owned native store for each
case. It invokes the child separately for the I1 stage, each I2 setup request,
an optional production scope termination, and the tested I2 request, all against
that same store. The child receives the complete actual input, public store
command and database path, never a case ID, expected result, or expected after
state. It must invoke production operations and return literal caller responses
and native transaction identities. The runner reads the store independently
after each child call, checks exact stage and recovery commits and transaction
fates, and computes before/after changes itself. Every operation also needs a
start and return entry in the driver-owned invocation journal from a reviewed,
source-anchored language-native bridge. The trusted runner caller supplies a
closed registration with reviewed bridge source, installed engine/build and
dependency anchors, public operation entrypoints and effective configuration.
The candidate child cannot select that registration. No production registration
is bundled because no I2 engine bridge exists yet. An arbitrary adapter command
cannot claim production success.
The registration format in `scripts/run_recovery_profile.py` is a conformance
driver contract. A trusted Python or Rust harness supplies its exact installed
source/build, dependencies, features, factory, public entrypoints and effective
configuration. Python bridges run with `-I -S` and explicitly resolve their
verified installation paths. Its reviewed bridge must resolve the *loaded* implementation,
invoke those public operations, and journal their literal returns; the store
receipt alone proves durability, not production origin. Dynamic source or
dependency substitution fails closed. This driver contract does not prescribe
an engine API, host database schema, or cross-language production plugin ABI.
A successful
takeover or clone requires its own fresh logical scope and external namespace;
strict restore is quarantined. Refusals and read-only guards leave all observed
storage unchanged. Unknown external work remains ambiguous and cannot be
automatically redispatched.
The observation lists contain complete checkpoint and participant objects,
permanent scope and namespace allocation identities, operation ledger identities,
worker claims, authoritative inventory and transfer proofs. The runner checks
their before/after bytes and forbids new external dispatch or ingress
acknowledgement during recovery itself.

The production runner currently exercises 42 standalone and refusal cases;
the 10 local transfer cases remain source-validated only. Their successful result may be
advertised only after the same configured host independently passes the §18
authority, §19 effect, and §21 delivery production profiles for its exact
installation, topology, provider closure, authority token, and required
participants. The timer profile applies only when a timer participant is
declared. The merged §21 delivery runner supplies the hosted proof gate.
Cross-authority safe relocation is unavailable without separately
proved continuity. Static fixture success is never a production certificate.

For an advertised local single-authority topology, the host runs
`scripts/run_hosted_recovery_profile.py --spec-root SPEC --adapter HOST
--authority-adapter AUTHORITY --recovery-bridge BRIDGE
--recovery-bridge-registration REGISTRATION
--source-lifecycle-plan PLAN`. This gate requires the same actual configured
installation to pass the §18/§19/§21 native runner. It verifies the merged
runner's same-run proof summary, including its unique parent run, C/D native
proof IDs, H durable store proofs, report digests and actual installed store and
transport sources. It binds those identities and the loaded recovery
closure/configuration and observed authority token to the §24 report, then executes all 42
normative, 6 two-root, and 4 namespace reuse requests. The ten local cases require durable transfer
proofs, a frozen full inventory, known native transaction fate, retired source,
single-use grant, imported checkpoint/participant bytes, and unchanged state on
refusal. A successful run requires a real production I2 adapter and is not
claimed by this repository's source checks.
For each local case, the trusted runner-selected plan drives source
configuration, allocation, root creation, admission, stepping, journal writes
and a worker claim through the reviewed production bridge. Its separate native
observer must find the exact source scope and root instances, complete source
checkpoints, host journals and participants in the same configured store. The
live source epoch and generation must match the transfer proof before freeze.
The complete frozen source inventory must remain byte-identical through archive
staging, preparation, transfer staging, retirement and activation; retirement
may change only its proved authority fields and append its native ledger entry. A
guarded freeze must revoke the actual worker and retain a native transaction
and complete inventory proof before `prepare_transfer`. A production §22 export
must read that frozen source and return the exact local archive; the export is
read-only in host state. The in-doubt case injects a native process cut after
the retained export and requires an unresolved source fate before its prepare
refusal. Commit must retire that same source and fence old writers in its native
transaction. The source plan contains operations, never preseeded checkpoints,
records or an expected after-state. Generic C/D/H capability proofs alone do
not establish this particular source.
No host may report `safe_relocation` from the static fixture or by copying a
requested profile claim. The standalone runner never certifies local transfer.

Run local source checks with:

```sh
python scripts/generate_recovery_profile.py --spec-root SPEC --check
python scripts/test_recovery_validator.py --spec-root SPEC
python scripts/validate_conformance.py --spec-root SPEC
```
